package main

// Pre-Build Doctor — slice 1: detect the recurring build-drift classes before a
// build runs. Read-only checks over a checkout; see docs/plans pre-build-doctor.
// Runs where a checkout exists (this CLI / a runner job) — the server is a CF
// Worker with no filesystem, so checks cannot live there.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The expo slug is a static string literal in app.config.* / app.json even when
// the rest of the config is dynamic — enough to map a checkout to a fleet app.
var expoSlugRe = regexp.MustCompile(`["']?slug["']?\s*:\s*["']([a-zA-Z0-9._-]+)["']`)

// The EAS project id is a static UUID literal — the canonical app identity,
// more reliable than slug for mapping a checkout to a fleet app.
var expoProjectIDRe = regexp.MustCompile(
	`["']?projectId["']?\s*:\s*["']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']`,
)

type doctorSeverity string

const (
	doctorOK     doctorSeverity = "ok"
	doctorWarn   doctorSeverity = "warn"
	doctorBroken doctorSeverity = "broken"
)

type doctorFinding struct {
	Check    string         `json:"check"`
	Severity doctorSeverity `json:"severity"`
	Message  string         `json:"message"`
	Fixable  bool           `json:"fixable"`
	Detail   string         `json:"detail,omitempty"`
}

type doctorCheck struct {
	id  string
	run func(appDir string) []doctorFinding
	// fix, when non-nil, applies a safe repair to the working tree (never
	// commits) and returns a human summary. Invoked by `--fix` only for checks
	// whose finding is marked Fixable.
	fix func(appDir string) (string, error)
}

func doctorChecks() []doctorCheck {
	return []doctorCheck{
		{id: "eas-json", run: checkEASJson},
		{id: "sentry-upload", run: checkSentryUpload, fix: fixSentryUpload},
		{id: "react-pin", run: checkReactPin},
		{id: "dirty-tree", run: checkDirtyTree},
		{id: "lockfile-drift", run: checkLockfileDrift, fix: fixLockfileDrift},
		{id: "config-poison", run: checkConfigPoison},
		{id: "expo-sdk-align", run: checkExpoSDKAlign},
		{id: "pods-codegen", run: checkPodsCodegen, fix: fixPodsCodegen},
		{id: "workspace-dist", run: checkWorkspaceDist, fix: fixWorkspaceDist},
	}
}

// findUp walks up from startDir looking for filename; returns its dir or "".
func findUp(startDir, filename string) string {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return ""
	}
	for {
		if fileExists(filepath.Join(dir, filename)) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func readJSONMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// checkEASJson: eas.json must exist and declare a production build profile.
func checkEASJson(appDir string) []doctorFinding {
	doc, err := readJSONMap(filepath.Join(appDir, "eas.json"))
	if err != nil {
		return []doctorFinding{{
			Check: "eas-json", Severity: doctorBroken,
			Message: "eas.json missing or unparseable", Detail: err.Error(),
		}}
	}
	build, _ := doc["build"].(map[string]any)
	if _, ok := build["production"]; !ok {
		return []doctorFinding{{
			Check: "eas-json", Severity: doctorBroken,
			Message: "no `production` build profile in eas.json",
		}}
	}
	return []doctorFinding{{
		Check: "eas-json", Severity: doctorOK,
		Message: "eas.json declares a production build profile",
	}}
}

// checkSentryUpload: if @sentry/react-native is a dep, every build profile must
// disable the sourcemap auto-upload (or carry a token) or the native build
// fails with no SENTRY_AUTH_TOKEN. This is the exact crucible XCODE_BUILD_ERROR.
func checkSentryUpload(appDir string) []doctorFinding {
	doc, err := readJSONMap(filepath.Join(appDir, "eas.json"))
	if err != nil {
		return nil // eas-json reports the missing/broken file
	}
	sentry := false
	if pkg, e := readJSONMap(filepath.Join(appDir, "package.json")); e == nil {
		for _, section := range []string{"dependencies", "devDependencies"} {
			if deps, ok := pkg[section].(map[string]any); ok {
				if _, ok := deps["@sentry/react-native"]; ok {
					sentry = true
				}
			}
		}
	}
	if !sentry {
		return []doctorFinding{{
			Check: "sentry-upload", Severity: doctorOK,
			Message: "no @sentry/react-native — sourcemap upload N/A",
		}}
	}
	build, _ := doc["build"].(map[string]any)
	var offenders []string
	for name := range build {
		if name == "base" {
			continue // conventional shared base — not built directly
		}
		if !sentryUploadDisabled(build, name) {
			offenders = append(offenders, name)
		}
	}
	sort.Strings(offenders)
	if len(offenders) == 0 {
		return []doctorFinding{{
			Check: "sentry-upload", Severity: doctorOK,
			Message: "all build profiles disable Sentry auto-upload or supply a token",
		}}
	}
	return []doctorFinding{{
		Check: "sentry-upload", Severity: doctorWarn, Fixable: true,
		Message: fmt.Sprintf("build profile(s) may fail Sentry sourcemap upload: %s", strings.Join(offenders, ", ")),
		Detail:  `add "SENTRY_DISABLE_AUTO_UPLOAD": "true" to each profile's env (or provide SENTRY_AUTH_TOKEN)`,
	}}
}

// checkLockfileDrift: reproduces ERR_PNPM_OUTDATED_LOCKFILE without a full
// install. Regenerates the lockfile-only and sees if it changes vs the
// committed one; restores it afterward. Skips when the lockfile is already
// dirty (that's the dirty-tree concern, reported separately).
func checkLockfileDrift(appDir string) []doctorFinding {
	root := findUp(appDir, "pnpm-lock.yaml")
	if root == "" {
		return []doctorFinding{{
			Check: "lockfile-drift", Severity: doctorOK,
			Message: "no pnpm-lock.yaml (not a pnpm project)",
		}}
	}
	if out, _ := gitOutput(root, "status", "--porcelain", "pnpm-lock.yaml"); strings.TrimSpace(out) != "" {
		return []doctorFinding{{
			Check: "lockfile-drift", Severity: doctorWarn,
			Message: "pnpm-lock.yaml has uncommitted changes — commit it; CI/EAS builds the committed state",
		}}
	}
	if _, err := runCmd(root, "pnpm", "install", "--lockfile-only", "--ignore-scripts"); err != nil {
		return []doctorFinding{{
			Check: "lockfile-drift", Severity: doctorWarn,
			Message: "could not probe lockfile (pnpm install --lockfile-only failed)", Detail: err.Error(),
		}}
	}
	changed := false
	if out, _ := gitOutput(root, "status", "--porcelain", "pnpm-lock.yaml"); strings.TrimSpace(out) != "" {
		changed = true
	}
	_, _ = gitRun(root, "checkout", "--", "pnpm-lock.yaml") // restore committed lockfile
	if changed {
		return []doctorFinding{{
			Check: "lockfile-drift", Severity: doctorBroken, Fixable: true,
			Message: "pnpm-lock.yaml is out of date with package.json — a frozen install (EAS/CI) will fail",
			Detail:  "fix: pnpm install --lockfile-only, then commit pnpm-lock.yaml",
		}}
	}
	return []doctorFinding{{
		Check: "lockfile-drift", Severity: doctorOK,
		Message: "lockfile matches manifests (a frozen install would pass)",
	}}
}

func doctorWorstSeverity(findings []doctorFinding) doctorSeverity {
	worst := doctorOK
	for _, f := range findings {
		switch f.Severity {
		case doctorBroken:
			return doctorBroken
		case doctorWarn:
			worst = doctorWarn
		}
	}
	return worst
}

func runDoctorChecks(appDir string) []doctorFinding {
	var findings []doctorFinding
	for _, c := range doctorChecks() {
		findings = append(findings, c.run(appDir)...)
	}
	return findings
}

// findEASAppDirs walks root and returns each dir holding an eas.json (an
// EAS-buildable app), pruning heavy/irrelevant dirs and not descending into a
// found app.
func findEASAppDirs(root string) []string {
	// Apps live shallow: <root>/<repo>/eas.json or <root>/<repo>/apps/<app>/
	// eas.json. Bound the walk so it never descends into deep source trees.
	const maxDepth = 5
	rootClean := filepath.Clean(root)
	rootDepth := strings.Count(rootClean, string(os.PathSeparator))
	var apps []string
	skip := map[string]bool{
		"node_modules": true, ".git": true, ".expo": true, "ios": true,
		"android": true, ".next": true, ".vinext": true, ".turbo": true,
		".preflight": true, ".preflight-ci": true, "Pods": true,
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if skip[d.Name()] {
			return filepath.SkipDir
		}
		if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxDepth {
			return filepath.SkipDir
		}
		if fileExists(filepath.Join(path, "eas.json")) {
			apps = append(apps, path)
			return filepath.SkipDir // an app won't contain another app
		}
		return nil
	})
	sort.Strings(apps)
	return apps
}

// doctorFastChecks runs only the cheap, side-effect-free checks — used by the
// fleet sweep so it stays fast and never shells out to pnpm across every app.
// The full lockfile probe (which regenerates the lockfile) is deep-mode only,
// reachable per app via `apps doctor --path`.
func doctorFastChecks(appDir string) []doctorFinding {
	f := checkEASJson(appDir)
	f = append(f, checkSentryUpload(appDir)...)
	f = append(f, checkConfigPoison(appDir)...)
	f = append(f, checkExpoSDKAlign(appDir)...)
	if root := findUp(appDir, "pnpm-lock.yaml"); root != "" {
		if out, _ := gitOutput(root, "status", "--porcelain", "pnpm-lock.yaml"); strings.TrimSpace(out) != "" {
			f = append(f, doctorFinding{
				Check: "lockfile-dirty", Severity: doctorWarn,
				Message: "pnpm-lock.yaml has uncommitted changes — commit it; CI/EAS builds the committed state",
			})
		}
	}
	return f
}

func doctorLabel(s doctorSeverity) string {
	switch s {
	case doctorBroken:
		return "FAIL"
	case doctorWarn:
		return "WARN"
	default:
		return "OK"
	}
}

// doctorSweep runs the checks over every eas.json app under root and prints a
// fleet drift matrix.
func doctorSweep(root string, asJSON bool, stdout io.Writer) int {
	appDirs := findEASAppDirs(root)
	type appReport struct {
		Path     string          `json:"path"`
		Health   doctorSeverity  `json:"health"`
		Findings []doctorFinding `json:"findings"`
	}
	var reports []appReport
	var broken, warn, ok int
	for _, ad := range appDirs {
		f := doctorFastChecks(ad)
		h := doctorWorstSeverity(f)
		switch h {
		case doctorBroken:
			broken++
		case doctorWarn:
			warn++
		default:
			ok++
		}
		reports = append(reports, appReport{Path: ad, Health: h, Findings: f})
	}
	if asJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"root": root, "apps": reports,
			"summary": map[string]int{"broken": broken, "warn": warn, "ok": ok, "total": len(reports)},
		}, "", "  ")
		fmt.Fprintln(stdout, string(out))
		if broken > 0 {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Fleet build health — %s\n\n", root)
	if len(reports) == 0 {
		fmt.Fprintln(stdout, "  no eas.json apps found under root")
		return 0
	}
	for _, r := range reports {
		var issues []string
		for _, f := range r.Findings {
			if f.Severity != doctorOK {
				issues = append(issues, f.Check)
			}
		}
		rel, relErr := filepath.Rel(root, r.Path)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			rel = r.Path
		}
		fmt.Fprintf(stdout, "  %-4s  %-44s %s\n", doctorLabel(r.Health), rel, strings.Join(issues, ", "))
	}
	fmt.Fprintf(stdout, "\n  %d broken · %d warn · %d ok  (%d apps)\n", broken, warn, ok, len(reports))
	if broken > 0 {
		return 1
	}
	return 0
}

// runAppsDoctor is the `preflight apps doctor` CLI handler (local, no API).
// applyDoctorFixesAt runs the fixable checks over one app dir and applies each
// repair, writing a line per fix. Returns the check ids fixed. With commit, lands
// them on a preflight/doctor-fix branch; with push, also pushes that branch and
// prints a URL for opening the PR.
func applyDoctorFixesAt(abs string, commit, push bool, stdout, stderr io.Writer) []string {
	pre := runDoctorChecks(abs)
	var fixed []string
	for _, c := range doctorChecks() {
		if c.fix == nil {
			continue
		}
		fixable := false
		for _, f := range pre {
			if f.Check == c.id && f.Fixable {
				fixable = true
			}
		}
		if !fixable {
			continue
		}
		if msg, ferr := c.fix(abs); ferr != nil {
			fmt.Fprintf(stdout, "  [fix] %-14s FAILED: %v\n", c.id, ferr)
		} else {
			fmt.Fprintf(stdout, "  [fix] %-14s %s\n", c.id, msg)
			fixed = append(fixed, c.id)
		}
	}
	if len(fixed) == 0 {
		return nil
	}
	if !commit {
		fmt.Fprintln(stdout, "  (working tree — review + commit, or re-run with --commit)")
		return fixed
	}
	branch, cerr := commitDoctorFixes(abs, fixed)
	if cerr != nil {
		fmt.Fprintf(stderr, "  commit failed: %v\n", cerr)
		return fixed
	}
	if branch == "" {
		fmt.Fprintln(stdout, "  (fixes were already committed / no change)")
		return fixed
	}
	if !push {
		fmt.Fprintf(stdout, "  committed on branch %s — push + open a PR\n", branch)
		return fixed
	}
	if prURL, perr := pushDoctorBranch(abs, branch); perr != nil {
		fmt.Fprintf(stderr, "  push failed: %v\n", perr)
	} else {
		fmt.Fprintf(stdout, "  pushed %s → open a PR: %s\n", branch, prURL)
	}
	return fixed
}

// doctorSweepFix applies safe fixes across every app under root. Each app's
// output is buffered and printed only when something was actually fixed, so a
// mostly-clean fleet stays quiet; a final line tallies the run.
func doctorSweepFix(root string, commit, push bool, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "Applying safe fixes across the fleet — %s\n\n", root)
	fixedApps, scanned := 0, 0
	for _, ad := range findEASAppDirs(root) {
		scanned++
		rel, err := filepath.Rel(root, ad)
		if err != nil {
			rel = ad
		}
		var buf bytes.Buffer
		if len(applyDoctorFixesAt(ad, commit, push, &buf, stderr)) == 0 {
			continue
		}
		fixedApps++
		fmt.Fprintf(stdout, "%s\n%s\n", rel, strings.TrimRight(buf.String(), "\n"))
	}
	fmt.Fprintf(stdout, "\nfixed %d app(s) of %d scanned\n", fixedApps, scanned)
	return 0
}

func runAppsDoctor(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	path, root, appID := "", "", ""
	all, asJSON, doFix, doReport, expoDoctor := false, false, false, false, false
	doCommit, doPush, resolveConfig := false, false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--resolve-config":
			resolveConfig = true
		case "--commit":
			doCommit = true
		case "--push":
			doCommit = true // pushing implies committing
			doPush = true
		case "--expo-doctor":
			expoDoctor = true
		case "--path":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "--root":
			if i+1 < len(args) {
				root = args[i+1]
				i++
			}
		case "--app":
			if i+1 < len(args) {
				appID = args[i+1]
				i++
			}
		case "--all":
			all = true
		case "--json":
			asJSON = true
		case "--fix":
			doFix = true
		case "--report":
			doReport = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "Usage:")
			fmt.Fprintln(stdout, "  preflight apps doctor [--path <app-dir>] [--fix] [--json]   one app (default: cwd)")
			fmt.Fprintln(stdout, "  preflight apps doctor --all [--root <dir>] [--json]        fleet drift matrix")
			fmt.Fprintln(stdout, "  preflight apps doctor --all --fix --push [--root <dir>]    fix every drifted app + open a PR each")
			fmt.Fprintln(stdout, "  --fix applies safe repairs (lockfile, sentry); --commit lands them on a preflight/doctor-fix branch; --push pushes it + prints the PR URL.")
			fmt.Fprintln(stdout, "  --report --app <app-id> posts the result to Preflight (surfaces on the fleet board).")
			fmt.Fprintln(stdout, "  --expo-doctor also runs `npx expo-doctor` (slower; single-app only).")
			return 0
		}
	}

	if all {
		if root == "" {
			root, _ = os.Getwd()
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			fmt.Fprintf(stderr, "invalid --root: %v\n", err)
			return 2
		}
		if doFix {
			return doctorSweepFix(absRoot, doCommit, doPush, stdout, stderr)
		}
		if doReport {
			return doctorSweepReport(client, absRoot, resolveConfig, stdout, stderr)
		}
		return doctorSweep(absRoot, asJSON, stdout)
	}

	if path == "" {
		path, _ = os.Getwd()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --path: %v\n", err)
		return 2
	}

	if doFix {
		fmt.Fprintln(stdout, "Applying safe fixes...")
		if len(applyDoctorFixesAt(abs, doCommit, doPush, stdout, stderr)) == 0 {
			fmt.Fprintln(stdout, "  nothing to auto-fix")
		}
		fmt.Fprintln(stdout)
	}

	findings := runDoctorChecks(abs)
	if expoDoctor {
		findings = append(findings, checkExpoDoctor(abs)...)
	}
	worst := doctorWorstSeverity(findings)
	if asJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"path": abs, "health": worst, "findings": findings,
		}, "", "  ")
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintf(stdout, "Build health: %s  (%s)\n\n", strings.ToUpper(string(worst)), abs)
		for _, f := range findings {
			icon := "OK  "
			switch f.Severity {
			case doctorWarn:
				icon = "WARN"
			case doctorBroken:
				icon = "FAIL"
			}
			fix := ""
			if f.Fixable {
				fix = "  [fixable]"
			}
			fmt.Fprintf(stdout, "  [%s] %-14s %s%s\n", icon, f.Check, f.Message, fix)
			if f.Detail != "" {
				fmt.Fprintf(stdout, "         %s\n", f.Detail)
			}
		}
	}

	if doReport {
		if appID == "" {
			fmt.Fprintln(stderr, "--report requires --app <app-id>")
		} else if err := reportBuildHealth(client, appID, findings); err != nil {
			fmt.Fprintf(stderr, "report failed: %v\n", err)
		} else {
			fmt.Fprintf(stdout, "\nreported build health for %s (%s)\n", appID, worst)
		}
	}

	if worst == doctorBroken {
		return 1
	}
	return 0
}

// preflightAPIConfig resolves the Preflight API url + token from env or the CLI
// config file (~/.config/preflight/config.json).
func preflightAPIConfig() (apiURL, token string) {
	apiURL = strings.TrimSpace(os.Getenv("PREFLIGHT_API_URL"))
	token = strings.TrimSpace(os.Getenv("PREFLIGHT_TOKEN"))
	if apiURL != "" && token != "" {
		return apiURL, token
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return apiURL, token
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "preflight", "config.json"))
	if err != nil {
		return apiURL, token
	}
	var cfg struct {
		APIURL string `json:"apiUrl"`
		Token  string `json:"token"`
	}
	if json.Unmarshal(raw, &cfg) == nil {
		if apiURL == "" {
			apiURL = strings.TrimSpace(cfg.APIURL)
		}
		if token == "" {
			token = strings.TrimSpace(cfg.Token)
		}
	}
	return apiURL, token
}

// reportBuildHealth POSTs the doctor verdict to the app's build-health route so
// it surfaces on the release ladder + fleet board.
func reportBuildHealth(client *http.Client, appID string, findings []doctorFinding) error {
	apiURL, token := preflightAPIConfig()
	if apiURL == "" || token == "" {
		return fmt.Errorf("no Preflight API url/token (set PREFLIGHT_API_URL/PREFLIGHT_TOKEN or run `preflight config`)")
	}
	payload := map[string]any{
		"status":   string(doctorWorstSeverity(findings)),
		"findings": findings,
	}
	endpoint := strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/build-health"
	_, err := postPreflightJSON(client, endpoint, token, payload)
	return err
}

func extractExpoSlug(appDir string) string {
	for _, name := range []string{"app.config.ts", "app.config.js", "app.json"} {
		raw, err := os.ReadFile(filepath.Join(appDir, name))
		if err != nil {
			continue
		}
		if m := expoSlugRe.FindSubmatch(raw); len(m) == 2 {
			return string(m[1])
		}
	}
	return ""
}

func extractEASProjectID(appDir string) string {
	for _, name := range []string{"app.config.ts", "app.config.js", "app.json"} {
		raw, err := os.ReadFile(filepath.Join(appDir, name))
		if err != nil {
			continue
		}
		if m := expoProjectIDRe.FindSubmatch(raw); len(m) == 2 {
			return strings.ToLower(string(m[1]))
		}
	}
	return ""
}

func repoNameUnderRoot(root, appDir string) string {
	rel, err := filepath.Rel(root, appDir)
	if err != nil {
		return ""
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// doctorSweepReport runs the fast checks over every app under root and posts
// each verdict to Preflight, mapping a checkout to a fleet app by its expo slug
// (falling back to the repo dir name).
func doctorSweepReport(client *http.Client, root string, resolveConfig bool, stdout, stderr io.Writer) int {
	apiURL, token := preflightAPIConfig()
	if apiURL == "" || token == "" {
		fmt.Fprintln(stderr, "--report needs a Preflight API url/token (run `preflight config`)")
		return 2
	}
	rows, err := fetchFleetReleaseRows(client, releaseStatusCLIOptions{
		apiURL: apiURL, token: token, platform: "ios",
	})
	if err != nil {
		fmt.Fprintf(stderr, "fetch fleet failed: %v\n", err)
		return 1
	}
	byProject := map[string]string{}
	bySlug := map[string]string{}
	byName := map[string]string{}
	byRepo := map[string]string{}
	for _, r := range rows {
		if r.EASProjectID != "" {
			byProject[strings.ToLower(r.EASProjectID)] = r.AppID
		}
		if r.Slug != "" {
			bySlug[strings.ToLower(r.Slug)] = r.AppID
		}
		if r.Name != "" {
			byName[strings.ToLower(r.Name)] = r.AppID
		}
		if norm := normalizeGitRemote(r.GithubRepoURL); norm != "" {
			byRepo[norm] = r.AppID
		}
	}

	reported := 0
	var unmatched []string
	fmt.Fprintf(stdout, "Reporting build health — %s\n\n", root)
	for _, ad := range findEASAppDirs(root) {
		rel, relErr := filepath.Rel(root, ad)
		if relErr != nil {
			rel = ad
		}
		appID := ""
		if pid := extractEASProjectID(ad); pid != "" {
			appID = byProject[pid] // canonical EAS identity — most reliable
		}
		if appID == "" {
			if slug := extractExpoSlug(ad); slug != "" {
				appID = bySlug[strings.ToLower(slug)]
			}
		}
		if appID == "" {
			repo := strings.ToLower(repoNameUnderRoot(root, ad))
			appID = firstNonEmpty(bySlug[repo], byName[repo])
		}
		if appID == "" && len(byRepo) > 0 {
			// Durable identity for checkouts whose slug/projectId drifted from
			// the fleet record: the git remote. Cheap + reliable, so try it
			// before the expensive expo-config resolve. A checkout can have
			// several remotes (origin + forge/gitea mirrors) — the fleet record
			// may match any of them, so check them all.
			for _, remote := range checkoutGitRemotes(ad) {
				if norm := normalizeGitRemote(remote); norm != "" {
					if appID = byRepo[norm]; appID != "" {
						break
					}
				}
			}
		}
		if appID == "" && resolveConfig && len(byProject) > 0 {
			// Opt-in last resort for dynamic app.config (no static slug/projectId
			// to regex): resolve the config with expo itself. Off by default —
			// it shells out per unmatched app (slow), and the git-remote pass
			// already catches every registered checkout. Enable with
			// --resolve-config for a one-off deep match.
			fmt.Fprintf(stdout, "  %-4s  %-42s → resolving via expo config…\n", "····", rel)
			if pid, slug := resolveAppIdentityViaExpo(ad); pid != "" || slug != "" {
				appID = firstNonEmpty(byProject[pid], bySlug[slug])
			}
		}
		if appID == "" {
			unmatched = append(unmatched, rel)
			continue
		}
		findings := doctorFastChecks(ad)
		if repErr := reportBuildHealth(client, appID, findings); repErr != nil {
			fmt.Fprintf(stderr, "  %-42s report failed: %v\n", rel, repErr)
			continue
		}
		reported++
		fmt.Fprintf(stdout, "  %-4s  %-42s → %s\n",
			doctorLabel(doctorWorstSeverity(findings)), rel, appID)
	}
	fmt.Fprintf(stdout, "\nreported %d apps; %d unmatched\n", reported, len(unmatched))
	if len(unmatched) > 0 {
		fmt.Fprintf(stdout, "unmatched (no fleet app by projectId/slug/name — template, clone, or unregistered checkout): %s\n",
			strings.Join(unmatched, ", "))
	}
	return 0
}
