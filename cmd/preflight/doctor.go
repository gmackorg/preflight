package main

// Pre-Build Doctor — slice 1: detect the recurring build-drift classes before a
// build runs. Read-only checks over a checkout; see docs/plans pre-build-doctor.
// Runs where a checkout exists (this CLI / a runner job) — the server is a CF
// Worker with no filesystem, so checks cannot live there.

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
func runAppsDoctor(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	path, root, appID := "", "", ""
	all, asJSON, doFix, doReport := false, false, false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
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
			fmt.Fprintln(stdout, "  --fix applies safe repairs (lockfile, sentry) to the working tree — never commits.")
			fmt.Fprintln(stdout, "  --report --app <app-id> posts the result to Preflight (surfaces on the fleet board).")
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
		pre := runDoctorChecks(abs)
		fmt.Fprintln(stdout, "Applying safe fixes (working tree only — review + commit)...")
		applied := 0
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
				applied++
			}
		}
		if applied == 0 {
			fmt.Fprintln(stdout, "  nothing to auto-fix")
		}
		fmt.Fprintln(stdout)
	}

	findings := runDoctorChecks(abs)
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
