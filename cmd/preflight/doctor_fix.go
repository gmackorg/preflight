package main

// Pre-Build Doctor — additional checks (react-pin, dirty-tree) and the auto-fix
// implementations for the fixable checks. See docs/plans pre-build-doctor.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// checkExpoDoctor wraps `npx expo-doctor` for the official SDK-consistency
// checks. Opt-in (via --expo-doctor) since it shells out and can be slow;
// bounded + graceful — a timeout or a tool that isn't installed is a soft
// signal, never a crash.
func checkExpoDoctor(appDir string) []doctorFinding {
	if !fileExists(filepath.Join(appDir, "package.json")) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npx", "--no-install", "expo-doctor")
	cmd.Dir = appDir
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return []doctorFinding{{
			Check: "expo-doctor", Severity: doctorWarn,
			Message: "expo-doctor timed out (120s)",
		}}
	}
	text := string(out)
	// Distinguish "expo-doctor ran and found issues" from "it isn't installed".
	if !strings.Contains(text, "check") && !strings.Contains(text, "issue") {
		return nil // couldn't run here — skip rather than false-warn
	}
	if err == nil {
		return []doctorFinding{{
			Check: "expo-doctor", Severity: doctorOK,
			Message: "expo-doctor: no issues detected",
		}}
	}
	var failed []string
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "✖") {
			failed = append(failed, strings.TrimSpace(strings.TrimPrefix(l, "✖")))
		}
	}
	detail := strings.Join(failed, "; ")
	if detail == "" {
		detail = "run `npx expo-doctor` for details"
	}
	return []doctorFinding{{
		Check: "expo-doctor", Severity: doctorWarn,
		Message: "expo-doctor found issues", Detail: detail,
	}}
}

// sentryUploadDisabled reports whether a build profile (or one it `extends`)
// disables Sentry sourcemap auto-upload or supplies a token. Shared by the
// check and its fix so they agree on what counts as covered.
func sentryUploadDisabled(build map[string]any, name string) bool {
	seen := map[string]bool{}
	for name != "" && !seen[name] {
		seen[name] = true
		prof, _ := build[name].(map[string]any)
		if prof == nil {
			break
		}
		if env, _ := prof["env"].(map[string]any); env != nil {
			if v, ok := env["SENTRY_DISABLE_AUTO_UPLOAD"]; ok && fmt.Sprint(v) == "true" {
				return true
			}
			if _, ok := env["SENTRY_AUTH_TOKEN"]; ok {
				return true
			}
		}
		name, _ = prof["extends"].(string)
	}
	return false
}

// cleanVer strips range operators so "^19.2.3" and "19.2.3" compare equal.
func cleanVer(v string) string {
	return strings.TrimLeft(strings.TrimSpace(v), "^~>=< v")
}

// checkReactPin: when the root pnpm.overrides pins react/react-dom, every
// workspace package.json must agree — a mismatch is what silently drifts the
// lockfile (the crucible apps/nextjs 19.2.7 vs override 19.2.3 that failed the
// frozen install). Read-only.
func checkReactPin(appDir string) []doctorFinding {
	root := findUp(appDir, "pnpm-workspace.yaml")
	if root == "" {
		root = findUp(appDir, "pnpm-lock.yaml")
	}
	if root == "" {
		return nil // not a pnpm workspace — other checks cover single packages
	}
	rootPkg, err := readJSONMap(filepath.Join(root, "package.json"))
	if err != nil {
		return nil
	}
	overrides := map[string]string{}
	if pnpmCfg, ok := rootPkg["pnpm"].(map[string]any); ok {
		if ov, ok := pnpmCfg["overrides"].(map[string]any); ok {
			for _, k := range []string{"react", "react-dom"} {
				if v, ok := ov[k].(string); ok {
					overrides[k] = v
				}
			}
		}
	}
	if len(overrides) == 0 {
		return []doctorFinding{{
			Check: "react-pin", Severity: doctorOK,
			Message: "no react override to enforce",
		}}
	}
	var mismatches []string
	seen := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if d.Name() == "node_modules" || d.Name() == ".git" {
			return filepath.SkipDir
		}
		pkgPath := filepath.Join(path, "package.json")
		if !fileExists(pkgPath) || seen[pkgPath] {
			return nil
		}
		seen[pkgPath] = true
		pkg, e := readJSONMap(pkgPath)
		if e != nil {
			return nil
		}
		for _, section := range []string{"dependencies", "devDependencies"} {
			deps, _ := pkg[section].(map[string]any)
			for dep, want := range overrides {
				if have, ok := deps[dep].(string); ok && cleanVer(have) != cleanVer(want) {
					rel, _ := filepath.Rel(root, pkgPath)
					mismatches = append(mismatches, fmt.Sprintf("%s: %s %s (override %s)", rel, dep, have, want))
				}
			}
		}
		return nil
	})
	if len(mismatches) == 0 {
		return []doctorFinding{{
			Check: "react-pin", Severity: doctorOK,
			Message: "react/react-dom consistent with the pnpm override",
		}}
	}
	return []doctorFinding{{
		Check: "react-pin", Severity: doctorWarn,
		Message: fmt.Sprintf("react/react-dom disagree with the pnpm override (%d) — will drift the lockfile", len(mismatches)),
		Detail:  strings.Join(mismatches, "; "),
	}}
}

// checkDirtyTree: build-critical files uncommitted → CI/EAS builds the committed
// state, not the working tree (the crucible ~80-file WIP with the lockfile fix
// uncommitted). Read-only.
func checkDirtyTree(appDir string) []doctorFinding {
	root := findUp(appDir, ".git")
	if root == "" {
		return nil
	}
	out, err := gitOutput(root, "status", "--porcelain")
	if err != nil {
		return nil
	}
	critical := map[string]bool{
		"package.json": true, "pnpm-lock.yaml": true, "eas.json": true,
		"app.config.ts": true, "app.config.js": true, "app.json": true,
	}
	var dirty []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		p := fields[len(fields)-1]
		if critical[filepath.Base(p)] {
			dirty = append(dirty, p)
		}
	}
	if len(dirty) == 0 {
		return []doctorFinding{{
			Check: "dirty-tree", Severity: doctorOK,
			Message: "no uncommitted build-critical files",
		}}
	}
	return []doctorFinding{{
		Check: "dirty-tree", Severity: doctorWarn,
		Message: fmt.Sprintf("%d build-critical file(s) uncommitted — CI/EAS builds the committed state", len(dirty)),
		Detail:  strings.Join(dirty, ", "),
	}}
}

// fixLockfileDrift regenerates pnpm-lock.yaml from the manifests. Leaves it in
// the working tree (unstaged) for review + commit — never commits.
func fixLockfileDrift(appDir string) (string, error) {
	root := findUp(appDir, "pnpm-lock.yaml")
	if root == "" {
		return "", fmt.Errorf("no pnpm-lock.yaml found")
	}
	if _, err := runCmd(root, "pnpm", "install", "--lockfile-only", "--ignore-scripts"); err != nil {
		return "", err
	}
	return "regenerated pnpm-lock.yaml — review and commit", nil
}

// fixSentryUpload adds SENTRY_DISABLE_AUTO_UPLOAD:"true" to each build profile
// that isn't already covered (following extends, skipping the abstract base).
// Rewrites eas.json in place (unstaged) for review + commit.
func fixSentryUpload(appDir string) (string, error) {
	easPath := filepath.Join(appDir, "eas.json")
	raw, err := os.ReadFile(easPath)
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	build, _ := doc["build"].(map[string]any)
	if build == nil {
		return "nothing to fix", nil
	}
	fixed := 0
	for name, v := range build {
		if name == "base" || sentryUploadDisabled(build, name) {
			continue
		}
		prof, _ := v.(map[string]any)
		if prof == nil {
			continue
		}
		env, _ := prof["env"].(map[string]any)
		if env == nil {
			env = map[string]any{}
			prof["env"] = env
		}
		env["SENTRY_DISABLE_AUTO_UPLOAD"] = "true"
		fixed++
	}
	if fixed == 0 {
		return "nothing to fix", nil
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(easPath, append(out, '\n'), 0o644); err != nil {
		return "", err
	}
	return fmt.Sprintf("added SENTRY_DISABLE_AUTO_UPLOAD to %d eas.json profile(s) — review and commit", fixed), nil
}

// resolveAppIdentityViaExpo asks `expo config --json` for the RESOLVED EAS
// project id + slug — the reliable fallback when app.config is dynamic (no
// static literal to regex). Bounded + best-effort; both return "" on any error.
// projectId is empty when the checkout links its EAS project server-side rather
// than embedding extra.eas.projectId (older `eas init` checkouts).
func resolveAppIdentityViaExpo(appDir string) (projectID, slug string) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npx", "--no-install", "expo", "config", "--json")
	cmd.Dir = appDir
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	var cfg struct {
		Slug  string `json:"slug"`
		Extra struct {
			Eas struct {
				ProjectID string `json:"projectId"`
			} `json:"eas"`
		} `json:"extra"`
	}
	if json.Unmarshal(out, &cfg) == nil {
		return strings.ToLower(cfg.Extra.Eas.ProjectID), strings.ToLower(cfg.Slug)
	}
	return "", ""
}

// checkoutGitRemotes returns the URLs of every git remote on a checkout. A
// checkout often has several (origin plus forge/gitea/forgejo mirrors) that
// point at differently-named repos, and the fleet record may match any one of
// them — so the caller tries them all rather than betting on origin.
func checkoutGitRemotes(appDir string) []string {
	root := findUp(appDir, ".git")
	if root == "" {
		return nil
	}
	out, err := gitOutput(root, "remote")
	if err != nil {
		return nil
	}
	var urls []string
	for _, name := range strings.Fields(out) {
		if url, e := gitOutput(root, "remote", "get-url", name); e == nil {
			if u := strings.TrimSpace(url); u != "" {
				urls = append(urls, u)
			}
		}
	}
	return urls
}

// normalizeGitRemote reduces a git remote URL to a comparable host/path key,
// bridging the ssh (git@host:path.git) and https (https://host/path.git) forms
// so a checkout and its fleet record match regardless of clone protocol.
// "" when the input isn't a recognizable host/repo remote.
func normalizeGitRemote(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:] // strip scheme
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:] // strip user@ (ssh)
	}
	s = strings.Replace(s, ":", "/", 1) // scp-form host:path → host/path
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	if !strings.Contains(s, "/") {
		return "" // need at least host/repo
	}
	return s
}

// pushDoctorBranch pushes the doctor-fix branch to the checkout's primary remote
// (origin if present, else the first) and returns a URL for opening a PR. The
// branch is doctor-exclusive, so a --force keeps re-runs idempotent.
func pushDoctorBranch(appDir, branch string) (string, error) {
	root := findUp(appDir, ".git")
	if root == "" {
		return "", fmt.Errorf("not a git repo")
	}
	out, err := gitOutput(root, "remote")
	if err != nil {
		return "", err
	}
	remotes := strings.Fields(out)
	if len(remotes) == 0 {
		return "", fmt.Errorf("no git remote to push to")
	}
	remote := remotes[0]
	for _, r := range remotes {
		if r == "origin" {
			remote = "origin"
			break
		}
	}
	if _, err := gitRun(root, "push", "--force", remote, branch); err != nil {
		return "", err
	}
	url, _ := gitOutput(root, "remote", "get-url", remote)
	return prCompareURL(strings.TrimSpace(url), branch), nil
}

// prCompareURL turns a git remote URL + branch into the forge's new-PR page.
// GitHub and Forgejo/Gitea both serve a /compare route (with different head
// syntax). "" inputs fall back to a plain hint.
func prCompareURL(remoteURL, branch string) string {
	np := normalizeGitRemote(remoteURL) // host/owner/repo
	i := strings.Index(np, "/")
	if np == "" || i < 0 {
		return "(pushed — open a PR in your forge)"
	}
	host, path := np[:i], np[i+1:]
	if host == "github.com" {
		return fmt.Sprintf("https://%s/%s/compare/%s?expand=1", host, path, branch)
	}
	// Forgejo/Gitea (git.forgegraf.com et al.): base...head.
	return fmt.Sprintf("https://%s/%s/compare/main...%s", host, path, branch)
}

// commitDoctorFixes lands the just-applied fixes on a `preflight/doctor-fix`
// branch (created/reset at the current HEAD, so it never disturbs other WIP)
// and commits ONLY the files the fixes touch. Leaves the repo on that branch
// for the operator to push + open a PR. Returns "" when nothing changed.
func commitDoctorFixes(appDir string, fixedChecks []string) (string, error) {
	repoRoot := findUp(appDir, ".git")
	if repoRoot == "" {
		return "", fmt.Errorf("not a git repo")
	}
	var files []string
	for _, c := range fixedChecks {
		switch c {
		case "sentry-upload":
			files = append(files, filepath.Join(appDir, "eas.json"))
		case "lockfile-drift":
			if lr := findUp(appDir, "pnpm-lock.yaml"); lr != "" {
				files = append(files, filepath.Join(lr, "pnpm-lock.yaml"))
			}
		}
	}
	var dirty []string
	for _, f := range files {
		rel, err := filepath.Rel(repoRoot, f)
		if err != nil {
			continue
		}
		if out, _ := gitOutput(repoRoot, "status", "--porcelain", rel); strings.TrimSpace(out) != "" {
			dirty = append(dirty, rel)
		}
	}
	if len(dirty) == 0 {
		return "", nil
	}
	const branch = "preflight/doctor-fix"
	if _, err := gitRun(repoRoot, "checkout", "-B", branch); err != nil {
		return "", fmt.Errorf("create branch: %w", err)
	}
	if _, err := gitRun(repoRoot, append([]string{"add"}, dirty...)...); err != nil {
		return "", fmt.Errorf("git add: %w", err)
	}
	msg := "fix: pre-build doctor auto-repair (" + strings.Join(fixedChecks, ", ") + ")"
	if _, err := gitRun(repoRoot, "commit", "-m", msg); err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}
	return branch, nil
}

// checkPodsCodegen: on a prebuilt (bare) iOS checkout, the CocoaPods sandbox
// must be installed and the React Native codegen output present.
//
// This is the single most common build-drift failure across the fleet — hit on
// five separate repos. The generated tree under ios/build/generated is not
// committed and is wiped by a clean, a branch switch, or an interrupted build.
// xcodebuild then fails with "Build input file cannot be found:
// …/ReactCodegen/<module>/<module>-generated.mm", which reads like a corrupt
// checkout rather than a missing `pod install`. Roughly 20 wasted minutes per
// occurrence, since the failure only surfaces deep into compilation.
func checkPodsCodegen(appDir string) []doctorFinding {
	iosDir := filepath.Join(appDir, "ios")
	if !fileExists(filepath.Join(iosDir, "Podfile")) {
		// Managed workflow — no native project to be stale.
		return nil
	}

	podfileLock := filepath.Join(iosDir, "Podfile.lock")
	manifestLock := filepath.Join(iosDir, "Pods", "Manifest.lock")
	if !fileExists(podfileLock) || !fileExists(manifestLock) {
		return []doctorFinding{{
			Check: "pods-codegen", Severity: doctorBroken, Fixable: true,
			Message: "CocoaPods sandbox is not installed — run `pod install` in ios/",
		}}
	}

	// CocoaPods' own out-of-sync definition: the installed manifest must match
	// the lockfile byte for byte.
	lockRaw, lockErr := os.ReadFile(podfileLock)
	manifestRaw, manifestErr := os.ReadFile(manifestLock)
	if lockErr == nil && manifestErr == nil && !bytes.Equal(lockRaw, manifestRaw) {
		return []doctorFinding{{
			Check: "pods-codegen", Severity: doctorBroken, Fixable: true,
			Message: "the Pods sandbox is out of sync with Podfile.lock — run `pod install` in ios/",
		}}
	}

	if !hasReactCodegenOutput(filepath.Join(iosDir, "build", "generated", "ios", "ReactCodegen")) {
		return []doctorFinding{{
			Check: "pods-codegen", Severity: doctorBroken, Fixable: true,
			Message: "React Native codegen output is missing — the build will fail on a " +
				"generated .mm file; run `pod install` in ios/",
		}}
	}

	return []doctorFinding{{
		Check: "pods-codegen", Severity: doctorOK,
		Message: "CocoaPods sandbox is in sync and codegen output is present",
	}}
}

// hasReactCodegenOutput reports whether the codegen tree holds at least one
// generated implementation file. An empty-but-present directory is the common
// half-wiped state and must not read as healthy.
func hasReactCodegenOutput(codegenDir string) bool {
	found := false
	_ = filepath.WalkDir(codegenDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil //nolint:nilerr // absent tree is simply "no output"
		}
		if strings.HasSuffix(path, "-generated.mm") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// fixPodsCodegen runs `pod install` in ios/. Bounded — a cold sandbox on a
// large app can legitimately take several minutes.
func fixPodsCodegen(appDir string) (string, error) {
	iosDir := filepath.Join(appDir, "ios")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pod", "install")
	cmd.Dir = iosDir
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("pod install timed out after 15m")
	}
	if err != nil {
		return "", fmt.Errorf("pod install failed: %w: %s", err, lastLines(string(out), 5))
	}
	return "ran `pod install` in ios/ (Pods sandbox + codegen regenerated)", nil
}

// lastLines returns the final n non-empty lines, for compact error detail.
func lastLines(text string, n int) string {
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			kept = append(kept, strings.TrimSpace(line))
		}
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return strings.Join(kept, "; ")
}

// checkWorkspaceDist: every workspace dependency the app resolves at *runtime*
// through a dist/ path must actually be built.
//
// These monorepos mix two export styles: packages that resolve `default` to
// ./src/index.ts (bundled from source, no build needed) and packages that
// resolve it to ./dist/index.js. Only the latter must be built before a native
// build, and nothing enforces it — the failure lands ~15 minutes in, as a Metro
// "unable to resolve module" that reads like a broken import rather than a
// missing build step. Seen on daily-dose (@dailydose/config).
//
// Deliberately ignores `types` conditions: a missing dist/index.d.ts breaks
// typecheck, not the bundle, and flagging it would false-positive on most of
// the fleet.
func checkWorkspaceDist(appDir string) []doctorFinding {
	unbuilt, applicable := unbuiltWorkspacePackages(appDir)
	if !applicable {
		return nil
	}
	if len(unbuilt) > 0 {
		return []doctorFinding{{
			Check: "workspace-dist", Severity: doctorBroken, Fixable: true,
			Message: fmt.Sprintf(
				"workspace package(s) %s resolve at runtime to dist/ but were never built — the Metro bundle will fail",
				strings.Join(unbuilt, ", ")),
			Detail: "run `pnpm --filter <pkg> build` for each",
		}}
	}
	return []doctorFinding{{
		Check: "workspace-dist", Severity: doctorOK,
		Message: "workspace dependencies resolve to built or source entrypoints",
	}}
}

// unbuiltWorkspacePackages returns the workspace dependencies that resolve at
// runtime through a missing dist/ file. The bool reports whether the check
// applies at all (false for a non-workspace app).
func unbuiltWorkspacePackages(appDir string) (names []string, applicable bool) {
	pkg, err := readJSONMap(filepath.Join(appDir, "package.json"))
	if err != nil {
		return nil, false // other checks report a missing/broken package.json
	}

	workspaceDeps := map[string]bool{}
	for _, field := range []string{"dependencies", "devDependencies"} {
		deps, _ := pkg[field].(map[string]any)
		for name, spec := range deps {
			if text, ok := spec.(string); ok && strings.HasPrefix(text, "workspace:") {
				workspaceDeps[name] = true
			}
		}
	}
	if len(workspaceDeps) == 0 {
		return nil, false
	}

	root := findUp(appDir, "pnpm-workspace.yaml")
	if root == "" {
		// Convention in every fleet repo: apps/<app> under the monorepo root.
		root = filepath.Dir(filepath.Dir(appDir))
	}

	var unbuilt []string
	for _, pkgDir := range workspacePackageDirs(root) {
		manifest, err := readJSONMap(filepath.Join(pkgDir, "package.json"))
		if err != nil {
			continue
		}
		name, _ := manifest["name"].(string)
		if !workspaceDeps[name] {
			continue
		}
		for _, target := range runtimeExportTargets(manifest["exports"]) {
			if !strings.Contains(target, "dist") {
				continue
			}
			if !fileExists(filepath.Join(pkgDir, filepath.FromSlash(strings.TrimPrefix(target, "./")))) {
				unbuilt = append(unbuilt, name)
				break
			}
		}
	}

	sort.Strings(unbuilt)
	return unbuilt, true
}

// workspacePackageDirs lists candidate package directories under a monorepo
// root. Covers the packages/* and apps/* layout every fleet repo uses.
func workspacePackageDirs(root string) []string {
	var dirs []string
	for _, group := range []string{"packages", "apps", "tooling"} {
		entries, err := os.ReadDir(filepath.Join(root, group))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				dirs = append(dirs, filepath.Join(root, group, entry.Name()))
			}
		}
	}
	return dirs
}

// runtimeExportTargets collects the export targets a bundler actually resolves,
// walking the conditional-exports tree. `types` is skipped deliberately — it
// affects typecheck, not the bundle.
func runtimeExportTargets(exports any) []string {
	switch value := exports.(type) {
	case string:
		return []string{value}
	case map[string]any:
		var targets []string
		for condition, nested := range value {
			if condition == "types" {
				continue
			}
			targets = append(targets, runtimeExportTargets(nested)...)
		}
		sort.Strings(targets)
		return targets
	}
	return nil
}

// fixWorkspaceDist builds the unbuilt workspace packages via pnpm.
func fixWorkspaceDist(appDir string) (string, error) {
	unbuilt, applicable := unbuiltWorkspacePackages(appDir)
	if !applicable || len(unbuilt) == 0 {
		return "nothing to build", nil
	}
	root := findUp(appDir, "pnpm-workspace.yaml")
	if root == "" {
		root = filepath.Dir(filepath.Dir(appDir))
	}

	args := make([]string, 0, len(unbuilt)*2+1)
	for _, name := range unbuilt {
		args = append(args, "--filter", name)
	}
	args = append(args, "build")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pnpm", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("pnpm build timed out after 15m")
	}
	if err != nil {
		return "", fmt.Errorf("pnpm build failed: %w: %s", err, lastLines(string(out), 5))
	}
	return fmt.Sprintf("built workspace package(s): %s", strings.Join(unbuilt, ", ")), nil
}
