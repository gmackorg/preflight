package main

// Pre-Build Doctor — additional checks (react-pin, dirty-tree) and the auto-fix
// implementations for the fixable checks. See docs/plans pre-build-doctor.

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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
