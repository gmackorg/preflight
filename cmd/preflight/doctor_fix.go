package main

// Pre-Build Doctor — additional checks (react-pin, dirty-tree) and the auto-fix
// implementations for the fixable checks. See docs/plans pre-build-doctor.

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

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
