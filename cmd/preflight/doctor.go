package main

// Pre-Build Doctor — slice 1: detect the recurring build-drift classes before a
// build runs. Read-only checks over a checkout; see docs/plans pre-build-doctor.
// Runs where a checkout exists (this CLI / a runner job) — the server is a CF
// Worker with no filesystem, so checks cannot live there.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
}

func doctorChecks() []doctorCheck {
	return []doctorCheck{
		{id: "eas-json", run: checkEASJson},
		{id: "sentry-upload", run: checkSentryUpload},
		{id: "lockfile-drift", run: checkLockfileDrift},
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
	// A profile is safe if it (or a profile it `extends`) disables auto-upload
	// or supplies a token. Follow the extends chain so inherited config counts.
	disablesUpload := func(name string) bool {
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
	var offenders []string
	for name := range build {
		if name == "base" {
			continue // conventional shared base — not built directly
		}
		if !disablesUpload(name) {
			offenders = append(offenders, name)
		}
	}
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

// runAppsDoctor is the `preflight apps doctor` CLI handler (local, no API).
func runAppsDoctor(args []string, stdout io.Writer, stderr io.Writer) int {
	path := ""
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "--json":
			asJSON = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "Usage: preflight apps doctor [--path <app-dir>] [--json]")
			fmt.Fprintln(stdout, "Runs build-health checks against an Expo app checkout (default: cwd).")
			return 0
		}
	}
	if path == "" {
		path, _ = os.Getwd()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --path: %v\n", err)
		return 2
	}

	var findings []doctorFinding
	for _, c := range doctorChecks() {
		findings = append(findings, c.run(abs)...)
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
	if worst == doctorBroken {
		return 1
	}
	return 0
}
