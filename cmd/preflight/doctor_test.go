package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDoctorFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSentryUpload_FlagsUncoveredProfileFollowingExtends(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "package.json", `{"dependencies":{"@sentry/react-native":"5.0.0"}}`)
	// production inherits the disable via extends->base; preview does not; base
	// is the conventional shared profile and must not be flagged.
	writeDoctorFile(t, dir, "eas.json", `{
	  "build": {
	    "base": { "env": { "SENTRY_DISABLE_AUTO_UPLOAD": "true" } },
	    "production": { "extends": "base", "env": {} },
	    "preview": { "env": {} }
	  }
	}`)
	findings := checkSentryUpload(dir)
	if len(findings) != 1 || findings[0].Severity != doctorWarn || !findings[0].Fixable {
		t.Fatalf("expected 1 fixable warn, got %+v", findings)
	}
	msg := findings[0].Message
	if !strings.Contains(msg, "preview") || strings.Contains(msg, "production") || strings.Contains(msg, "base") {
		t.Fatalf("expected only preview flagged, got %q", msg)
	}
}

func TestCheckSentryUpload_OkWhenNoSentryDep(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "package.json", `{"dependencies":{}}`)
	writeDoctorFile(t, dir, "eas.json", `{"build":{"production":{"env":{}}}}`)
	findings := checkSentryUpload(dir)
	if len(findings) != 1 || findings[0].Severity != doctorOK {
		t.Fatalf("expected ok when no @sentry/react-native, got %+v", findings)
	}
}

func TestCheckEASJson_RequiresProductionProfile(t *testing.T) {
	ok := t.TempDir()
	writeDoctorFile(t, ok, "eas.json", `{"build":{"production":{}}}`)
	if f := checkEASJson(ok); f[0].Severity != doctorOK {
		t.Fatalf("expected ok, got %+v", f)
	}
	missing := t.TempDir()
	writeDoctorFile(t, missing, "eas.json", `{"build":{"preview":{}}}`)
	if f := checkEASJson(missing); f[0].Severity != doctorBroken {
		t.Fatalf("expected broken (no production profile), got %+v", f)
	}
	none := t.TempDir()
	if f := checkEASJson(none); f[0].Severity != doctorBroken {
		t.Fatalf("expected broken (no eas.json), got %+v", f)
	}
}

func TestDoctorWorstSeverity(t *testing.T) {
	cases := []struct {
		in   []doctorFinding
		want doctorSeverity
	}{
		{nil, doctorOK},
		{[]doctorFinding{{Severity: doctorOK}, {Severity: doctorWarn}}, doctorWarn},
		{[]doctorFinding{{Severity: doctorWarn}, {Severity: doctorBroken}}, doctorBroken},
	}
	for _, c := range cases {
		if got := doctorWorstSeverity(c.in); got != c.want {
			t.Fatalf("worst(%+v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestCheckReactPin_FlagsOverrideMismatch(t *testing.T) {
	root := t.TempDir()
	writeDoctorFile(t, root, "pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
	writeDoctorFile(t, root, "package.json", `{"pnpm":{"overrides":{"react":"19.2.3","react-dom":"19.2.3"}}}`)
	if err := os.MkdirAll(filepath.Join(root, "packages", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, filepath.Join(root, "packages", "app"), "package.json", `{"dependencies":{"react":"19.2.7"}}`)
	f := checkReactPin(root)
	if len(f) != 1 || f[0].Severity != doctorWarn {
		t.Fatalf("expected warn, got %+v", f)
	}
	if !strings.Contains(f[0].Detail, "19.2.7") {
		t.Fatalf("expected mismatch detail, got %q", f[0].Detail)
	}
}

func TestCheckReactPin_OkWhenConsistentIgnoringRange(t *testing.T) {
	root := t.TempDir()
	writeDoctorFile(t, root, "pnpm-workspace.yaml", "packages:\n")
	writeDoctorFile(t, root, "package.json", `{"pnpm":{"overrides":{"react":"19.2.3"}}}`)
	if err := os.MkdirAll(filepath.Join(root, "packages", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, filepath.Join(root, "packages", "app"), "package.json", `{"dependencies":{"react":"^19.2.3"}}`)
	f := checkReactPin(root)
	if len(f) != 1 || f[0].Severity != doctorOK {
		t.Fatalf("expected ok (^19.2.3 == 19.2.3), got %+v", f)
	}
}

func TestFixSentryUpload_AddsFlagFollowingExtends(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "eas.json", `{"build":{"base":{"env":{"SENTRY_DISABLE_AUTO_UPLOAD":"true"}},"production":{"extends":"base"},"preview":{"env":{"APP_VARIANT":"preview"}}}}`)
	msg, err := fixSentryUpload(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "1 ") {
		t.Fatalf("expected 1 profile fixed, got %q", msg)
	}
	doc, _ := readJSONMap(filepath.Join(dir, "eas.json"))
	build := doc["build"].(map[string]any)
	prev := build["preview"].(map[string]any)["env"].(map[string]any)
	if prev["SENTRY_DISABLE_AUTO_UPLOAD"] != "true" || prev["APP_VARIANT"] != "preview" {
		t.Fatalf("preview env wrong after fix: %+v", prev)
	}
	if _, hasEnv := build["production"].(map[string]any)["env"]; hasEnv {
		t.Fatalf("production should stay untouched (inherits via extends)")
	}
}
