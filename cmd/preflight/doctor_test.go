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
