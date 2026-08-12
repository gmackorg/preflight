package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFileT(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func severityOf(findings []doctorFinding, check string) doctorSeverity {
	worst := doctorOK
	for _, f := range findings {
		if f.Check != check {
			continue
		}
		if f.Severity == doctorBroken {
			return doctorBroken
		}
		if f.Severity == doctorWarn {
			worst = doctorWarn
		}
	}
	return worst
}

func TestCheckConfigPoisonLocalhostDefault(t *testing.T) {
	dir := t.TempDir()
	// The daily-dose/playtrek class: env-defaulted localhost in app config.
	writeFileT(t, dir, "app.config.ts",
		`const API_URL = process.env.API_URL ?? "http://localhost:3000";
export default { extra: { API_URL } };`)
	findings := checkConfigPoison(dir)
	if severityOf(findings, "config-poison") == doctorOK {
		t.Fatalf("expected poison finding, got %+v", findings)
	}
}

func TestCheckConfigPoisonEnvFlags(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "app.config.ts", `export default {};`)
	// The latchflow class: E2E stub + localhost baked via dotenv.
	writeFileT(t, dir, ".env",
		"EXPO_PUBLIC_API_URL=http://localhost:3001\nEXPO_PUBLIC_E2E_BYPASS_AUTH=1\n")
	findings := checkConfigPoison(dir)
	poison := 0
	for _, f := range findings {
		if f.Check == "config-poison" && f.Severity != doctorOK {
			poison++
		}
	}
	if poison != 2 {
		t.Fatalf("expected 2 poison findings (localhost + E2E flag), got %d: %+v",
			poison, findings)
	}
}

func TestCheckConfigPoisonCleanConfig(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "app.config.ts",
		`const API_URL = process.env.API_URL ?? "https://dose.gmac.io";
export default { extra: { API_URL } };`)
	writeFileT(t, dir, ".env", "EXPO_PUBLIC_API_URL=https://dose.gmac.io\n")
	findings := checkConfigPoison(dir)
	if severityOf(findings, "config-poison") != doctorOK {
		t.Fatalf("expected clean, got %+v", findings)
	}
}

func TestCheckExpoSDKAlignMismatch(t *testing.T) {
	dir := t.TempDir()
	// The habitplay class: expo 54 + an SDK-56 module.
	writeFileT(t, dir, "package.json",
		`{"dependencies":{"expo":"~54.0.19","expo-font":"^56.0.5"}}`)
	findings := checkExpoSDKAlign(dir)
	if severityOf(findings, "expo-sdk-align") == doctorOK {
		t.Fatalf("expected mismatch finding, got %+v", findings)
	}
}

func TestCheckExpoSDKAlignAligned(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "package.json",
		`{"dependencies":{"expo":"~56.0.13","expo-camera":"~56.0.0","expo-font":"^56.0.5"}}`)
	findings := checkExpoSDKAlign(dir)
	if severityOf(findings, "expo-sdk-align") != doctorOK {
		t.Fatalf("expected aligned, got %+v", findings)
	}
}

func TestCheckExpoSDKAlignPre54Skipped(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "package.json",
		`{"dependencies":{"expo":"~51.0.0","expo-font":"^52.0.0"}}`)
	if findings := checkExpoSDKAlign(dir); len(findings) != 0 {
		t.Fatalf("pre-54 should be skipped, got %+v", findings)
	}
}

func TestScanBundleBytes(t *testing.T) {
	poisoned := []byte("gibberish\x00\x01 fetch(\"http://localhost:3000/api\") more \x02 EXPO_PUBLIC_E2E_BYPASS_AUTH junk")
	findings := scanBundleBytes(poisoned)
	bad := 0
	for _, f := range findings {
		if f.Severity != doctorOK {
			bad++
		}
	}
	if bad < 2 {
		t.Fatalf("expected localhost + E2E findings, got %+v", findings)
	}

	clean := []byte("hermes\x00bytecode with https://crucible.gmac.io only")
	findings = scanBundleBytes(clean)
	for _, f := range findings {
		if f.Severity != doctorOK {
			t.Fatalf("expected clean scan, got %+v", f)
		}
	}
}
