package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demoAccountsFleet = `{"apps":[{"appId":"pfapp_playtrek","slug":"playtrek","name":"PlayTrek"}]}`

const demoAccountsList = `{"accounts":[
 {"id":"pfdemo_pfapp_playtrek_parent","appId":"pfapp_playtrek","label":"parent","flavor":"password","identifier":"reviewer+parent@example.test","lastProbeOk":true,"hasSecret":true},
 {"id":"pfdemo_pfapp_playtrek_deletable","appId":"pfapp_playtrek","label":"deletable","flavor":"password","identifier":"reviewer+delete@example.test","lastProbeOk":false,"lastProbeNote":"password sign-in got 401","hasSecret":true}
]}`

const demoAccountReveal = `{"account":{"id":"pfdemo_pfapp_playtrek_platform-admin","appId":"pfapp_playtrek","label":"platform-admin","flavor":"password","identifier":"reviewer+platform-admin@example.test"},"secret":"test-only-secret","revealedAt":"2026-11-23T12:00:00.000Z"}`

func demoAccountsPlane(t *testing.T) (*fakeControlPlane, func(args ...string) (int, string, string)) {
	plane, server := newFakeControlPlane(t, map[string]any{
		"GET /api/preflight/v1/release-status":                                           demoAccountsFleet,
		"GET /api/preflight/v1/apps/pfapp_playtrek/demo-accounts":                        demoAccountsList,
		"POST /api/preflight/v1/apps/pfapp_playtrek/demo-accounts/platform-admin/reveal": demoAccountReveal,
	})
	return plane, func(args ...string) (int, string, string) { return runCLI(t, server, args...) }
}

func TestAppsDemoAccountsListsWithoutRevealing(t *testing.T) {
	plane, cli := demoAccountsPlane(t)
	code, stdout, stderr := cli("apps", "demo-accounts", "playtrek")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"parent", "reviewer+parent@example.test", "stored", "failed: password sign-in got 401"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q:\n%s", want, stdout)
		}
	}
	for _, request := range plane.requests {
		if strings.HasSuffix(request.Path, "/reveal") {
			t.Fatalf("listing must not call reveal: %+v", request)
		}
	}
	if auth := plane.only(t, "GET /api/preflight/v1/apps/pfapp_playtrek/demo-accounts").Auth; auth != "Bearer pf_test_token" {
		t.Fatalf("auth header = %q", auth)
	}

	code, stdout, _ = cli("apps", "demo-accounts", "playtrek", "--json")
	var accounts []cliDemoAccount
	if code != 0 || json.Unmarshal([]byte(stdout), &accounts) != nil || len(accounts) != 2 {
		t.Fatalf("json list code=%d out=%s", code, stdout)
	}
}

func TestAppsDemoAccountsRevealToFileWritesMode0600AndDoesNotEcho(t *testing.T) {
	plane, cli := demoAccountsPlane(t)
	path := filepath.Join(t.TempDir(), "platform-admin.secret")
	// A pre-existing world-readable file must come out 0600, not keep its mode.
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := cli("apps", "demo-accounts", "playtrek", "--reveal", "platform-admin", "--output-file", path)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if strings.Contains(stdout+stderr, "test-only-secret") {
		t.Fatalf("secret echoed to terminal: %s %s", stdout, stderr)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "test-only-secret" {
		t.Fatalf("file content = %q err=%v", content, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	plane.only(t, "POST /api/preflight/v1/apps/pfapp_playtrek/demo-accounts/platform-admin/reveal")

	code, stdout, _ = cli("apps", "demo-accounts", "playtrek", "--reveal", "platform-admin", "--output-file", path, "--json")
	if code != 0 || strings.Contains(stdout, "test-only-secret") || !strings.Contains(stdout, `"secretFile"`) {
		t.Fatalf("json+file output should name the file, not the secret: %s", stdout)
	}
}

func TestAppsDemoAccountsRevealJSONAndBare(t *testing.T) {
	_, cli := demoAccountsPlane(t)
	code, stdout, stderr := cli("apps", "demo-accounts", "playtrek", "--reveal", "platform-admin", "--json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var revealed map[string]string
	if err := json.Unmarshal([]byte(stdout), &revealed); err != nil {
		t.Fatalf("decode %s: %v", stdout, err)
	}
	if revealed["secret"] != "test-only-secret" || revealed["identifier"] != "reviewer+platform-admin@example.test" {
		t.Fatalf("revealed = %+v", revealed)
	}

	code, stdout, _ = cli("apps", "demo-accounts", "playtrek", "--reveal", "platform-admin")
	if code != 0 || stdout != "test-only-secret\n" {
		t.Fatalf("bare reveal code=%d out=%q", code, stdout)
	}
}

func TestAppsDemoAccountsRejectsBadFlags(t *testing.T) {
	_, cli := demoAccountsPlane(t)
	if code, _, stderr := cli("apps", "demo-accounts", "playtrek", "--output-file", "/tmp/x"); code != 2 || !strings.Contains(stderr, "--reveal") {
		t.Fatalf("--output-file without --reveal: code=%d stderr=%s", code, stderr)
	}
	if code, _, _ := cli("apps", "demo-accounts", "playtrek", "--reveal", "--json"); code != 2 {
		t.Fatalf("--reveal without label should exit 2, got %d", code)
	}
	if code, _, _ := cli("apps", "demo-accounts"); code != 2 {
		t.Fatalf("missing app should exit 2, got %d", code)
	}
}
