package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOTAPublishResolvesCheckoutAndPlatformsBeforeEnqueue(t *testing.T) {
	const route = "POST /api/preflight/v1/apps/drift/ota/publish"
	plane, server := newFakeControlPlane(t, map[string]any{route: `{"workflowId":"wf"}`})
	local := t.TempDir()
	checkout := t.TempDir()
	for _, root := range []string{local, checkout} {
		if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "apps", "mobile"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	resolver := filepath.Join(bin, "npx")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("EXPECTED_PROJECT", filepath.Join(checkout, "apps", "mobile"))
	writeResolver := func(script string) {
		t.Helper()
		if err := os.WriteFile(resolver, []byte("#!/bin/sh\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"ota", "publish", "--platform", "all", "--app", "drift", "--channel", "preview", "--app-dir", filepath.Join(local, "apps", "mobile"), "--workspace-root", checkout, "--json"}
	writeResolver("test \"$5\" = ios || exit 1\necho '{\"runtimeVersion\":\"ios-hash\"}'\n")
	if code, _, _ := runCLI(t, server, args...); code == 0 || len(plane.requests) != 0 {
		t.Fatalf("unresolved platform queued work: code %d, requests %d", code, len(plane.requests))
	}
	writeResolver(`test "$(pwd -P)" = "$(cd "$EXPECTED_PROJECT" && pwd -P)" || exit 2
test "$1 $2 $3 $4" = "--no-install expo-updates runtimeversion:resolve --platform" || exit 3
test "$APP_VARIANT:$EXPO_NO_DOTENV" = "preview:1" || exit 4
printf '{"runtimeVersion":"%s-hash"}\n' "$5"
`)
	code, stdout, stderr := runCLI(t, server, args...)
	if code != 0 || len(plane.requests) != 2 {
		t.Fatalf("publish: %d %s %s", code, stdout, stderr)
	}
	var receipts []otaPublishReceipt
	if err := json.Unmarshal([]byte(stdout), &receipts); err != nil || len(receipts) != 2 {
		t.Fatalf("receipts %q: %v", stdout, err)
	}
	for i, platform := range []string{"ios", "android"} {
		body := decodeRequestJSON(t, plane.requests[i])
		if body["workspaceRoot"] != checkout || body["runtimeVersion"] != platform+"-hash" || body["platform"] != platform || receipts[i].WorkflowID != "wf" {
			t.Fatalf("request %d: %#v; receipts %+v", i, body, receipts)
		}
	}
}

func TestOTAPublishValidatesInputAndSupportsExplicitRuntime(t *testing.T) {
	const route = "POST /api/preflight/v1/apps/drift/ota/publish"
	plane, server := newFakeControlPlane(t, map[string]any{route: `{"workflowId":"wf"}`})
	base := []string{"ota", "publish", "--app", "drift", "--channel", "production", "--platform", "ios", "--runtime-version", "2.0"}
	for _, flags := range [][]string{{"--platform", "iphone"}, {"--channel", "prodution"}} {
		if code, _, _ := runCLI(t, server, append(append([]string{}, base...), flags...)...); code != 2 {
			t.Fatalf("accepted %v", flags)
		}
	}
	code, stdout, stderr := runCLI(t, server, base...)
	if code != 0 || !strings.Contains(stdout, "wf") {
		t.Fatalf("%d: %s %s", code, stdout, stderr)
	}
	if body := decodeRequestJSON(t, plane.only(t, route)); body["runtimeVersion"] != "2.0" {
		t.Fatal(body)
	}
}
