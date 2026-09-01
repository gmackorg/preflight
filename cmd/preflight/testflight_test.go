package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestFlightEnrollPostsFleetRequestAndPrintsSummary(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/testflight/enroll" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("authorization = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"enrollment":{"email":"mackieg@umich.edu","dryRun":true,"results":[{"appId":"pfapp-1","appName":"Alpha","ascAppId":"asc-1","groupName":"Internal Testers","status":"would_enroll"}],"summary":{"total":1,"enrolled":0,"alreadyEnrolled":0,"wouldEnroll":1,"failed":0,"noInternalGroup":0}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req-1"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"testflight", "enroll",
		"--email", "mackieg@umich.edu",
		"--workspace-id", "ws-1",
		"--api-url", server.URL,
		"--dry-run",
	}, &stdout, &stderr, server.Client())

	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if requestBody["email"] != "mackieg@umich.edu" || requestBody["workspaceId"] != "ws-1" || requestBody["dryRun"] != true {
		t.Fatalf("request body = %#v", requestBody)
	}
	for _, expected := range []string{"Alpha", "Internal Testers", "would_enroll", "1 app", "dry run"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q: %s", expected, stdout.String())
		}
	}
}

func TestTestFlightEnrollPrintsNextActionForMissingGroups(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"enrollment":{"email":"mackieg@umich.edu","dryRun":true,"results":[{"appId":"playtrek","appName":"PlayTrek","ascAppId":"asc-1","status":"no_internal_group","nextAction":"preflight testflight groups create playtrek --internal"}],"summary":{"total":1,"enrolled":0,"alreadyEnrolled":0,"wouldEnroll":0,"failed":0,"noInternalGroup":1}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req-1"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"testflight", "enroll",
		"--email", "mackieg@umich.edu",
		"--api-url", server.URL,
		"--dry-run",
	}, &stdout, &stderr, server.Client())

	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "preflight testflight groups create playtrek --internal") {
		t.Fatalf("stdout missing next action: %s", stdout.String())
	}
}

func TestTestFlightGroupsCreatePostsInternalGroup(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	var createBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/release-status":
			_, _ = w.Write([]byte(`{"data":{"apps":[{"appId":"pfapp-playtrek","slug":"playtrek","name":"PlayTrek"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req-1"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp-playtrek/testflight/groups":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"group":{"id":"group-9","name":"Internal Testers","isInternal":true,"publicLinkEnabled":false,"publicLink":null}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req-2"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"testflight", "groups", "create", "playtrek",
		"--internal",
		"--api-url", server.URL,
	}, &stdout, &stderr, server.Client())

	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if createBody["name"] != "Internal Testers" || createBody["internal"] != true {
		t.Fatalf("create body = %#v", createBody)
	}
	for _, expected := range []string{"internal", "Internal Testers", "group-9"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q: %s", expected, stdout.String())
		}
	}
}

func TestTestFlightGroupsCreateRequiresNameForExternalGroups(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"testflight", "groups", "create", "playtrek"}, &stdout, &stderr, http.DefaultClient)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--name is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestTestFlightGroupsListPrintsGroups(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/release-status":
			_, _ = w.Write([]byte(`{"data":{"apps":[{"appId":"pfapp-playtrek","slug":"playtrek","name":"PlayTrek"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req-1"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/apps/pfapp-playtrek/testflight/groups":
			_, _ = w.Write([]byte(`{"data":{"configured":true,"ascLinked":true,"groups":[{"id":"group-1","name":"Internal Testers","isInternal":true,"publicLinkEnabled":false,"publicLink":null}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req-2"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"testflight", "groups", "list", "playtrek",
		"--api-url", server.URL,
	}, &stdout, &stderr, server.Client())

	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{"Internal Testers", "group-1", "internal"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q: %s", expected, stdout.String())
		}
	}
}

func TestTestFlightEnrollRequiresEmail(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"testflight", "enroll"}, &stdout, &stderr, http.DefaultClient)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--email is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
