package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func scopedRunnerOptions(t *testing.T, apiURL string) runnerOnceOptions {
	t.Helper()
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	options, err := parseRunnerOnceOptions([]string{
		"--api-url", apiURL, "--workspace-id", "workspace", "--workspace-root", t.TempDir(),
		"--workflow-id", "pfw_appeal",
	})
	if err != nil {
		t.Fatalf("parse scoped runner: %v", err)
	}
	return options
}

func scopedRegistration(t *testing.T) runnerRegistrationData {
	t.Helper()
	var registration runnerRegistrationData
	if err := json.Unmarshal([]byte(`{"runner":{"id":"runner_scope"},"token":"scope-token","claimScopes":["workflow"]}`), &registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func TestWorkflowScopedClaimSendsSelectionOnEveryPoll(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["workflowId"] != "pfw_appeal" || r.Header.Get("Authorization") != "Bearer scope-token" {
			t.Errorf("claim lost workflow scope or runner authentication")
		}
		if requests == 1 {
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"job":{"id":"job_appeal","workflowId":"pfw_appeal"}}}`))
	}))
	t.Cleanup(server.Close)
	options := scopedRunnerOptions(t, server.URL)
	for i := 0; i < 2; i++ {
		claim, err := claimRunnerJob(server.Client(), options, scopedRegistration(t))
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && (claim == nil || claim.Job.WorkflowID != "pfw_appeal") {
			t.Fatalf("expected selected workflow, got %#v", claim)
		}
	}
	if requests != 2 {
		t.Fatalf("expected two scoped polls, got %d", requests)
	}
}

func TestWorkflowScopedClaimRefusesUnadvertisedServerBeforeAnyRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	t.Cleanup(server.Close)
	options := scopedRunnerOptions(t, server.URL)
	registration := runnerRegistrationData{Runner: apiRunner{ID: "old_runner"}}
	_, err := claimRunnerJob(server.Client(), options, registration)
	if err == nil || !strings.Contains(err.Error(), "workflow-scoped claims") || requests != 0 {
		t.Fatalf("old server must refuse before claiming: requests=%d err=%v", requests, err)
	}
}

func TestWorkflowScopedClaimRejectsUnexpectedWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"job":{"id":"foreign","workflowId":"pfw_foreign"}}}`))
	}))
	t.Cleanup(server.Close)
	_, err := claimRunnerJob(server.Client(), scopedRunnerOptions(t, server.URL), scopedRegistration(t))
	if err == nil || !strings.Contains(err.Error(), "outside selected workflow") {
		t.Fatalf("unexpected workflow must never reach execution: %v", err)
	}
}

func TestWorkflowScopedStreamSendsSelection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("workflowId") != "pfw_appeal" {
			t.Error("stream lost workflow selection")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: runner.queue.empty\ndata: {\"eventType\":\"runner.queue.empty\"}\n\n"))
	}))
	t.Cleanup(server.Close)
	available, err := streamRunnerJobAvailable(server.Client(), scopedRunnerOptions(t, server.URL), scopedRegistration(t))
	if err != nil || available {
		t.Fatalf("expected scoped empty stream: available=%v err=%v", available, err)
	}
}

func TestWorkflowScopeRequiresNonemptyID(t *testing.T) {
	for _, args := range [][]string{{"--workflow-id"}, {"--workflow-id", ""}, {"--workflow-id", "   "}} {
		if _, err := parseRunnerOnceOptions(args); err == nil {
			t.Fatalf("invalid workflow scope accepted: %v", args)
		}
	}
}
