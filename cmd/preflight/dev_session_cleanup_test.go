package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDevSessionStartRetainsOnlyAcknowledgedLiveSession(t *testing.T) {
	for _, status := range []string{"succeeded", "cancelled", "failed", "expired", "request_failed"} {
		t.Run(status, func(t *testing.T) {
			appDir := writeExpoFixture(t)
			foreign := startTestMetroProcess(t, t.TempDir())
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			fakeBin := t.TempDir()
			script := "#!/bin/sh\nexport PREFLIGHT_TEST_METRO_PROCESS=1\nexec '" + strings.ReplaceAll(binary, "'", "'\\''") + "' -test.run='^TestMetroOwnerHelperProcess$' -- \"$@\"\n"
			if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "10ms")
			port := allocateBuildMetroPort(19000)
			pid := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/complete") {
					content, err := os.ReadFile(filepath.Join(appDir, ".preflight", "expo-dev-session.pid"))
					if err != nil {
						t.Error(err)
					}
					pid, err = strconv.Atoi(strings.TrimSpace(string(content)))
					if err != nil {
						t.Error(err)
					}
					if status == "request_failed" {
						http.Error(w, "completion unavailable", http.StatusServiceUnavailable)
						return
					}
					fmt.Fprintf(w, `{"data":{"job":{"id":"start_1","status":%q}}}`, status)
					return
				}
				fmt.Fprint(w, `{"data":{"job":{"id":"start_1","status":"running","runnerId":"runner_1"}}}`)
			}))
			defer server.Close()
			t.Cleanup(func() {
				if pid > 0 {
					terminateCommandProcess(pid)
				}
			})
			options := runnerOnceOptions{apiURL: server.URL, workspaceRoot: appDir, hostMode: "localhost", metroPort: port}
			registration := runnerRegistrationData{Runner: apiRunner{ID: "runner_1", Capabilities: map[string]any{"runnerJobHeartbeat": false}}, Token: "test-token"}
			job := apiRunnerJob{ID: "start_1", WorkflowID: "workflow_1", Kind: "dev_session.start", Payload: runnerJobPayload{
				Platform: "ios", Lane: "development", SourceBinding: runnerJobSourceBinding{WorkspaceRoot: appDir, PackagePath: ".", AppScheme: "forgegraph", ExpoSlug: "forgegraf"},
			}}
			var output bytes.Buffer
			continued, err := handleDevSessionStartJob(server.Client(), options, registration, job, &output)
			if pid <= 0 || (err != nil) != (status == "request_failed") {
				t.Fatalf("unexpected start completion: pid=%d continued=%v err=%v output=%s", pid, continued, err, output.String())
			}
			keep := status == "succeeded"
			if continued != keep || devSessionProcessGroupLive(pid) != keep {
				t.Fatalf("only an acknowledged successful start may retain its Metro: continued=%v status=%s", continued, status)
			}
			for _, name := range []string{"expo-dev-session.pid", "expo-dev-session-owner.json"} {
				_, err := os.Stat(filepath.Join(appDir, ".preflight", name))
				if keep && err != nil || !keep && !os.IsNotExist(err) {
					t.Fatalf("unexpected ownership handle after %s: %s %v", status, name, err)
				}
			}
			if !metroStatusReady(http.DefaultClient, foreign.URL+"/status") {
				t.Fatal("completion cleanup stopped a foreign session")
			}
		})
	}
}

func TestCancelledNativeJobDrainsOnlyItsSessionCleanup(t *testing.T) {
	appDir := t.TempDir()
	writeExpoConfigIdentity(t, appDir)
	owned := startTestMetroProcess(t, appDir)
	foreign := startTestMetroProcess(t, t.TempDir())
	writeTestMetroPID(t, appDir, owned.PID)
	var completed []string
	claims := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/jobs/pfjob_open/complete"):
			completed = append(completed, "cancelled")
			fmt.Fprint(w, `{"data":{"job":{"id":"pfjob_open","status":"cancelled"}}}`)
		case strings.HasSuffix(r.URL.Path, "/jobs/claim"):
			if claims > 0 {
				fmt.Fprint(w, `null`)
				return
			}
			claims++
			var body struct {
				WorkflowID string `json:"workflowId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.WorkflowID != "workflow_1" {
				t.Errorf("cleanup claim must stay in cancelled workflow: %+v %v", body, err)
			}
			fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_stop","workflowId":"workflow_1","kind":"dev_session.stop","status":"running","payload":{"sourceBinding":{"workspaceRoot":%q,"packagePath":".","appScheme":"forgegraph","expoSlug":"forgegraf"},"devSession":{"id":"session_1","pid":%d,"statusUrl":%q}}}}}`, appDir, owned.PID, owned.URL+"/status")
		case strings.HasSuffix(r.URL.Path, "/jobs/pfjob_stop/complete"):
			var body struct {
				Result struct {
					Status string `json:"status"`
				} `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Result.Status != "ok" {
				t.Errorf("expected verified cleanup: %+v %v", body, err)
			}
			completed = append(completed, "stopped")
			fmt.Fprint(w, `{"data":{"job":{"id":"pfjob_stop","status":"succeeded"}}}`)
		default:
			t.Errorf("unexpected cleanup request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	options := runnerOnceOptions{apiURL: server.URL, workspaceRoot: appDir}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "runner_1", Capabilities: map[string]any{"runnerJobHeartbeat": false}}, Token: "test-token", ClaimScopes: []string{"workflow"}}
	job := apiRunnerJob{ID: "pfjob_open", WorkflowID: "workflow_1"}
	var output bytes.Buffer
	if err := completeCancelledJobAndCleanup(server.Client(), options, registration, job, map[string]any{"status": "cancelled"}, &output); err != nil {
		t.Fatal(err)
	}
	if claims != 1 || strings.Join(completed, ",") != "cancelled,stopped" {
		t.Fatalf("cleanup not drained exactly once: %d %v", claims, completed)
	}
	if metroStatusReady(server.Client(), owned.URL+"/status") {
		t.Fatal("owned Metro survived cancellation")
	}
	if !metroStatusReady(server.Client(), foreign.URL+"/status") {
		t.Fatal("foreign Metro must survive cancellation")
	}
}

func TestVerifiedSessionStopRejectsForeignAndUnownedProcesses(t *testing.T) {
	appDir := t.TempDir()
	foreign := startTestMetroProcess(t, t.TempDir())
	writeTestMetroPID(t, appDir, foreign.PID)
	job := apiRunnerJob{WorkflowID: "workflow_1", Payload: runnerJobPayload{DevSession: runnerJobDevSession{PID: foreign.PID, StatusURL: foreign.URL + "/status"}}}
	if _, err := stopVerifiedDevSession(appDir, job); err == nil {
		t.Fatal("a pid handle alone cannot authorize stopping a foreign process")
	}
	if !metroStatusReady(http.DefaultClient, foreign.URL+"/status") {
		t.Fatal("unverified process was stopped")
	}
	if _, err := os.Stat(filepath.Join(appDir, ".preflight", "expo-dev-session.pid")); err != nil {
		t.Fatal("rejected ownership must retain the handle for diagnosis")
	}
}

func TestVerifiedSessionStopPreservesBorrowedAndReplacedSessions(t *testing.T) {
	for _, mode := range []string{"borrowed", "replaced"} {
		t.Run(mode, func(t *testing.T) {
			appDir := t.TempDir()
			owned := startTestMetroProcess(t, appDir)
			writeTestMetroPID(t, appDir, owned.PID)
			start := apiRunnerJob{ID: "start_1", WorkflowID: "workflow_1"}
			if err := writeDevSessionProcessOwner(appDir, owned.PID, start); err != nil {
				t.Fatal(err)
			}
			if mode == "borrowed" {
				if err := recordDevSessionBorrower(appDir, apiRunnerJob{WorkflowID: "workflow_2"}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := writeDevSessionProcessOwner(appDir, owned.PID, apiRunnerJob{ID: "start_2", WorkflowID: "workflow_2"}); err != nil {
					t.Fatal(err)
				}
			}
			stop := apiRunnerJob{WorkflowID: start.WorkflowID, Payload: runnerJobPayload{DevSession: runnerJobDevSession{PID: owned.PID, RunnerJobID: start.ID, StatusURL: owned.URL + "/status"}}}
			if _, err := stopVerifiedDevSession(appDir, stop); err == nil {
				t.Fatal("a shared or replaced session must survive its old workflow cancellation")
			}
			if !metroStatusReady(http.DefaultClient, owned.URL+"/status") {
				t.Fatal("another live owner lost its session")
			}
		})
	}
}
