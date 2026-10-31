package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRunnerJobCancellationStopsOnLostClaim(t *testing.T) {
	for _, tc := range []struct {
		name, code, status, runner, owner, claimed string
	}{
		{name: "lease denied", code: "runner_job_lease_denied"},
		{name: "lease expired", code: "runner_job_lease_expired"},
		{name: "not running", code: "runner_job_not_running"},
		{name: "device lease lost", code: "target_busy"},
		{name: "requeued", status: "queued"},
		{name: "completed", status: "succeeded"},
		{name: "failed", status: "failed"},
		{name: "reassigned", status: "running", runner: "other-runner"},
		{name: "same runner new owner", status: "running", runner: "runner", owner: "other-owner"},
		{name: "same runner reclaimed", status: "running", runner: "runner", owner: "owner", claimed: "2026-10-31T21:00:01Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tc.code != "" {
					w.WriteHeader(http.StatusConflict)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":"claim lost"}}`, tc.code)
					return
				}
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"job","status":%q,"runnerId":%q,"leaseOwner":%q,"claimedAt":%q}}}`, tc.status, tc.runner, tc.owner, tc.claimed)
			}))
			defer server.Close()
			var job apiRunnerJob
			if err := json.Unmarshal([]byte(`{"id":"job","status":"running","runnerId":"runner","leaseOwner":"owner","claimedAt":"2026-10-31T21:00:00Z"}`), &job); err != nil {
				t.Fatal(err)
			}
			cancelled, err := runnerJobCancellationCheck(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}, Token: "token"}, job)()
			if cancelled || !jobLeaseLost(err) {
				t.Fatalf("lost claim must stop with ownership error, not cancellation: cancelled=%v err=%v", cancelled, err)
			}
		})
	}
}

func TestRunnerJobCancellationBoundsTransientFailuresByConfirmedClaim(t *testing.T) {
	initial := time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, lease string
		deadline    time.Duration
	}{
		{"short lease", "2026-10-31T21:01:00Z", time.Minute},
		{"long lease stale heartbeat", "2026-10-31T21:40:00Z", 5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// HTTP 429 is a temporary service refusal, not lost ownership, and
			// avoids the client's transport retry backoff in this clock test.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"error":{"code":"rate_limited"}}`)
			}))
			defer server.Close()
			var job apiRunnerJob
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"id":"job","status":"running","leaseExpiresAt":%q,"lastHeartbeatAt":"2026-10-31T21:00:00Z"}`, tc.lease)), &job); err != nil {
				t.Fatal(err)
			}
			now := initial
			check := runnerJobCancellationCheckWithClock(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, job, func() time.Time { return now })
			if cancelled, err := check(); cancelled || err != nil {
				t.Fatalf("temporary failure killed a still-live claim: %v %v", cancelled, err)
			}
			now = initial.Add(tc.deadline)
			if cancelled, err := check(); cancelled || !jobLeaseLost(err) {
				t.Fatalf("unconfirmed claim ran beyond its deadline: %v %v", cancelled, err)
			}
		})
	}
}

func TestRunnerJobCancellationFallbackReadRetainsRealCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":{"code":"runner_job_not_running"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"job":{"id":"job","status":"cancelled","runnerId":"runner"}}}`)
	}))
	defer server.Close()
	cancelled, err := runnerJobCancellationCheck(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, apiRunnerJob{ID: "job"})()
	if !cancelled || err != nil {
		t.Fatalf("same-claim cancellation was lost: %v %v", cancelled, err)
	}
}

func TestRunnerJobCancellationRenewsLongBuildAndBoundsFallbackRead(t *testing.T) {
	initial := time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC)
	now := initial
	failHeartbeat := false
	confirmed := initial
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if failHeartbeat {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"error":{"code":"rate_limited"}}`)
				return
			}
			confirmed = now
		}
		_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"job","status":"running","runnerId":"runner","leaseOwner":"owner","attempt":1,"claimedAt":%q,"lastHeartbeatAt":%q,"leaseExpiresAt":%q}}}`, initial.Format(time.RFC3339), confirmed.Format(time.RFC3339), confirmed.Add(40*time.Minute).Format(time.RFC3339))
	}))
	defer server.Close()
	job := apiRunnerJob{ID: "job", Status: "running", RunnerID: "runner", LeaseOwner: "owner", Attempt: 1, ClaimedAt: initial.Format(time.RFC3339), LastHeartbeatAt: initial.Format(time.RFC3339), LeaseExpiresAt: initial.Add(40 * time.Minute).Format(time.RFC3339)}
	check := runnerJobCancellationCheckWithClock(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, job, func() time.Time { return now })
	for minute := 1; minute <= 45; minute++ {
		now = initial.Add(time.Duration(minute) * time.Minute)
		if cancelled, err := check(); cancelled || err != nil {
			t.Fatalf("healthy long native build stopped at minute %d: %v %v", minute, cancelled, err)
		}
	}
	failHeartbeat = true
	now = confirmed.Add(4 * time.Minute)
	if cancelled, err := check(); cancelled || err != nil {
		t.Fatalf("fallback read killed still-live ownership: %v %v", cancelled, err)
	}
	now = confirmed.Add(5 * time.Minute)
	if cancelled, err := check(); cancelled || !jobLeaseLost(err) {
		t.Fatalf("read-only fallback renewed a stale claim: %v %v", cancelled, err)
	}
}

func TestLostClaimStopsCocoaPodsWithoutKillingForeignProcess(t *testing.T) {
	app := t.TempDir()
	if err := os.Mkdir(filepath.Join(app, "ios"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "npx"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The HTTP fixture changes ownership only after this actual setup subprocess
	// starts. Its inherited output pipe makes a surviving child visible as a hang.
	started := filepath.Join(app, "pod-started")
	childPID := filepath.Join(app, "pod-child")
	pod := fmt.Sprintf("#!/bin/sh\nsleep 30 &\necho $! > %q\ntouch %q\nwait\n", childPID, started)
	if err := os.WriteFile(filepath.Join(bin, "pod"), []byte(pod), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_SIMULATOR_OPEN_TIMEOUT", "1s")
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "5ms")
	foreign := exec.Command("sleep", "30")
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Process.Kill(); _ = foreign.Wait() }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(started); err == nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"runner_job_lease_denied","message":"job requeued"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"job":{"id":"job","status":"running","runnerId":"runner"}}}`)
	}))
	defer server.Close()
	log, err := os.Create(filepath.Join(app, "setup.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	check := runnerJobCancellationCheck(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, apiRunnerJob{ID: "job", Status: "running"})
	err = runExpoPrebuild(log, app, "ios", apiRunnerJob{}, check)
	if !jobLeaseLost(err) || errors.Is(err, errCommandTimedOut) {
		t.Fatalf("CocoaPods must stop on lost ownership, not its build timeout: %v", err)
	}
	if err := foreign.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("foreign process was interrupted: %v", err)
	}
	pidText, err := os.ReadFile(childPID)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(pidText)), "%d", &pid); err != nil {
		t.Fatal(err)
	}
	// The child can briefly remain a zombie until its system reaper runs. It
	// must never still be an executing process after the owned group is stopped.
	state, _ := exec.Command("ps", "-o", "stat=", "-p", fmt.Sprint(pid)).Output()
	if s := strings.TrimSpace(string(state)); s != "" && !strings.HasPrefix(s, "Z") {
		t.Fatalf("owned CocoaPods child survived: pid=%d state=%s", pid, s)
	}
}

func TestSimulatorJobDoesNotSubmitCompletionAfterClaimLoss(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "apps", "mobile")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "5ms")
	t.Setenv("PREFLIGHT_RUNNER_JOB_HEARTBEAT_INTERVAL", "1h")
	t.Setenv("PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT", "1s")
	started := filepath.Join(root, "boot-started")
	xcrun := writeFakeExecutable(t, "xcrun", fmt.Sprintf("#!/bin/sh\ntouch %q\nexec sleep 30\n", started))
	var completions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/complete") {
			completions.Add(1)
			_, _ = io.WriteString(w, `{"data":{"job":{"id":"job","status":"failed"}}}`)
			return
		}
		if _, err := os.Stat(started); err == nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"runner_job_lease_denied"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"job":{"id":"job","status":"running","runnerId":"runner"}}}`)
	}))
	defer server.Close()
	job := apiRunnerJob{ID: "job", Status: "running", TargetID: "target"}
	job.Payload.Platform = "ios"
	job.Payload.Lane = "simulator"
	job.Payload.SourceBinding = runnerJobSourceBinding{WorkspaceRoot: root, PackagePath: "apps/mobile"}
	var output bytes.Buffer
	err := handleSimulatorOpenJob(server.Client(), runnerOnceOptions{apiURL: server.URL, workspaceRoot: root, xcrunPath: xcrun}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, job, &output)
	if !jobLeaseLost(err) || completions.Load() != 0 {
		t.Fatalf("lost job submitted stale completion: completions=%d err=%v output=%s", completions.Load(), err, &output)
	}
}
