package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain keeps the package's many `runner once` tests on the single-claim
// behaviour their fakes were written for: they answer one empty claim and
// expect the command to return. The idle tests below opt back in explicitly.
func TestMain(m *testing.M) {
	defaultRunnerIdleWait = 0
	os.Exit(m.Run())
}

// fakeRunnerIdleClock replaces the idle sleep with a clock that advances
// instantly and records every delay.
func fakeRunnerIdleClock(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	current := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	delays := []time.Duration{}
	previousSleep, previousNow := runnerIdleSleep, runnerIdleNow
	runnerIdleSleep = func(delay time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		delays = append(delays, delay)
		current = current.Add(delay)
	}
	runnerIdleNow = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	t.Cleanup(func() { runnerIdleSleep, runnerIdleNow = previousSleep, previousNow })
	return &delays
}

func TestNextRunnerIdleDelayDoublesToTheCeiling(t *testing.T) {
	policy := runnerIdlePolicy{pollMin: 10 * time.Second, pollMax: 60 * time.Second}
	var got []time.Duration
	delay := time.Duration(0)
	for range 6 {
		delay = nextRunnerIdleDelay(delay, policy)
		got = append(got, delay)
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestRunnerIdlePolicyNormalizesAnInvertedRange(t *testing.T) {
	policy := runnerIdlePolicy{pollMin: 90 * time.Second, pollMax: 30 * time.Second}.normalized()
	if policy.pollMax != 90*time.Second {
		t.Fatalf("expected max raised to min, got %v", policy.pollMax)
	}
}

func TestParseRunnerOnceOptionsIdleDefaultsFlagsAndEnv(t *testing.T) {
	previous := defaultRunnerIdleWait
	defaultRunnerIdleWait = 10 * time.Minute
	t.Cleanup(func() { defaultRunnerIdleWait = previous })
	base := []string{"--api-url", "https://preflight.test", "--workspace-id", "ws", "--workspace-root", t.TempDir()}

	options, err := parseRunnerOnceOptions(base)
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if options.idle != (runnerIdlePolicy{wait: 10 * time.Minute, pollMin: 10 * time.Second, pollMax: 60 * time.Second}) {
		t.Fatalf("unexpected default idle policy %+v", options.idle)
	}

	t.Setenv("PREFLIGHT_RUNNER_IDLE_WAIT", "0")
	t.Setenv("PREFLIGHT_RUNNER_IDLE_POLL_MAX", "2m")
	options, err = parseRunnerOnceOptions(base)
	if err != nil {
		t.Fatalf("parse env: %v", err)
	}
	if options.idle.wait != 0 || options.idle.pollMax != 2*time.Minute {
		t.Fatalf("expected env idle policy, got %+v", options.idle)
	}

	options, err = parseRunnerOnceOptions(append(base, "--idle-wait", "5m", "--idle-poll-min", "15s", "--idle-poll-max", "45s"))
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if options.idle != (runnerIdlePolicy{wait: 5 * time.Minute, pollMin: 15 * time.Second, pollMax: 45 * time.Second}) {
		t.Fatalf("expected flag idle policy, got %+v", options.idle)
	}

	if _, err := parseRunnerOnceOptions(append(base, "--idle-poll-min", "0")); err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("expected a zero poll interval to be rejected, got %v", err)
	}
	if _, err := parseRunnerOnceOptions(append(base, "--idle-wait", "soon")); err == nil {
		t.Fatal("expected an unparseable idle wait to be rejected")
	}
}

// idleRunnerServer is a Preflight API fake for an idle `runner once`: every
// claim is empty until claimsBeforeJob claims have been answered, then the
// claim returns a job the runner cannot handle (so the command ends right
// after claiming it).
func idleRunnerServer(t *testing.T, claimsBeforeJob int) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	claims := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs") {
			_, _ = w.Write([]byte(`{"data":{},"meta":{"apiVersion":"v1"}}`))
			return
		}
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_idle","workspaceId":"ws","name":"idle","hostIdentity":"idle.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"runnerJobStream":true}},"token":"runner_token"},"meta":{"apiVersion":"v1"}}`))
		case "GET /api/preflight/v1/runners/pfrun_idle/signing-cert":
			w.WriteHeader(http.StatusNotFound)
		case "POST /api/preflight/v1/runners/pfrun_idle/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_idle","status":"online"}},"meta":{"apiVersion":"v1"}}`))
		case "POST /api/preflight/v1/runners/pfrun_idle/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1"}}`))
		case "POST /api/preflight/v1/runners/pfrun_idle/jobs/claim":
			mu.Lock()
			claims++
			current := claims
			mu.Unlock()
			if claimsBeforeJob < 0 || current <= claimsBeforeJob {
				_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_idle","kind":"runner.capabilities.probe","status":"running","runnerId":"pfrun_idle"}},"meta":{"apiVersion":"v1"}}`))
		default:
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}
}

func countIdleRunnerCalls(calls []string, call string) int {
	count := 0
	for _, candidate := range calls {
		if candidate == call {
			count++
		}
	}
	return count
}

func TestRunnerOnceIdleBacksOffWithoutReregisteringOrStreaming(t *testing.T) {
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	delays := fakeRunnerIdleClock(t)
	server, calls := idleRunnerServer(t, -1)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"runner", "once",
			"--api-url", server.URL,
			"--workspace-id", "ws",
			"--workspace-root", t.TempDir(),
			"--host-identity", "idle.local",
			"--idle-wait", "5m",
		},
		&stdout, &stderr, server.Client(),
	)
	if code != 0 {
		t.Fatalf("expected exit 0\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}

	// 10+20+40+60+60+60 = 250 s; one more 60 s poll would pass the 300 s
	// window, so the command exits and the supervisor re-registers.
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second}
	if len(*delays) != len(want) {
		t.Fatalf("idle delays: got %v want %v", *delays, want)
	}
	for i := range want {
		if (*delays)[i] != want[i] {
			t.Fatalf("idle delays: got %v want %v", *delays, want)
		}
	}
	got := calls()
	if n := countIdleRunnerCalls(got, "POST /api/preflight/v1/runners/register"); n != 1 {
		t.Fatalf("expected one registration for the whole idle window, got %d: %v", n, got)
	}
	if n := countIdleRunnerCalls(got, "POST /api/preflight/v1/runners/pfrun_idle/reconcile"); n != 1 {
		t.Fatalf("expected one reconcile for the whole idle window, got %d: %v", n, got)
	}
	if n := countIdleRunnerCalls(got, "POST /api/preflight/v1/runners/pfrun_idle/jobs/claim"); n != 1+len(want) {
		t.Fatalf("expected %d claims, got %d: %v", 1+len(want), n, got)
	}
	for _, call := range got {
		if strings.Contains(call, "/jobs/stream") {
			t.Fatalf("idle runner must not open the job stream: %v", got)
		}
	}
	if !strings.Contains(stdout.String(), "no runner jobs available") {
		t.Fatalf("expected the idle exit message, got %s", stdout.String())
	}
}

func TestWaitForIdleRunnerJobStopsPollingWhenWorkArrives(t *testing.T) {
	delays := fakeRunnerIdleClock(t)
	server, calls := idleRunnerServer(t, 2)
	options := runnerOnceOptions{
		apiURL:        server.URL,
		workspaceRoot: t.TempDir(),
		idle:          runnerIdlePolicy{wait: 10 * time.Minute, pollMin: 10 * time.Second, pollMax: 60 * time.Second},
	}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_idle"}, Token: "runner_token"}

	// The caller's own first claim is the first empty one.
	if first, err := claimRunnerJob(server.Client(), options, registration); err != nil || first != nil {
		t.Fatalf("expected an empty first claim, got %#v %v", first, err)
	}
	var stdout bytes.Buffer
	claim, err := waitForIdleRunnerJob(server.Client(), options, registration, &stdout)
	if err != nil {
		t.Fatalf("wait for idle job: %v", err)
	}
	if claim == nil || claim.Job.ID != "pfjob_idle" {
		t.Fatalf("expected the queued job, got %#v", claim)
	}
	if len(*delays) != 2 || (*delays)[0] != 10*time.Second || (*delays)[1] != 20*time.Second {
		t.Fatalf("expected pickup on the second idle poll, got delays %v", *delays)
	}
	if n := countIdleRunnerCalls(calls(), "POST /api/preflight/v1/runners/pfrun_idle/jobs/claim"); n != 3 {
		t.Fatalf("expected three claims, got %d", n)
	}
}

func TestWaitForIdleRunnerJobDisabledByZeroWait(t *testing.T) {
	delays := fakeRunnerIdleClock(t)
	server, calls := idleRunnerServer(t, -1)
	claim, err := waitForIdleRunnerJob(
		server.Client(),
		runnerOnceOptions{apiURL: server.URL, workspaceRoot: t.TempDir()},
		runnerRegistrationData{Runner: apiRunner{ID: "pfrun_idle"}, Token: "runner_token"},
		&bytes.Buffer{},
	)
	if err != nil || claim != nil {
		t.Fatalf("expected nothing, got %#v %v", claim, err)
	}
	if len(*delays) != 0 || len(calls()) != 0 {
		t.Fatalf("expected no polling, got delays %v calls %v", *delays, calls())
	}
}
