package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func testClaimLoadPolicy() runnerClaimLoadPolicy {
	return runnerClaimLoadPolicy{enabled: true, maxLoadPerCore: 1.5, maxXcodebuilds: 2, maxDefer: 3 * time.Minute, minMemoryLevel: memoryPressureCritical}
}

func TestClaimLoadPolicyBusyReasons(t *testing.T) {
	policy := testClaimLoadPolicy()
	cases := []struct {
		name     string
		pressure hostPressure
		want     string // substring; "" means not busy
	}{
		{"idle host", hostPressure{load1: 2, cores: 10, memoryLevel: 1}, ""},
		{"at the per-core limit", hostPressure{load1: 15, cores: 10, memoryLevel: 1}, ""},
		// labtop on 2026-11-23.
		{"labtop meltdown", hostPressure{load1: 930, cores: 12, memoryLevel: 2}, "load 930.0 on 12 cores"},
		// gmacko-mini on 2026-11-23: warn for minutes while otherwise idle.
		{"memory warn alone is not busy", hostPressure{load1: 4, cores: 10, memoryLevel: 2}, ""},
		{"memory critical", hostPressure{load1: 1, cores: 10, memoryLevel: 4}, "memory pressure critical"},
		{"one xcodebuild is fine", hostPressure{load1: 1, cores: 10, xcodebuilds: 1}, ""},
		{"two xcodebuilds", hostPressure{load1: 1, cores: 10, xcodebuilds: 2}, "2 xcodebuild builds running"},
		{"unknown signals never block", hostPressure{load1: -1, cores: 0, memoryLevel: 0, xcodebuilds: -1}, ""},
	}
	for _, tc := range cases {
		got := policy.busyReason(tc.pressure)
		if tc.want == "" && got != "" {
			t.Errorf("%s: expected not busy, got %q", tc.name, got)
		}
		if tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: expected %q in %q", tc.name, tc.want, got)
		}
	}
	// PREFLIGHT_CLAIM_MEMORY_PRESSURE=warn restores the stricter signal.
	strict := policy
	strict.minMemoryLevel = memoryPressureWarn
	if got := strict.busyReason(hostPressure{load1: 1, cores: 10, memoryLevel: 2}); !strings.Contains(got, "memory pressure warn") {
		t.Errorf("expected warn to count under the strict policy, got %q", got)
	}
	// A zero xcodebuild limit turns that signal off.
	policy.maxXcodebuilds = 0
	if got := policy.busyReason(hostPressure{load1: 1, cores: 10, xcodebuilds: 9}); got != "" {
		t.Errorf("expected the xcodebuild signal disabled, got %q", got)
	}
}

func TestClaimGateDefersThenClaimsAnywayAfterMaxDefer(t *testing.T) {
	current := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	busy := true
	gate := &runnerClaimGate{
		policy: testClaimLoadPolicy(),
		sample: func() hostPressure {
			if busy {
				return hostPressure{load1: 930, cores: 12, memoryLevel: 2}
			}
			return hostPressure{load1: 2, cores: 12, memoryLevel: 1}
		},
		now: func() time.Time { return current },
	}
	var out bytes.Buffer
	if gate.admit(&out) {
		t.Fatal("a busy host must defer its first claim")
	}
	current = current.Add(2*time.Minute + 59*time.Second)
	if gate.admit(&out) {
		t.Fatal("a busy host must keep deferring inside the window")
	}
	current = current.Add(time.Second)
	if !gate.admit(&out) {
		t.Fatal("a busy host must claim once the window has passed, so work never starves")
	}
	// The window restarts: at most one claim attempt per window while busy.
	current = current.Add(10 * time.Second)
	if gate.admit(&out) {
		t.Fatal("expected a fresh deferral window after a forced claim")
	}
	// Recovery admits immediately and clears the window.
	busy = false
	if !gate.admit(&out) {
		t.Fatal("an idle host must claim")
	}
	busy = true
	if gate.admit(&out) {
		t.Fatal("a host that becomes busy again starts a new window")
	}
	log := out.String()
	if !strings.Contains(log, "deferring claim, host busy: load 930.0 on 12 cores") || !strings.Contains(log, "claiming anyway") {
		t.Fatalf("expected deferral and override in the log, got:\n%s", log)
	}
}

func TestClaimGateDisabledAndNilAlwaysAdmit(t *testing.T) {
	var nilGate *runnerClaimGate
	if !nilGate.admit(&bytes.Buffer{}) {
		t.Fatal("a nil gate must admit")
	}
	policy := testClaimLoadPolicy()
	policy.enabled = false
	gate := &runnerClaimGate{policy: policy, sample: func() hostPressure { return hostPressure{load1: 999, cores: 1, memoryLevel: 4} }, now: time.Now}
	if !gate.admit(&bytes.Buffer{}) {
		t.Fatal("a disabled gate must admit")
	}
}

func TestClaimLoadPolicyFromEnv(t *testing.T) {
	policy := defaultRunnerClaimLoadPolicy()
	if !policy.enabled || policy.maxLoadPerCore != defaultClaimMaxLoadPerCore || policy.maxXcodebuilds != defaultClaimMaxXcodebuilds || policy.maxDefer != defaultClaimMaxDefer || policy.minMemoryLevel != memoryPressureCritical {
		t.Fatalf("unexpected defaults %+v", policy)
	}
	t.Setenv("PREFLIGHT_CLAIM_LOAD_GATE", "off")
	t.Setenv("PREFLIGHT_CLAIM_MAX_LOAD_PER_CORE", "1.0")
	t.Setenv("PREFLIGHT_CLAIM_MAX_XCODEBUILDS", "0")
	t.Setenv("PREFLIGHT_CLAIM_MAX_DEFER", "90s")
	t.Setenv("PREFLIGHT_CLAIM_MEMORY_PRESSURE", "warn")
	policy = defaultRunnerClaimLoadPolicy()
	if policy.enabled || policy.maxLoadPerCore != 1.0 || policy.maxXcodebuilds != 0 || policy.maxDefer != 90*time.Second || policy.minMemoryLevel != memoryPressureWarn {
		t.Fatalf("expected env overrides, got %+v", policy)
	}
}

func TestWorkflowScopedRunnerSkipsClaimGate(t *testing.T) {
	if newRunnerClaimGate(runnerOnceOptions{workflowID: "wf_1"}).policy.enabled {
		t.Fatal("a workflow-scoped runner must not defer its own workflow")
	}
	if !newRunnerClaimGate(runnerOnceOptions{}).policy.enabled {
		t.Fatal("a farm runner must gate claims by default")
	}
}

func TestParseDarwinLoadavg(t *testing.T) {
	if load, ok := parseDarwinLoadavg("{ 930.12 400.50 395.66 }\n"); !ok || load != 930.12 {
		t.Fatalf("got %v %v", load, ok)
	}
	if _, ok := parseDarwinLoadavg("{ }"); ok {
		t.Fatal("expected an empty loadavg to fail")
	}
}

func TestCountBusyXcodebuildsIgnoresDriversAndQueries(t *testing.T) {
	commands := []string{
		// A Preflight store archive (real work).
		"/Applications/Xcode-27.2.app/Contents/Developer/usr/bin/xcodebuild archive -workspace /x/Preflight.xcworkspace -scheme Preflight",
		// A plain build (real work).
		"xcodebuild -workspace App.xcworkspace -scheme App -sdk iphonesimulator build",
		// agent-device's long-lived UI driver: not a build.
		"/Applications/Xcode-27.2.app/Contents/Developer/usr/bin/xcodebuild test-without-building -only-testing AgentDeviceRunnerUITests/RunnerTests/testCommand",
		// Quick queries.
		"xcodebuild -showBuildSettings -json",
		"xcodebuild -version",
		// Not xcodebuild.
		"/usr/bin/grep xcodebuild",
		"",
	}
	if got := countBusyXcodebuilds(commands); got != 2 {
		t.Fatalf("expected 2 busy xcodebuilds, got %d", got)
	}
}

// End to end through the idle loop: a busy host never calls the claim
// endpoint inside the deferral window, then claims once it has passed.
func TestWaitForIdleRunnerJobDefersClaimsWhileHostBusy(t *testing.T) {
	delays := fakeRunnerIdleClock(t)
	server, calls := idleRunnerServer(t, 0)
	options := runnerOnceOptions{
		apiURL:        server.URL,
		workspaceRoot: t.TempDir(),
		idle:          runnerIdlePolicy{wait: 10 * time.Minute, pollMin: 10 * time.Second, pollMax: 60 * time.Second},
	}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_idle"}, Token: "runner_token"}
	gate := &runnerClaimGate{
		policy: testClaimLoadPolicy(),
		sample: func() hostPressure { return hostPressure{load1: 930, cores: 12, memoryLevel: 2} },
		now:    func() time.Time { return runnerIdleNow() },
	}
	var stdout bytes.Buffer
	claim, err := waitForIdleRunnerJob(server.Client(), options, registration, &stdout, gate)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if claim == nil || claim.Job.ID != "pfjob_idle" {
		t.Fatalf("expected the job after the deferral window, got %#v", claim)
	}
	if n := countIdleRunnerCalls(calls(), "POST /api/preflight/v1/runners/pfrun_idle/jobs/claim"); n != 1 {
		t.Fatalf("expected exactly one claim call, got %d", n)
	}
	// Polls at 10s, 30s, 70s, 130s, 190s; deferral starts at the 10s poll, so
	// the 190s poll is the first at or past the 3m window.
	elapsed := time.Duration(0)
	for _, delay := range *delays {
		elapsed += delay
	}
	if elapsed != 190*time.Second {
		t.Fatalf("expected the claim at 190s, got %v (delays %v)", elapsed, *delays)
	}
	if strings.Count(stdout.String(), "deferring claim") != 4 {
		t.Fatalf("expected four deferrals, got:\n%s", stdout.String())
	}
}
