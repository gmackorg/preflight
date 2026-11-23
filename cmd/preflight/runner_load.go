package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Load-aware claims.
//
// The control plane hands the next claimable job to whichever runner asks
// first (claimNextJob in preflight-app). It caps Preflight's own heavy jobs per
// machine, but it cannot see anything else running on the host. On 2026-11-23
// labtop (12 cores) ran at a load average around 930 with memory pressure at
// warn, its T3 server stopped answering, and its runner kept claiming jobs
// (and, through `simlock --local`, their simulators) while gmacko-mini's three
// runners sat idle logging "no runner jobs available".
//
// Before a fresh claim the runner now samples host pressure. A busy host
// defers: it skips that poll and keeps its idle backoff, so a quieter host that
// polls in the meantime takes the job. Deferral is bounded. After
// maxDefer of continuous deferral the runner claims anyway, so work still runs
// when every host is busy and no host is starved. The window then restarts, so
// a busy host takes at most one claim attempt per window while it stays busy.
//
// Continuation claims inside one work sequence (probe -> discover ->
// dev_session -> build) are not gated: workflow machine affinity pins those
// jobs to this machine, so deferring would only delay them.

const (
	defaultClaimMaxLoadPerCore = 1.5
	defaultClaimMaxXcodebuilds = 2
	defaultClaimMaxDefer       = 3 * time.Minute

	// kern.memorystatus_vm_pressure_level: 1 normal, 2 warn, 4 critical.
	memoryPressureWarn = 2
)

type hostPressure struct {
	load1       float64 // 1-minute load average; <0 when unknown
	cores       int
	memoryLevel int // kern.memorystatus_vm_pressure_level; 0 when unknown
	xcodebuilds int // concurrent xcodebuild builds/archives/tests; <0 when unknown
}

type runnerClaimLoadPolicy struct {
	enabled        bool
	maxLoadPerCore float64
	maxXcodebuilds int
	maxDefer       time.Duration
}

func defaultRunnerClaimLoadPolicy() runnerClaimLoadPolicy {
	policy := runnerClaimLoadPolicy{
		enabled:        true,
		maxLoadPerCore: defaultClaimMaxLoadPerCore,
		maxXcodebuilds: defaultClaimMaxXcodebuilds,
		maxDefer:       nonNegativeDurationFromEnv("PREFLIGHT_CLAIM_MAX_DEFER", defaultClaimMaxDefer),
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PREFLIGHT_CLAIM_LOAD_GATE"))) {
	case "0", "false", "off", "no":
		policy.enabled = false
	}
	if raw := strings.TrimSpace(os.Getenv("PREFLIGHT_CLAIM_MAX_LOAD_PER_CORE")); raw != "" {
		if value, err := strconv.ParseFloat(raw, 64); err == nil && value > 0 {
			policy.maxLoadPerCore = value
		}
	}
	if raw := strings.TrimSpace(os.Getenv("PREFLIGHT_CLAIM_MAX_XCODEBUILDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 {
			policy.maxXcodebuilds = value
		}
	}
	return policy
}

// busyReason explains why the host is too busy to claim, or returns "" when it
// may claim. Unknown signals never count as busy: a sampler that fails (for
// example on a Linux runner) must not stop the host from working.
func (policy runnerClaimLoadPolicy) busyReason(pressure hostPressure) string {
	reasons := []string{}
	if pressure.load1 >= 0 && pressure.cores > 0 {
		perCore := pressure.load1 / float64(pressure.cores)
		if perCore > policy.maxLoadPerCore {
			reasons = append(reasons, fmt.Sprintf("load %.1f on %d cores (%.2f/core > %.2f)", pressure.load1, pressure.cores, perCore, policy.maxLoadPerCore))
		}
	}
	if pressure.memoryLevel >= memoryPressureWarn {
		level := "warn"
		if pressure.memoryLevel >= 4 {
			level = "critical"
		}
		reasons = append(reasons, "memory pressure "+level)
	}
	if policy.maxXcodebuilds > 0 && pressure.xcodebuilds >= policy.maxXcodebuilds {
		reasons = append(reasons, fmt.Sprintf("%d xcodebuild builds running (limit %d)", pressure.xcodebuilds, policy.maxXcodebuilds))
	}
	return strings.Join(reasons, ", ")
}

// runnerClaimGate holds one `runner once` invocation's deferral window.
type runnerClaimGate struct {
	policy        runnerClaimLoadPolicy
	sample        func() hostPressure
	now           func() time.Time
	deferredSince time.Time
	lastReason    string
}

// sampleHostPressure is replaced by tests.
var sampleHostPressure = sampleLocalHostPressure

func newRunnerClaimGate(options runnerOnceOptions) *runnerClaimGate {
	policy := defaultRunnerClaimLoadPolicy()
	// A workflow-scoped runner was started for one specific workflow; it is
	// not competing with the farm for general work.
	if options.workflowID != "" {
		policy.enabled = false
	}
	return &runnerClaimGate{
		policy: policy,
		sample: func() hostPressure { return sampleHostPressure() },
		now:    func() time.Time { return runnerIdleNow() },
	}
}

// admit reports whether the runner should claim now. A nil gate always admits.
func (gate *runnerClaimGate) admit(stdout io.Writer) bool {
	if gate == nil || !gate.policy.enabled {
		return true
	}
	reason := gate.policy.busyReason(gate.sample())
	gate.lastReason = reason
	if reason == "" {
		gate.deferredSince = time.Time{}
		return true
	}
	now := gate.now()
	if gate.deferredSince.IsZero() {
		gate.deferredSince = now
	}
	waited := now.Sub(gate.deferredSince)
	if waited >= gate.policy.maxDefer {
		fmt.Fprintf(stdout, "host busy (%s) but deferred %s; claiming anyway\n", reason, waited.Round(time.Second))
		gate.deferredSince = now
		return true
	}
	fmt.Fprintf(stdout, "deferring claim, host busy: %s (deferred %s of %s)\n", reason, waited.Round(time.Second), gate.policy.maxDefer)
	return false
}

func sampleLocalHostPressure() hostPressure {
	return hostPressure{
		load1:       sampleLoad1(),
		cores:       runtime.NumCPU(),
		memoryLevel: sampleMemoryPressureLevel(),
		xcodebuilds: countBusyXcodebuilds(sampleProcessCommands()),
	}
}

func sysctlValue(name string) (string, bool) {
	out, err := exec.Command("/usr/sbin/sysctl", "-n", name).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func sampleLoad1() float64 {
	if raw, ok := sysctlValue("vm.loadavg"); ok {
		if load, ok := parseDarwinLoadavg(raw); ok {
			return load
		}
	}
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(raw)); len(fields) > 0 {
			if load, err := strconv.ParseFloat(fields[0], 64); err == nil {
				return load
			}
		}
	}
	return -1
}

// parseDarwinLoadavg reads `sysctl -n vm.loadavg`, e.g. "{ 4.12 3.80 3.55 }".
func parseDarwinLoadavg(raw string) (float64, bool) {
	fields := strings.Fields(strings.Trim(strings.TrimSpace(raw), "{}"))
	if len(fields) == 0 {
		return 0, false
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return load, true
}

func sampleMemoryPressureLevel() int {
	raw, ok := sysctlValue("kern.memorystatus_vm_pressure_level")
	if !ok {
		return 0
	}
	level, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return level
}

func sampleProcessCommands() []string {
	out, err := exec.Command("/bin/ps", "-axo", "command=").Output()
	if err != nil {
		return nil
	}
	return strings.Split(string(out), "\n")
}

// countBusyXcodebuilds counts xcodebuild processes doing real work. Quick
// queries (-list, -showBuildSettings, -version, ...) are ignored, and so is
// `test-without-building`: agent-device keeps one alive for the whole life of
// a simulator session as its UI-automation driver, which costs little CPU.
func countBusyXcodebuilds(commands []string) int {
	count := 0
	for _, command := range commands {
		fields := strings.Fields(command)
		if len(fields) == 0 || filepath.Base(fields[0]) != "xcodebuild" {
			continue
		}
		light := false
		for _, arg := range fields[1:] {
			switch arg {
			case "test-without-building", "-list", "-showBuildSettings", "-version",
				"-showsdks", "-showdestinations", "-resolvePackageDependencies",
				"-checkFirstLaunchStatus", "-runFirstLaunch":
				light = true
			}
		}
		if !light {
			count++
		}
	}
	return count
}
