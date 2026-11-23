package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Claim admission: whether this runner is taking work right now, and if not,
// why.
//
// A runner that declines claims (disk under PREFLIGHT_MIN_FREE_DISK_GB) or
// defers them (host busy, see runner_load.go) used to say so only in its own
// log. On 2026-11-23 gmacko-mini's three agents declined every claim for disk
// while `preflight nodes` showed the node online with 22GB free and no
// warning (the server judged disk against a fixed 15GB, not the host's 25GB
// floor), so labtop took all the work. Every heartbeat now carries the
// runner's admission state and configured floor inside its capabilities, and
// the control plane surfaces them per node.

type runnerAdmissionTracker struct {
	mu     sync.Mutex
	state  string // "claiming", "declining" (cannot take work) or "deferring" (busy, will claim later)
	reason string // "disk" or "load" when not claiming
	detail string
	since  time.Time
}

var runnerAdmission = &runnerAdmissionTracker{}

func (tracker *runnerAdmissionTracker) set(state, reason, detail string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.state != state || tracker.reason != reason {
		tracker.since = runnerIdleNow()
	}
	tracker.state, tracker.reason, tracker.detail = state, reason, detail
}

// snapshot is the heartbeat form, or nil before the first admission decision.
func (tracker *runnerAdmissionTracker) snapshot() map[string]any {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.state == "" {
		return nil
	}
	out := map[string]any{
		"state": tracker.state,
		"since": tracker.since.UTC().Format(time.RFC3339),
	}
	if tracker.reason != "" {
		out["reason"] = tracker.reason
	}
	if tracker.detail != "" {
		out["detail"] = tracker.detail
	}
	return out
}

// admitRunnerClaim applies both admission guards before a claim: the disk
// floor, then host pressure (gate may be nil, e.g. for continuation claims
// inside a work sequence). It records the outcome for the heartbeat.
func admitRunnerClaim(options runnerOnceOptions, gate *runnerClaimGate, stdout io.Writer) bool {
	if err := ensureBuildDiskHeadroom(options.workspaceRoot, stdout); err != nil {
		fmt.Fprintf(stdout, "declining claims: %v\n", err)
		runnerAdmission.set("declining", "disk", err.Error())
		maybeAutoPrunePnpmStore(stdout)
		return false
	}
	if gate != nil && gate.policy.enabled {
		if !gate.admit(stdout) {
			runnerAdmission.set("deferring", "load", gate.lastReason)
			return false
		}
	}
	runnerAdmission.set("claiming", "", "")
	return true
}

// heartbeatCapabilities adds the admission state and configured disk floor to
// a copy of the runner's capabilities; the map passed in is shared with the
// liveness goroutine and must not be mutated.
func heartbeatCapabilities(capabilities map[string]any) map[string]any {
	out := make(map[string]any, len(capabilities)+2)
	for key, value := range capabilities {
		out[key] = value
	}
	if admission := runnerAdmission.snapshot(); admission != nil {
		out["claimAdmission"] = admission
	}
	if floor, err := buildDiskHeadroomFloor(os.Getenv("PREFLIGHT_MIN_FREE_DISK_GB")); err == nil && floor > 0 {
		out["minFreeDiskGb"] = float64(floor / bytesPerGiB)
	}
	return out
}

// Automatic pnpm store prune for a runner stuck under its disk floor.
//
// The floor deliberately never deletes build products (other runners on the
// host may need them), and the hourly launchd "disk sweep" only reports. So a
// host that fell under the floor stayed out of the farm until someone pruned
// by hand: on 2026-11-23 `pnpm store prune` freed 10GB on gmacko-mini. The
// store is content-addressable and regenerable, the same reasoning
// `preflight disk --reclaim` already uses. Guards:
//   - at most once per autoPruneInterval per host (shared stamp file, so three
//     agents on one Mac do not prune three times);
//   - skipped while any pnpm install/add is running, so a prune never races a
//     link in progress;
//   - PREFLIGHT_AUTO_PRUNE_PNPM_STORE=0 turns it off.
// T3 and other worktrees are never touched: they are live checkouts that may
// hold unpushed work.

const autoPruneInterval = time.Hour

// Replaced by tests.
var autoPruneStampPath = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".preflight", "pnpm-auto-prune.stamp")
}
var autoPruneRun = func(stdout io.Writer) bool { return prunePnpmStore(false, stdout, stdout) }
var autoPruneProcessCommands = sampleProcessCommands

func maybeAutoPrunePnpmStore(stdout io.Writer) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PREFLIGHT_AUTO_PRUNE_PNPM_STORE"))) {
	case "0", "false", "off", "no":
		return
	}
	stamp := autoPruneStampPath()
	if stamp == "" {
		return
	}
	if info, err := os.Stat(stamp); err == nil && runnerIdleNow().Sub(info.ModTime()) < autoPruneInterval {
		return
	}
	if pnpmInstallRunning(autoPruneProcessCommands()) {
		fmt.Fprintln(stdout, "under the disk floor; pnpm install running, not pruning the pnpm store now")
		return
	}
	// Claim the interval before pruning so concurrent agents skip it.
	if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(stamp, []byte(runnerIdleNow().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return
	}
	_ = os.Chtimes(stamp, runnerIdleNow(), runnerIdleNow())
	fmt.Fprintln(stdout, "under the disk floor; pruning unreferenced packages from the pnpm store (at most hourly)")
	autoPruneRun(stdout)
}

// pnpmInstallRunning reports a pnpm process that may be linking from the
// store right now.
func pnpmInstallRunning(commands []string) bool {
	for _, command := range commands {
		fields := strings.Fields(command)
		for index, field := range fields {
			base := filepath.Base(field)
			isPnpm := base == "pnpm" || base == "pnpm.cjs" || base == "pnpm.js"
			if !isPnpm || index+1 >= len(fields) {
				continue
			}
			switch fields[index+1] {
			case "install", "i", "add", "update", "up", "rebuild", "import", "fetch", "dlx", "store":
				return true
			}
		}
	}
	return false
}
