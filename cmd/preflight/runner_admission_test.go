package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetRunnerAdmission(t *testing.T) {
	t.Helper()
	previous := runnerAdmission
	runnerAdmission = &runnerAdmissionTracker{}
	t.Cleanup(func() { runnerAdmission = previous })
}

func TestAdmitRunnerClaimRecordsDiskDeclineAndPrunes(t *testing.T) {
	resetRunnerAdmission(t)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "999999")
	pruned := 0
	previousRun := autoPruneRun
	autoPruneRun = func(io.Writer) bool { pruned++; return true }
	stamp := filepath.Join(t.TempDir(), "stamp")
	previousStamp := autoPruneStampPath
	autoPruneStampPath = func() string { return stamp }
	previousCommands := autoPruneProcessCommands
	autoPruneProcessCommands = func() []string { return nil }
	t.Cleanup(func() {
		autoPruneRun, autoPruneStampPath, autoPruneProcessCommands = previousRun, previousStamp, previousCommands
	})

	var out bytes.Buffer
	if admitRunnerClaim(runnerOnceOptions{workspaceRoot: t.TempDir()}, nil, &out) {
		t.Fatal("expected a claim under the disk floor to be declined")
	}
	snapshot := runnerAdmission.snapshot()
	if snapshot["state"] != "declining" || snapshot["reason"] != "disk" || !strings.Contains(snapshot["detail"].(string), "below configured") {
		t.Fatalf("unexpected admission %v", snapshot)
	}
	if pruned != 1 {
		t.Fatalf("expected one automatic prune, got %d", pruned)
	}
	// The stamp throttles the next decline, including from other agents.
	admitRunnerClaim(runnerOnceOptions{workspaceRoot: t.TempDir()}, nil, &out)
	if pruned != 1 {
		t.Fatalf("expected the prune to be throttled, got %d", pruned)
	}
}

func TestAutoPruneSkipsWhilePnpmInstallsAndWhenDisabled(t *testing.T) {
	pruned := 0
	previousRun, previousStamp, previousCommands := autoPruneRun, autoPruneStampPath, autoPruneProcessCommands
	autoPruneRun = func(io.Writer) bool { pruned++; return true }
	stamp := filepath.Join(t.TempDir(), "stamp")
	autoPruneStampPath = func() string { return stamp }
	autoPruneProcessCommands = func() []string {
		return []string{"node /opt/homebrew/bin/pnpm install --frozen-lockfile"}
	}
	t.Cleanup(func() {
		autoPruneRun, autoPruneStampPath, autoPruneProcessCommands = previousRun, previousStamp, previousCommands
	})
	var out bytes.Buffer
	maybeAutoPrunePnpmStore(&out)
	if pruned != 0 || !strings.Contains(out.String(), "pnpm install running") {
		t.Fatalf("expected no prune during an install, pruned=%d out=%q", pruned, out.String())
	}
	if _, err := os.Stat(stamp); err == nil {
		t.Fatal("a skipped prune must not consume the interval")
	}
	autoPruneProcessCommands = func() []string { return nil }
	t.Setenv("PREFLIGHT_AUTO_PRUNE_PNPM_STORE", "0")
	maybeAutoPrunePnpmStore(&out)
	if pruned != 0 {
		t.Fatal("expected the opt-out to disable pruning")
	}
}

func TestPnpmInstallRunning(t *testing.T) {
	cases := map[string]bool{
		"pnpm install":                          true,
		"/usr/local/bin/pnpm i --filter app...": true,
		"node /x/pnpm.cjs add left-pad":         true,
		"pnpm store prune":                      true,
		"pnpm exec expo start --port 8100":      false,
		"pnpm run build":                        false,
		"node metro.js":                         false,
	}
	for command, want := range cases {
		if got := pnpmInstallRunning([]string{command}); got != want {
			t.Errorf("%q: got %v want %v", command, got, want)
		}
	}
}

func TestAdmitRunnerClaimRecordsLoadDeferral(t *testing.T) {
	resetRunnerAdmission(t)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "")
	gate := &runnerClaimGate{
		policy: testClaimLoadPolicy(),
		sample: func() hostPressure { return hostPressure{load1: 930, cores: 12, memoryLevel: 2} },
		now:    time.Now,
	}
	if admitRunnerClaim(runnerOnceOptions{workspaceRoot: t.TempDir()}, gate, &bytes.Buffer{}) {
		t.Fatal("expected a busy host to defer")
	}
	snapshot := runnerAdmission.snapshot()
	if snapshot["state"] != "deferring" || snapshot["reason"] != "load" || !strings.Contains(snapshot["detail"].(string), "load 930.0 on 12 cores") {
		t.Fatalf("unexpected admission %v", snapshot)
	}
	gate.sample = func() hostPressure { return hostPressure{load1: 1, cores: 12, memoryLevel: 1} }
	if !admitRunnerClaim(runnerOnceOptions{workspaceRoot: t.TempDir()}, gate, &bytes.Buffer{}) {
		t.Fatal("expected an idle host to claim")
	}
	if snapshot := runnerAdmission.snapshot(); snapshot["state"] != "claiming" || snapshot["reason"] != nil {
		t.Fatalf("unexpected admission %v", snapshot)
	}
}

func TestHeartbeatReportsAdmissionAndFloorWithoutMutatingCapabilities(t *testing.T) {
	resetRunnerAdmission(t)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "25")
	runnerAdmission.set("declining", "disk", "build disk headroom: /x has 22.1 GiB free, below configured 25 GiB floor")

	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"data":{},"meta":{"apiVersion":"v1"}}`))
	}))
	t.Cleanup(server.Close)

	capabilities := map[string]any{"platforms": []string{"ios"}}
	err := heartbeatRunner(server.Client(), runnerOnceOptions{apiURL: server.URL, workspaceRoot: t.TempDir()},
		runnerRegistrationData{Runner: apiRunner{ID: "pfrun_hb"}, Token: "t"}, capabilities)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, mutated := capabilities["claimAdmission"]; mutated {
		t.Fatal("heartbeat must not mutate the shared capabilities map")
	}
	sent, _ := body["capabilities"].(map[string]any)
	admission, _ := sent["claimAdmission"].(map[string]any)
	if admission["state"] != "declining" || admission["reason"] != "disk" {
		t.Fatalf("expected claimAdmission in the heartbeat, got %v", sent)
	}
	if sent["minFreeDiskGb"] != float64(25) {
		t.Fatalf("expected minFreeDiskGb 25, got %v", sent["minFreeDiskGb"])
	}
}

func TestPnpmStorePruneFloorSitsAboveTheClaimFloor(t *testing.T) {
	t.Setenv("PREFLIGHT_STORE_PRUNE_FLOOR_GB", "")
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "")
	if got := pnpmStorePruneFloorGb(); got != 25 {
		t.Fatalf("default: got %d", got)
	}
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "25")
	if got := pnpmStorePruneFloorGb(); got != 35 {
		t.Fatalf("expected the prune floor 10GB above a 25GB claim floor, got %d", got)
	}
	t.Setenv("PREFLIGHT_STORE_PRUNE_FLOOR_GB", "50")
	if got := pnpmStorePruneFloorGb(); got != 50 {
		t.Fatalf("explicit override: got %d", got)
	}
}

func TestClaimAdmissionWarningsNameDecliningAndDeferringNodes(t *testing.T) {
	var nodes []farmNode
	raw := `[
	  {"name":"gmacko-mini","status":"online","liveAgentCount":3,"agentCount":4,
	   "claimAdmission":{"agents":3,"declining":3,"deferring":0,"reason":"disk",
	     "detail":"build disk headroom: /Users/mackieg/preflight-ci has 22.1 GiB free, below configured 25 GiB floor","minFreeDiskGb":25}},
	  {"name":"labtop","status":"online","liveAgentCount":1,"agentCount":1,
	   "claimAdmission":{"agents":1,"declining":0,"deferring":1,"reason":"load","detail":"load 473.1 on 12 cores (39.43/core > 1.50), memory pressure warn"}},
	  {"name":"labnuc","status":"online","liveAgentCount":1,"agentCount":1,
	   "claimAdmission":{"agents":1,"declining":0,"deferring":0}},
	  {"name":"old","status":"stale","claimAdmission":{"agents":1,"declining":1,"reason":"disk"}},
	  {"name":"legacy","status":"online"}
	]`
	if err := json.Unmarshal([]byte(raw), &nodes); err != nil {
		t.Fatalf("decode: %v", err)
	}
	lines, blocking := claimAdmissionWarnings(nodes)
	if !blocking {
		t.Fatal("a declining node must make `preflight nodes` exit non-zero")
	}
	if len(lines) != 2 {
		t.Fatalf("expected warnings for gmacko-mini and labtop only, got %q", lines)
	}
	if !strings.Contains(lines[0], "WARNING: gmacko-mini: 3 of 3 agent(s) declining claims (disk)") || !strings.Contains(lines[0], "22.1 GiB free, below configured 25 GiB floor") || !strings.Contains(lines[0], "preflight disk --reclaim") {
		t.Fatalf("unexpected gmacko-mini warning %q", lines[0])
	}
	if !strings.Contains(lines[1], "NOTE: labtop: 1 of 1 agent(s) deferring claims, host busy: load 473.1") {
		t.Fatalf("unexpected labtop note %q", lines[1])
	}
	if _, blocking := claimAdmissionWarnings(nodes[1:2]); blocking {
		t.Fatal("deferring alone is not blocking")
	}
}
