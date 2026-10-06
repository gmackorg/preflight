package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStandaloneTunnelWaitsForDelayedURL(t *testing.T) {
	script := filepath.Join(t.TempDir(), "expo-start")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'Starting Metro\\n'\nsleep 0.15\nprintf 'exp+forgegraf://expo-development-client/?url=https%%3A%%2F%%2Fpreflight-tunnel.ngrok-free.app\\n'\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command, output, err := startStandaloneObservedPlannedCommandWithOutput(simulatorProofPlanCommand{Command: script}, io.Discard, time.Second, func(output string) bool { _, ready := expoTunnelDevServerURLFromLogContent(output); return ready })
	if command != nil {
		defer terminateProcessGroup(command)
	}
	if err != nil {
		t.Fatal(err)
	}
	if standaloneDevelopmentSessionReplacements(output)["EXPO_TUNNEL_URL"] != "https://preflight-tunnel.ngrok-free.app" {
		t.Fatalf("tunnel accepted startup output before URL: %q", output)
	}
}
