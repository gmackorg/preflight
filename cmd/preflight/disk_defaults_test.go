package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultReclaimRootsFindRealXcodeLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_WORKSPACE_ROOTS", "")
	cache := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "App-abc", "cache")
	writeCleanupFixture(t, cache, "regenerable", time.Now().Add(-48*time.Hour))
	artifact := filepath.Join(home, "Library", "Developer", "Xcode", "Archives", "release.xcarchive")
	writeCleanupFixture(t, artifact, "release", time.Now().Add(-48*time.Hour))
	var out bytes.Buffer
	for _, root := range defaultReclaimRoots() {
		if _, err := cleanupBuilds(root, 24*time.Hour, true, false, &out); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "App-abc") || strings.Contains(out.String(), "release.xcarchive") {
		t.Fatalf("incorrect cleanup scope: %s", out.String())
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("dry run removed cache: %v", err)
	}
}

func TestSubsequentRunnerClaimRefusesLowDiskBeforeHTTPRequest(t *testing.T) {
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "1000000000")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Errorf("low disk must refuse before claiming: %s", r.URL)
	}))
	defer server.Close()
	var out bytes.Buffer
	err := claimAndHandleNextRunnerJob(server.Client(), runnerOnceOptions{workspaceRoot: t.TempDir()}, runnerRegistrationData{}, &out, nil)
	if err != nil || requests != 0 || !strings.Contains(out.String(), "declining claims") {
		t.Fatalf("err=%v requests=%d output=%s", err, requests, out.String())
	}
}
