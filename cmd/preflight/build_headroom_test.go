package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBuildDiskHeadroomPreservesUnownedStaleProduct(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "0")
	product := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "PersonalApp", "Build", "Products", "Debug-iphonesimulator", "Personal.app")
	writeCleanupFixture(t, product, "preserved-product", time.Now().Add(-48*time.Hour))
	root := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "PersonalApp")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(root, old, old); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ensureBuildDiskHeadroomWithProbe(t.TempDir(), &output, func(string) (uint64, error) { t.Fatal("disabled floor probed a volume"); return 0, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(product); err != nil {
		t.Fatalf("unowned stale product changed: %v", err)
	}
}

func TestBuildDiskHeadroomDoesNotReadBlockedGlobalCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "10")
	global := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData")
	if err := os.MkdirAll(filepath.Dir(global), 0755); err != nil {
		t.Fatal(err)
	}
	// This global-cache sentinel is not a directory. Disk checks have no need
	// to enumerate it, even when enabled under pressure.
	if err := syscall.Mkfifo(global, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		err := ensureBuildDiskHeadroomWithProbe(home, &bytes.Buffer{}, func(path string) (uint64, error) {
			if path != home {
				return 0, errors.New("blocked global cache path must never be probed")
			}
			return 5 * bytesPerGiB, nil
		})
		if err == nil || !strings.Contains(err.Error(), "below configured") {
			t.Errorf("expected low-space refusal, got %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("disk headroom check blocked on global cache")
	}
}

func TestBuildDiskHeadroomConfiguredFloor(t *testing.T) {
	home := t.TempDir()
	build := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "10")
	var probes []string
	var output bytes.Buffer
	err := ensureBuildDiskHeadroomWithProbe(build, &output, func(path string) (uint64, error) {
		probes = append(probes, path)
		return 10*bytesPerGiB + bytesPerGiB/5, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 2 || probes[0] != build || probes[1] != home {
		t.Fatalf("unexpected probe paths: %v", probes)
	}
	if !strings.Contains(output.String(), "configured 10 GiB") {
		t.Fatalf("missing configured floor: %s", output.String())
	}
}

func TestBuildDiskHeadroomHomeVolumeRefusesBuild(t *testing.T) {
	home := t.TempDir()
	build := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "10")
	err := ensureBuildDiskHeadroomWithProbe(build, &bytes.Buffer{}, func(path string) (uint64, error) {
		if path == home {
			return 5 * bytesPerGiB, nil
		}
		return 30 * bytesPerGiB, nil
	})
	if err == nil || !strings.Contains(err.Error(), home) || !strings.Contains(err.Error(), "below configured") {
		t.Fatalf("expected home-volume refusal, got %v", err)
	}
}

func TestBuildDiskHeadroomProbeErrorsFailClosed(t *testing.T) {
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "10")
	sentinel := errors.New("volume unavailable")
	err := ensureBuildDiskHeadroomWithProbe(t.TempDir(), &bytes.Buffer{}, func(string) (uint64, error) { return 0, sentinel })
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "cannot verify free space") {
		t.Fatalf("expected actionable probe failure, got %v", err)
	}
}

func TestBuildDiskHeadroomInvalidFloorFailsClosed(t *testing.T) {
	for _, raw := range []string{"-1", "abc", "1.5", "18446744073709551615"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", raw)
			err := ensureBuildDiskHeadroomWithProbe(t.TempDir(), &bytes.Buffer{}, func(string) (uint64, error) { t.Fatal("invalid floor probed filesystem"); return 0, nil })
			if err == nil || !strings.Contains(err.Error(), "PREFLIGHT_MIN_FREE_DISK_GB") {
				t.Fatalf("expected configuration failure, got %v", err)
			}
		})
	}
}

func TestBuildDiskHeadroomLowSpacePreservesOwnedAndSharedProducts(t *testing.T) {
	home := t.TempDir()
	build := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "10")
	products := []string{filepath.Join(build, ".preflight", "ios-sim-deriveddata", "Build", "Products", "Current.app"), filepath.Join(build, "artifacts", "Evidence.app"), filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "Personal", "Personal.app")}
	for _, product := range products {
		writeCleanupFixture(t, product, "retained", time.Now().Add(-48*time.Hour))
	}
	err := ensureBuildDiskHeadroomWithProbe(build, &bytes.Buffer{}, func(string) (uint64, error) { return 5 * bytesPerGiB, nil })
	if err == nil {
		t.Fatal("low space was accepted")
	}
	for _, product := range products {
		data, err := os.ReadFile(product)
		if err != nil || string(data) != "retained" {
			t.Fatalf("product changed: %s: %v", product, err)
		}
	}
}

func TestBuildDiskHeadroomBlockedVolumeProbeIsBounded(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	start := time.Now()
	_, err := probeBuildDiskFreeBytes("/blocked-volume", func(string) (uint64, error) { <-release; close(finished); return 0, nil }, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		close(release)
		t.Fatalf("expected bounded probe refusal, got %v", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		close(release)
		t.Fatal("blocked volume probe did not return promptly")
	}
	_, err = probeBuildDiskFreeBytes("/blocked-volume", func(string) (uint64, error) {
		t.Error("timed-out probe spawned another filesystem syscall")
		return 0, nil
	}, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "still running") {
		close(release)
		t.Fatalf("expected in-flight probe refusal, got %v", err)
	}
	close(release)
	<-finished
	// Wait for the pending probe's deferred slot release before subsequent tests.
	deadline := time.Now().Add(time.Second)
	for len(buildDiskProbeSlot) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(buildDiskProbeSlot) != 0 {
		t.Fatal("finished probe retained its slot")
	}
}

func TestSimulatorOpenReportsHeadroomFailureBeforeNativeCommands(t *testing.T) {
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "invalid")
	workspace := t.TempDir()
	app := filepath.Join(workspace, "apps", "mobile")
	if err := os.MkdirAll(app, 0755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, app)
	completed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/complete") {
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		var body struct {
			Result struct {
				Status  string `json:"status"`
				Failure struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"failure"`
			} `json:"result"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Result.Status != "failed" || body.Result.Failure.Code != "build_disk_headroom_unavailable" || !strings.Contains(body.Result.Failure.Message, "PREFLIGHT_MIN_FREE_DISK_GB") {
			t.Errorf("unexpected failure: %+v", body)
		}
		completed = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"job":{"id":"disk-job","status":"failed"}}}`))
	}))
	defer server.Close()
	job := apiRunnerJob{ID: "disk-job", Kind: "simulator.open"}
	job.Payload.Platform = "ios"
	job.Payload.ProviderIdentity = "fake-simulator"
	job.Payload.SourceBinding.WorkspaceRoot = workspace
	job.Payload.SourceBinding.PackagePath = "apps/mobile"
	err := handleSimulatorOpenJob(server.Client(), runnerOnceOptions{apiURL: server.URL, workspaceRoot: workspace}, runnerRegistrationData{Runner: apiRunner{ID: "test-runner"}, Token: "fixture"}, job, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !completed {
		t.Fatal("headroom failure did not complete source-bound job")
	}
	if _, err := os.Stat(filepath.Join(app, ".preflight", "expo-run-ios.log")); !os.IsNotExist(err) {
		t.Fatalf("native command log created before headroom refusal: %v", err)
	}
}

func TestRunnerCompletionPreservesStaleGlobalCacheUnderPressure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "1000000")
	product := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "PersonalProduct")
	writeCleanupFixture(t, product, "preserved", time.Now().Add(-48*time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"job":{"id":"complete-job","status":"succeeded"}}}`))
	}))
	defer server.Close()
	err := completeRunnerJob(server.Client(), runnerOnceOptions{apiURL: server.URL, workspaceRoot: t.TempDir()}, runnerRegistrationData{Runner: apiRunner{ID: "test-runner"}, Token: "fixture"}, apiRunnerJob{ID: "complete-job"}, map[string]any{"status": "ok"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(product)
	if err != nil || string(data) != "preserved" {
		t.Fatalf("post-job completion deleted personal product: %v", err)
	}
}
