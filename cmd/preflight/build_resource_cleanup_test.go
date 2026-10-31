package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDiskReclaimReportsCleanupFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "absent-config.json"))
	t.Setenv("PREFLIGHT_WORKSPACE_ID", "")
	t.Setenv("PREFLIGHT_STORE_PRUNE_FLOOR_GB", "0")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".preflight", "checkout.lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{nil, {"--json"}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"--reclaim", "--root", root}, extra...)
		if code := runDisk(args, &stdout, &stderr, http.DefaultClient); code != 1 {
			t.Fatalf("cleanup failure returned success: code=%d stderr=%s", code, stderr.String())
		}
		if len(extra) > 0 {
			var report struct {
				CleanupFailed bool `json:"cleanupFailed"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || !report.CleanupFailed {
				t.Fatalf("missing machine-readable cleanup failure: %v: %s", err, stdout.String())
			}
		}
	}
}

func TestDiskReclaimJSONReportsDryRunCandidatesWithoutMutation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "absent-config.json"))
	t.Setenv("PREFLIGHT_WORKSPACE_ID", "")
	t.Setenv("PREFLIGHT_STORE_PRUNE_FLOOR_GB", "0")
	root := t.TempDir()
	cache := filepath.Join(root, ".preflight", "ios-sim-deriveddata", "ModuleCache.noindex", "cache")
	writeCleanupFixture(t, cache, "regenerable", time.Now().Add(-48*time.Hour))
	var stdout, stderr bytes.Buffer
	if code := runDisk([]string{"--reclaim", "--root", root, "--dry-run", "--json"}, &stdout, &stderr, http.DefaultClient); code != 0 {
		t.Fatalf("dry-run failed: code=%d stderr=%s", code, stderr.String())
	}
	var report struct {
		ReclaimedItems int  `json:"reclaimedItems"`
		CleanupFailed  bool `json:"cleanupFailed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || report.ReclaimedItems != 1 || report.CleanupFailed {
		t.Fatalf("invalid candidate report: %v: %s", err, stdout.String())
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("preview deleted native cache: %v", err)
	}
}

func TestDiskReclaimRejectsInvalidRetentionBeforeCleanup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "absent-config.json"))
	t.Setenv("PREFLIGHT_WORKSPACE_ID", "")
	t.Setenv("PREFLIGHT_WORKSPACE_ROOTS", t.TempDir())
	t.Setenv("PREFLIGHT_STORE_PRUNE_FLOOR_GB", "0")
	for _, age := range []string{"invalid", "0s", "-1h"} {
		var stdout, stderr bytes.Buffer
		if code := runDisk([]string{"--reclaim", "--max-age", age}, &stdout, &stderr, http.DefaultClient); code != 2 {
			t.Fatalf("invalid retention %q accepted: code=%d", age, code)
		}
	}
}

func TestCleanupBuildsFindsStaleOwnedNativeIntermediates(t *testing.T) {
	for _, lane := range []string{"ios-sim-deriveddata", "ios-device-deriveddata"} {
		t.Run(lane, func(t *testing.T) {
			root := t.TempDir()
			derived := filepath.Join(root, ".preflight", lane)
			intermediate := filepath.Join(derived, "Build", "Intermediates.noindex", "old.o")
			product := filepath.Join(derived, "Build", "Products", "Review.app", "Review")
			writeCleanupFixture(t, intermediate, "regenerable", time.Now().Add(-48*time.Hour))
			writeCleanupFixture(t, product, "retained product", time.Now().Add(-48*time.Hour))
			var output bytes.Buffer
			removed, err := cleanupBuilds(root, 24*time.Hour, false, false, &output)
			if err != nil {
				t.Fatal(err)
			}
			if removed != 1 {
				t.Fatalf("cleanup missed native intermediates: removed=%d, output=%s", removed, output.String())
			}
			if _, err := os.Stat(intermediate); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale intermediate retained: %v", err)
			}
			if content, err := os.ReadFile(product); err != nil || string(content) != "retained product" {
				t.Fatalf("installable product changed: %v", err)
			}
		})
	}
}

func TestNativeCleanupPreservesActiveCheckoutAndRecentDescendants(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, ".preflight", "ios-sim-deriveddata", "Build", "Intermediates.noindex")
	object := filepath.Join(cache, "old.o")
	old := time.Now().Add(-48 * time.Hour)
	writeCleanupFixture(t, object, "regenerable", old)
	release, err := acquireCheckoutLock(filepath.Join(root, ".preflight"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	removed, err := cleanupBuilds(root, 24*time.Hour, false, false, &output)
	release()
	if err != nil || removed != 0 || !strings.Contains(output.String(), "skipped active native build") {
		t.Fatalf("active checkout not preserved: removed=%d err=%v output=%s", removed, err, output.String())
	}
	if _, err := os.Stat(object); err != nil {
		t.Fatalf("active checkout cache removed: %v", err)
	}
	// Writing an existing child does not update its directory's timestamp.
	if err := os.Chtimes(object, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cache, old, old); err != nil {
		t.Fatal(err)
	}
	removed, err = cleanupBuilds(root, 24*time.Hour, false, false, io.Discard)
	if err != nil || removed != 0 {
		t.Fatalf("recent descendant treated as stale: removed=%d err=%v", removed, err)
	}
	if _, err := os.Stat(object); err != nil {
		t.Fatalf("recently used native cache removed: %v", err)
	}
}

func TestNativeCleanupDryRunPreservesResourcesAndDoesNotCreateMutex(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, ".preflight", "ios-sim-deriveddata", "ModuleCache.noindex", "cache")
	writeCleanupFixture(t, cache, "regenerable", time.Now().Add(-48*time.Hour))
	removed, err := cleanupBuilds(root, 24*time.Hour, true, false, io.Discard)
	if err != nil || removed != 1 {
		t.Fatalf("dry-run selection: removed=%d err=%v", removed, err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("dry-run removed cache: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".preflight", "checkout.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created mutex: %v", err)
	}
}

func TestNativeCleanupRejectsLinkedGeneratedPathsAndUnavailableMutex(t *testing.T) {
	for _, relative := range []string{".preflight", ".preflight/ios-sim-deriveddata", ".preflight/ios-sim-deriveddata/Build", ".preflight/ios-sim-deriveddata/Build/Intermediates.noindex", ".preflight/checkout.lock"} {
		t.Run(relative, func(t *testing.T) {
			root, foreign := t.TempDir(), t.TempDir()
			foreignFile := filepath.Join(foreign, "retained")
			writeCleanupFixture(t, foreignFile, "foreign", time.Now().Add(-48*time.Hour))
			linked := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(linked), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(foreign, linked); err != nil {
				t.Fatal(err)
			}
			if _, err := cleanupBuilds(root, 24*time.Hour, false, false, io.Discard); err == nil {
				t.Fatal("linked generated path was accepted")
			}
			if data, err := os.ReadFile(foreignFile); err != nil || string(data) != "foreign" {
				t.Fatalf("foreign resource changed: %v", err)
			}
		})
	}
	t.Run("mutex-directory", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".preflight", "checkout.lock"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := cleanupBuilds(root, 24*time.Hour, false, false, io.Discard); err == nil {
			t.Fatal("cleanup proceeded without a usable mutex")
		}
	})
}

func TestNativeCleanupRetainsEvidenceAndUnknownLayouts(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{".preflight/maestro/pfjob_review/video.mp4", ".preflight/ios-sim-deriveddata/Logs/build.xcactivitylog", ".preflight/dd-screenshots/Build/Products/Review.app", ".preflight/unknown-native/cache", "artifacts/release.ipa", "ios/Podfile", "android/app/build/outputs/apk/release/app-release.apk"} {
		file := filepath.Join(root, filepath.FromSlash(path))
		writeCleanupFixture(t, file, "preserved", time.Now().Add(-48*time.Hour))
		defer func() {
			if data, err := os.ReadFile(file); err != nil || string(data) != "preserved" {
				t.Errorf("required resource changed: %s: %v", file, err)
			}
		}()
	}
	if removed, err := cleanupBuilds(root, 24*time.Hour, false, false, io.Discard); err != nil || removed != 0 {
		t.Fatalf("non-cache resource selected: removed=%d err=%v", removed, err)
	}
}

func TestCommandCompletionPreservesForeignProcessGroup(t *testing.T) {
	foreign := exec.Command("/bin/sleep", "600")
	foreign.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreign.Process.Kill(); _ = foreign.Wait() })
	if err := runCommandWithTimeout(exec.Command("/bin/sh", "-c", "sleep 600 </dev/null >/dev/null 2>&1 & exit 0"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(foreign.Process.Pid, 0); err != nil {
		t.Fatalf("foreign process was terminated: %v", err)
	}
}

func TestCommandCompletionReleasesOwnedDescendantResources(t *testing.T) {
	for _, exitCode := range []int{0, 7} {
		t.Run(strconv.Itoa(exitCode), func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			// The command leader exits while its TERM-ignoring child retains
			// fd 3. No output pipe is involved, so WaitDelay cannot reclaim it.
			command := exec.Command("/bin/sh", "-c", "trap '' TERM; sleep 600 </dev/null >/dev/null 2>&1 & exit "+strconv.Itoa(exitCode))
			command.ExtraFiles = []*os.File{writer}
			t.Cleanup(func() {
				if command.Process != nil {
					_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				}
			})
			err = runCommandWithTimeout(command, 5*time.Second)
			if exitCode == 0 && err != nil {
				t.Fatal(err)
			}
			if exitCode != 0 {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != exitCode {
					t.Fatalf("original command failure changed: %v", err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("finished command left its descendant holding a resource: %v", err)
			}
		})
	}
}
