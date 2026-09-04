package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleanupBuildsRemovesOnlyStaleManagedCacheEntries(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "DerivedData", "stale-build")
	fresh := filepath.Join(root, "DerivedData", "active-build")
	artifact := filepath.Join(root, "artifacts", "release.app")
	diskImage := filepath.Join(root, "build.sparseimage")

	writeCleanupFixture(t, stale, "cache", time.Now().Add(-48*time.Hour))
	writeCleanupFixture(t, fresh, "cache", time.Now())
	writeCleanupFixture(t, artifact, "release", time.Now().Add(-48*time.Hour))
	if err := os.WriteFile(diskImage, []byte("disk image"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(diskImage, old, old); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"cleanup", "builds", "--root", root, "--max-age", "24h"},
		&stdout,
		&stderr,
		http.DefaultClient,
	)
	if code != 0 {
		t.Fatalf("expected exit 0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale managed cache to be removed, stat err=%v", err)
	}
	for _, retained := range []string{fresh, artifact, diskImage} {
		if _, err := os.Stat(retained); err != nil {
			t.Fatalf("expected %s to be retained: %v", retained, err)
		}
	}
	if !strings.Contains(stdout.String(), "removed 1 stale build cache entry") {
		t.Fatalf("unexpected summary: %q", stdout.String())
	}
}

func TestCleanupBuildsDryRunDoesNotDelete(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "tmp", "stale-codegen")
	writeCleanupFixture(t, stale, "cache", time.Now().Add(-48*time.Hour))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"cleanup", "builds", "--root", root, "--max-age", "24h", "--dry-run"},
		&stdout,
		&stderr,
		http.DefaultClient,
	)
	if code != 0 {
		t.Fatalf("expected exit 0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("dry-run removed stale cache: %v", err)
	}
	if !strings.Contains(stdout.String(), "would remove") {
		t.Fatalf("expected dry-run output, got %q", stdout.String())
	}
}

func TestCleanupBuildsIncludesOldDiskImagesOnlyWithExplicitFlag(t *testing.T) {
	root := t.TempDir()
	diskImage := filepath.Join(root, "build.sparseimage")
	if err := os.WriteFile(diskImage, []byte("disk image"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(diskImage, old, old); err != nil {
		t.Fatal(err)
	}

	code := run(
		[]string{"cleanup", "builds", "--root", root, "--max-age", "24h", "--include-disk-images"},
		&bytes.Buffer{},
		&bytes.Buffer{},
		http.DefaultClient,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if _, err := os.Stat(diskImage); !os.IsNotExist(err) {
		t.Fatalf("expected explicitly included stale disk image to be removed, stat err=%v", err)
	}
}

func TestCleanupBuildStorageUnderPressureSkipsHealthyVolume(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "CocoaPods", "stale-pod")
	writeCleanupFixture(t, stale, "cache", time.Now().Add(-48*time.Hour))

	result, err := cleanupBuildStorageUnderPressure(
		root,
		24*time.Hour,
		20*bytesPerGiB,
		func(string) (uint64, error) { return 21 * bytesPerGiB, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 0 || !result.SkippedForHeadroom {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("healthy-volume cleanup removed cache: %v", err)
	}
}

func writeCleanupFixture(t *testing.T, path string, content string, modified time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Dir(path), modified, modified); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupBuildStorageUnderPressureSweepsHostCachesToo(t *testing.T) {
	// Regression for 2026-08-13: every labtop runner logged "after sweeping 0
	// cache entries — declining claims" and stopped, because the sweep only
	// looked under the workspace root while the space sat in Xcode's own
	// DerivedData. A sweep that can only report 0 makes a recoverable host
	// look dead.
	home := t.TempDir()
	t.Setenv("HOME", home)

	root := t.TempDir()
	workspaceStale := filepath.Join(root, "DerivedData", "workspace-build")
	writeCleanupFixture(t, workspaceStale, "cache", time.Now().Add(-48*time.Hour))

	hostStale := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "App-abc123")
	writeCleanupFixture(t, hostStale, "cache", time.Now().Add(-48*time.Hour))

	result, err := cleanupBuildStorageUnderPressure(
		root,
		24*time.Hour,
		20*bytesPerGiB,
		func(string) (uint64, error) { return 5 * bytesPerGiB, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 2 {
		t.Fatalf("removed = %d, want 2 (workspace + host cache)", result.Removed)
	}
	if _, err := os.Stat(hostStale); !os.IsNotExist(err) {
		t.Fatalf("host-level Xcode DerivedData was not swept: %v", err)
	}
}

func TestHostCacheRootsStayNarrow(t *testing.T) {
	// Widening this is how a "cleanup" starts deleting things people miss.
	home := t.TempDir()
	t.Setenv("HOME", home)
	roots := hostCacheRoots()
	if len(roots) != 1 {
		t.Fatalf("hostCacheRoots() = %v, want exactly one narrow root", roots)
	}
	if !strings.HasSuffix(roots[0], filepath.Join("Library", "Developer", "Xcode")) {
		t.Fatalf("unexpected host cache root: %s", roots[0])
	}
}

func TestTightestFreeBytes(t *testing.T) {
	// The incident this exists for: the runner reported its workspace volume
	// only. That workspace sat on an external SSD with 572 GB free while every
	// xcodebuild wrote DerivedData to an internal volume down to 7 GB, so the
	// fleet board showed the node healthy through a disk-full outage.
	free := map[string]uint64{
		"/Volumes/dev-ssd/checkout": 572 << 30,
		"/Users/someone":            7 << 30,
	}
	fn := func(path string) (uint64, error) {
		v, ok := free[path]
		if !ok {
			return 0, errors.New("no such volume")
		}
		return v, nil
	}

	got, ok := tightestFreeBytes([]string{"/Volumes/dev-ssd/checkout", "/Users/someone"}, fn)
	if !ok || got != 7<<30 {
		t.Fatalf("want the tightest volume (7GiB), got %d ok=%v", got, ok)
	}

	// A path that cannot be stat'd is skipped, not counted as zero — otherwise
	// a stale workspace root would raise a permanent false alarm.
	got, ok = tightestFreeBytes([]string{"/gone", "/Volumes/dev-ssd/checkout"}, fn)
	if !ok || got != 572<<30 {
		t.Fatalf("want unreadable paths skipped, got %d ok=%v", got, ok)
	}

	if _, ok = tightestFreeBytes([]string{"/gone"}, fn); ok {
		t.Fatal("want ok=false when nothing could be read")
	}
	if _, ok = tightestFreeBytes(nil, fn); ok {
		t.Fatal("want ok=false for no paths")
	}
}

func TestBuildVolumePathsIncludesHome(t *testing.T) {
	// Home is where DerivedData, simulator runtimes and toolchain caches live,
	// and it is routinely a different volume from the checkout.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	paths := buildVolumePaths("/some/workspace")
	if len(paths) != 2 || paths[0] != "/some/workspace" || paths[1] != home {
		t.Fatalf("want [workspace, home], got %v", paths)
	}

	// A runner with no workspace root still reports something useful.
	if paths = buildVolumePaths(""); len(paths) != 1 || paths[0] != home {
		t.Fatalf("want [home] when there is no workspace root, got %v", paths)
	}
}
