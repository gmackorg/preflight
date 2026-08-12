package main

import (
	"bytes"
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
