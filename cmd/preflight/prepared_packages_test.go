package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeWorkspace(t *testing.T, packageDir string, withPods bool) {
	t.Helper()
	iosDir := filepath.Join(packageDir, "ios")
	if err := os.MkdirAll(filepath.Join(iosDir, "App.xcworkspace"), 0o755); err != nil {
		t.Fatal(err)
	}
	if withPods {
		if err := os.MkdirAll(filepath.Join(iosDir, "Pods", "Target Support Files"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// A runner must only advertise packages it can actually build, or it claims a
// native build for an unprepared repo, fails minutes later, and starves a host
// that was ready.
func TestPreparedIOSPackagesRequiresWorkspaceAndPods(t *testing.T) {
	root := t.TempDir()

	ready := filepath.Join(root, "ready-repo", "apps", "expo")
	writeWorkspace(t, ready, true)

	noPods := filepath.Join(root, "no-pods-repo", "apps", "expo")
	writeWorkspace(t, noPods, false)

	noIos := filepath.Join(root, "no-ios-repo", "apps", "expo")
	if err := os.MkdirAll(noIos, 0o755); err != nil {
		t.Fatal(err)
	}

	got := preparedIOSPackages(root)
	if len(got) != 1 || got[0] != filepath.Join("ready-repo", "apps", "expo") {
		t.Fatalf("expected only the fully prepared package, got %v", got)
	}
}

func TestPreparedIOSPackagesDetectsRepoRootLayout(t *testing.T) {
	root := t.TempDir()
	writeWorkspace(t, filepath.Join(root, "flat-repo"), true)

	got := preparedIOSPackages(root)
	if len(got) != 1 || got[0] != "flat-repo" {
		t.Fatalf("expected flat repo layout to be detected, got %v", got)
	}
}

func TestPreparedIOSPackagesEmptyRootIsSafe(t *testing.T) {
	if got := preparedIOSPackages(""); len(got) != 0 {
		t.Fatalf("expected empty slice for empty root, got %v", got)
	}
	if got := preparedIOSPackages("/nonexistent-xyz"); len(got) != 0 {
		t.Fatalf("expected empty slice for missing root, got %v", got)
	}
}
