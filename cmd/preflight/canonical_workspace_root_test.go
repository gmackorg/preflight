package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A runner registering a symlinked workspace root must advertise the real path,
// or textual job-eligibility matching silently starves the host.
func TestCanonicalWorkspaceRootResolvesSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := canonicalWorkspaceRoot(link)
	want, _ := filepath.EvalSymlinks(real)
	if got != want {
		t.Fatalf("canonicalWorkspaceRoot(%q) = %q, want %q", link, got, want)
	}
}

func TestCanonicalWorkspaceRootFallsBackWhenUnresolvable(t *testing.T) {
	missing := filepath.Join(os.TempDir(), "preflight-does-not-exist-xyz")
	if got := canonicalWorkspaceRoot(missing); got != missing {
		t.Fatalf("expected passthrough for unresolvable path, got %q", got)
	}
}
