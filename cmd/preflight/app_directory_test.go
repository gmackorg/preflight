package main

import (
	"os"
	"path/filepath"
	"testing"
)

// appDirectoryForJob falls back to the agent's --workspace-root when a job
// carries no sourceBinding.workspaceRoot. That root is a container of repos,
// not a repo, so joining a package path onto it drops the repo name — a
// release-candidate gate resolved to /Volumes/T9-APFS/apps/apps/mobile, which
// startExpoDevServer then CREATED, and Expo died there in a log nobody reads
// while the workflow burned its whole timeout waiting for Metro.
func TestRequireAppDirectory(t *testing.T) {
	t.Run("accepts a real app directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := requireAppDirectory(dir); err != nil {
			t.Fatalf("expected a directory with package.json to pass: %v", err)
		}
	})

	t.Run("rejects a directory with no manifest", func(t *testing.T) {
		err := requireAppDirectory(t.TempDir())
		if err == nil {
			t.Fatal("expected a directory without package.json to be rejected")
		}
	})

	t.Run("rejects a path that does not exist at all", func(t *testing.T) {
		if err := requireAppDirectory(filepath.Join(t.TempDir(), "apps", "mobile")); err == nil {
			t.Fatal("expected a missing directory to be rejected")
		}
	})
}

// The doubled-path shape the fallback produces, so the regression is legible.
func TestAppDirectoryForJobFallsBackToRunnerRoot(t *testing.T) {
	job := apiRunnerJob{}
	job.Payload.SourceBinding.PackagePath = "apps/mobile"
	got := appDirectoryForJob(runnerOnceOptions{workspaceRoot: "/Volumes/T9-APFS/apps"}, job)
	if got != "/Volumes/T9-APFS/apps/apps/mobile" {
		t.Fatalf("got %q", got)
	}
	// ...which is exactly why requireAppDirectory has to reject it.
	if err := requireAppDirectory(got); err == nil {
		t.Fatal("the fallback path must not be accepted as an app directory")
	}
}
