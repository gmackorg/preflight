package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func jjFixtureCommand(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("jj", append([]string{"--color=never"}, args...)...)
	command.Dir = dir
	command.Env = os.Environ()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("jj %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestJJSourceBindingSnapshotsDirtyWorkspaceAndResolvesPublishedEmptyChild(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj is required for the real workspace integration test")
	}
	root := t.TempDir()
	config := filepath.Join(root, "fixture.toml")
	if err := os.WriteFile(config, []byte("[user]\nname = 'Fixture'\nemail = 'fixture@example.invalid'\n[snapshot]\nauto-track = 'all()'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJ_CONFIG", config)
	remote := filepath.Join(root, "remote.git")
	runGit(t, root, "init", "--bare", remote)
	checkout := filepath.Join(root, "checkout")
	runGit(t, root, "clone", remote, checkout)
	for path, content := range map[string]string{
		"pnpm-workspace.yaml":      "packages:\n  - apps/*\n",
		"apps/mobile/package.json": `{"name":"@fixture/mobile","main":"expo-router/entry","dependencies":{"expo":"55"}}`,
		"apps/mobile/eas.json":     `{"build":{"development":{"developmentClient":true,"distribution":"internal","ios":{"simulator":true}}}}`,
		"apps/mobile/app.json":     `{"expo":{"slug":"fixture","scheme":"fixture","ios":{"bundleIdentifier":"fixture.dev"}}}`,
	} {
		file := filepath.Join(checkout, path)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, checkout, "add", ".")
	runGit(t, checkout, "-c", "user.email=fixture@example.invalid", "-c", "user.name=Fixture", "commit", "-m", "published fixture")
	runGit(t, checkout, "push", "origin", "HEAD:main")
	sha := runGitOutput(t, checkout, "rev-parse", "HEAD")
	jjFixtureCommand(t, checkout, "git", "init", "--colocate")
	workspace := filepath.Join(root, "workspace")
	jjFixtureCommand(t, checkout, "workspace", "add", "-r", sha, workspace)
	app := filepath.Join(workspace, "apps", "mobile")
	binding, err := discoverSourceBinding(proveAppOptions{appDir: app, platform: "ios", lane: "simulator"})
	if err != nil {
		t.Fatal(err)
	}
	if binding.GitCommitSHA != sha || binding.GitRemoteURL != remote || binding.DirtyWorkspace {
		t.Fatalf("published empty child binding: %+v", binding)
	}
	if !sourceCommitIsOnRemote(workspace, remote, sha) {
		t.Fatal("published jj revision must be available on selected remote")
	}
	if err := os.WriteFile(filepath.Join(app, "eas.json"), []byte(`{"build":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "new-source.ts"), []byte("export const changed = true"), 0o644); err != nil {
		t.Fatal(err)
	}
	binding, err = discoverSourceBinding(proveAppOptions{appDir: app, platform: "ios", lane: "simulator"})
	if err != nil {
		t.Fatal(err)
	}
	if !binding.DirtyWorkspace || !contains(binding.ChangedSetupFiles, "apps/mobile/eas.json") {
		t.Fatalf("dirty jj files must be included: %+v", binding)
	}
	if binding.GitCommitSHA == sha || sourceCommitIsOnRemote(workspace, remote, binding.GitCommitSHA) {
		t.Fatal("unpublished working-copy snapshot must not be passed as a published source")
	}
	if sourceCommitIsOnRemote(workspace, filepath.Join(root, "different.git"), sha) {
		t.Fatal("a different remote must not validate")
	}
	// A config disabling auto-track must not hide unsnapshotted source files.
	config = filepath.Join(root, "no-auto-track.toml")
	if err := os.WriteFile(config, []byte("[user]\nname = 'Fixture'\nemail = 'fixture@example.invalid'\n[snapshot]\nauto-track = 'none()'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJ_CONFIG", config)
	if err := os.WriteFile(filepath.Join(app, "unsnapshotted.ts"), []byte("export const hidden = true"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverSourceBinding(proveAppOptions{appDir: app, platform: "ios", lane: "simulator"}); err == nil {
		t.Fatal("unsnapshotted source must fail closed")
	}
}

func TestGitSourceCommitChecksExplicitWorkspaceAndSelectedRemote(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	runGit(t, root, "init", "--bare", remote)
	checkout := filepath.Join(root, "checkout")
	runGit(t, root, "clone", remote, checkout)
	if err := os.WriteFile(filepath.Join(checkout, "source.txt"), []byte("published"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, checkout, "add", ".")
	runGit(t, checkout, "-c", "user.email=fixture@example.invalid", "-c", "user.name=Fixture", "commit", "-m", "published")
	runGit(t, checkout, "push", "origin", "HEAD:main")
	sha := runGitOutput(t, checkout, "rev-parse", "HEAD")
	if !sourceCommitIsOnRemote(checkout, remote, sha) {
		t.Fatal("must inspect explicit checkout rather than caller cwd")
	}
	if sourceCommitIsOnRemote(checkout, filepath.Join(root, "other.git"), sha) {
		t.Fatal("must reject source present only on a different remote")
	}
	if sourceCommitIsOnRemote(t.TempDir(), remote, sha) {
		t.Fatal("uninspectable repo must fail closed")
	}
	runGit(t, checkout, "-c", "user.email=fixture@example.invalid", "-c", "user.name=Fixture", "commit", "--allow-empty", "-m", "unpublished")
	if sourceCommitIsOnRemote(checkout, remote, runGitOutput(t, checkout, "rev-parse", "HEAD")) {
		t.Fatal("local-only commit must be rejected")
	}
}

func TestCIRepositoryNameSeparatesSameNamedAgentWorkspaces(t *testing.T) {
	first, err := ciRepositoryName("/work/crucible/simulator-evidence", "ssh://git@example.invalid/team/crucible.git")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ciRepositoryName("/work/poker/simulator-evidence", "git@example.invalid:team/poker.git")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first != "crucible" || second != "poker" {
		t.Fatalf("colliding checkout names: %q %q", first, second)
	}
	for _, remote := range []string{"https://example.invalid/", "https://example.invalid/team/..", "https://example.invalid/team/repo%2Fother.git"} {
		if _, err := ciRepositoryName("/work/simulator-evidence", remote); err == nil {
			t.Fatalf("unsafe remote path accepted: %s", remote)
		}
	}
}

func TestColdCICheckoutResolvesSymlinkAfterClone(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	runGit(t, root, "init", "--bare", remote)
	checkout := filepath.Join(root, "checkout")
	runGit(t, root, "clone", remote, checkout)
	app := filepath.Join(checkout, "apps", "mobile")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "package.json"), []byte(`{"name":"fixture","dependencies":{"expo":"55"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, checkout, "add", ".")
	runGit(t, checkout, "-c", "user.email=fixture@example.invalid", "-c", "user.name=Fixture", "commit", "-m", "source")
	runGit(t, checkout, "push", "origin", "HEAD:main")
	sha := runGitOutput(t, checkout, "rev-parse", "HEAD")
	physical := filepath.Join(root, "external-disk")
	alias := filepath.Join(root, "workspace", ciCheckoutRootSegment)
	if err := os.MkdirAll(physical, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(alias, "fixture", "apps", "mobile")
	resolved, err := resolvedPathForBindingCheck(missing)
	if err != nil {
		t.Fatal(err)
	}
	physicalRoot, err := filepath.EvalSymlinks(physical)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(physicalRoot, "fixture", "apps", "mobile") {
		t.Fatalf("cold clone must canonicalize before queue capacity check: %s", resolved)
	}
	tools := filepath.Join(root, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "pnpm"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	binding := runnerJobSourceBinding{WorkspaceRoot: filepath.Join(alias, "fixture"), PackagePath: "apps/mobile", GitRemoteURL: remote, GitCommitSHA: sha}
	job := apiRunnerJob{Payload: runnerJobPayload{SourceBinding: binding}}
	if err := validateRunnerJobSourceBinding(runnerOnceOptions{workspaceRoot: filepath.Dir(alias)}, job); err != nil {
		t.Fatal(err)
	}
}
