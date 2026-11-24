package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func hookRuntime(t *testing.T, packageJSON string, handle func(storeCommand) ([]byte, error)) (*storeJobRuntime, *fakeStoreRunner, *bytes.Buffer) {
	t.Helper()
	appDir := t.TempDir()
	if packageJSON != "" {
		if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(packageJSON), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeStoreRunner{handle: handle}
	log := &bytes.Buffer{}
	return &storeJobRuntime{run: runner, log: log, appDir: appDir}, runner, log
}

// HabitPlay's config plugin refuses to prebuild without its Unity framework,
// which only a pre-build hook can fetch; store build 20 failed exactly there.
func TestStorePreBuildHookRunsWithPlatformEnvironment(t *testing.T) {
	rt, runner, _ := hookRuntime(t, `{"scripts":{"preflight-build-pre-install":"node fetch.mjs"}}`, nil)

	if err := runStorePreBuildHook(rt, "ios", []string{"APP_VARIANT=production"}); err != nil {
		t.Fatal(err)
	}
	calls := runner.find("npm run --silent preflight-build-pre-install")
	if len(calls) != 1 {
		t.Fatalf("hook calls = %v", runner.lines())
	}
	for _, want := range []string{"APP_VARIANT=production", "PREFLIGHT_BUILD_PLATFORM=ios", "EAS_BUILD_PLATFORM=ios"} {
		if !slices.Contains(calls[0].Env, want) {
			t.Errorf("hook env missing %s: %v", want, calls[0].Env)
		}
	}
	if calls[0].Dir != rt.appDir {
		t.Errorf("hook ran in %s, want %s", calls[0].Dir, rt.appDir)
	}
}

func TestStorePreBuildHookSkipsAppsWithoutOne(t *testing.T) {
	for name, manifest := range map[string]string{
		"no package.json": "",
		"no scripts":      `{"name":"app"}`,
	} {
		rt, runner, _ := hookRuntime(t, manifest, nil)
		if err := runStorePreBuildHook(rt, "android", nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(runner.lines()) != 0 {
			t.Fatalf("%s: ran %v", name, runner.lines())
		}
	}
}

// EAS hooks assume EAS's image (global installs, EAS-only env checks), so they
// are reported, not run.
func TestStorePreBuildHookDoesNotRunEASHooks(t *testing.T) {
	rt, runner, log := hookRuntime(t, `{"scripts":{"eas-build-pre-install":"npm install -g corepack"}}`, nil)
	if err := runStorePreBuildHook(rt, "ios", nil); err != nil {
		t.Fatal(err)
	}
	if len(runner.lines()) != 0 {
		t.Fatalf("ran %v", runner.lines())
	}
	if !strings.Contains(log.String(), "does not run EAS hooks") {
		t.Errorf("log does not explain the skipped EAS hook: %q", log.String())
	}
}

func TestStorePreBuildHookFailureStopsTheBuild(t *testing.T) {
	rt, _, _ := hookRuntime(t, `{"scripts":{"preflight-build-pre-install":"exit 1"}}`, func(storeCommand) ([]byte, error) {
		return []byte("Unity ios archive checksum mismatch"), errors.New("exit status 1")
	})
	err := runStorePreBuildHook(rt, "ios", nil)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "store_pre_build_hook_failed" {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(failure.message, "checksum mismatch") {
		t.Errorf("failure hides the hook output: %s", failure.message)
	}
}
