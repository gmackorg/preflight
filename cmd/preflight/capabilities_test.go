package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveAndroidSdkToolFindsSdkNotOnPath(t *testing.T) {
	// The regression this guards: labtop builds Android daily with adb at
	// ~/Library/Android/sdk/platform-tools/adb and ANDROID_HOME unset. A bare
	// LookPath("adb") reports nothing, which would have stripped android from
	// a host that genuinely has it.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANDROID_HOME", "")
	t.Setenv("ANDROID_SDK_ROOT", "")

	adb := filepath.Join(home, "Library", "Android", "sdk", "platform-tools", "adb")
	if err := os.MkdirAll(filepath.Dir(adb), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adb, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := resolveAndroidSdkTool("adb"); got != adb {
		t.Fatalf("resolveAndroidSdkTool(adb) = %q, want the SDK copy at %q", got, adb)
	}
	if !localToolAvailable("adb") {
		t.Fatal("adb present in the SDK must count as available")
	}
}

func TestResolveAndroidSdkToolAbsentHost(t *testing.T) {
	// labnuc: Linux, no SDK anywhere. It must not advertise android.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANDROID_HOME", "")
	t.Setenv("ANDROID_SDK_ROOT", "")
	t.Setenv("PATH", t.TempDir())

	if got := resolveAndroidSdkTool("adb"); got != "" {
		t.Fatalf("resolveAndroidSdkTool(adb) = %q, want empty on a host with no SDK", got)
	}
	if platforms := detectedPlatforms(); len(platforms) != 0 {
		t.Fatalf("detectedPlatforms() = %v, want none — no xcrun and no adb", platforms)
	}
}

func TestSimctlTracksXcrunNotItsOwnBinary(t *testing.T) {
	// simctl is `xcrun simctl`; it is never on PATH, so probing for it
	// directly would drop it from every Mac.
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only behaviour")
	}
	if commandOnPath("simctl") {
		t.Skip("host unexpectedly has a standalone simctl")
	}
	if localToolAvailable("xcrun") != localToolAvailable("simctl") {
		t.Fatal("simctl availability must track xcrun")
	}
}

func TestFilterAdaptersDropsUnbackedPlatforms(t *testing.T) {
	adapters := []string{
		"ios.simulator", "android.emulator", "eas.cli",
		"fastlane.cli", "sentry.api",
	}
	got := filterAdaptersForPlatforms(adapters, []string{"android"})

	for _, unwanted := range []string{"ios.simulator", "fastlane.cli"} {
		for _, kept := range got {
			if kept == unwanted {
				t.Fatalf("%s survived on an android-only host: %v", unwanted, got)
			}
		}
	}
	// Platform-agnostic adapters must survive.
	seen := map[string]bool{}
	for _, a := range got {
		seen[a] = true
	}
	if !seen["eas.cli"] || !seen["sentry.api"] || !seen["android.emulator"] {
		t.Fatalf("dropped adapters that should remain: %v", got)
	}
}

func TestDetectedPlatformsNeverClaimsIOSOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("checked on non-darwin")
	}
	for _, p := range detectedPlatforms() {
		if p == "ios" {
			t.Fatal("a non-darwin host must never advertise ios")
		}
	}
}

// TestThisHostDetection prints what the current machine reports, so a runner
// host can be checked with `go test -run ThisHostDetection -v`.
func TestThisHostDetection(t *testing.T) {
	t.Logf("GOOS=%s platforms=%v", runtime.GOOS, detectedPlatforms())
	t.Logf("tools=%v", detectedLocalTools())
}
