package main

// Honest runner capability detection.
//
// defaultRunnerCapabilities used to advertise a fixed list — adb, xcrun,
// simctl, fastlane, … and platforms ["ios","android"] — on every host
// regardless of what was installed. Verified 2026-08-13: labnuc (Linux x86_64)
// advertised the full macOS toolchain while xcrun, simctl, fastlane and adb
// were all absent, so the scheduler could route iOS *and* Android work to a
// machine that could not run either.
//
// Detection has to match how the runner actually invokes each tool, not just
// PATH, or it swings the other way and strips capability from working hosts:
//
//   - simctl is not a binary; it is `xcrun simctl`.
//   - The Android SDK tools are usually NOT on PATH. labtop builds Android
//     daily with adb at ~/Library/Android/sdk/platform-tools/adb and no
//     ANDROID_HOME set, so a bare LookPath("adb") would have dropped android
//     from a host that genuinely has it.
//   - expo is normally run through npx rather than installed globally.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Tools a runner may advertise. Membership is decided per host by
// localToolAvailable.
var candidateLocalTools = []string{
	"adb",
	"avdmanager",
	"eas",
	"emulator",
	"expo",
	"fastlane",
	"gcloud",
	"java",
	"maestro",
	"sdkmanager",
	"simctl",
	"xcrun",
}

// androidSdkRelativePaths maps an Android tool to its location inside an SDK
// root. Used when the tool is not on PATH, which is the normal case.
var androidSdkRelativePaths = map[string][]string{
	"adb":        {"platform-tools/adb"},
	"emulator":   {"emulator/emulator"},
	"avdmanager": {"cmdline-tools/latest/bin/avdmanager", "tools/bin/avdmanager"},
	"sdkmanager": {"cmdline-tools/latest/bin/sdkmanager", "tools/bin/sdkmanager"},
}

func commandOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// androidSdkRoots are the places an SDK is found, most explicit first.
func androidSdkRoots() []string {
	roots := []string{}
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if value := os.Getenv(env); value != "" {
			roots = append(roots, value)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(home, "Library", "Android", "sdk"), // macOS default
			filepath.Join(home, "Android", "Sdk"),            // Linux default
		)
	}
	return roots
}

// resolveAndroidSdkTool returns a usable path for an Android SDK tool, or ""
// when the host does not have it. PATH wins; otherwise the SDK roots are
// searched, because the SDK is rarely on PATH.
func resolveAndroidSdkTool(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, root := range androidSdkRoots() {
		for _, relative := range androidSdkRelativePaths[name] {
			candidate := filepath.Join(root, relative)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	return ""
}

// localToolAvailable reports whether this host can actually run the tool.
func localToolAvailable(name string) bool {
	switch name {
	case "simctl":
		// Shipped as an xcrun subcommand, never as its own binary.
		return runtime.GOOS == "darwin" && commandOnPath("xcrun")
	case "xcrun":
		return runtime.GOOS == "darwin" && commandOnPath("xcrun")
	case "adb", "emulator", "avdmanager", "sdkmanager":
		return resolveAndroidSdkTool(name) != ""
	case "expo":
		// `npx expo` is the supported invocation; a global install is optional.
		return commandOnPath("expo") || commandOnPath("npx")
	case "unity":
		return unityCommandAvailable()
	default:
		return commandOnPath(name)
	}
}

// detectedLocalTools is the advertised tool list for this host.
func detectedLocalTools() []string {
	tools := make([]string, 0, len(candidateLocalTools))
	for _, tool := range candidateLocalTools {
		if localToolAvailable(tool) {
			tools = append(tools, tool)
		}
	}
	return tools
}

// detectedPlatforms derives platforms from real capability rather than
// asserting both. A runner that claims a platform it cannot build takes the
// job and fails it, which is worse than never claiming it.
func detectedPlatforms() []string {
	platforms := []string{}
	if runtime.GOOS == "darwin" && commandOnPath("xcrun") {
		platforms = append(platforms, "ios")
	}
	if resolveAndroidSdkTool("adb") != "" {
		platforms = append(platforms, "android")
	}
	return platforms
}

// adapterRequirements gates capability-specific adapters on the platform that
// backs them, so an adapter is never advertised by a host that cannot honour it.
var adapterRequirements = map[string]string{
	"android.emulator":           "android",
	"android.emulator.discovery": "android",
	"android.emulator.install":   "android",
	"android.sdk.management":     "android",
	"ios.simulator":              "ios",
	"ios.simulator.boot":         "ios",
	"ios.simulator.discovery":    "ios",
	"ios.simulator.install":      "ios",
	"fastlane.cli":               "ios",
	"app_store_connect.api":      "ios",
	"apple_oauth.management":     "ios",
	"expo.local_build":           "ios",
}

// filterAdaptersForPlatforms drops adapters whose backing platform is absent.
func filterAdaptersForPlatforms(adapters []string, platforms []string) []string {
	have := map[string]bool{}
	for _, platform := range platforms {
		have[platform] = true
	}
	kept := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		if required, ok := adapterRequirements[adapter]; ok && !have[required] {
			continue
		}
		kept = append(kept, adapter)
	}
	return kept
}
