package main

// Store build/upload capabilities (PREFLT-66). The store.build contract needs
// expo.prebuild plus xcodebuild/xcode.archive (iOS) or android.sdk/java
// (Android); store.upload on iOS needs xcrun.altool. Advertised only when the
// host can run them, following capabilities.go.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type storeToolProbe struct {
	goos       string
	onPath     func(name string) bool
	xcrunFind  func(tool string) bool
	androidSDK func() bool
}

func defaultStoreToolProbe() storeToolProbe {
	return storeToolProbe{
		goos:   runtime.GOOS,
		onPath: commandOnPath,
		xcrunFind: func(tool string) bool {
			output, err := exec.Command("xcrun", "--find", tool).Output()
			return err == nil && strings.TrimSpace(string(output)) != ""
		},
		androidSDK: androidSDKPresent,
	}
}

// androidSDKPresent: an SDK root with platforms and build-tools installed
// (adb alone is not enough to build).
func androidSDKPresent() bool {
	for _, root := range androidSdkRoots() {
		platforms, _ := filepath.Glob(filepath.Join(root, "platforms", "android-*"))
		buildTools, _ := filepath.Glob(filepath.Join(root, "build-tools", "*"))
		if len(platforms) > 0 && len(buildTools) > 0 {
			return true
		}
	}
	return false
}

func detectStoreAdapters(probe storeToolProbe) []string {
	adapters := []string{}
	if probe.onPath("npx") || probe.onPath("expo") {
		adapters = append(adapters, "expo.prebuild")
	}
	if probe.goos == "darwin" && probe.onPath("xcodebuild") && probe.onPath("xcrun") {
		// xcode-select pointing at the Command Line Tools leaves an
		// xcodebuild shim that cannot archive; xcrun --find fails there.
		if probe.xcrunFind("xcodebuild") {
			adapters = append(adapters, "xcodebuild", "xcode.archive")
		}
		if probe.xcrunFind("altool") {
			adapters = append(adapters, "xcrun.altool")
		}
	}
	if probe.androidSDK() {
		adapters = append(adapters, "android.sdk")
	}
	if probe.onPath("java") || javaHomeHasJava() {
		adapters = append(adapters, "java")
	}
	return adapters
}

func javaHomeHasJava() bool {
	home := strings.TrimSpace(os.Getenv("JAVA_HOME"))
	if home == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(home, "bin", "java"))
	return err == nil && !info.IsDir()
}

// missingStoreTools lists the required adapters this host lacks.
func missingStoreTools(probe storeToolProbe, required ...string) []string {
	have := map[string]bool{}
	for _, adapter := range detectStoreAdapters(probe) {
		have[adapter] = true
	}
	missing := []string{}
	for _, adapter := range required {
		if !have[adapter] {
			missing = append(missing, adapter)
		}
	}
	return missing
}
