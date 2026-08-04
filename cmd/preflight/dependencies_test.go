package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestSnapshotAppDeps_CapturesSDKPluginsAndDrift(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{
	  "dependencies": {
	    "expo": "~56.0.18",
	    "react-native": "~0.85.3",
	    "expo-router": "~56.2.17",
	    "expo-image": "~55.0.6",
	    "@expo/dom-webview": "55.0.3",
	    "react-native-svg": "15.15.1",
	    "react-native-reanimated": "~4.3.1"
	  },
	  "devDependencies": { "typescript": "5.9.3" }
	}`)
	writeFile(t, dir, "app.config.ts", `import type { ExpoConfig } from "expo/config";
export default (): ExpoConfig => {
  const plugins: ExpoConfig["plugins"] = [
    "expo-router",
    "expo-localization",
    ["expo-splash-screen", { "backgroundColor": "#fff" }],
  ];
  return { name: "x", slug: "x", plugins };
};`)

	snap, err := snapshotAppDeps(dir)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected a snapshot, got nil")
	}
	if snap.ExpoSDK != "~56.0.18" || snap.ExpoMajor != 56 {
		t.Fatalf("expo sdk = %q/%d, want ~56.0.18/56", snap.ExpoSDK, snap.ExpoMajor)
	}
	if snap.ReactNative != "~0.85.3" {
		t.Fatalf("react-native = %q, want ~0.85.3", snap.ReactNative)
	}
	// expo-image@55 and @expo/dom-webview@55 drift below expo 56; expo-router@56 does not.
	if len(snap.Drift) != 2 {
		t.Fatalf("drift = %v, want 2 entries (expo-image, @expo/dom-webview)", snap.Drift)
	}
	// react-native-svg is an rn package, not counted as expo drift.
	if _, ok := snap.RNPackages["react-native-svg"]; !ok {
		t.Fatalf("react-native-svg missing from rnPackages: %v", snap.RNPackages)
	}
	// Typed-TS plugins array is parsed.
	want := map[string]bool{"expo-router": true, "expo-localization": true, "expo-splash-screen": true}
	if len(snap.Plugins) != 3 {
		t.Fatalf("plugins = %v, want 3", snap.Plugins)
	}
	for _, p := range snap.Plugins {
		if !want[p] {
			t.Fatalf("unexpected plugin %q in %v", p, snap.Plugins)
		}
	}
}

func TestSnapshotAppDeps_SkipsNonExpoApp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"react":"19.0.0"}}`)
	snap, err := snapshotAppDeps(dir)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap != nil {
		t.Fatalf("expected nil for non-Expo app, got %+v", snap)
	}
}

func TestDepsExitCode_FlagsDriftAndLag(t *testing.T) {
	clean := []*depSnapshot{{ExpoMajor: 56}}
	if code := depsExitCode(clean, 56); code != 0 {
		t.Fatalf("clean fleet exit = %d, want 0", code)
	}
	drift := []*depSnapshot{{ExpoMajor: 56, Drift: []string{"expo-image@55"}}}
	if code := depsExitCode(drift, 0); code != 1 {
		t.Fatalf("drift exit = %d, want 1", code)
	}
	lag := []*depSnapshot{{ExpoMajor: 54}}
	if code := depsExitCode(lag, 56); code != 1 {
		t.Fatalf("lagging exit = %d, want 1", code)
	}
}
