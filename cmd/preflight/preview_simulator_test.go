package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePreviewSimulatorFixture(t *testing.T) (string, string) {
	t.Helper()
	appDir := writeExpoFixture(t)
	profiles := `{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":true}},"preview":{"developmentClient":false,"distribution":"internal","env":{"APP_VARIANT":"preview","API_URL":"https://example.test/$apiSuffix"}},"preview-simulator":{"extends":"preview","ios":{"simulator":true}}}}`
	if err := os.WriteFile(filepath.Join(appDir, "eas.json"), []byte(profiles), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	script := `#!/bin/sh
if [ "$2" = "config" ]; then
  if [ "$APP_VARIANT" = "preview" ]; then
    echo '{"slug":"sortie","scheme":"sortey-dev","ios":{"bundleIdentifier":"com.gmacko.sortey.dev"},"extra":{"eas":{"projectId":"preview-project"}}}'
  else
    echo '{"slug":"sortie","scheme":"sortey-expo","ios":{"bundleIdentifier":"com.gmacko.sortey.expo"},"extra":{"eas":{"projectId":"preview-project"}}}'
  fi
fi
`
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_FORCE_EXPO_CONFIG_CLI", "1")
	return appDir, fakeBin
}

func TestPreviewSimulatorExplicitProfileReadiness(t *testing.T) {
	appDir, _ := writePreviewSimulatorFixture(t)
	flow := filepath.Join(t.TempDir(), "preview.yaml")
	if err := os.WriteFile(flow, []byte("appId: com.gmacko.sortey.dev\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"prove-app", "--app-dir", appDir, "--platform", "ios", "--lane", "simulator", "--build-profile", "preview-simulator", "--flow-path", flow, "--local-readiness", "--json"}, &stdout, &stderr, http.DefaultClient)
	if code != 0 {
		t.Fatalf("preview readiness failed: code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	var report localReadinessReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.SourceBinding.EASProfileName != "preview-simulator" || report.SourceBinding.IOSBundleID != "com.gmacko.sortey.dev" || report.SourceBinding.AppScheme != "sortey-dev" {
		t.Fatalf("explicit preview profile was replaced: %#v", report)
	}
}

func TestPreviewSimulatorMissingExplicitProfileFails(t *testing.T) {
	appDir, _ := writePreviewSimulatorFixture(t)
	_, err := discoverSourceBinding(proveAppOptions{appDir: appDir, platform: "ios", lane: "simulator", buildProfile: "missing-preview"})
	if err == nil {
		t.Fatal("missing explicit profile must fail instead of falling back to development")
	}
}

func TestPreviewSimulatorRejectsUnsupportedProfileLanes(t *testing.T) {
	appDir, _ := writePreviewSimulatorFixture(t)
	for _, options := range []proveAppOptions{
		{appDir: appDir, platform: "android", lane: "simulator", buildProfile: "preview-simulator"},
		{appDir: appDir, platform: "ios", lane: "development", buildProfile: "preview-simulator"},
		{appDir: appDir, platform: "ios", lane: "simulator", buildProfile: "preview-simulator", buildStrategy: "eas"},
		{appDir: appDir, platform: "ios", lane: "simulator", buildProfile: "preview-simulator", standalonePlan: true},
	} {
		if _, err := discoverSourceBinding(options); err == nil {
			t.Fatalf("unsupported packaged profile combination must fail: %#v", options)
		}
	}
}

func TestPreviewSimulatorBuildEmbedsBundleAndLaunchesNative(t *testing.T) {
	appDir, fakeBin := writePreviewSimulatorFixture(t)
	t.Setenv("apiSuffix", "unexpected-runner-expansion")
	nativeLog := filepath.Join(t.TempDir(), "native.log")
	t.Setenv("NATIVE_LOG", nativeLog)
	for name, script := range map[string]string{
		"npx": `#!/bin/sh
printf 'npx %s variant=%s api=%s\n' "$*" "$APP_VARIANT" "$API_URL" >> "$NATIVE_LOG"
mkdir -p ios/SorteyDev.xcworkspace
`,
		"pod": `#!/bin/sh
printf 'pod %s variant=%s\n' "$*" "$APP_VARIANT" >> "$NATIVE_LOG"
`,
		"xcodebuild": `#!/bin/sh
printf 'xcodebuild %s variant=%s api=%s\n' "$*" "$APP_VARIANT" "$API_URL" >> "$NATIVE_LOG"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -configuration) shift; config="$1" ;;
    -derivedDataPath) shift; derived="$1" ;;
  esac
  shift
done
mkdir -p "$derived/Build/Products/$config-iphonesimulator/SorteyDev.app"
if [ "$config" = Release ]; then
  echo embedded > "$derived/Build/Products/$config-iphonesimulator/SorteyDev.app/main.jsbundle"
fi
`,
		"xcrun": `#!/bin/sh
printf 'xcrun %s\n' "$*" >> "$NATIVE_LOG"
`,
	} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	job := apiRunnerJob{}
	job.Payload.Platform = "ios"
	job.Payload.Lane = "simulator"
	job.Payload.SourceBinding = runnerJobSourceBinding{WorkspaceRoot: appDir, PackagePath: ".", EASProfileName: "preview-simulator", IOSBundleID: "com.gmacko.sortey.dev", AppScheme: "sortey-dev"}
	_, err := runExpoAppOpen(nil, runnerRegistrationData{}, runnerOnceOptions{xcrunPath: filepath.Join(fakeBin, "xcrun")}, "ios", appDir, "preview-device", 8609, job)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(nativeLog)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	for _, expected := range []string{"variant=preview", "api=https://example.test/$apiSuffix", "-configuration Release", "Release-iphonesimulator/SorteyDev.app", "simctl launch preview-device com.gmacko.sortey.dev"} {
		if !strings.Contains(log, expected) {
			t.Fatalf("missing %q in native boundary log:\n%s", expected, log)
		}
	}
	if strings.Contains(log, "variant=development") || strings.Contains(log, "simctl openurl") {
		t.Fatalf("preview build used development launch path:\n%s", log)
	}
}

func TestPreviewSimulatorRejectsMissingEmbeddedBundleBeforeInstall(t *testing.T) {
	appDir, fakeBin := writePreviewSimulatorFixture(t)
	if err := os.MkdirAll(filepath.Join(appDir, "ios", "SorteyDev.xcworkspace"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "xcodebuild"), []byte(`#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-derivedDataPath" ]; then
    shift
    mkdir -p "$1/Build/Products/Release-iphonesimulator/SorteyDev.app"
    exit 0
  fi
  shift
done
exit 1
`), 0o755); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "build.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	job := apiRunnerJob{}
	job.Payload.Platform = "ios"
	job.Payload.Lane = "simulator"
	job.Payload.SourceBinding = runnerJobSourceBinding{WorkspaceRoot: appDir, PackagePath: ".", EASProfileName: "preview-simulator"}
	// An invalid xcrun path makes any attempted installation fail distinctly.
	err = buildAndInstallIOSSimulatorApp(logFile, runnerOnceOptions{xcrunPath: "/missing-install-command"}, appDir, "preview-device", job, nil)
	if err == nil || !strings.Contains(err.Error(), "missing main.jsbundle") {
		t.Fatalf("missing embedded JavaScript must fail before install: %v", err)
	}
}
