package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAndroidPreviewFixture(t *testing.T) (string, string) {
	t.Helper()
	appDir, bin := writePreviewSimulatorFixture(t)
	profiles := `{"build":{"preview":{"developmentClient":false,"distribution":"internal","env":{"APP_VARIANT":"preview","API_URL":"https://example.test/$apiSuffix"},"android":{"buildType":"apk"}},"preview-android":{"extends":"preview"}}}`
	if err := os.WriteFile(filepath.Join(appDir, "eas.json"), []byte(profiles), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
if [ "$2" = config ]; then
 echo '{"slug":"sortie","scheme":"sortey-dev","android":{"package":"com.gmacko.sortey.dev"},"extra":{"eas":{"projectId":"preview-project"}}}'
fi
`
	if err := os.WriteFile(filepath.Join(bin, "npx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return appDir, bin
}

func TestAndroidPackagedPreviewReadiness(t *testing.T) {
	appDir, _ := writeAndroidPreviewFixture(t)
	flow := filepath.Join(t.TempDir(), "preview.yaml")
	if err := os.WriteFile(flow, []byte("appId: com.gmacko.sortey.dev\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"prove-app", "--app-dir", appDir, "--platform", "android", "--lane", "simulator", "--build-profile", "preview-android", "--flow-path", flow, "--local-readiness", "--json"}, &stdout, &stderr, http.DefaultClient)
	if code != 0 {
		t.Fatalf("Android preview refused: %s %s", &stdout, &stderr)
	}
	var report localReadinessReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.SourceBinding.AndroidPackage != "com.gmacko.sortey.dev" || report.SourceBinding.EASProfileName != "preview-android" {
		t.Fatalf("incorrect binding: %#v", report)
	}
}

func TestAndroidPackagedPreviewRejectsUnsupportedModes(t *testing.T) {
	for _, tc := range []struct {
		name, lane, strategy string
		standalone           bool
	}{
		{"physical", "development", "", false}, {"eas", "simulator", "eas", false}, {"standalone", "simulator", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appDir, _ := writeAndroidPreviewFixture(t)
			_, err := discoverSourceBinding(proveAppOptions{appDir: appDir, platform: "android", lane: tc.lane, buildProfile: "preview-android", buildStrategy: tc.strategy, standalonePlan: tc.standalone})
			if err == nil {
				t.Fatal("unsupported preview accepted")
			}
		})
	}
}

func writePreviewAPK(t *testing.T, path string, embedded bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entries := map[string]string{"AndroidManifest.xml": "manifest", "classes.dex": "dex"}
	if embedded {
		entries["assets/index.android.bundle"] = "embedded Hermes fixture"
	}
	for name, content := range entries {
		e, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAndroidPackagedPreviewBuildInstallLaunch(t *testing.T) {
	for _, embedded := range []bool{true, false} {
		t.Run(map[bool]string{true: "embedded", false: "missing JS"}[embedded], func(t *testing.T) {
			appDir, bin := writeAndroidPreviewFixture(t)
			t.Setenv("apiSuffix", "must-not-expand")
			log := filepath.Join(t.TempDir(), "commands.log")
			t.Setenv("NATIVE_LOG", log)
			apk := filepath.Join(t.TempDir(), "fixture.apk")
			writePreviewAPK(t, apk, embedded)
			t.Setenv("FIXTURE_APK", apk)
			if err := os.MkdirAll(filepath.Join(appDir, "android"), 0o755); err != nil {
				t.Fatal(err)
			}
			for path, script := range map[string]string{
				filepath.Join(bin, "npx"): "#!/bin/sh\nprintf 'npx %s\\n' \"$*\" >> \"$NATIVE_LOG\"\n",
				filepath.Join(appDir, "android", "gradlew"): `#!/bin/sh
printf 'gradle %s variant=%s api=%s\n' "$*" "$APP_VARIANT" "$API_URL" >> "$NATIVE_LOG"
case "$*" in *:app:assembleRelease*)
 mkdir -p app/build/outputs/apk/release
 cp "$FIXTURE_APK" app/build/outputs/apk/release/app-release.apk
 echo '{"applicationId":"com.gmacko.sortey.dev","variantName":"release","elements":[{"type":"SINGLE","filters":[],"outputFile":"app-release.apk"}]}' > app/build/outputs/apk/release/output-metadata.json
esac
`,
				filepath.Join(bin, "adb"):   "#!/bin/sh\nprintf 'adb %s\\n' \"$*\" >> \"$NATIVE_LOG\"\nprintf 'Success\\nStatus: ok\\n'\n",
				filepath.Join(bin, "aapt2"): "#!/bin/sh\nprintf \"package: name='com.gmacko.sortey.dev' versionCode='1'\\n\"\n",
			} {
				if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			job := apiRunnerJob{}
			job.Payload.Platform = "android"
			job.Payload.Lane = "simulator"
			job.Payload.SourceBinding = runnerJobSourceBinding{WorkspaceRoot: appDir, PackagePath: ".", EASProfileName: "preview-android", AndroidPackage: "com.gmacko.sortey.dev"}
			_, err := runExpoAppOpen(nil, runnerRegistrationData{}, runnerOnceOptions{adbPath: filepath.Join(bin, "adb")}, "android", appDir, "emulator-5590", 18122, job)
			if embedded && err != nil {
				t.Fatal(err)
			}
			if !embedded && (err == nil || !strings.Contains(err.Error(), "index.android.bundle")) {
				t.Fatalf("missing JS did not refuse: %v", err)
			}
			raw, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			commands := string(raw)
			if !embedded {
				if strings.Contains(commands, "adb ") {
					t.Fatalf("invalid APK reached device: %s", commands)
				}
				return
			}
			for _, want := range []string{":app:assembleRelease", "variant=preview", "api=https://example.test/$apiSuffix", "adb -s emulator-5590 install -r", "adb -s emulator-5590 shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p com.gmacko.sortey.dev"} {
				if !strings.Contains(commands, want) {
					t.Fatalf("missing %q:\n%s", want, commands)
				}
			}
			if strings.Contains(commands, "expo run:android") || strings.Contains(commands, "expo-development-client") || strings.Contains(commands, "variant=development") {
				t.Fatalf("preview used dev-client path:\n%s", commands)
			}
		})
	}
}

func TestAndroidPreviewBinaryManifestIdentity(t *testing.T) {
	for _, response := range []string{"package: name='com.foreign.app' versionCode='1'", "package: name='com.gmacko.sortey.dev.extra' versionCode='1'", "", "package: name='com.gmacko.sortey.dev' versionCode='1'\npackage: name='com.foreign.app' versionCode='1'"} {
		t.Run(response, func(t *testing.T) {
			bin := t.TempDir()
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("AAPT_RESPONSE", response)
			if err := os.WriteFile(filepath.Join(bin, "aapt2"), []byte("#!/bin/sh\nprintf '%s\\n' \"$AAPT_RESPONSE\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := os.CreateTemp(t.TempDir(), "log")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := verifyAndroidPreviewPackage(f, "fixture.apk", "com.gmacko.sortey.dev", nil); err == nil {
				t.Fatal("foreign/ambiguous binary identity accepted")
			}
		})
	}
}

func TestAndroidPreviewAPKRefusesInvalidOutputs(t *testing.T) {
	for _, tc := range []struct {
		name, metadata string
		symlink        bool
	}{
		{"foreign identity", `{"applicationId":"com.foreign.app","variantName":"release","elements":[{"type":"SINGLE","filters":[],"outputFile":"app-release.apk"}]}`, false},
		{"traversal", `{"applicationId":"com.gmacko.sortey.dev","variantName":"release","elements":[{"type":"SINGLE","filters":[],"outputFile":"../app-release.apk"}]}`, false},
		{"split", `{"applicationId":"com.gmacko.sortey.dev","variantName":"release","elements":[{"type":"SINGLE","filters":[{"filterType":"ABI","value":"arm64-v8a"}],"outputFile":"app-release.apk"}]}`, false},
		{"debug", `{"applicationId":"com.gmacko.sortey.dev","variantName":"debug","elements":[{"type":"SINGLE","filters":[],"outputFile":"app-release.apk"}]}`, false},
		{"no output", `{"applicationId":"com.gmacko.sortey.dev","variantName":"release","elements":[]}`, false},
		{"malformed", `{`, false},
		{"linked APK", `{"applicationId":"com.gmacko.sortey.dev","variantName":"release","elements":[{"type":"SINGLE","filters":[],"outputFile":"app-release.apk"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			apk := filepath.Join(dir, "app-release.apk")
			if tc.symlink {
				other := filepath.Join(t.TempDir(), "other.apk")
				writePreviewAPK(t, other, true)
				if err := os.Symlink(other, apk); err != nil {
					t.Fatal(err)
				}
			} else {
				writePreviewAPK(t, apk, true)
			}
			if err := os.WriteFile(filepath.Join(dir, "output-metadata.json"), []byte(tc.metadata), 0o644); err != nil {
				t.Fatal(err)
			}
			if path, err := androidPreviewAPK(dir, "com.gmacko.sortey.dev"); err == nil {
				t.Fatalf("accepted invalid output %s", path)
			}
		})
	}
}

func TestAndroidPreviewCleanupRefusesLinkedGeneratedParent(t *testing.T) {
	appDir, _ := writeAndroidPreviewFixture(t)
	android := filepath.Join(appDir, "android")
	if err := os.MkdirAll(filepath.Join(android, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := t.TempDir()
	marker := filepath.Join(foreign, "keep.txt")
	if err := os.WriteFile(marker, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, filepath.Join(android, "app", "build")); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	job := apiRunnerJob{}
	job.Payload.SourceBinding.AndroidPackage = "com.gmacko.sortey.dev"
	err = buildAndInstallAndroidPreview(f, runnerOnceOptions{}, appDir, "emulator-5590", job, nil)
	if err == nil || !strings.Contains(err.Error(), "ancestor") {
		t.Fatalf("linked generated parent not refused: %v", err)
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "foreign" {
		t.Fatal("foreign tree changed")
	}
}

func TestAndroidPreviewADBRequiresPositiveConfirmation(t *testing.T) {
	for _, response := range []string{"", "Error: Activity not started\nStatus: ok", "Failure [INSTALL_FAILED]\nSuccess"} {
		t.Run(response, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "adb")
			t.Setenv("ADB_RESPONSE", response)
			if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$ADB_RESPONSE\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := os.CreateTemp(t.TempDir(), "log")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := runAndroidPreviewADB(f, runnerOnceOptions{adbPath: bin}, nil, "Status: ok", "-s", "emulator-5590", "shell", "am", "start"); err == nil {
				t.Fatal("ambiguous/failed adb response accepted")
			}
		})
	}
}
