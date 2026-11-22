package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const expoAppBuildGradle = `apply plugin: "com.android.application"

android {
    ndkVersion rootProject.ext.ndkVersion
    namespace 'com.example.storeapp'
    defaultConfig {
        applicationId 'com.example.storeapp'
        minSdkVersion rootProject.ext.minSdkVersion
        targetSdkVersion rootProject.ext.targetSdkVersion
        versionCode 1
        versionName "1.0.0"
        buildConfigField "String", "REACT_NATIVE_RELEASE_LEVEL", "\"stable\""
    }
    signingConfigs {
        debug {
            storeFile file('debug.keystore')
            storePassword 'android'
            keyAlias 'androiddebugkey'
            keyPassword 'android'
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.debug
        }
    }
}
`

func TestSetAndroidVersionPatchesExpoBuildGradle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "build.gradle")
	mustWrite(t, path, expoAppBuildGradle)
	if err := setAndroidVersion(path, "1.4.0", "42"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	if !strings.Contains(text, "        versionCode 42\n") || !strings.Contains(text, "        versionName \"1.4.0\"\n") {
		t.Fatalf("defaultConfig not patched:\n%s", text)
	}
	if strings.Count(text, "versionCode") != 1 || !strings.Contains(text, "storePassword 'android'") {
		t.Fatalf("unrelated lines changed:\n%s", text)
	}

	// Missing keys are inserted into defaultConfig.
	stripped := strings.Replace(strings.Replace(expoAppBuildGradle, "        versionCode 1\n", "", 1), "        versionName \"1.0.0\"\n", "", 1)
	mustWrite(t, path, stripped)
	if err := setAndroidVersion(path, "2.0.0", "7"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), "defaultConfig {\n        versionName \"2.0.0\"\n        versionCode 7\n") {
		t.Fatalf("keys not inserted:\n%s", raw)
	}

	kts := filepath.Join(t.TempDir(), "build.gradle.kts")
	mustWrite(t, kts, "android {\n    defaultConfig {\n        versionCode = 1\n        versionName = \"1.0\"\n    }\n}\n")
	if err := setAndroidVersion(kts, "3.1.0", "300"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(kts)
	if !strings.Contains(string(raw), "versionCode = 300") || !strings.Contains(string(raw), `versionName = "3.1.0"`) {
		t.Fatalf("kts not patched:\n%s", raw)
	}

	if err := setAndroidVersion(path, "1.0", "1.2"); err == nil {
		t.Fatal("non-integer versionCode must be rejected")
	}
}

type androidBuildFixture struct {
	t            *testing.T
	runtime      *storeJobRuntime
	runner       *fakeStoreRunner
	plan         storeBuildPlan
	signerSHA1   string
	keystoreSeen bool
	gradleErr    error
}

func newAndroidBuildFixture(t *testing.T) *androidBuildFixture {
	fixture := &androidBuildFixture{t: t, signerSHA1: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"}
	secrets := map[string]string{
		"ref_keystore": mustJSON(t, map[string]string{
			"keystoreBase64": b64("keystore-bytes"), "keystorePassword": "store-pass-secret", "keyAlias": "upload",
			"keyPassword": "key-pass-secret", "sha1Fingerprint": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",
			"sha256Fingerprint": "00",
		}),
	}
	fixture.plan = storeBuildPlan{
		BuildID: "build_2", Platform: "android", Lane: "store", Version: "1.4.0", BuildNumber: "42",
		Android: &storeBuildAndroidPlan{KeystoreSecretReferenceID: "ref_keystore", GradleTask: "bundleRelease", ApplicationID: "com.example.storeapp"},
	}
	fixture.runner = &fakeStoreRunner{handle: fixture.handle}
	fixture.runtime, _ = newTestStoreRuntime(t, fixture.runner, secrets)
	return fixture
}

func (fixture *androidBuildFixture) handle(command storeCommand) ([]byte, error) {
	t := fixture.t
	androidDir := filepath.Join(fixture.runtime.appDir, "android")
	switch command.Name {
	case "npx":
		if strings.Join(command.Args, " ") != "expo prebuild --platform android --clean --no-install" {
			t.Errorf("prebuild args = %v", command.Args)
		}
		mustWrite(t, filepath.Join(androidDir, "app", "build.gradle"), expoAppBuildGradle)
		mustWrite(t, filepath.Join(androidDir, "gradlew"), "#!/bin/sh\n")
	case "./gradlew":
		if command.Dir != androidDir || command.Args[0] != ":app:bundleRelease" {
			t.Errorf("gradle ran %v in %s", command.Args, command.Dir)
		}
		storeFile := ""
		for _, arg := range command.Args {
			if value, ok := strings.CutPrefix(arg, "-Pandroid.injected.signing.store.file="); ok {
				storeFile = value
			}
		}
		info, err := os.Stat(storeFile)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("keystore %s missing or not 0600: %v", storeFile, err)
		} else {
			fixture.keystoreSeen = true
		}
		for _, want := range []string{"-Pandroid.injected.signing.store.password=store-pass-secret", "-Pandroid.injected.signing.key.alias=upload", "-Pandroid.injected.signing.key.password=key-pass-secret"} {
			if !containsString(command.Args, want) {
				t.Errorf("gradle args missing %s", want)
			}
		}
		gradle, _ := os.ReadFile(filepath.Join(androidDir, "app", "build.gradle"))
		if !strings.Contains(string(gradle), "versionCode 42") {
			t.Error("versionCode not patched before gradle ran")
		}
		if fixture.gradleErr != nil {
			return []byte("FAILURE: Build failed with an exception.\n"), fixture.gradleErr
		}
		mustWrite(t, filepath.Join(androidDir, "app", "build", "outputs", "bundle", "release", "app-release.aab"), "aab-bytes")
	case "keytool":
		return []byte("Signer #1:\n\nCertificate fingerprints:\n\t SHA1: " + fixture.signerSHA1 + "\n\t SHA256: 00\n"), nil
	default:
		t.Errorf("unexpected command %s", command.String())
	}
	return nil, nil
}

func TestRunAndroidStoreBuildSignsWithLeasedKeystore(t *testing.T) {
	fixture := newAndroidBuildFixture(t)
	outcome, err := runAndroidStoreBuild(fixture.runtime, fixture.plan, nil)
	if err != nil {
		t.Fatalf("runAndroidStoreBuild: %v", err)
	}
	if !fixture.keystoreSeen {
		t.Fatal("gradle did not see the keystore")
	}
	if outcome.kind != "aab" || outcome.artifactPath != filepath.Join(fixture.runtime.workDir, "output", "app-release.aab") {
		t.Fatalf("outcome = %+v", outcome)
	}
	if outcome.signing["keystoreSha1"] != "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01" {
		t.Fatalf("signing = %v", outcome.signing)
	}
	// Passwords are redacted from anything logged while the job runs.
	if got := redactSetupTranscriptText("gradle -Pandroid.injected.signing.store.password=store-pass-secret"); strings.Contains(got, "store-pass-secret") {
		t.Fatalf("keystore password not redacted: %s", got)
	}
	fixture.runtime.cleanup.Run()
	if filePresent(filepath.Join(fixture.runtime.workDir, "keystore")) {
		t.Fatal("keystore left on disk after cleanup")
	}
	if redactRegisteredSecrets("key-pass-secret") != "key-pass-secret" {
		t.Fatal("redaction registration leaked past the job")
	}
}

func TestRunAndroidStoreBuildRejectsWrongSigner(t *testing.T) {
	fixture := newAndroidBuildFixture(t)
	fixture.signerSHA1 = "00:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99"
	_, err := runAndroidStoreBuild(fixture.runtime, fixture.plan, nil)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "signing_verification_failed" {
		t.Fatalf("err = %v", err)
	}
	fixture.runtime.cleanup.Run()
	if filePresent(filepath.Join(fixture.runtime.workDir, "keystore")) {
		t.Fatal("keystore left on disk after a failed build")
	}
}

func TestRunAndroidStoreBuildCleansUpAfterGradleFailure(t *testing.T) {
	fixture := newAndroidBuildFixture(t)
	fixture.gradleErr = errors.New("./gradlew: exit status 1")
	_, err := runAndroidStoreBuild(fixture.runtime, fixture.plan, nil)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "gradle_build_failed" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(failure.message, "store-pass-secret") {
		t.Fatal("failure message leaks the keystore password")
	}
	fixture.runtime.cleanup.Run()
	if filePresent(filepath.Join(fixture.runtime.workDir, "keystore")) {
		t.Fatal("keystore left on disk after gradle failed")
	}
}
