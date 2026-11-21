package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisteredSecretsAreRedactedUntilReleased(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg\nabcdefghijklmnopqrstuvwx\n-----END PRIVATE KEY-----"
	release := registerRedactedSecrets("keychain-pass-123", pem, "abc")
	line := "security unlock-keychain -p keychain-pass-123 /tmp/k"
	if got := redactSetupTranscriptText(line); strings.Contains(got, "keychain-pass-123") {
		t.Fatalf("password not redacted: %s", got)
	}
	if got := redactSetupTranscriptText("key line MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg\n"); strings.Contains(got, "MIGTAgEAMBMG") {
		t.Fatalf("PEM body line not redacted: %s", got)
	}
	if got := redactSetupTranscriptText("abc stays"); got != "abc stays" {
		t.Fatalf("short values must not be registered: %s", got)
	}
	// A second holder of the same value keeps it registered.
	releaseAgain := registerRedactedSecrets("keychain-pass-123")
	release()
	if strings.Contains(redactSetupTranscriptText(line), "keychain-pass-123") {
		t.Fatal("value released while another job still holds it")
	}
	releaseAgain()
	release()
	if !strings.Contains(redactSetupTranscriptText(line), "keychain-pass-123") {
		t.Fatal("value still redacted after every holder released it")
	}
}

func TestStoreArtifactUploadSendsPartsAndVerifiesSHA(t *testing.T) {
	plane := newFakeStoreControlPlane(t)
	data := make([]byte, int(minStorePartSizeBytes)*2+1234)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "StoreApp.ipa")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := plane.client().upload(path, "ipa")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if artifact.SHA256 != hex.EncodeToString(sum[:]) || artifact.SizeBytes != int64(len(data)) || artifact.StorageKey != "store/pfjob_store/StoreApp.ipa" || artifact.Kind != "ipa" {
		t.Fatalf("artifact = %+v", artifact)
	}
	if plane.completed["parts"] != 3 {
		t.Fatalf("expected 3 parts, got %v", plane.completed)
	}

	// Download round-trips and is verified against the recorded sha256.
	destination := filepath.Join(t.TempDir(), "download", "StoreApp.ipa")
	if err := plane.client().download(artifact, destination); err != nil {
		t.Fatal(err)
	}
	downloaded, _ := os.ReadFile(destination)
	if !bytes.Equal(downloaded, data) {
		t.Fatal("downloaded bytes differ")
	}
	artifact.SHA256 = strings.Repeat("0", 64)
	if err := plane.client().download(artifact, destination+".bad"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("sha mismatch not detected: %v", err)
	}
	if filePresent(destination+".bad") || filePresent(destination+".bad.partial") {
		t.Fatal("unverified download left on disk")
	}
}

func TestResolveStoreArtifactFileReusesLocalBuildOutput(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, ".preflight", "store-builds", "pfjob_build", "output", "app-release.aab")
	mustWrite(t, local, "aab-bytes")
	sum, size, _ := fileSHA256(local)
	runtime, _ := newTestStoreRuntime(t, &fakeStoreRunner{}, nil)
	runtime.uploads = &storeArtifactClient{baseURL: "http://127.0.0.1:1"} // must not be called
	path, err := resolveStoreArtifactFile(runtime, storeBuildArtifact{Kind: "aab", FileName: "app-release.aab", SHA256: sum, SizeBytes: size, StorageKey: "k"}, root)
	if err != nil || path != local {
		t.Fatalf("path = %q, err = %v", path, err)
	}
}

func TestStoreCapabilitiesFollowInstalledTools(t *testing.T) {
	tools := map[string]bool{"npx": true, "xcodebuild": true, "xcrun": true, "java": true}
	probe := storeToolProbe{
		goos:       "darwin",
		onPath:     func(name string) bool { return tools[name] },
		xcrunFind:  func(tool string) bool { return tool == "xcodebuild" || tool == "altool" },
		androidSDK: func() bool { return true },
	}
	got := strings.Join(detectStoreAdapters(probe), ",")
	if got != "expo.prebuild,xcodebuild,xcode.archive,xcrun.altool,android.sdk,java" {
		t.Fatalf("mac adapters = %s", got)
	}
	// Command Line Tools only: xcodebuild exists but cannot archive.
	probe.xcrunFind = func(string) bool { return false }
	if got := strings.Join(detectStoreAdapters(probe), ","); strings.Contains(got, "xcode") {
		t.Fatalf("CLT-only host advertised Xcode: %s", got)
	}
	probe.goos = "linux"
	probe.androidSDK = func() bool { return false }
	if got := strings.Join(detectStoreAdapters(probe), ","); got != "expo.prebuild,java" {
		t.Fatalf("linux adapters = %s", got)
	}
	if missing := missingStoreTools(probe, "android.sdk", "java"); strings.Join(missing, ",") != "android.sdk" {
		t.Fatalf("missing = %v", missing)
	}
	// iOS-only adapters are dropped on hosts without the ios platform.
	if kept := filterAdaptersForPlatforms([]string{"xcodebuild", "xcrun.altool", "android.sdk", "java", "expo.prebuild"}, []string{"android"}); strings.Join(kept, ",") != "android.sdk,java,expo.prebuild" {
		t.Fatalf("filtered = %v", kept)
	}
}

// End to end through the job handler: reveal, build (fake tools), chunked
// upload, completion — for Android, which needs no keychain fakes.
func TestHandleStoreBuildJobAndroidCompletesWithUploadedArtifact(t *testing.T) {
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "0")
	plane := newFakeStoreControlPlane(t)
	fixture := newAndroidBuildFixture(t)
	plane.secrets["ref_keystore"] = mustJSON(t, map[string]string{
		"keystoreBase64": b64("keystore-bytes"), "keystorePassword": "store-pass-secret", "keyAlias": "upload",
		"keyPassword": "key-pass-secret", "sha1Fingerprint": fixture.signerSHA1, "sha256Fingerprint": "00",
	})
	plane.secrets["ref_env"] = "build-env-secret"
	plane.secretKeys["ref_env"] = "SENTRY_AUTH_TOKEN"

	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "mobile")
	mustWrite(t, filepath.Join(appDir, "package.json"), "{}")
	fixture.runtime.appDir = appDir

	originalRunner := newStoreCommandRunner
	newStoreCommandRunner = func(io.Writer, func() (bool, error)) storeCommandRunner { return fixture.runner }
	originalProbe := storeToolProbeForJobs
	storeToolProbeForJobs = func() storeToolProbe {
		return storeToolProbe{goos: "linux", onPath: func(string) bool { return true }, xcrunFind: func(string) bool { return false }, androidSDK: func() bool { return true }}
	}
	t.Cleanup(func() {
		newStoreCommandRunner = originalRunner
		storeToolProbeForJobs = originalProbe
	})

	fixture.plan.AppDirectory = "apps/mobile"
	fixture.plan.SecretEnvironmentReferenceIDs = []string{"ref_env"}
	planJSON, _ := json.Marshal(fixture.plan)
	job := apiRunnerJob{
		ID:   "pfjob_store",
		Kind: "store.build",
		Payload: runnerJobPayload{
			Platform:      "android",
			Lane:          "store",
			BuildID:       "build_2",
			StorePlan:     planJSON,
			SourceBinding: runnerJobSourceBinding{WorkspaceRoot: root},
		},
	}
	options := runnerOnceOptions{apiURL: plane.server.URL, workspaceRoot: root}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_store", Capabilities: map[string]any{"runnerJobHeartbeat": false}}, Token: "runner_token"}
	var stdout bytes.Buffer
	if err := handleStoreBuildJob(plane.server.Client(), options, registration, job, &stdout); err != nil {
		t.Fatalf("handleStoreBuildJob: %v\n%s", err, stdout.String())
	}
	if len(plane.completions) != 1 {
		t.Fatalf("completions = %v\n%s", plane.completions, stdout.String())
	}
	result := plane.completions[0]
	if result["status"] != "ok" {
		t.Fatalf("result = %v\n%s", result, stdout.String())
	}
	artifact := result["artifact"].(map[string]any)
	if artifact["kind"] != "aab" || artifact["fileName"] != "app-release.aab" || artifact["storageKey"] != "store/pfjob_store/app-release.aab" {
		t.Fatalf("artifact = %v", artifact)
	}
	if result["signing"].(map[string]any)["keystoreSha1"] != fixture.signerSHA1 {
		t.Fatalf("signing = %v", result["signing"])
	}
	prebuild := fixture.runner.find("npx expo prebuild")
	if len(prebuild) != 1 || prebuild[0].Dir != appDir || !containsString(prebuild[0].Env, "SENTRY_AUTH_TOKEN=build-env-secret") {
		t.Fatalf("prebuild ran in the wrong place or without secret env: %+v", prebuild)
	}
	logBytes, _ := os.ReadFile(filepath.Join(root, ".preflight", "store-builds", "pfjob_store", "store.log"))
	for _, secret := range []string{"store-pass-secret", "key-pass-secret", "build-env-secret"} {
		if strings.Contains(string(logBytes), secret) || strings.Contains(stdout.String(), secret) {
			t.Fatalf("secret %q leaked into the job log", secret)
		}
	}
	if filePresent(filepath.Join(root, ".preflight", "store-builds", "pfjob_store", "keystore")) {
		t.Fatal("keystore not cleaned up by the handler")
	}
}

func TestHandleStoreBuildJobReportsSetupRequiredForUnrevealableKeystore(t *testing.T) {
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "0")
	plane := newFakeStoreControlPlane(t)
	fixture := newAndroidBuildFixture(t)
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), "{}")
	originalRunner := newStoreCommandRunner
	newStoreCommandRunner = func(io.Writer, func() (bool, error)) storeCommandRunner { return fixture.runner }
	originalProbe := storeToolProbeForJobs
	storeToolProbeForJobs = func() storeToolProbe {
		return storeToolProbe{goos: "linux", onPath: func(string) bool { return true }, xcrunFind: func(string) bool { return false }, androidSDK: func() bool { return true }}
	}
	t.Cleanup(func() {
		newStoreCommandRunner = originalRunner
		storeToolProbeForJobs = originalProbe
	})
	planJSON, _ := json.Marshal(fixture.plan)
	job := apiRunnerJob{ID: "pfjob_store", Kind: "store.build", Payload: runnerJobPayload{Platform: "android", StorePlan: planJSON, SourceBinding: runnerJobSourceBinding{WorkspaceRoot: root}}}
	options := runnerOnceOptions{apiURL: plane.server.URL, workspaceRoot: root}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_store", Capabilities: map[string]any{"runnerJobHeartbeat": false}}, Token: "runner_token"}
	if err := handleStoreBuildJob(plane.server.Client(), options, registration, job, io.Discard); err != nil {
		t.Fatal(err)
	}
	result := plane.completions[0]
	failure := result["failure"].(map[string]any)
	if result["status"] != "setup_required" || failure["code"] != "signing_credential_unavailable" {
		t.Fatalf("result = %v", result)
	}
	if len(fixture.runner.calls) != 0 {
		t.Fatalf("tools ran without signing material: %v", fixture.runner.lines())
	}
}

func TestDecodeStoreBuildPlanValidates(t *testing.T) {
	for name, payload := range map[string]string{
		"no plan":      ``,
		"no version":   `{"platform":"ios","buildNumber":"1","ios":{}}`,
		"no ios":       `{"platform":"ios","version":"1.0","buildNumber":"1"}`,
		"bad platform": `{"platform":"web","version":"1.0","buildNumber":"1"}`,
	} {
		job := apiRunnerJob{Payload: runnerJobPayload{StorePlan: json.RawMessage(payload)}}
		if _, err := decodeStoreBuildPlan(job); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	job := apiRunnerJob{Payload: runnerJobPayload{Platform: "android", Lane: "beta", BuildID: "b1", StorePlan: json.RawMessage(`{"version":"1.0","buildNumber":"3","android":{"keystoreSecretReferenceId":"k"}}`)}}
	plan, err := decodeStoreBuildPlan(job)
	if err != nil || plan.Platform != "android" || plan.Lane != "beta" || plan.BuildID != "b1" {
		t.Fatalf("plan = %+v, err = %v", plan, err)
	}
}
