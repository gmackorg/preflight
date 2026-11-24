package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// bob (BOB-113) embeds updates.codeSigningCertificate in every variant, so its
// dev client asks Metro for a signed manifest. `expo start` signs one only with
// --private-key-path; without it Metro answered 500 ("Must specify
// --private-key-path argument to sign development manifest") and BobDev showed
// "There was a problem loading the project". The control plane now attaches
// the app's OTA key to dev_session.start; the runner must hand it to Expo.

const testOtaPEM = "-----BEGIN PRIVATE KEY-----\nMIIfake\n-----END PRIVATE KEY-----\n"

func otaSigningJob() apiRunnerJob {
	return apiRunnerJob{
		ID:   "pfjob_dev",
		Kind: "dev_session.start",
		Payload: runnerJobPayload{
			Lane: "simulator",
			SecretReferences: []runnerJobSecretReference{{
				ID:       "pfsecret_bob_ota",
				Provider: "generic",
				Purpose:  "ota_code_signing_key",
				Key:      "OTA_CODE_SIGNING_KEY_JSON",
			}},
		},
	}
}

func otaRevealer(t *testing.T, calls *[]string, value string) storeSecretRevealer {
	t.Helper()
	return func(id string) (runnerJobSecretRevealData, error) {
		*calls = append(*calls, id)
		return runnerJobSecretRevealData{Value: value}, nil
	}
}

func otaKeyValue(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"privateKeyPem":  testOtaPEM,
		"certificatePem": "CERT",
		"keyId":          "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestDevSessionSigningKeyIsRevealedAndWrittenPrivately(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	var calls []string
	keyPath, err := prepareDevSessionSigningKey(otaSigningJob(), otaRevealer(t, &calls, otaKeyValue(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeDevSessionSigningKeyFile(keyPath) })
	if !slices.Equal(calls, []string{"pfsecret_bob_ota"}) {
		t.Fatalf("revealed %v, want only the job's OTA key", calls)
	}
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != testOtaPEM {
		t.Fatalf("key file holds %q", content)
	}
	fileInfo, _ := os.Stat(keyPath)
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("key file mode %o, want 600", mode)
	}
	dirInfo, _ := os.Stat(filepath.Dir(keyPath))
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("key dir mode %o, want 700", mode)
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(keyPath)), devSessionSigningDirPrefix) {
		t.Fatalf("key dir %s is not a Preflight signing dir", filepath.Dir(keyPath))
	}
}

func TestDevSessionSigningKeyAbsentWhenJobCarriesNone(t *testing.T) {
	var calls []string
	job := otaSigningJob()
	job.Payload.SecretReferences = nil
	keyPath, err := prepareDevSessionSigningKey(job, otaRevealer(t, &calls, otaKeyValue(t)))
	if err != nil || keyPath != "" || len(calls) != 0 {
		t.Fatalf("got path %q err %v reveals %v; want nothing revealed", keyPath, err, calls)
	}
}

func TestDevSessionSigningKeyRejectsAMalformedSecretWithoutLeavingAFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	var calls []string
	_, err := prepareDevSessionSigningKey(otaSigningJob(), otaRevealer(t, &calls, `{"keyId":"main"}`))
	if err == nil {
		t.Fatal("a secret without privateKeyPem must fail")
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("error must not echo key material")
	}
	entries, _ := os.ReadDir(tmp)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), devSessionSigningDirPrefix) {
			t.Fatalf("left %s behind", entry.Name())
		}
	}
}

func TestDevSessionSigningKeyRevealFailureIsReported(t *testing.T) {
	_, err := prepareDevSessionSigningKey(otaSigningJob(), func(string) (runnerJobSecretRevealData, error) {
		return runnerJobSecretRevealData{}, errors.New("denied")
	})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("got %v, want the reveal failure", err)
	}
}

func TestExpoDevServerArgsPassThePrivateKeyPath(t *testing.T) {
	options := runnerOnceOptions{hostMode: "localhost", metroPort: 8142}
	job := apiRunnerJob{Payload: runnerJobPayload{Lane: "simulator"}}
	args := expoDevServerArgs(options, job, "/tmp/preflight-ota-signing-1/ota-private-key.pem")
	index := slices.Index(args, "--private-key-path")
	if index < 0 || index+1 >= len(args) || args[index+1] != "/tmp/preflight-ota-signing-1/ota-private-key.pem" {
		t.Fatalf("args %v lack --private-key-path <file>", args)
	}
	if !slices.Contains(args, "--dev-client") || !slices.Contains(args, "8142") {
		t.Fatalf("args %v dropped the existing flags", args)
	}
	if slices.Contains(expoDevServerArgs(options, job, ""), "--private-key-path") {
		t.Fatal("no key, no --private-key-path")
	}
}

func TestDevSessionSigningKeyIsRemovedWhenTheSessionStops(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	appDir := t.TempDir()
	var calls []string
	keyPath, err := prepareDevSessionSigningKey(otaSigningJob(), otaRevealer(t, &calls, otaKeyValue(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := recordDevSessionSigningKey(appDir, keyPath); err != nil {
		t.Fatal(err)
	}
	// No pid file: the session is already gone, which must still clean up.
	outcome, err := stopPreflightOwnedDevSession(appDir, 0)
	if err != nil || outcome != "already_stopped" {
		t.Fatalf("stop: %s %v", outcome, err)
	}
	if _, err := os.Stat(filepath.Dir(keyPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key dir survived the session stop: %v", err)
	}
	if _, err := os.Stat(devSessionSigningHandlePath(appDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("signing handle survived the session stop")
	}
}

func TestDevSessionSigningKeyIsRemovedWithADeadSessionHandle(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	appDir := t.TempDir()
	var calls []string
	keyPath, err := prepareDevSessionSigningKey(otaSigningJob(), otaRevealer(t, &calls, otaKeyValue(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := recordDevSessionSigningKey(appDir, keyPath); err != nil {
		t.Fatal(err)
	}
	// A pid that cannot exist: the previous Metro died without a stop job.
	if err := os.WriteFile(filepath.Join(appDir, ".preflight", "expo-dev-session.pid"), []byte("999999999"), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanupStalePreflightDevServers(appDir, &strings.Builder{})
	if _, err := os.Stat(filepath.Dir(keyPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key dir survived its dead session: %v", err)
	}
}

func TestRemoveDevSessionSigningKeyRefusesAForeignPath(t *testing.T) {
	appDir := t.TempDir()
	foreign := t.TempDir()
	keep := filepath.Join(foreign, "keep.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(appDir, ".preflight"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(devSessionSigningHandlePath(appDir), []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	removeDevSessionSigningKey(appDir)
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("removed a directory Preflight did not create")
	}
}
