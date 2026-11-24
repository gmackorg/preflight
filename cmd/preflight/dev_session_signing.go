package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// An app that embeds updates.codeSigningCertificate (bob since BOB-113) makes
// its development client request a signed manifest, which `expo start` can
// produce only with --private-key-path. Without it Metro answers 500 ("Must
// specify --private-key-path argument to sign development manifest") and the
// client shows "There was a problem loading the project". The control plane
// attaches the app's OTA code-signing key to dev_session.start; this file
// reveals it into a private temp file for the lifetime of that Metro session.
//
// The key file lives outside the checkout (a 0700 dir under TMPDIR, file 0600)
// and is recorded beside the session's pid file, so every path that ends the
// session — a failed start, dev_session.stop, or reaping a dead session — can
// remove it. Metro reads the file per signed request, so it must outlive the
// dev_session.start job, which hands the running server to simulator.open and
// maestro.run.

const (
	devSessionSigningKeyPurpose = "ota_code_signing_key"
	devSessionSigningDirPrefix  = "preflight-ota-signing-"
	devSessionSigningKeyFile    = "ota-private-key.pem"
)

func devSessionSigningKeyReference(job apiRunnerJob) (runnerJobSecretReference, bool) {
	for _, reference := range job.Payload.SecretReferences {
		if reference.Purpose == devSessionSigningKeyPurpose && strings.TrimSpace(reference.ID) != "" {
			return reference, true
		}
	}
	return runnerJobSecretReference{}, false
}

// prepareDevSessionSigningKey reveals the job's OTA code-signing key and writes
// its private key to a fresh private temp file. It returns "" when the job
// carries no key. Errors never include key material.
func prepareDevSessionSigningKey(job apiRunnerJob, reveal storeSecretRevealer) (string, error) {
	reference, ok := devSessionSigningKeyReference(job)
	if !ok {
		return "", nil
	}
	revealed, err := reveal(reference.ID)
	if err != nil {
		return "", fmt.Errorf("reveal OTA code-signing key %s: %w", reference.ID, err)
	}
	var payload struct {
		PrivateKeyPEM string `json:"privateKeyPem"`
	}
	if err := json.Unmarshal([]byte(revealed.Value), &payload); err != nil {
		return "", fmt.Errorf("OTA code-signing key %s is not valid JSON", reference.ID)
	}
	if strings.TrimSpace(payload.PrivateKeyPEM) == "" {
		return "", fmt.Errorf("OTA code-signing key %s has no privateKeyPem", reference.ID)
	}
	dir, err := os.MkdirTemp("", devSessionSigningDirPrefix)
	if err != nil {
		return "", fmt.Errorf("create OTA signing key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("restrict OTA signing key directory: %w", err)
	}
	keyPath := filepath.Join(dir, devSessionSigningKeyFile)
	if err := os.WriteFile(keyPath, []byte(payload.PrivateKeyPEM), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("write OTA signing key: %w", err)
	}
	return keyPath, nil
}

func devSessionSigningHandlePath(appDir string) string {
	return filepath.Join(appDir, ".preflight", "expo-dev-session-signing-dir")
}

// recordDevSessionSigningKey notes the key's directory beside the session's
// pid file, so whatever ends the session can remove it.
func recordDevSessionSigningKey(appDir string, keyPath string) error {
	if keyPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(appDir, ".preflight"), 0o755); err != nil {
		return fmt.Errorf("create Preflight session directory: %w", err)
	}
	return os.WriteFile(devSessionSigningHandlePath(appDir), []byte(filepath.Dir(keyPath)), 0o600)
}

// removeDevSessionSigningKey removes the key recorded for this app's session.
func removeDevSessionSigningKey(appDir string) {
	handle := devSessionSigningHandlePath(appDir)
	content, err := os.ReadFile(handle)
	if err != nil {
		return
	}
	removeDevSessionSigningDir(strings.TrimSpace(string(content)))
	_ = os.Remove(handle)
}

// removeDevSessionSigningKeyFile removes a key written by
// prepareDevSessionSigningKey that was never recorded (a failed start).
func removeDevSessionSigningKeyFile(keyPath string) {
	if keyPath == "" {
		return
	}
	removeDevSessionSigningDir(filepath.Dir(keyPath))
}

// removeDevSessionSigningDir deletes only a directory this file created: a
// direct child of the temp dir carrying the Preflight prefix. A handle that
// names anything else is ignored rather than trusted.
func removeDevSessionSigningDir(dir string) {
	if dir == "" || !strings.HasPrefix(filepath.Base(dir), devSessionSigningDirPrefix) {
		return
	}
	resolvedDir, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		return
	}
	resolvedTemp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil || resolvedDir != resolvedTemp {
		return
	}
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}

// expoDevServerArgs is the `npx` argv for a Preflight-owned Metro session.
func expoDevServerArgs(options runnerOnceOptions, job apiRunnerJob, signingKeyPath string) []string {
	args := []string{"expo", "start", "--dev-client", "--host", expoHostArgForJob(options.hostMode, job), "--port", fmt.Sprint(options.metroPort)}
	if signingKeyPath != "" {
		args = append(args, "--private-key-path", signingKeyPath)
	}
	return args
}
