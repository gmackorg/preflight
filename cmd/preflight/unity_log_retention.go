package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Unity also writes directly to -logFile, outside our stdout redaction writer.
// Freeze and redact a separate, content-addressed snapshot before registration.
// Late editor teardown writes can change the original without changing evidence.
func retainUnityLogSnapshot(logPath string) (string, string, error) {
	info, err := os.Lstat(logPath)
	if err != nil {
		return "", "", fmt.Errorf("stat Unity log: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("Unity log must be a regular file")
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return "", "", fmt.Errorf("read Unity log: %w", err)
	}
	redacted := redactSetupTranscriptText(string(raw))
	redacted = regexp.MustCompile(`(?im)((?:machine[ _-]?id|serial(?: number)?|license key)\s*[:=]\s*)[^\r\n]+`).ReplaceAllString(redacted, "$1[REDACTED]")
	content := []byte(redacted)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	path := filepath.Join(filepath.Dir(logPath), fmt.Sprintf("unity-build-%x.retained.log", sha256.Sum256(content)))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if os.IsExist(err) {
		retainedInfo, statErr := os.Lstat(path)
		if statErr != nil || !retainedInfo.Mode().IsRegular() {
			return "", "", fmt.Errorf("retained Unity log must be a regular file")
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", "", readErr
		}
		if !bytes.Equal(existing, content) {
			return "", "", fmt.Errorf("retained Unity log content differs from digest")
		}
		return path, digest, nil
	}
	if err != nil {
		return "", "", fmt.Errorf("create retained Unity log: %w", err)
	}
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return "", "", fmt.Errorf("write retained Unity log: %w", writeErr)
	}
	if syncErr != nil {
		return "", "", fmt.Errorf("sync retained Unity log: %w", syncErr)
	}
	if closeErr != nil {
		return "", "", fmt.Errorf("close retained Unity log: %w", closeErr)
	}
	return path, digest, nil
}
