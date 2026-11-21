package main

// store.upload for iOS (PREFLT-66): `xcrun altool --upload-package` with the
// team's App Store Connect API key, written to a private temporary
// private_keys directory that altool finds through API_PRIVATE_KEYS_DIR.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type altoolResult struct {
	SuccessMessage string `json:"success-message"`
	Details        struct {
		DeliveryUUID string `json:"delivery-uuid"`
		Transferred  string `json:"transferred"`
	} `json:"details"`
	ProductErrors []struct {
		Code     int            `json:"code"`
		Message  string         `json:"message"`
		UserInfo map[string]any `json:"userInfo"`
	} `json:"product-errors"`
}

// parseAltoolOutput finds the JSON document in altool's output (it can be
// preceded by log lines).
func parseAltoolOutput(output string) (altoolResult, bool) {
	var result altoolResult
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start < 0 || end <= start {
		return result, false
	}
	if err := json.Unmarshal([]byte(output[start:end+1]), &result); err != nil {
		return result, false
	}
	return result, true
}

var altoolTransientMarkers = []string{
	"timed out", "network connection was lost", "could not connect", "not connected to the internet",
	"service unavailable", "internal server error", "bad gateway", "gateway timeout", "try again later",
	"please try again", "-1001", "-1004", "-1005", "-1009", "-19235", "http 5", "status code 5",
	"connection reset", "too many requests", "429",
}

// classifyAltoolFailure maps altool output to a failure code. Transient
// failures are retried by the control plane (asc_upload_transient).
func classifyAltoolFailure(output string, err error) *storeFailure {
	message := strings.TrimSpace(output)
	if result, ok := parseAltoolOutput(output); ok && len(result.ProductErrors) > 0 {
		parts := []string{}
		for _, productError := range result.ProductErrors {
			parts = append(parts, fmt.Sprintf("%d: %s", productError.Code, productError.Message))
		}
		message = strings.Join(parts, "; ")
	}
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "not_authorized") || strings.Contains(lower, "unable to authenticate") ||
		strings.Contains(lower, "authentication credentials are missing or invalid") || strings.Contains(lower, "401"):
		return storeFailuref("asc_auth_failed", "altool: %s", message)
	case strings.Contains(lower, "bundle version must be higher") || strings.Contains(lower, "has already been uploaded") ||
		strings.Contains(lower, "redundant binary upload") || strings.Contains(lower, "entity_error"):
		return storeFailuref("asc_upload_rejected", "altool: %s", message)
	}
	for _, marker := range altoolTransientMarkers {
		if strings.Contains(lower, marker) {
			return storeFailuref("asc_upload_transient", "altool: %s", message)
		}
	}
	if err != nil && strings.Contains(err.Error(), errCommandTimedOut.Error()) {
		return storeFailuref("asc_upload_transient", "altool timed out: %v", err)
	}
	return storeFailuref("asc_upload_failed", "altool: %v: %s", err, message)
}

var ascKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9]+$`)

func runIOSStoreUpload(rt *storeJobRuntime, job apiRunnerJob, artifact storeBuildArtifact, ipaPath string) (map[string]any, error) {
	payload := job.Payload
	for field, value := range map[string]string{"ascAppId": payload.ASCAppID, "bundleId": payload.BundleID, "version": payload.Version, "buildNumber": payload.BuildNumber} {
		if strings.TrimSpace(value) == "" {
			return nil, storeFailuref("store_upload_payload_invalid", "testflight upload requires %s", field)
		}
	}
	referenceID := storeSecretReferenceFor(job, "asc_api_key", "ASC_API_KEY_JSON")
	revealed, err := revealStoreSecret(rt.reveal, rt.cleanup, referenceID, "App Store Connect API key")
	if err != nil {
		return nil, err
	}
	var key ascAPIKeyPayload
	if err := parseStoreSecretPayload("asc_api_key", revealed.Value, &key, "keyId", "issuerId", "privateKeyP8"); err != nil {
		return nil, err
	}
	registerPayloadSecrets(rt.cleanup, key.PrivateKeyP8)
	if !ascKeyIDPattern.MatchString(key.KeyID) {
		return nil, storeFailuref("signing_credential_invalid", "asc_api_key keyId has unexpected characters")
	}

	keysRoot := filepath.Join(rt.workDir, "asc")
	keysDir := filepath.Join(keysRoot, "private_keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, err
	}
	rt.cleanup.removeAll(keysRoot)
	p8 := strings.ReplaceAll(key.PrivateKeyP8, `\n`, "\n")
	if err := os.WriteFile(filepath.Join(keysDir, "AuthKey_"+key.KeyID+".p8"), []byte(strings.TrimSpace(p8)+"\n"), 0o600); err != nil {
		return nil, err
	}
	env := upsertEnv(append([]string{}, os.Environ()...), "API_PRIVATE_KEYS_DIR", keysDir)

	output, err := rt.run.Run(storeCommand{
		Name: "xcrun",
		Args: []string{
			"altool", "--upload-package", ipaPath,
			"--type", "ios",
			"--apiKey", key.KeyID,
			"--apiIssuer", key.IssuerID,
			"--apple-id", payload.ASCAppID,
			"--bundle-id", payload.BundleID,
			"--bundle-version", payload.BuildNumber,
			"--bundle-short-version-string", payload.Version,
			"--output-format", "json",
		},
		Env:     env,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_ALTOOL_TIMEOUT", 60*time.Minute),
	})
	if err != nil {
		return nil, wrapStoreCommandError(err, classifyAltoolFailure(string(output), err))
	}
	parsed, ok := parseAltoolOutput(string(output))
	if ok && len(parsed.ProductErrors) > 0 {
		return nil, classifyAltoolFailure(string(output), fmt.Errorf("altool reported errors"))
	}
	result := map[string]any{
		"status":      "ok",
		"buildId":     job.Payload.BuildID,
		"destination": "testflight",
		// altool returns a delivery id, not the ASC build resource; the build
		// appears (and processes) asynchronously. The control plane's ASC
		// reconciler resolves ascBuildId and the final processing state.
		"ascProcessingState": "UPLOADED",
		"artifact":           artifact.toMap(),
	}
	if ok && parsed.Details.DeliveryUUID != "" {
		result["ascDeliveryUuid"] = parsed.Details.DeliveryUUID
	}
	return result, nil
}

func handleStoreUploadJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()

	var artifact storeBuildArtifact
	if len(job.Payload.StoreArtifact) == 0 || json.Unmarshal(job.Payload.StoreArtifact, &artifact) != nil || artifact.SHA256 == "" {
		return completeStoreJobFailure(client, options, registration, job, stdout,
			storeFailuref("store_upload_payload_invalid", "store.upload requires artifact {fileName, sha256, storageKey}"), "", nil)
	}
	destination := strings.TrimSpace(job.Payload.Destination)
	workDir := storeJobWorkDir(options, job)
	log, closeLog, err := openStoreJobLog(workDir, stdout)
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_upload_workspace_failed", nil)
	}
	defer closeLog()
	runtime, err := newStoreJobRuntime(client, options, registration, job, log, "")
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_upload_workspace_failed", nil)
	}
	defer runtime.cleanup.Run()

	result, err := runStoreUpload(runtime, job, artifact, destination, storeWorkspaceRoot(options, job))
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_upload_failed", nil)
	}
	if err := completeRunnerJob(client, options, registration, job, result); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "completed store.upload %s (%s)\n", job.ID, destination)
	return nil
}

func runStoreUpload(runtime *storeJobRuntime, job apiRunnerJob, artifact storeBuildArtifact, destination string, workspaceRoot string) (map[string]any, error) {
	switch destination {
	case "testflight":
	case "play_internal", "play_alpha", "play_beta", "play_production":
	default:
		return nil, storeFailuref("store_upload_payload_invalid", "unsupported store upload destination %q", destination)
	}
	path, err := resolveStoreArtifactFile(runtime, artifact, workspaceRoot)
	if err != nil {
		return nil, err
	}
	if destination == "testflight" {
		return runIOSStoreUpload(runtime, job, artifact, path)
	}
	return runPlayStoreUpload(runtime, job, artifact, path, destination)
}
