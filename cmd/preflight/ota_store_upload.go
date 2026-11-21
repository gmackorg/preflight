package main

// OTA publish into the control plane's update store (PREFLT-66).
//
// publish-local.mjs writes an update into a filesystem store:
//
//	<storeRoot>/updates/<appSlug>/<updateId>/record.json
//	<storeRoot>/updates/<appSlug>/<updateId>/<file listed on the record>
//
// When the control plane serves updates from R2 (its OTA store is not this
// runner's disk), ota.publish stages the update in a scratch store, uploads
// every listed file and then record.json through
// PUT /api/preflight/v1/apps/:id/ota/store/:updateId/<file>, and drops the
// scratch copy. The record goes last: it is what makes the update resolvable,
// so a half-uploaded update is never served. Without a server store the
// runner keeps publishing into its own filesystem store as before.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// otaStoreUploadError marks a failure to reach or write the server store, so
// the job reports the retryable ota_store_unavailable code.
type otaStoreUploadError struct{ err error }

func (e *otaStoreUploadError) Error() string {
	return "upload to the control plane OTA store: " + e.err.Error()
}
func (e *otaStoreUploadError) Unwrap() error { return e.err }

// otaServerStoreKind reports the control plane's OTA store backend ("r2",
// "filesystem", …) from GET /api/preflight/v1/ota/health, or "" when it
// cannot tell. PREFLIGHT_OTA_SERVER_STORE overrides the probe: "r2" (or
// "upload") forces uploads, "off"/"filesystem" keeps the local store.
func otaServerStoreKind(client *http.Client, apiURL string) string {
	switch override := strings.ToLower(strings.TrimSpace(os.Getenv("PREFLIGHT_OTA_SERVER_STORE"))); override {
	case "r2", "upload", "server":
		return "r2"
	case "off", "none", "filesystem", "local":
		return "filesystem"
	}
	if strings.TrimSpace(apiURL) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, runnerEndpoint(apiURL, "/api/preflight/v1/ota/health"), nil)
	if err != nil {
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	var health struct {
		OK   bool   `json:"ok"`
		Kind string `json:"kind"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&health) != nil || !health.OK {
		return ""
	}
	return strings.TrimSpace(health.Kind)
}

// otaServerStoreUploadsEnabled: upload unless the server store is the
// filesystem (shared with the runner in local setups) or unknown.
func otaServerStoreUploadsEnabled(kind string) bool {
	return kind != "" && kind != "filesystem"
}

type otaStoreRecordFile struct {
	File        string `json:"file"`
	ContentType string `json:"contentType"`
}

type otaStoreRecord struct {
	ID          string               `json:"id"`
	AppSlug     string               `json:"appSlug"`
	LaunchAsset otaStoreRecordFile   `json:"launchAsset"`
	Assets      []otaStoreRecordFile `json:"assets"`
}

type otaStoreUploadTarget struct {
	apiURL      string
	token       string
	workspaceID string
	appID       string
}

// uploadOtaUpdateToServerStore uploads one staged update and returns how many
// files (record included) it sent.
func uploadOtaUpdateToServerStore(client *http.Client, target otaStoreUploadTarget, storeRoot string, appSlug string, updateID string) (int, error) {
	if strings.TrimSpace(target.appID) == "" {
		return 0, &otaStoreUploadError{fmt.Errorf("the job carries no app id")}
	}
	updateDir := filepath.Join(storeRoot, "updates", appSlug, updateID)
	recordBytes, err := os.ReadFile(filepath.Join(updateDir, "record.json"))
	if err != nil {
		return 0, fmt.Errorf("read staged OTA record: %w", err)
	}
	var record otaStoreRecord
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return 0, fmt.Errorf("decode staged OTA record: %w", err)
	}
	if record.ID != updateID || record.AppSlug != appSlug || record.LaunchAsset.File == "" {
		return 0, fmt.Errorf("staged OTA record %s does not describe update %s of %s", filepath.Join(updateDir, "record.json"), updateID, appSlug)
	}

	files := []otaStoreRecordFile{record.LaunchAsset}
	files = append(files, record.Assets...)
	seen := map[string]bool{}
	uploaded := 0
	for _, file := range files {
		relative := filepath.ToSlash(file.File)
		if seen[relative] {
			continue
		}
		seen[relative] = true
		if !safeOtaRelativePath(relative) {
			return uploaded, fmt.Errorf("staged OTA record lists an unsafe path %q", file.File)
		}
		content, err := os.ReadFile(filepath.Join(updateDir, filepath.FromSlash(relative)))
		if err != nil {
			return uploaded, fmt.Errorf("read staged OTA asset %s: %w", relative, err)
		}
		contentType := firstNonEmpty(file.ContentType, "application/octet-stream")
		if err := putOtaStoreFile(client, target, updateID, relative, appSlug, contentType, content); err != nil {
			return uploaded, &otaStoreUploadError{fmt.Errorf("%s: %w", relative, err)}
		}
		uploaded++
	}
	if err := putOtaStoreFile(client, target, updateID, "record.json", appSlug, "application/json", recordBytes); err != nil {
		return uploaded, &otaStoreUploadError{fmt.Errorf("record.json: %w", err)}
	}
	return uploaded + 1, nil
}

func safeOtaRelativePath(relative string) bool {
	if relative == "" || relative == "record.json" || strings.HasPrefix(relative, "/") || strings.Contains(relative, "\\") {
		return false
	}
	return path.Clean(relative) == relative && !strings.HasPrefix(relative, "../") && relative != ".."
}

func putOtaStoreFile(client *http.Client, target otaStoreUploadTarget, updateID string, relative string, appSlug string, contentType string, content []byte) error {
	segments := strings.Split(relative, "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	endpoint := runnerEndpoint(target.apiURL, fmt.Sprintf(
		"/api/preflight/v1/apps/%s/ota/store/%s/%s?appSlug=%s",
		url.PathEscape(target.appID), url.PathEscape(updateID), strings.Join(segments, "/"), url.QueryEscape(appSlug),
	))
	request, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(content))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", contentType)
	addPreflightAuthHeaders(request, target.token, target.workspaceID)
	_, err = doPreflightJSON(client, request)
	return err
}

// publishOtaUpdate runs publish-local.mjs and, when the control plane serves
// updates from its own store, moves the result there. It returns the update id,
// the script output, and the job result fields describing where the update
// lives.
func publishOtaUpdate(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, appDir, exportDir, appSlug, channel, platform, runtimeVersion, message string, cancelled func() (bool, error)) (string, []byte, map[string]any, error) {
	kind := otaServerStoreKind(client, options.apiURL)
	if !otaServerStoreUploadsEnabled(kind) {
		storeRoot := otaStoreRoot()
		updateID, output, err := runOtaPublish(options, appDir, exportDir, appSlug, channel, platform, runtimeVersion, message, storeRoot, cancelled)
		return updateID, output, map[string]any{"store": "filesystem", "storeRoot": storeRoot}, err
	}

	staging, err := os.MkdirTemp("", "preflight-ota-staging-")
	if err != nil {
		return "", nil, nil, fmt.Errorf("create OTA staging store: %w", err)
	}
	defer os.RemoveAll(staging)
	updateID, output, err := runOtaPublish(options, appDir, exportDir, appSlug, channel, platform, runtimeVersion, message, staging, cancelled)
	if err != nil {
		return updateID, output, nil, err
	}
	if strings.TrimSpace(updateID) == "" {
		return "", output, nil, fmt.Errorf("publish-local.mjs did not report PREFLIGHT_OTA_UPDATE_ID")
	}
	uploaded, err := uploadOtaUpdateToServerStore(client, otaStoreUploadTarget{
		apiURL:      options.apiURL,
		token:       registration.Token,
		workspaceID: firstNonEmpty(job.WorkspaceID, options.workspaceID),
		appID:       job.AppID,
	}, staging, appSlug, updateID)
	if err != nil {
		return updateID, output, nil, err
	}
	return updateID, output, map[string]any{"store": kind, "uploadedFiles": uploaded}, nil
}

func isOtaStoreUploadError(err error) bool {
	var uploadErr *otaStoreUploadError
	return errors.As(err, &uploadErr)
}
