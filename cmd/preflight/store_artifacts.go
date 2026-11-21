package main

// Chunked store-artifact transfer (PREFLT-66).
//
//   POST {job}/artifacts/store/uploads {fileName, kind, sizeBytes} -> {uploadId, key, partSizeBytes}
//   PUT  {job}/artifacts/store/uploads/{uploadId}/parts/{n} (raw bytes) -> {partNumber, etag}
//   POST {job}/artifacts/store/uploads/{uploadId}/complete {parts, sha256, sizeBytes, fileName, kind} -> StoreBuildArtifact
//   GET  {job}/artifacts/store?key=... -> object bytes
//
// JSON responses use the standard {data: ...} envelope; a bare object is
// accepted too so a route that skips the envelope still works.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultStorePartSizeBytes int64 = 16 * 1024 * 1024
	// S3/R2 multipart minimum (except for the last part).
	minStorePartSizeBytes int64 = 5 * 1024 * 1024
	storePartAttempts           = 3
)

type storeArtifactClient struct {
	client   *http.Client
	baseURL  string
	runnerID string
	jobID    string
	token    string
}

func (c *storeArtifactClient) endpoint(suffix string) string {
	return fmt.Sprintf("%s/api/preflight/v1/runners/%s/jobs/%s/artifacts/store%s", c.baseURL, c.runnerID, c.jobID, suffix)
}

func fileSHA256(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func decodeStoreJSON(body []byte, output any) error {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && len(bytes.TrimSpace(envelope.Data)) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return json.Unmarshal(envelope.Data, output)
	}
	return json.Unmarshal(body, output)
}

func (c *storeArtifactClient) postJSON(endpoint string, payload any, output any) error {
	data, err := postPreflightJSON(c.client, endpoint, c.token, payload)
	if err != nil {
		return err
	}
	return decodeStoreJSON(data, output)
}

// upload streams path to artifact storage in parts and returns the stored
// artifact. sha256 and size are computed locally and sent on completion so the
// server can verify them.
func (c *storeArtifactClient) upload(path string, kind string) (storeBuildArtifact, error) {
	sum, size, err := fileSHA256(path)
	if err != nil {
		return storeBuildArtifact{}, fmt.Errorf("hash artifact: %w", err)
	}
	fileName := filepath.Base(path)
	var started struct {
		UploadID      string `json:"uploadId"`
		Key           string `json:"key"`
		PartSizeBytes int64  `json:"partSizeBytes"`
	}
	if err := c.postJSON(c.endpoint("/uploads"), map[string]any{
		"fileName":  fileName,
		"kind":      kind,
		"sizeBytes": size,
	}, &started); err != nil {
		return storeBuildArtifact{}, fmt.Errorf("start artifact upload: %w", err)
	}
	if started.UploadID == "" {
		return storeBuildArtifact{}, fmt.Errorf("start artifact upload: response had no uploadId")
	}
	partSize := started.PartSizeBytes
	if partSize <= 0 {
		partSize = defaultStorePartSizeBytes
	}
	if partSize < minStorePartSizeBytes && size > partSize {
		partSize = minStorePartSizeBytes
	}

	file, err := os.Open(path)
	if err != nil {
		return storeBuildArtifact{}, err
	}
	defer file.Close()
	type part struct {
		PartNumber int    `json:"partNumber"`
		ETag       string `json:"etag"`
	}
	parts := []part{}
	buffer := make([]byte, partSize)
	for partNumber := 1; ; partNumber++ {
		n, readErr := io.ReadFull(file, buffer)
		if n == 0 && partNumber > 1 {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return storeBuildArtifact{}, readErr
		}
		etag, err := c.putPart(started.UploadID, partNumber, buffer[:n])
		if err != nil {
			return storeBuildArtifact{}, err
		}
		parts = append(parts, part{PartNumber: partNumber, ETag: etag})
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			break
		}
	}

	var artifact storeBuildArtifact
	if err := c.postJSON(c.endpoint("/uploads/"+url.PathEscape(started.UploadID)+"/complete"), map[string]any{
		"parts":     parts,
		"sha256":    sum,
		"sizeBytes": size,
		"fileName":  fileName,
		"kind":      kind,
	}, &artifact); err != nil {
		return storeBuildArtifact{}, fmt.Errorf("complete artifact upload: %w", err)
	}
	if artifact.SHA256 != "" && !strings.EqualFold(artifact.SHA256, sum) {
		return storeBuildArtifact{}, fmt.Errorf("artifact storage recorded sha256 %s, local file is %s", artifact.SHA256, sum)
	}
	if artifact.Kind == "" {
		artifact.Kind = kind
	}
	if artifact.FileName == "" {
		artifact.FileName = fileName
	}
	if artifact.SHA256 == "" {
		artifact.SHA256 = sum
	}
	if artifact.SizeBytes == 0 {
		artifact.SizeBytes = size
	}
	if artifact.StorageKey == "" {
		artifact.StorageKey = started.Key
	}
	return artifact, nil
}

// putPart uploads one part, retrying transport errors and 5xx. PUT of the
// same part number is idempotent.
func (c *storeArtifactClient) putPart(uploadID string, partNumber int, data []byte) (string, error) {
	endpoint := c.endpoint(fmt.Sprintf("/uploads/%s/parts/%d", url.PathEscape(uploadID), partNumber))
	var lastErr error
	for attempt := 1; attempt <= storePartAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(preflightRequestRetryBackoff(attempt))
		}
		etag, status, err := c.putPartOnce(endpoint, partNumber, data)
		if err == nil {
			return etag, nil
		}
		lastErr = err
		if status != 0 && status < 500 {
			break
		}
	}
	return "", fmt.Errorf("upload artifact part %d: %w", partNumber, lastErr)
}

func (c *storeArtifactClient) putPartOnce(endpoint string, partNumber int, data []byte) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), durationFromEnv("PREFLIGHT_STORE_PART_TIMEOUT", 10*time.Minute))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", 0, err
	}
	request.ContentLength = int64(len(data))
	request.Header.Set("Content-Type", "application/octet-stream")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return "", 0, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", response.StatusCode, fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var uploaded struct {
		PartNumber int    `json:"partNumber"`
		ETag       string `json:"etag"`
	}
	if err := decodeStoreJSON(body, &uploaded); err != nil {
		return "", response.StatusCode, fmt.Errorf("decode part response: %w", err)
	}
	if uploaded.ETag == "" {
		return "", response.StatusCode, fmt.Errorf("part response had no etag")
	}
	return uploaded.ETag, response.StatusCode, nil
}

// download fetches a stored artifact into destination and verifies sha256.
func (c *storeArtifactClient) download(artifact storeBuildArtifact, destination string) error {
	if strings.TrimSpace(artifact.StorageKey) == "" {
		return fmt.Errorf("artifact has no storageKey")
	}
	ctx, cancel := context.WithTimeout(context.Background(), durationFromEnv("PREFLIGHT_STORE_DOWNLOAD_TIMEOUT", 30*time.Minute))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("?key="+url.QueryEscape(artifact.StorageKey)), nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("download artifact: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temp := destination + ".partial"
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, hash), response.Body)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(temp)
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	if sum := hex.EncodeToString(hash.Sum(nil)); !strings.EqualFold(sum, artifact.SHA256) {
		_ = os.Remove(temp)
		return fmt.Errorf("downloaded artifact sha256 %s does not match %s", sum, artifact.SHA256)
	}
	return os.Rename(temp, destination)
}

// resolveStoreArtifactFile reuses a local build output with the same sha256
// (a store.build on this runner) or downloads the artifact into the job's
// work directory. The download is removed by the job cleanup.
func resolveStoreArtifactFile(runtime *storeJobRuntime, artifact storeBuildArtifact, workspaceRoot string) (string, error) {
	fileName := filepath.Base(strings.TrimSpace(artifact.FileName))
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = "artifact." + artifact.Kind
	}
	if local := findLocalStoreArtifact(workspaceRoot, fileName, artifact.SHA256); local != "" {
		_, _ = fmt.Fprintf(runtime.log, "reusing local artifact %s (sha256 match)\n", local)
		return local, nil
	}
	destination := filepath.Join(runtime.workDir, "download", fileName)
	if err := runtime.uploads.download(artifact, destination); err != nil {
		if jobLeaseLost(err) {
			return "", err
		}
		return "", storeFailuref("store_artifact_download_failed", "%v", err)
	}
	runtime.cleanup.removeAll(filepath.Dir(destination))
	return destination, nil
}

func findLocalStoreArtifact(workspaceRoot string, fileName string, sha string) string {
	if strings.TrimSpace(workspaceRoot) == "" || sha == "" {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(workspaceRoot, ".preflight", "store-builds", "*", "output", fileName))
	for _, candidate := range matches {
		if sum, _, err := fileSHA256(candidate); err == nil && strings.EqualFold(sum, sha) {
			return candidate
		}
	}
	return ""
}
