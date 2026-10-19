package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func oversizedRecording(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flow.mp4")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(runnerMediaMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrepareVideoUploadPreservesOriginalAndBoundsDerivative(t *testing.T) {
	original := oversizedRecording(t)
	calls := 0
	upload, err := prepareVideoUpload(original, func(name string, args ...string) error {
		calls++
		if name != "ffmpeg" {
			t.Fatalf("unexpected encoder %s", name)
		}
		output := args[len(args)-1]
		if output == original {
			t.Fatal("encoder would overwrite original")
		}
		return os.WriteFile(output, []byte("encoded video"), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || upload == original {
		t.Fatalf("unexpected derivative %s, calls %d", upload, calls)
	}
	info, _ := os.Stat(original)
	if info.Size() != runnerMediaMaxBytes+1 {
		t.Fatal("original changed")
	}
	encoded, _ := os.ReadFile(upload)
	if string(encoded) != "encoded video" {
		t.Fatalf("unexpected bytes %q", encoded)
	}
}

func TestPrepareVideoUploadRejectsUnboundedOrFailedEncode(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "oversized", true: "encoder unavailable"}[broken], func(t *testing.T) {
			original := oversizedRecording(t)
			calls := 0
			_, err := prepareVideoUpload(original, func(_ string, args ...string) error {
				calls++
				if broken {
					return errors.New("ffmpeg unavailable")
				}
				file, err := os.OpenFile(args[len(args)-1], os.O_WRONLY, 0600)
				if err != nil {
					return err
				}
				defer file.Close()
				return file.Truncate(runnerMediaMaxBytes + 1)
			})
			if err == nil {
				t.Fatal("unusable media accepted")
			}
			if !broken && calls != 3 {
				t.Fatalf("unbounded retry count %d", calls)
			}
			info, _ := os.Stat(original)
			if info.Size() != runnerMediaMaxBytes+1 {
				t.Fatal("original changed")
			}
		})
	}
}

func TestMaestroArtifactPublicationPropagatesBlobFailureAndContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "screen.png")
	if err := os.WriteFile(path, []byte("png"), 0600); err != nil {
		t.Fatal(err)
	}
	puts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts++
			http.Error(w, "storage unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"artifact":{"id":"pfart_test"}}}`)
	}))
	defer server.Close()
	err := uploadMaestroRunArtifacts(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner", Capabilities: map[string]any{"runnerArtifactUpload": true}}}, apiRunnerJob{ID: "job"}, "sim", "flow", maestroRunArtifacts{ScreenshotPaths: []string{path, path}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("lost upload failure: %v", err)
	}
	if puts != 6 {
		t.Fatalf("did not publish independent remaining artifacts: %d", puts)
	}
}

func TestMaestroUnchangedVideoRetainsOriginalPathAfterBlobUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow.mp4")
	if err := os.WriteFile(path, []byte("small recording"), 0600); err != nil {
		t.Fatal(err)
	}
	registered := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			io.WriteString(w, `{"ok":true,"uri":"/api/preflight/v1/artifacts/pfart_video/blob"}`)
			return
		}
		var payload struct {
			URI      string `json:"uri"`
			Metadata struct {
				OriginalPath string `json:"originalPath"`
			} `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.URI != path || payload.Metadata.OriginalPath != path {
			t.Errorf("completion cannot resolve video after blob URI rewrite: %+v", payload)
		}
		registered = true
		io.WriteString(w, `{"data":{"artifact":{"id":"pfart_video"}}}`)
	}))
	defer server.Close()
	err := uploadMaestroRunArtifacts(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner", Capabilities: map[string]any{"runnerArtifactUpload": true}}}, apiRunnerJob{ID: "job"}, "sim", "flow", maestroRunArtifacts{VideoPaths: []string{path}}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !registered {
		t.Fatal("video not registered")
	}
}

func TestPassedMaestroWithUnpublishedEvidenceRemainsBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "screen.png")
	if err := os.WriteFile(path, []byte("png"), 0600); err != nil {
		t.Fatal(err)
	}
	completed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			http.Error(w, "storage unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/complete") {
			var payload struct {
				Result struct {
					Status  string `json:"status"`
					Maestro struct {
						ExecutionStatus string `json:"executionStatus"`
						EvidenceStatus  string `json:"evidenceStatus"`
					} `json:"maestro"`
					Failure struct {
						Code string `json:"code"`
					} `json:"failure"`
				} `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload.Result.Status != "failed" || payload.Result.Maestro.ExecutionStatus != "passed" || payload.Result.Maestro.EvidenceStatus != "blocked" || payload.Result.Failure.Code != "maestro_evidence_upload_failed" {
				t.Errorf("lost execution/evidence distinction: %+v", payload)
			}
			completed = true
			io.WriteString(w, `{"data":{"job":{"id":"job","status":"failed"}}}`)
			return
		}
		io.WriteString(w, `{"data":{"artifact":{"id":"pfart_test"}}}`)
	}))
	defer server.Close()
	var output strings.Builder
	err := completePassedMaestroRun(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner", Capabilities: map[string]any{"runnerArtifactUpload": true}}}, apiRunnerJob{ID: "job"}, "sim", "flow", maestroRunArtifacts{ScreenshotPaths: []string{path}}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if !completed || !strings.Contains(output.String(), "evidence publication blocked") || strings.Contains(output.String(), "completed Maestro smoke") {
		t.Fatalf("misleading completion: %s", output.String())
	}
}

// Opt-in integration check for a real retained runner recording. It exercises
// the production encoder instead of manufacturing a tiny substitute.
func TestPrepareRealRetainedRecording(t *testing.T) {
	original := os.Getenv("PREFLIGHT_TEST_RECORDING")
	if original == "" {
		t.Skip("set PREFLIGHT_TEST_RECORDING for the real-media integration check")
	}
	before, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := prepareVideoUpload(original, runMediaCommand)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("retained original changed")
	}
	encoded, err := os.Stat(upload)
	if err != nil {
		t.Fatal(err)
	}
	if encoded.Size() > runnerMediaMaxBytes || encoded.Size() == 0 {
		t.Fatal("invalid encoded size")
	}
	if err := runMediaCommand("ffmpeg", "-v", "error", "-i", upload, "-f", "null", "-"); err != nil {
		t.Fatal(err)
	}
	t.Logf("original=%d bytes upload=%d bytes path=%s", before.Size(), encoded.Size(), upload)
}

func TestMediaPublicationRetriesTransferWithoutRerunningSmoke(t *testing.T) {
	calls := 0
	err := retryMediaPublication(func() error {
		calls++
		if calls < 3 {
			return errors.New("temporary storage failure")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("retry failed: calls=%d err=%v", calls, err)
	}
}

func TestMissingUploadCapabilityCannotPublishMedia(t *testing.T) {
	err := uploadMaestroRunArtifacts(nil, runnerOnceOptions{}, runnerRegistrationData{}, apiRunnerJob{}, "sim", "flow", maestroRunArtifacts{VideoPaths: []string{"retained.mp4"}}, io.Discard)
	if err == nil {
		t.Fatal("unpublished media reported as published")
	}
}
