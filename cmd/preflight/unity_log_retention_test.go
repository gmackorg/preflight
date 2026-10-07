package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUnityLogUploadRetainsSnapshotBeforeSourceMutation(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "unity-build.log")
	original := []byte("build timeout\n")
	if err := os.WriteFile(logPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	var registeredURI string
	var uploaded []byte
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runner-token" {
			t.Error("runner auth missing")
		}
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			registeredURI, _ = payload["uri"].(string)
			if err := os.WriteFile(logPath, []byte("late teardown mutation\n"), 0600); err != nil {
				t.Fatal(err)
			}
			_, _ = fmt.Fprintf(w, `{"data":{"artifact":{"id":"artifact","kind":"unity_build_log","uri":%q}}}`, registeredURI)
			return
		}
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected %s", r.Method)
		}
		uploaded, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	registration := runnerRegistrationData{Runner: apiRunner{ID: "runner", Capabilities: map[string]any{"runnerArtifactUpload": true}}, Token: "runner-token"}
	err := uploadUnityBuildArtifacts(server.Client(), runnerOnceOptions{apiURL: server.URL}, registration, apiRunnerJob{ID: "job", Kind: "unity.build.player"}, unityBuildArtifacts{LogPath: logPath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uploaded, original) {
		t.Fatalf("retained bytes = %q; expected immutable original", uploaded)
	}
	if registeredURI == logPath {
		t.Fatal("mutable Unity log was registered")
	}
	retained, err := os.ReadFile(registeredURI)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, uploaded) {
		t.Fatal("local snapshot differs from uploaded bytes")
	}
}

func TestUnityLogUploadFailurePreservesImmutableLocalSnapshot(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "unity-build.log")
	if err := os.WriteFile(logPath, []byte("timeout\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var uri string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			uri, _ = body["uri"].(string)
			_, _ = fmt.Fprintf(w, `{"data":{"artifact":{"id":"artifact","uri":%q}}}`, uri)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	registration := runnerRegistrationData{Runner: apiRunner{ID: "runner", Capabilities: map[string]any{"runnerArtifactUpload": true}}, Token: "runner-token"}
	err := uploadUnityBuildArtifacts(server.Client(), runnerOnceOptions{apiURL: server.URL}, registration, apiRunnerJob{ID: "job"}, unityBuildArtifacts{LogPath: logPath})
	if err == nil {
		t.Fatal("byte upload failure was silently treated as retained")
	}
	if uri == logPath {
		t.Fatal("mutable log remained the artifact reference")
	}
	if _, statErr := os.Stat(uri); statErr != nil {
		t.Fatal("local snapshot lost after upload failure", statErr)
	}
}

func TestUnityLogSnapshotRedactsDirectEditorFileAndPreservesOriginal(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "unity-build.log")
	raw := []byte("Authorization: Bearer confidential-value\nhttps://example.test/?access_token=secret-value\nMachine Id: machine-private-value\n")
	if err := os.WriteFile(logPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, digest, err := retainUnityLogSnapshot(logPath)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(retained, []byte("confidential-value")) || bytes.Contains(retained, []byte("secret-value")) || bytes.Contains(retained, []byte("machine-private-value")) {
		t.Fatal("direct editor file secrets escaped snapshot redaction")
	}
	original, _ := os.ReadFile(logPath)
	if !bytes.Equal(original, raw) {
		t.Fatal("original diagnostic log was changed")
	}
	if digest != fmt.Sprintf("sha256:%x", sha256.Sum256(retained)) {
		t.Fatal("snapshot digest does not hash retained bytes")
	}
	again, _, err := retainUnityLogSnapshot(logPath)
	if err != nil || again != path {
		t.Fatal("identical content did not reuse immutable snapshot", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm()&0222 != 0 {
		t.Fatal("snapshot remained writable")
	}
}

func TestUnityLogSnapshotRejectsSymlinkSource(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.log")
	if err := os.WriteFile(target, []byte("private log"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "unity-build.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := retainUnityLogSnapshot(link); err == nil {
		t.Fatal("symlink log was retained")
	}
}
