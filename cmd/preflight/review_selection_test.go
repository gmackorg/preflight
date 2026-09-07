package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewExactSelection(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "test")
	var writes []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			writes = append(writes, body)
			_, _ = w.Write([]byte(`{"data":{"submission":{"id":"sub","version":"2.0","status":"waiting_for_review"},"review":{}}}`))
			return
		}
		if r.URL.Path == "/api/preflight/v1/apps/app-1/testflight/builds" {
			_, _ = w.Write([]byte(`{"data":{"builds":[{"id":"asc-42","version":"2.0","buildNumber":"42","processingState":"VALID"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"apps":[{"appId":"app-1","slug":"checkout","name":"Checkout","submittable":true}],"platform":"ios"}}`))
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	base := []string{"--api-url", server.URL, "checkout"}
	if code := runAppsSubmitForReview(base, &out, &errs, server.Client()); code != 2 || len(writes) != 0 {
		t.Fatalf("missing selection code=%d writes=%d", code, len(writes))
	}
	if code := runAppsSubmitForReview(append(base, "--list-builds"), &out, &errs, server.Client()); code != 0 || len(writes) != 0 {
		t.Fatalf("list code=%d err=%s", code, errs.String())
	}
	args := append(base, "--asc-build-id", "asc-42", "--version", "2.0", "--build-number", "42")
	if code := runAppsSubmitForReview(args, &out, &errs, server.Client()); code != 0 {
		t.Fatalf("code=%d err=%s", code, errs.String())
	}
	if len(writes) != 1 || writes[0]["ascBuildId"] != "asc-42" || writes[0]["version"] != "2.0" || writes[0]["buildNumber"] != "42" || writes[0]["autoRelease"] != false {
		t.Fatalf("wrong payload: %#v", writes)
	}
}
func TestFleetReviewRequiresAllSelectionsBeforeWrite(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "test")
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			writes++
		}
		_, _ = w.Write([]byte(`{"data":{"apps":[{"appId":"app-1","submittable":true},{"appId":"app-2","submittable":true}]}}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "selections.json")
	_ = os.WriteFile(path, []byte(`{"app-1":{"ascBuildId":"asc-1","version":"1.0","buildNumber":"1"}}`), 0600)
	var out, errs bytes.Buffer
	code := runAppsSubmitForReview([]string{"--api-url", server.URL, "--all", "--fire", "--selections-file", path}, &out, &errs, server.Client())
	if code != 2 || writes != 0 {
		t.Fatalf("code=%d writes=%d err=%s", code, writes, errs.String())
	}
}
