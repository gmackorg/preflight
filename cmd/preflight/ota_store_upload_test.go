package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type otaStorePut struct {
	Path        string
	AppSlug     string
	ContentType string
	Auth        string
	Workspace   string
	Body        string
}

// fakeOtaControlPlane serves /ota/health with the given store kind and records
// every PUT to the app's ota/store route. putStatus != 200 fails every PUT.
func fakeOtaControlPlane(t *testing.T, kind string, putStatus int) (*httptest.Server, func() []otaStorePut) {
	t.Helper()
	var mu sync.Mutex
	var puts []otaStorePut
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/ota/health":
			if kind == "" {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"ok":false,"error":"store unavailable"}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"ok":true,"kind":%q}`, kind)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/preflight/v1/apps/pfapp_ota/ota/store/"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			puts = append(puts, otaStorePut{
				Path:        strings.TrimPrefix(r.URL.EscapedPath(), "/api/preflight/v1/apps/pfapp_ota/ota/store/"),
				AppSlug:     r.URL.Query().Get("appSlug"),
				ContentType: r.Header.Get("Content-Type"),
				Auth:        r.Header.Get("Authorization"),
				Workspace:   r.Header.Get("x-preflight-workspace-id"),
				Body:        string(body),
			})
			mu.Unlock()
			if putStatus != http.StatusOK {
				w.WriteHeader(putStatus)
				_, _ = w.Write([]byte(`{"error":{"code":"validation_error","message":"Upload these files before the record"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"stored":"ok","store":"r2"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, func() []otaStorePut {
		mu.Lock()
		defer mu.Unlock()
		return append([]otaStorePut{}, puts...)
	}
}

// writeStagedOtaUpdate lays out an update the way publish-local.mjs does.
func writeStagedOtaUpdate(t *testing.T, storeRoot string, slug string, id string, launch string) {
	t.Helper()
	dir := filepath.Join(storeRoot, "updates", slug, id)
	files := map[string]string{
		launch:                        "bundle-bytes",
		"export/assets/4f1c2a":        "png-bytes",
		"export/assets/fonts/Inter 1": "font-bytes",
	}
	for name, content := range files {
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	record := fmt.Sprintf(`{"id":%q,"appSlug":%q,"channel":"preview","platform":"ios","runtimeVersion":"1.0.0","createdAt":"2026-11-21T00:00:00Z","launchAsset":{"key":"bundle","contentType":"application/javascript","file":%q},"assets":[{"key":"4f1c2a","contentType":"image/png","file":"export/assets/4f1c2a"},{"key":"inter","contentType":"font/ttf","file":"export/assets/fonts/Inter 1"},{"key":"4f1c2a-dup","contentType":"image/png","file":"export/assets/4f1c2a"}]}`, id, slug, launch)
	if err := os.WriteFile(filepath.Join(dir, "record.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOtaServerStoreKindProbesHealthAndHonoursOverride(t *testing.T) {
	t.Setenv("PREFLIGHT_OTA_SERVER_STORE", "")
	r2, _ := fakeOtaControlPlane(t, "r2", http.StatusOK)
	if kind := otaServerStoreKind(r2.Client(), r2.URL); kind != "r2" || !otaServerStoreUploadsEnabled(kind) {
		t.Fatalf("r2 health: %q", kind)
	}
	fs, _ := fakeOtaControlPlane(t, "filesystem", http.StatusOK)
	if kind := otaServerStoreKind(fs.Client(), fs.URL); kind != "filesystem" || otaServerStoreUploadsEnabled(kind) {
		t.Fatalf("filesystem health: %q", kind)
	}
	down, _ := fakeOtaControlPlane(t, "", http.StatusOK)
	if kind := otaServerStoreKind(down.Client(), down.URL); kind != "" || otaServerStoreUploadsEnabled(kind) {
		t.Fatalf("unavailable store must keep the local path, got %q", kind)
	}
	t.Setenv("PREFLIGHT_OTA_SERVER_STORE", "off")
	if kind := otaServerStoreKind(r2.Client(), r2.URL); otaServerStoreUploadsEnabled(kind) {
		t.Fatalf("override off still uploads: %q", kind)
	}
	t.Setenv("PREFLIGHT_OTA_SERVER_STORE", "r2")
	if kind := otaServerStoreKind(down.Client(), ""); !otaServerStoreUploadsEnabled(kind) {
		t.Fatalf("override r2 must upload without probing: %q", kind)
	}
}

func TestUploadOtaUpdateSendsEveryAssetThenRecord(t *testing.T) {
	server, puts := fakeOtaControlPlane(t, "r2", http.StatusOK)
	storeRoot := t.TempDir()
	launch := "export/_expo/static/js/ios/entry-abc.hbc"
	writeStagedOtaUpdate(t, storeRoot, "fixture", "upd_1", launch)

	count, err := uploadOtaUpdateToServerStore(server.Client(), otaStoreUploadTarget{apiURL: server.URL, token: "runner_token", workspaceID: "ws_ota", appID: "pfapp_ota"}, storeRoot, "fixture", "upd_1")
	if err != nil {
		t.Fatal(err)
	}
	got := puts()
	if count != 4 || len(got) != 4 {
		t.Fatalf("expected 3 unique assets + record, got count=%d puts=%+v", count, got)
	}
	if got[0].Path != "upd_1/export/_expo/static/js/ios/entry-abc.hbc" || got[0].Body != "bundle-bytes" || got[0].ContentType != "application/javascript" {
		t.Fatalf("launch asset upload %+v", got[0])
	}
	decoded, _ := url.PathUnescape(got[2].Path)
	if decoded != "upd_1/export/assets/fonts/Inter 1" || got[2].Body != "font-bytes" || got[2].ContentType != "font/ttf" {
		t.Fatalf("escaped asset upload %+v", got[2])
	}
	last := got[len(got)-1]
	if last.Path != "upd_1/record.json" || last.ContentType != "application/json" || !strings.Contains(last.Body, `"id":"upd_1"`) {
		t.Fatalf("record must be uploaded last: %+v", last)
	}
	for _, put := range got {
		if put.AppSlug != "fixture" || put.Auth != "Bearer runner_token" || put.Workspace != "ws_ota" {
			t.Fatalf("upload missing slug/auth: %+v", put)
		}
	}
}

func TestUploadOtaUpdateRejectsUnsafePathsAndReportsStoreFailures(t *testing.T) {
	server, puts := fakeOtaControlPlane(t, "r2", http.StatusOK)
	storeRoot := t.TempDir()
	writeStagedOtaUpdate(t, storeRoot, "fixture", "upd_bad", "../../outside.js")
	target := otaStoreUploadTarget{apiURL: server.URL, token: "runner_token", appID: "pfapp_ota"}
	if _, err := uploadOtaUpdateToServerStore(server.Client(), target, storeRoot, "fixture", "upd_bad"); err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("expected unsafe path refusal, got %v", err)
	}
	if len(puts()) != 0 {
		t.Fatalf("nothing may be uploaded from an unsafe record: %+v", puts())
	}

	refusing, _ := fakeOtaControlPlane(t, "r2", http.StatusBadRequest)
	writeStagedOtaUpdate(t, storeRoot, "fixture", "upd_2", "export/bundle.hbc")
	_, err := uploadOtaUpdateToServerStore(refusing.Client(), otaStoreUploadTarget{apiURL: refusing.URL, appID: "pfapp_ota"}, storeRoot, "fixture", "upd_2")
	if err == nil || otaFailureCode(err) != "ota_store_unavailable" {
		t.Fatalf("store refusal must map to ota_store_unavailable, got %v (%s)", err, otaFailureCode(err))
	}
}

// fakePublishLocal stands in for `node publish-local.mjs`: it writes an update
// into $PREFLIGHT_OTA_STORE and prints its id the way the script does.
func fakePublishLocal(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
dir="$PREFLIGHT_OTA_STORE/updates/fixture/upd_local"
mkdir -p "$dir/export"
printf 'bundle' > "$dir/export/bundle.hbc"
printf '{"id":"upd_local","appSlug":"fixture","channel":"preview","platform":"ios","runtimeVersion":"1.0.0","createdAt":"2026-11-21T00:00:00Z","launchAsset":{"key":"bundle","contentType":"application/javascript","file":"export/bundle.hbc"},"assets":[]}' > "$dir/record.json"
echo "PREFLIGHT_OTA_UPDATE_ID=upd_local"
`
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	publishScript := filepath.Join(t.TempDir(), "publish-local.mjs")
	if err := os.WriteFile(publishScript, []byte("// fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_OTA_PUBLISH_SCRIPT", publishScript)
}

func TestPublishOtaUpdateUploadsToServerStoreAndDropsStaging(t *testing.T) {
	fakePublishLocal(t)
	t.Setenv("PREFLIGHT_OTA_SERVER_STORE", "")
	localStore := t.TempDir()
	t.Setenv("PREFLIGHT_OTA_STORE", localStore)
	server, puts := fakeOtaControlPlane(t, "r2", http.StatusOK)
	exportDir := t.TempDir()
	job := apiRunnerJob{ID: "pfjob_ota", AppID: "pfapp_ota", WorkspaceID: "ws_ota", Kind: "ota.publish"}

	updateID, _, fields, err := publishOtaUpdate(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Token: "runner_token"}, job, t.TempDir(), exportDir, "fixture", "preview", "ios", "1.0.0", "msg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if updateID != "upd_local" || fields["store"] != "r2" || fields["uploadedFiles"] != 2 {
		t.Fatalf("unexpected publish result %q %#v", updateID, fields)
	}
	if _, has := fields["storeRoot"]; has {
		t.Fatalf("server-stored update must not report a runner storeRoot: %#v", fields)
	}
	if got := puts(); len(got) != 2 || got[1].Path != "upd_local/record.json" {
		t.Fatalf("uploads %+v", got)
	}
	if _, err := os.Stat(filepath.Join(localStore, "updates")); !os.IsNotExist(err) {
		t.Fatalf("server publish wrote into the runner's filesystem store: %v", err)
	}
}

func TestPublishOtaUpdateKeepsFilesystemStoreWithoutServerStore(t *testing.T) {
	fakePublishLocal(t)
	t.Setenv("PREFLIGHT_OTA_SERVER_STORE", "")
	localStore := t.TempDir()
	t.Setenv("PREFLIGHT_OTA_STORE", localStore)
	server, puts := fakeOtaControlPlane(t, "filesystem", http.StatusOK)
	job := apiRunnerJob{ID: "pfjob_ota", AppID: "pfapp_ota", Kind: "ota.publish"}

	updateID, _, fields, err := publishOtaUpdate(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Token: "runner_token"}, job, t.TempDir(), t.TempDir(), "fixture", "preview", "ios", "1.0.0", "msg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if updateID != "upd_local" || fields["store"] != "filesystem" || fields["storeRoot"] != localStore {
		t.Fatalf("unexpected publish result %q %#v", updateID, fields)
	}
	if len(puts()) != 0 {
		t.Fatalf("filesystem store must not upload: %+v", puts())
	}
	if _, err := os.Stat(filepath.Join(localStore, "updates", "fixture", "upd_local", "record.json")); err != nil {
		t.Fatalf("update missing from the filesystem store: %v", err)
	}
}
