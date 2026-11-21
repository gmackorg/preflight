package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testP8 = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgP8secretP8secretAA\n-----END PRIVATE KEY-----"

func iosUploadJob() apiRunnerJob {
	return apiRunnerJob{
		ID:   "pfjob_store",
		Kind: "store.upload",
		Payload: runnerJobPayload{
			Platform: "ios", BuildID: "build_1", Destination: "testflight",
			ASCAppID: "6400000001", BundleID: "com.example.storeapp", Version: "1.4.0", BuildNumber: "42",
			SecretReferences: []runnerJobSecretReference{{ID: "ref_asc", Provider: "app_store_connect", Purpose: "asc_api_key", Key: "ASC_API_KEY_JSON"}},
		},
	}
}

func TestRunIOSStoreUploadUsesPrivateKeysDirAndCleansUp(t *testing.T) {
	var keyFile string
	runner := &fakeStoreRunner{}
	runner.handle = func(command storeCommand) ([]byte, error) {
		if command.Name != "xcrun" || command.Args[0] != "altool" {
			t.Fatalf("unexpected command %s", command.String())
		}
		dir := ""
		for _, entry := range command.Env {
			if value, ok := strings.CutPrefix(entry, "API_PRIVATE_KEYS_DIR="); ok {
				dir = value
			}
		}
		keyFile = filepath.Join(dir, "AuthKey_ABC123XYZ.p8")
		info, err := os.Stat(keyFile)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("p8 missing or not 0600: %v", err)
		}
		raw, _ := os.ReadFile(keyFile)
		if !strings.Contains(string(raw), "P8secretP8secret") {
			t.Fatal("p8 contents wrong")
		}
		for flag, want := range map[string]string{"--apiKey": "ABC123XYZ", "--apiIssuer": "issuer-uuid", "--apple-id": "6400000001", "--bundle-id": "com.example.storeapp", "--bundle-version": "42", "--bundle-short-version-string": "1.4.0", "--type": "ios", "--output-format": "json"} {
			if got := argAfter(command.Args, flag); got != want {
				t.Errorf("%s = %q, want %q", flag, got, want)
			}
		}
		return []byte(`{"tool-version":"8.0","success-message":"No errors uploading archive.","details":{"delivery-uuid":"d-123","transferred":"10 MB"}}`), nil
	}
	runtime, _ := newTestStoreRuntime(t, runner, map[string]string{
		"ref_asc": mustJSON(t, map[string]string{"keyId": "ABC123XYZ", "issuerId": "issuer-uuid", "privateKeyP8": testP8}),
	})
	ipa := filepath.Join(t.TempDir(), "StoreApp.ipa")
	mustWrite(t, ipa, "ipa")
	result, err := runIOSStoreUpload(runtime, iosUploadJob(), storeBuildArtifact{Kind: "ipa", FileName: "StoreApp.ipa", SHA256: "x"}, ipa)
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "ok" || result["ascDeliveryUuid"] != "d-123" || result["ascProcessingState"] != "UPLOADED" {
		t.Fatalf("result = %v", result)
	}
	if got := redactSetupTranscriptText("MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgP8secretP8secretAA"); strings.Contains(got, "P8secret") {
		t.Fatal("p8 not redacted while the job runs")
	}
	runtime.cleanup.Run()
	if filePresent(keyFile) || filePresent(filepath.Dir(filepath.Dir(keyFile))) {
		t.Fatal("p8 left on disk after the upload")
	}
}

func TestClassifyAltoolFailure(t *testing.T) {
	cases := map[string]string{
		`{"product-errors":[{"code":-19235,"message":"The network connection was lost."}]}`:                                        "asc_upload_transient",
		`{"product-errors":[{"code":-19232,"message":"The bundle version must be higher than the previously uploaded version."}]}`: "asc_upload_rejected",
		`{"product-errors":[{"code":-19209,"message":"Unable to authenticate. NOT_AUTHORIZED"}]}`:                                  "asc_auth_failed",
		`*** Error: Internal Server Error`:                         "asc_upload_transient",
		`{"product-errors":[{"code":-1,"message":"Invalid IPA"}]}`: "asc_upload_failed",
	}
	for output, want := range cases {
		if got := classifyAltoolFailure(output, errors.New("exit status 1")).code; got != want {
			t.Errorf("%s -> %s, want %s", output, got, want)
		}
	}
	if got := classifyAltoolFailure("", fmt.Errorf("xcrun: %w after 1h", errCommandTimedOut)).code; got != "asc_upload_transient" {
		t.Errorf("timeout -> %s", got)
	}
}

func TestRunIOSStoreUploadReportsTransientFailure(t *testing.T) {
	runner := &fakeStoreRunner{handle: func(storeCommand) ([]byte, error) {
		return []byte(`{"product-errors":[{"code":-1009,"message":"The Internet connection appears to be offline."}]}`), errors.New("exit status 1")
	}}
	runtime, _ := newTestStoreRuntime(t, runner, map[string]string{
		"ref_asc": mustJSON(t, map[string]string{"keyId": "ABC123XYZ", "issuerId": "issuer-uuid", "privateKeyP8": testP8}),
	})
	_, err := runIOSStoreUpload(runtime, iosUploadJob(), storeBuildArtifact{}, "/tmp/x.ipa")
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "asc_upload_transient" {
		t.Fatalf("err = %v", err)
	}
	runtime.cleanup.Run()
}

// fakePlay is a Google OAuth token endpoint plus the androidpublisher edits
// API, enough to drive one edit.
type fakePlay struct {
	t          *testing.T
	server     *httptest.Server
	key        *rsa.PrivateKey
	mu         sync.Mutex
	requests   []string
	draftApp   bool
	failUpload int
	trackBody  []map[string]any
	uploaded   []byte
	deleted    bool
	committed  bool
}

func newFakePlay(t *testing.T) *fakePlay {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	play := &fakePlay{t: t, key: key}
	play.server = httptest.NewServer(http.HandlerFunc(play.serve))
	t.Cleanup(play.server.Close)
	return play
}

func (play *fakePlay) serviceAccountJSON() string {
	der, _ := x509.MarshalPKCS8PrivateKey(play.key)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	raw, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "publisher@example.iam.gserviceaccount.com",
		"private_key": pemText, "private_key_id": "kid1", "token_uri": play.server.URL + "/token",
	})
	return string(raw)
}

func (play *fakePlay) serve(w http.ResponseWriter, r *http.Request) {
	play.mu.Lock()
	defer play.mu.Unlock()
	play.requests = append(play.requests, r.Method+" "+r.URL.Path)
	const app = "/androidpublisher/v3/applications/com.example.storeapp/edits"
	switch {
	case r.URL.Path == "/token":
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			play.t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			play.t.Fatalf("assertion is not a JWT")
		}
		claimsRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(claimsRaw, &claims)
		if claims["scope"] != playPublisherScope || claims["aud"] != play.server.URL+"/token" || claims["iss"] != "publisher@example.iam.gserviceaccount.com" {
			play.t.Errorf("claims = %v", claims)
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.play-access-token","token_type":"Bearer","expires_in":3600}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer ya29.play-access-token" {
		play.t.Errorf("missing bearer on %s", r.URL.Path)
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == app:
		_, _ = w.Write([]byte(`{"id":"edit-1"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/upload"+app+"/edit-1/bundles":
		if r.URL.Query().Get("uploadType") != "media" {
			play.t.Errorf("uploadType = %q", r.URL.Query().Get("uploadType"))
		}
		if play.failUpload > 0 {
			w.WriteHeader(play.failUpload)
			_, _ = w.Write([]byte(`{"error":{"code":503,"message":"Backend Error"}}`))
			return
		}
		play.uploaded, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"versionCode":42,"sha256":"abc"}`))
	case r.Method == http.MethodPut && r.URL.Path == app+"/edit-1/tracks/beta":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		play.trackBody = append(play.trackBody, body)
		release := body["releases"].([]any)[0].(map[string]any)
		if play.draftApp && release["status"] != "draft" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":400,"message":"Only releases with status draft may be created on draft app."}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodPost && r.URL.Path == app+"/edit-1:commit":
		play.committed = true
		_, _ = w.Write([]byte(`{"id":"edit-1"}`))
	case r.Method == http.MethodDelete && r.URL.Path == app+"/edit-1":
		play.deleted = true
		w.WriteHeader(http.StatusNoContent)
	default:
		play.t.Errorf("unexpected Play request %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func playUploadJob() apiRunnerJob {
	return apiRunnerJob{
		ID: "pfjob_store", Kind: "store.upload",
		Payload: runnerJobPayload{
			Platform: "android", BuildID: "build_2", Destination: "play_beta", ApplicationID: "com.example.storeapp",
			Version: "1.4.0", BuildNumber: "42", ReleaseNotes: "Bug fixes",
			SecretReferences: []runnerJobSecretReference{{ID: "ref_play", Provider: "google_play", Purpose: "play_service_account", Key: "GOOGLE_PLAY_SERVICE_ACCOUNT_JSON"}},
		},
	}
}

func runPlayFixture(t *testing.T, play *fakePlay) (map[string]any, error) {
	t.Helper()
	original := playAPIBaseURL
	playAPIBaseURL = play.server.URL
	t.Cleanup(func() { playAPIBaseURL = original })
	runtime, _ := newTestStoreRuntime(t, &fakeStoreRunner{}, map[string]string{
		"ref_play": mustJSON(t, map[string]string{"serviceAccountJson": play.serviceAccountJSON(), "clientEmail": "publisher@example.iam.gserviceaccount.com", "projectId": "example"}),
	})
	aab := filepath.Join(t.TempDir(), "app-release.aab")
	mustWrite(t, aab, "aab-bytes")
	defer runtime.cleanup.Run()
	return runPlayStoreUpload(runtime, playUploadJob(), storeBuildArtifact{Kind: "aab", FileName: "app-release.aab"}, aab, "play_beta")
}

func TestRunPlayStoreUploadPublishesToTrack(t *testing.T) {
	play := newFakePlay(t)
	result, err := runPlayFixture(t, play)
	if err != nil {
		t.Fatal(err)
	}
	if result["playVersionCode"] != "42" || result["playTrack"] != "beta" || result["playReleaseStatus"] != "completed" {
		t.Fatalf("result = %v", result)
	}
	if !bytes.Equal(play.uploaded, []byte("aab-bytes")) || !play.committed || play.deleted {
		t.Fatalf("uploaded %q committed %v deleted %v", play.uploaded, play.committed, play.deleted)
	}
	release := play.trackBody[0]["releases"].([]any)[0].(map[string]any)
	if fmt.Sprint(release["versionCodes"]) != "[42]" || release["status"] != "completed" || !strings.Contains(fmt.Sprint(release["releaseNotes"]), "Bug fixes") {
		t.Fatalf("track release = %v", release)
	}
	want := []string{"POST /token", "POST /androidpublisher/v3/applications/com.example.storeapp/edits", "POST /upload/androidpublisher/v3/applications/com.example.storeapp/edits/edit-1/bundles", "PUT /androidpublisher/v3/applications/com.example.storeapp/edits/edit-1/tracks/beta", "POST /androidpublisher/v3/applications/com.example.storeapp/edits/edit-1:commit"}
	if strings.Join(play.requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(play.requests, "\n"))
	}
	if redactRegisteredSecrets("ya29.play-access-token") != "ya29.play-access-token" {
		t.Fatal("access token stayed registered after the upload")
	}
}

func TestRunPlayStoreUploadRetriesDraftAppAsDraft(t *testing.T) {
	play := newFakePlay(t)
	play.draftApp = true
	result, err := runPlayFixture(t, play)
	if err != nil {
		t.Fatal(err)
	}
	if result["playReleaseStatus"] != "draft" || len(play.trackBody) != 2 || !play.committed {
		t.Fatalf("result = %v, track updates = %d", result, len(play.trackBody))
	}
}

func TestRunPlayStoreUploadMapsServerErrorsToTransientAndDeletesEdit(t *testing.T) {
	play := newFakePlay(t)
	play.failUpload = http.StatusServiceUnavailable
	_, err := runPlayFixture(t, play)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "play_upload_transient" {
		t.Fatalf("err = %v", err)
	}
	if !play.deleted || play.committed {
		t.Fatal("failed edit must be deleted, not committed")
	}

	play = newFakePlay(t)
	play.failUpload = http.StatusTooManyRequests
	if _, err := runPlayFixture(t, play); !errors.As(err, &failure) || failure.code != "play_upload_transient" {
		t.Fatalf("429 -> %v", err)
	}
	play = newFakePlay(t)
	play.failUpload = http.StatusForbidden
	if _, err := runPlayFixture(t, play); !errors.As(err, &failure) || failure.code != "play_auth_failed" {
		t.Fatalf("403 -> %v", err)
	}
}

func TestPlayTrackForDestination(t *testing.T) {
	for destination, want := range map[string]string{"play_internal": "internal", "play_alpha": "alpha", "play_beta": "beta", "play_production": "production"} {
		if got, ok := playTrackForDestination(destination); !ok || got != want {
			t.Errorf("%s -> %s", destination, got)
		}
	}
	if _, ok := playTrackForDestination("testflight"); ok {
		t.Error("testflight is not a Play track")
	}
}

// Through the handler: download the stored artifact (no local copy) and
// publish it to Play.
func TestHandleStoreUploadJobDownloadsArtifactAndCompletes(t *testing.T) {
	plane := newFakeStoreControlPlane(t)
	play := newFakePlay(t)
	original := playAPIBaseURL
	playAPIBaseURL = play.server.URL
	t.Cleanup(func() { playAPIBaseURL = original })
	plane.secrets["ref_play"] = mustJSON(t, map[string]string{"serviceAccountJson": play.serviceAccountJSON(), "clientEmail": "publisher@example.iam.gserviceaccount.com", "projectId": "example"})
	plane.stored["store/pfjob_build/app-release.aab"] = []byte("aab-bytes")
	sum, _, _ := fileSHA256(func() string { p := filepath.Join(t.TempDir(), "x"); mustWrite(t, p, "aab-bytes"); return p }())

	job := playUploadJob()
	artifact, _ := json.Marshal(storeBuildArtifact{Kind: "aab", FileName: "app-release.aab", SHA256: sum, SizeBytes: 9, StorageKey: "store/pfjob_build/app-release.aab"})
	job.Payload.StoreArtifact = artifact
	root := t.TempDir()
	options := runnerOnceOptions{apiURL: plane.server.URL, workspaceRoot: root}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_store", Capabilities: map[string]any{"runnerJobHeartbeat": false}}, Token: "runner_token"}
	if err := handleStoreUploadJob(plane.server.Client(), options, registration, job, io.Discard); err != nil {
		t.Fatal(err)
	}
	result := plane.completions[0]
	if result["status"] != "ok" || result["playVersionCode"] != "42" || result["playTrack"] != "beta" {
		t.Fatalf("result = %v", result)
	}
	if !bytes.Equal(play.uploaded, []byte("aab-bytes")) {
		t.Fatal("Play did not receive the downloaded artifact")
	}
	if filePresent(filepath.Join(root, ".preflight", "store-builds", "pfjob_store", "download")) {
		t.Fatal("downloaded artifact not cleaned up")
	}
}
