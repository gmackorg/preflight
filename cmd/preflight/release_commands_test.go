package main

import (
	"bytes"
	"encoding/json"
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

type recordedAPIRequest struct {
	Method      string
	Path        string
	Query       string
	Auth        string
	ContentType string
	Body        []byte
}

// fakeControlPlane answers each "METHOD /path" with the envelope data given
// (a JSON string, or a func for stateful answers) and records every request.
type fakeControlPlane struct {
	t        *testing.T
	mu       sync.Mutex
	requests []recordedAPIRequest
	routes   map[string]any
}

func newFakeControlPlane(t *testing.T, routes map[string]any) (*fakeControlPlane, *httptest.Server) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PREFLIGHT_TOKEN", "pf_test_token")
	t.Setenv("PREFLIGHT_API_URL", "")
	t.Setenv("PREFLIGHT_WORKSPACE_ID", "")
	plane := &fakeControlPlane{t: t, routes: routes}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		plane.mu.Lock()
		plane.requests = append(plane.requests, recordedAPIRequest{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"), Body: body,
		})
		plane.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		answer, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"no route"}}`))
			return
		}
		data := ""
		switch typed := answer.(type) {
		case string:
			data = typed
		case func(*http.Request, []byte) string:
			data = typed(r, body)
		}
		if strings.HasPrefix(data, "ERROR ") {
			w.WriteHeader(http.StatusConflict)
			_, _ = fmt.Fprintf(w, `{"error":%s}`, strings.TrimPrefix(data, "ERROR "))
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":%s,"meta":{"apiVersion":"v1"}}`, data)
	}))
	t.Cleanup(server.Close)
	return plane, server
}

func (plane *fakeControlPlane) only(t *testing.T, key string) recordedAPIRequest {
	t.Helper()
	plane.mu.Lock()
	defer plane.mu.Unlock()
	var found []recordedAPIRequest
	for _, request := range plane.requests {
		if request.Method+" "+request.Path == key {
			found = append(found, request)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected one %s, got %d (all: %+v)", key, len(found), plane.requests)
	}
	return found[0]
}

func decodeRequestJSON(t *testing.T, request recordedAPIRequest) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(request.Body, &body); err != nil {
		t.Fatalf("decode %s %s body: %v (%s)", request.Method, request.Path, err, request.Body)
	}
	return body
}

func runCLI(t *testing.T, server *httptest.Server, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	full := append(append([]string{}, args...), "--api-url", server.URL, "--workspace-id", "ws_test")
	code := run(full, &stdout, &stderr, server.Client())
	return code, stdout.String(), stderr.String()
}

func TestCredentialsListShowsAppAndWorkspaceVault(t *testing.T) {
	plane, server := newFakeControlPlane(t, map[string]any{
		"GET /api/preflight/v1/apps/pfapp_one/credentials": `{"appId":"pfapp_one","credentials":[{"id":"pfsec_cert","kind":"ios_distribution_certificate","scope":"team","laneScope":"all","status":"active","version":2,"expiresAt":"2027-01-01T00:00:00Z","purpose":"ios_distribution_certificate"}]}`,
		"GET /api/preflight/v1/credentials":                `{"workspaceId":"ws_test","credentials":[]}`,
	})
	code, stdout, stderr := runCLI(t, server, "credentials", "list", "--app", "pfapp_one")
	if code != 0 || !strings.Contains(stdout, "pfsec_cert ios_distribution_certificate team all active v2 expires=2027-01-01T00:00:00Z") {
		t.Fatalf("app list: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if request := plane.only(t, "GET /api/preflight/v1/apps/pfapp_one/credentials"); request.Auth != "Bearer pf_test_token" {
		t.Fatalf("missing bearer token: %+v", request)
	}
	code, stdout, _ = runCLI(t, server, "credentials", "list", "--include-revoked")
	if code != 0 || !strings.Contains(stdout, "no signing credentials") {
		t.Fatalf("workspace list: code=%d stdout=%q", code, stdout)
	}
	if query := plane.only(t, "GET /api/preflight/v1/credentials").Query; !strings.Contains(query, "workspaceId=ws_test") || !strings.Contains(query, "includeRevoked=true") {
		t.Fatalf("workspace list query %q", query)
	}
}

func TestCredentialsImportEASStoresTokenThenImportsWithoutPrintingIt(t *testing.T) {
	t.Setenv("PREFLIGHT_TEST_EXPO_TOKEN", "expo-secret-value-1234")
	plane, server := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/secret-refs":                           `{"secretReference":{"id":"pfsec_expo","provider":"expo","key":"EXPO_TOKEN","laneScope":"all","status":"active"}}`,
		"POST /api/preflight/v1/apps/pfapp_one/credentials/import/eas": `{"appId":"pfapp_one","easProjectId":"proj","bundleIds":["com.example.one"],"entries":[{"kind":"ios_distribution_certificate","key":"IOS_DIST","status":"imported","verified":true},{"kind":"android_upload_keystore","key":"ANDROID","status":"missing","verified":null,"reason":"no keystore in the Expo account"}],"summary":{"imported":1,"unchanged":0,"missing":1,"failed":0}}`,
	})
	code, stdout, stderr := runCLI(t, server, "credentials", "import-eas", "--app", "pfapp_one", "--expo-token-env", "PREFLIGHT_TEST_EXPO_TOKEN")
	if code != 0 {
		t.Fatalf("import: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"stored Expo access token pfsec_expo", "pfapp_one imported=1 unchanged=0 missing=1 failed=0", "missing android_upload_keystore ANDROID — no keystore in the Expo account"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("missing %q in %q", want, stdout)
		}
	}
	if strings.Contains(stdout+stderr, "expo-secret-value-1234") {
		t.Fatal("import printed the Expo token")
	}
	secret := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/secret-refs"))
	if secret["provider"] != "expo" || secret["purpose"] != "api_token" || secret["value"] != "expo-secret-value-1234" || secret["workspaceId"] != "ws_test" {
		t.Fatalf("token stored wrongly: %#v", secret)
	}
	imported := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/credentials/import/eas"))
	if imported["expoTokenSecretReferenceId"] != "pfsec_expo" {
		t.Fatalf("import body %#v", imported)
	}
}

func TestCredentialsImportEASAllUsesWorkspaceRouteAndFailsOnAppError(t *testing.T) {
	plane, server := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/credentials/import/eas": `{"workspaceId":"ws_test","apps":[{"appId":"pfapp_one","report":{"appId":"pfapp_one","entries":[],"summary":{"imported":2,"unchanged":1,"missing":0,"failed":0}}},{"appId":"pfapp_two","error":{"code":"expo_project_not_found","message":"not visible"}}]}`,
	})
	code, stdout, _ := runCLI(t, server, "credentials", "import-eas", "--all")
	if code != 1 || !strings.Contains(stdout, "pfapp_one imported=2") || !strings.Contains(stdout, "pfapp_two error expo_project_not_found: not visible") {
		t.Fatalf("import --all: code=%d stdout=%q", code, stdout)
	}
	if body := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/credentials/import/eas")); body["workspaceId"] != "ws_test" {
		t.Fatalf("body %#v", body)
	}
	var stderr bytes.Buffer
	if code := run([]string{"credentials", "import-eas", "--app", "a", "--all", "--api-url", server.URL}, io.Discard, &stderr, server.Client()); code != 2 {
		t.Fatalf("--app with --all must be rejected, got %d %s", code, stderr.String())
	}
}

func TestCredentialsDoctorSendsFixAndExitsNonZeroWhenBlocked(t *testing.T) {
	plane, server := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/apps/pfapp_one/credentials/doctor": `{"appId":"pfapp_one","fix":true,"ok":false,"findings":[{"check":"provisioning_profile","status":"fixed","message":"created App Store profile","bundleId":"com.example.one","action":"created profile","resourceId":"PROFILE123"},{"check":"apns_key","status":"error","message":"no APNs key in the vault"}]}`,
	})
	code, stdout, _ := runCLI(t, server, "credentials", "doctor", "--app", "pfapp_one", "--fix")
	if code != 1 {
		t.Fatalf("blocked doctor must exit 1, got %d", code)
	}
	for _, want := range []string{"signing pfapp_one blocked", "FIXED provisioning_profile: created App Store profile [com.example.one] (created profile PROFILE123)", "ERROR apns_key: no APNs key in the vault"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("missing %q in %q", want, stdout)
		}
	}
	if body := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/credentials/doctor")); body["fix"] != true {
		t.Fatalf("doctor body %#v", body)
	}
}

func TestCredentialsUploadSendsMultipartWithKindFileAndPassword(t *testing.T) {
	p12 := filepath.Join(t.TempDir(), "dist.p12")
	if err := os.WriteFile(p12, []byte{0x30, 0x82, 0x01, 0x02}, 0o600); err != nil {
		t.Fatal(err)
	}
	plane, server := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/apps/pfapp_one/credentials": `{"outcome":"created","credential":{"id":"pfsec_new","kind":"ios_distribution_certificate","scope":"team","version":1}}`,
		"POST /api/preflight/v1/credentials":                `{"outcome":"updated","credential":{"id":"pfsec_asc","kind":"asc_api_key","scope":"team","version":3}}`,
	})
	code, stdout, stderr := runCLI(t, server, "credentials", "upload", "--app", "pfapp_one", "--kind", "ios_distribution_certificate", "--file", p12, "--password", "p12-pass")
	if code != 0 || !strings.Contains(stdout, "created pfsec_new ios_distribution_certificate team v1") {
		t.Fatalf("upload: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	request := plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/credentials")
	form := parseMultipartRequest(t, request)
	if form.Value["kind"][0] != "ios_distribution_certificate" || form.Value["p12Password"][0] != "p12-pass" {
		t.Fatalf("form values %#v", form.Value)
	}
	if files := form.File["p12"]; len(files) != 1 || files[0].Filename != "dist.p12" {
		t.Fatalf("form files %#v", form.File)
	}

	p8 := filepath.Join(t.TempDir(), "AuthKey.p8")
	if err := os.WriteFile(p8, []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, server, "credentials", "upload", "--kind", "asc_api_key", "--file", p8, "--field", "keyId=ABC123", "--field", "issuerId=issuer-1")
	if code != 0 || !strings.Contains(stdout, "updated pfsec_asc asc_api_key team v3") {
		t.Fatalf("team upload: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	team := parseMultipartRequest(t, plane.only(t, "POST /api/preflight/v1/credentials"))
	if team.Value["workspaceId"][0] != "ws_test" || team.Value["keyId"][0] != "ABC123" || team.Value["issuerId"][0] != "issuer-1" || len(team.File["p8"]) != 1 {
		t.Fatalf("team form %#v %#v", team.Value, team.File)
	}

	if code, _, stderr := runCLI(t, server, "credentials", "upload", "--kind", "android_upload_keystore", "--file", p8); code != 2 || !strings.Contains(stderr, "app-scoped") {
		t.Fatalf("app-scoped kind without --app must be refused: %d %q", code, stderr)
	}
}

type multipartFile struct{ Filename string }

type multipartForm struct {
	Value map[string][]string
	File  map[string][]multipartFile
}

func parseMultipartRequest(t *testing.T, request recordedAPIRequest) multipartForm {
	t.Helper()
	httpRequest, err := http.NewRequest(request.Method, "http://example.invalid"+request.Path, bytes.NewReader(request.Body))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", request.ContentType)
	if err := httpRequest.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("parse multipart: %v", err)
	}
	form := multipartForm{Value: httpRequest.MultipartForm.Value, File: map[string][]multipartFile{}}
	for field, headers := range httpRequest.MultipartForm.File {
		for _, header := range headers {
			form.File[field] = append(form.File[field], multipartFile{Filename: header.Filename})
		}
	}
	return form
}

func TestSigningTargetsSetAndGet(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(targets, []byte(`{"targets":[{"targetName":"App","bundleId":"com.example.one","capabilities":["PUSH_NOTIFICATIONS"]},{"targetName":"Widget","bundleId":"com.example.one.widget","capabilities":[]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	read := `{"appId":"pfapp_one","bundleId":"com.example.one","androidApplicationId":"com.example.one","targets":[{"targetName":"App","bundleId":"com.example.one","capabilities":["PUSH_NOTIFICATIONS"]},{"targetName":"Widget","bundleId":"com.example.one.widget","capabilities":[]}]}`
	plane, server := newFakeControlPlane(t, map[string]any{
		"PUT /api/preflight/v1/apps/pfapp_one/signing-targets": read,
		"GET /api/preflight/v1/apps/pfapp_one/signing-targets": read,
	})
	code, stdout, stderr := runCLI(t, server, "signing-targets", "set", "--app", "pfapp_one", "--file", targets)
	if code != 0 || !strings.Contains(stdout, "Widget com.example.one.widget") {
		t.Fatalf("set: %d %q %q", code, stdout, stderr)
	}
	body := decodeRequestJSON(t, plane.only(t, "PUT /api/preflight/v1/apps/pfapp_one/signing-targets"))
	if list, _ := body["targets"].([]any); len(list) != 2 {
		t.Fatalf("PUT body %#v", body)
	}
	code, stdout, _ = runCLI(t, server, "signing-targets", "get", "--app", "pfapp_one", "--json")
	if code != 0 || !strings.Contains(stdout, `"androidApplicationId": "com.example.one"`) {
		t.Fatalf("get --json: %d %q", code, stdout)
	}
}

func TestBuildProfilesGetSetAndImport(t *testing.T) {
	profiles := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(profiles, []byte(`{"profiles":[{"lane":"beta","environment":{"APP_VARIANT":"production"},"secretEnvironmentReferenceIds":["pfsec_sentry"],"versionSource":"remote","stored":true},{"lane":"store","environment":{},"secretEnvironmentReferenceIds":[],"versionSource":"remote"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(t.TempDir(), "build-config.json")
	if err := os.WriteFile(legacy, []byte(`{"build":{"production":{"env":{"APP_VARIANT":"production"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plane, server := newFakeControlPlane(t, map[string]any{
		"GET /api/preflight/v1/apps/pfapp_one/build-profiles": `{"profiles":[{"lane":"internal","environment":{},"secretEnvironmentReferenceIds":[],"versionSource":"remote","stored":false},{"lane":"beta","environment":{"APP_VARIANT":"production"},"secretEnvironmentReferenceIds":["pfsec_sentry"],"versionSource":"remote","iosScheme":"App","stored":true}]}`,
		"PUT /api/preflight/v1/apps/pfapp_one/build-profiles": func(r *http.Request, body []byte) string {
			var profile map[string]any
			_ = json.Unmarshal(body, &profile)
			encoded, _ := json.Marshal(map[string]any{"profile": profile})
			return string(encoded)
		},
		"POST /api/preflight/v1/apps/pfapp_one/build-profiles/import-eas": `{"profiles":[{"lane":"store","environment":{"APP_VARIANT":"production"},"secretEnvironmentReferenceIds":[],"versionSource":"remote","importedFromEasProfile":"production"}],"warnings":["submit profiles are not imported"],"applied":false}`,
	})
	code, stdout, _ := runCLI(t, server, "build-profiles", "get", "--app", "pfapp_one")
	if code != 0 || !strings.Contains(stdout, "internal (default) version=remote") || !strings.Contains(stdout, "beta version=remote ios-scheme=App") || !strings.Contains(stdout, "  secret pfsec_sentry") {
		t.Fatalf("get: %d %q", code, stdout)
	}
	code, stdout, stderr := runCLI(t, server, "build-profiles", "set", "--app", "pfapp_one", "--file", profiles)
	if code != 0 || strings.Count(stdout, "saved ") != 2 {
		t.Fatalf("set: %d %q %q", code, stdout, stderr)
	}
	plane.mu.Lock()
	puts := 0
	for _, request := range plane.requests {
		if request.Method == http.MethodPut {
			puts++
			var body map[string]any
			_ = json.Unmarshal(request.Body, &body)
			if _, leaked := body["stored"]; leaked {
				t.Errorf("read-only field sent: %s", request.Body)
			}
		}
	}
	plane.mu.Unlock()
	if puts != 2 {
		t.Fatalf("expected one PUT per lane, got %d", puts)
	}
	code, stdout, _ = runCLI(t, server, "build-profiles", "import-eas", "--app", "pfapp_one", "--file", legacy, "--dry-run")
	if code != 0 || !strings.Contains(stdout, "would import (dry run) 1 build profile(s)") || !strings.Contains(stdout, "warning: submit profiles are not imported") {
		t.Fatalf("import: %d %q", code, stdout)
	}
	body := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/build-profiles/import-eas"))
	if body["dryRun"] != true || body["easJson"] == nil {
		t.Fatalf("import body %#v", body)
	}
}

func storeBuildRoutes(platform string, progression []string) map[string]any {
	var mu sync.Mutex
	polls := 0
	return map[string]any{
		"POST /api/preflight/v1/apps/pfapp_one/store-builds": `{"build":{"id":"pfbuild_1","platform":"` + platform + `","version":"1.4.0","buildNumber":"42","status":"queued","storeUploadStatus":"queued"},"workflow":{"id":"pfw_store"},"runnerJob":{"id":"pfjob_store","kind":"store.build","status":"queued"}}`,
		"GET /api/preflight/v1/apps/pfapp_one/store-builds/pfbuild_1": func(*http.Request, []byte) string {
			mu.Lock()
			defer mu.Unlock()
			step := progression[min(polls, len(progression)-1)]
			polls++
			return `{"build":` + step + `,"runnerJobs":[]}`
		},
	}
}

func TestBuildStoreWaitPrintsASCBuildID(t *testing.T) {
	plane, server := newFakeControlPlane(t, storeBuildRoutes("ios", []string{
		`{"id":"pfbuild_1","status":"building","storeUploadStatus":"queued"}`,
		`{"id":"pfbuild_1","status":"completed","storeUploadStatus":"uploaded"}`,
		`{"id":"pfbuild_1","status":"completed","storeUploadStatus":"processing","ascBuildId":"asc-build-9"}`,
	}))
	code, stdout, stderr := runCLI(t, server, "build", "store", "--app", "pfapp_one", "--platform", "ios", "--lane", "beta", "--git-ref", "main", "--build-number-seed", "40", "--wait", "--poll-interval", "1ms")
	if code != 0 {
		t.Fatalf("build store: %d %q %q", code, stdout, stderr)
	}
	for _, want := range []string{"queued store build pfbuild_1 ios beta 1.4.0 (42) workflow=pfw_store", "build pfbuild_1 completed upload=uploaded", "uploaded pfbuild_1 ascBuildId=asc-build-9 (processing)"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("missing %q in %q", want, stdout)
		}
	}
	body := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/store-builds"))
	if body["platform"] != "ios" || body["lane"] != "beta" || body["gitRef"] != "main" || body["buildNumberSeed"] != float64(40) {
		t.Fatalf("store build body %#v", body)
	}
	if _, has := body["destination"]; has {
		t.Fatalf("default destination must be left to the control plane: %#v", body)
	}
}

func TestBuildStoreWaitPrintsPlayVersionCodeAndReportsFailures(t *testing.T) {
	_, server := newFakeControlPlane(t, storeBuildRoutes("android", []string{
		`{"id":"pfbuild_1","status":"completed","storeUploadStatus":"uploaded","playVersionCode":"42","playReleaseStatus":"completed"}`,
	}))
	code, stdout, _ := runCLI(t, server, "build", "store", "--app", "pfapp_one", "--platform", "android", "--lane", "internal", "--destination", "play_internal", "--wait", "--poll-interval", "1ms")
	if code != 0 || !strings.Contains(stdout, "uploaded pfbuild_1 playVersionCode=42 (completed)") {
		t.Fatalf("android: %d %q", code, stdout)
	}

	_, failing := newFakeControlPlane(t, storeBuildRoutes("ios", []string{
		`{"id":"pfbuild_1","status":"failed","errorMessage":"signing_material_missing: no provisioning profile"}`,
	}))
	code, _, stderr := runCLI(t, failing, "build", "store", "--app", "pfapp_one", "--platform", "ios", "--lane", "store", "--wait", "--poll-interval", "1ms")
	if code != 1 || !strings.Contains(stderr, "no provisioning profile") {
		t.Fatalf("failure: %d %q", code, stderr)
	}

	_, refused := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/apps/pfapp_one/store-builds": `ERROR {"code":"signing_material_missing","message":"Signing material is missing for this store build."}`,
	})
	code, _, stderr = runCLI(t, refused, "build", "store", "--app", "pfapp_one", "--platform", "ios", "--lane", "store")
	if code != 1 || !strings.Contains(stderr, "signing_material_missing") {
		t.Fatalf("refusal: %d %q", code, stderr)
	}
	if code, _, stderr := runCLI(t, refused, "build", "store", "--app", "pfapp_one", "--platform", "ios", "--lane", "production"); code != 2 || !strings.Contains(stderr, "--lane must be") {
		t.Fatalf("bad lane: %d %q", code, stderr)
	}
}

func TestPushSendAndKeysCreate(t *testing.T) {
	message := filepath.Join(t.TempDir(), "message.json")
	if err := os.WriteFile(message, []byte(`{"to":{"userRef":"user-1"},"notification":{"title":"Hi","body":"There"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plane, server := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/apps/pfapp_one/push/send": `{"matched":2,"sent":2,"failed":0,"deactivated":0,"results":[]}`,
		"POST /api/preflight/v1/apps/pfapp_one/push/keys": `{"id":"pfpk_1","key":"pfps_secret_value","keyPrefix":"pfps_sec","scope":"push:send","note":"Server secret: store it in the app backend's secrets; it will not be shown again."}`,
	})
	code, stdout, _ := runCLI(t, server, "push", "send", "--app", "pfapp_one", "--file", message)
	if code != 0 || !strings.Contains(stdout, "matched=2 sent=2 failed=0 deactivated=0") {
		t.Fatalf("send: %d %q", code, stdout)
	}
	sent := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/push/send"))
	if to, _ := sent["to"].(map[string]any); to["userRef"] != "user-1" {
		t.Fatalf("send body %#v", sent)
	}
	code, stdout, stderr := runCLI(t, server, "push", "keys", "create", "--app", "pfapp_one", "--scope", "send")
	if code != 0 || !strings.Contains(stdout, "created push:send key pfpk_1\npfps_secret_value") || !strings.Contains(stderr, "will not be shown again") {
		t.Fatalf("keys create: %d %q %q", code, stdout, stderr)
	}
	if body := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/push/keys")); body["scope"] != "push:send" {
		t.Fatalf("keys body %#v", body)
	}
	if code, _, stderr := runCLI(t, server, "push", "keys", "create", "--app", "pfapp_one", "--scope", "admin"); code != 2 || !strings.Contains(stderr, "--scope must be send or register") {
		t.Fatalf("bad scope: %d %q", code, stderr)
	}
}

func TestOTACodeSigningRollbackAndRepublish(t *testing.T) {
	plane, server := newFakeControlPlane(t, map[string]any{
		"POST /api/preflight/v1/apps/pfapp_one/ota/code-signing": `{"secretReferenceId":"pfsecret_ota","keyId":"main","notAfter":"2036-11-21T00:00:00Z","rotated":false,"updates":{"codeSigningCertificate":"./certs/preflight-ota-certificate.pem","codeSigningMetadata":{"keyid":"main","alg":"rsa-v1_5-sha256"},"certificatePem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}}`,
		"POST /api/preflight/v1/apps/pfapp_one/ota/rollback": func(r *http.Request, body []byte) string {
			var request map[string]any
			_ = json.Unmarshal(body, &request)
			return fmt.Sprintf(`{"channel":"production","platform":%q,"directive":"rollBackToEmbedded"}`, request["platform"])
		},
		"POST /api/preflight/v1/apps/pfapp_one/ota/republish": `{"updateId":"upd_new","republishedFromId":"upd_old","headId":"upd_new","previousUpdateId":"upd_cur","channel":"production","platform":"ios"}`,
	})
	out := filepath.Join(t.TempDir(), "certs", "cert.pem")
	code, stdout, stderr := runCLI(t, server, "ota", "code-signing", "generate", "--app", "pfapp_one", "--out", out)
	if code != 0 || !strings.Contains(stdout, "generated code signing key pfsecret_ota keyId=main") || !strings.Contains(stdout, `"keyid":"main"`) {
		t.Fatalf("generate: %d %q %q", code, stdout, stderr)
	}
	if pem, err := os.ReadFile(out); err != nil || !strings.HasPrefix(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("certificate not written: %v %q", err, pem)
	}

	code, stdout, _ = runCLI(t, server, "ota", "rollback", "--app", "pfapp_one", "--channel", "production", "--to-embedded")
	if code != 0 || !strings.Contains(stdout, "production ios: rollBackToEmbedded") || !strings.Contains(stdout, "production android: rollBackToEmbedded") {
		t.Fatalf("rollback: %d %q", code, stdout)
	}
	plane.mu.Lock()
	rollbacks := []map[string]any{}
	for _, request := range plane.requests {
		if strings.HasSuffix(request.Path, "/ota/rollback") {
			var body map[string]any
			_ = json.Unmarshal(request.Body, &body)
			rollbacks = append(rollbacks, body)
		}
	}
	plane.mu.Unlock()
	if len(rollbacks) != 2 || rollbacks[0]["to"] != "embedded" || rollbacks[0]["platform"] != "ios" || rollbacks[1]["platform"] != "android" {
		t.Fatalf("rollback bodies %#v", rollbacks)
	}
	if code, _, stderr := runCLI(t, server, "ota", "rollback", "--app", "pfapp_one", "--channel", "production", "--to-embedded", "--to", "upd_1"); code != 2 || !strings.Contains(stderr, "pass one of") {
		t.Fatalf("conflicting targets: %d %q", code, stderr)
	}

	code, stdout, _ = runCLI(t, server, "ota", "republish", "--app", "pfapp_one", "--update", "upd_old", "--channel", "production", "--rollout", "25")
	if code != 0 || !strings.Contains(stdout, "republished upd_old as upd_new on production (ios)") {
		t.Fatalf("republish: %d %q", code, stdout)
	}
	if body := decodeRequestJSON(t, plane.only(t, "POST /api/preflight/v1/apps/pfapp_one/ota/republish")); body["rolloutPercent"] != float64(25) || body["updateId"] != "upd_old" {
		t.Fatalf("republish body %#v", body)
	}
}
