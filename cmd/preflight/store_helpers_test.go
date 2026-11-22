package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStoreRunner stands in for every external tool. handle simulates a
// tool's side effects; nothing real is executed.
type fakeStoreRunner struct {
	mu     sync.Mutex
	calls  []storeCommand
	handle func(command storeCommand) ([]byte, error)
}

func (runner *fakeStoreRunner) Run(command storeCommand) ([]byte, error) {
	runner.mu.Lock()
	runner.calls = append(runner.calls, command)
	runner.mu.Unlock()
	if runner.handle != nil {
		return runner.handle(command)
	}
	return nil, nil
}

func (runner *fakeStoreRunner) lines() []string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	lines := []string{}
	for _, call := range runner.calls {
		lines = append(lines, call.String())
	}
	return lines
}

func (runner *fakeStoreRunner) find(prefix string) []storeCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	found := []storeCommand{}
	for _, call := range runner.calls {
		if strings.HasPrefix(call.String(), prefix) {
			found = append(found, call)
		}
	}
	return found
}

// fakeSecurity simulates security(1) state: the user keychain search list
// and the identities imported per keychain.
type fakeSecurity struct {
	mu          sync.Mutex
	searchList  []string
	keychains   map[string]bool
	identity    string
	failCommand string
}

func newFakeSecurity(identitySHA1 string) *fakeSecurity {
	return &fakeSecurity{
		searchList: []string{"/Users/runner/Library/Keychains/login.keychain-db", "/Library/Keychains/System.keychain"},
		keychains:  map[string]bool{},
		identity:   identitySHA1,
	}
}

func (security *fakeSecurity) handle(command storeCommand) ([]byte, error) {
	security.mu.Lock()
	defer security.mu.Unlock()
	if len(command.Args) == 0 {
		return nil, fmt.Errorf("security: no args")
	}
	if security.failCommand == command.Args[0] {
		return []byte("simulated failure"), fmt.Errorf("security %s: exit status 1", command.Args[0])
	}
	switch command.Args[0] {
	case "create-keychain":
		security.keychains[command.Args[len(command.Args)-1]] = true
	case "delete-keychain":
		delete(security.keychains, command.Args[len(command.Args)-1])
	case "list-keychains":
		if len(command.Args) > 3 && command.Args[3] == "-s" {
			security.searchList = append([]string{}, command.Args[4:]...)
			return nil, nil
		}
		var out strings.Builder
		for _, keychain := range security.searchList {
			fmt.Fprintf(&out, "    \"%s\"\n", keychain)
		}
		return []byte(out.String()), nil
	case "find-identity":
		return []byte(fmt.Sprintf("  1) %s \"Apple Distribution: Example (TEAM123456)\"\n     1 valid identities found\n", security.identity)), nil
	}
	return nil, nil
}

func (security *fakeSecurity) list() []string {
	security.mu.Lock()
	defer security.mu.Unlock()
	return append([]string{}, security.searchList...)
}

func testCertificateDER(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x5E1A1),
		Subject:      pkix.Name{CommonName: "Apple Distribution: Example (TEAM123456)"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(der)
	return der, strings.ToUpper(hex.EncodeToString(sum[:]))
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func secretMapRevealer(secrets map[string]string, keys map[string]string) storeSecretRevealer {
	return func(id string) (runnerJobSecretRevealData, error) {
		value, ok := secrets[id]
		if !ok {
			return runnerJobSecretRevealData{}, &preflightAPIError{status: 404, code: "secret_not_found", message: "no secret " + id}
		}
		return runnerJobSecretRevealData{SecretReference: runnerJobSecretReference{ID: id, Key: keys[id]}, Value: value}, nil
	}
}

func newTestStoreRuntime(t *testing.T, runner storeCommandRunner, secrets map[string]string) (*storeJobRuntime, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	log := &bytes.Buffer{}
	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &storeJobRuntime{
		jobID:   "pfjob_store",
		run:     runner,
		reveal:  secretMapRevealer(secrets, nil),
		log:     log,
		homeDir: filepath.Join(root, "home"),
		workDir: filepath.Join(root, "work"),
		appDir:  appDir,
		cleanup: &storeCleanup{log: log},
	}, log
}

func filePresent(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fakeStoreControlPlane implements the runner side of the control plane the
// store jobs talk to: secret reveal, chunked artifact upload/download and job
// completion.
type fakeStoreControlPlane struct {
	t           *testing.T
	server      *httptest.Server
	mu          sync.Mutex
	secrets     map[string]string
	secretKeys  map[string]string
	parts       map[int][]byte
	partSize    int64
	completed   map[string]any
	stored      map[string][]byte
	completions []map[string]any
	reveals     []string
}

func newFakeStoreControlPlane(t *testing.T) *fakeStoreControlPlane {
	plane := &fakeStoreControlPlane{
		t:          t,
		secrets:    map[string]string{},
		secretKeys: map[string]string{},
		parts:      map[int][]byte{},
		stored:     map[string][]byte{},
		partSize:   minStorePartSizeBytes,
	}
	plane.server = httptest.NewServer(http.HandlerFunc(plane.serve))
	t.Cleanup(plane.server.Close)
	return plane
}

func writeEnvelope(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func (plane *fakeStoreControlPlane) serve(w http.ResponseWriter, r *http.Request) {
	plane.mu.Lock()
	defer plane.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer runner_token" {
		plane.t.Errorf("missing runner token on %s %s", r.Method, r.URL.Path)
	}
	prefix := "/api/preflight/v1/runners/pfrun_store/jobs/pfjob_store"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/secrets/") && strings.HasSuffix(path, "/reveal"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/secrets/"), "/reveal")
		plane.reveals = append(plane.reveals, id)
		value, ok := plane.secrets[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "secret_not_found", "message": "missing"}})
			return
		}
		writeEnvelope(w, map[string]any{"secretReference": map[string]any{"id": id, "key": plane.secretKeys[id]}, "value": value})
	case r.Method == http.MethodPost && path == "/artifacts/store/uploads":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["fileName"] == "" || body["kind"] == "" {
			plane.t.Errorf("upload start missing fields: %v", body)
		}
		writeEnvelope(w, map[string]any{"uploadId": "up_1", "key": "store/pfjob_store/" + fmt.Sprint(body["fileName"]), "partSizeBytes": plane.partSize})
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/artifacts/store/uploads/up_1/parts/"):
		number, _ := strconv.Atoi(strings.TrimPrefix(path, "/artifacts/store/uploads/up_1/parts/"))
		data, _ := io.ReadAll(r.Body)
		plane.parts[number] = data
		writeEnvelope(w, map[string]any{"partNumber": number, "etag": fmt.Sprintf("etag-%d", number)})
	case r.Method == http.MethodPost && path == "/artifacts/store/uploads/up_1/complete":
		var body struct {
			Parts []struct {
				PartNumber int    `json:"partNumber"`
				ETag       string `json:"etag"`
			} `json:"parts"`
			SHA256    string `json:"sha256"`
			SizeBytes int64  `json:"sizeBytes"`
			FileName  string `json:"fileName"`
			Kind      string `json:"kind"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var whole []byte
		for index, part := range body.Parts {
			if part.PartNumber != index+1 || part.ETag != fmt.Sprintf("etag-%d", part.PartNumber) {
				plane.t.Errorf("parts out of order or wrong etag: %+v", body.Parts)
			}
			whole = append(whole, plane.parts[part.PartNumber]...)
		}
		sum := sha256.Sum256(whole)
		if hex.EncodeToString(sum[:]) != body.SHA256 || int64(len(whole)) != body.SizeBytes {
			plane.t.Errorf("complete sha/size mismatch: sent %s/%d, assembled %x/%d", body.SHA256, body.SizeBytes, sum, len(whole))
		}
		key := "store/pfjob_store/" + body.FileName
		plane.stored[key] = whole
		plane.completed = map[string]any{"parts": len(body.Parts)}
		writeEnvelope(w, map[string]any{"kind": body.Kind, "fileName": body.FileName, "sha256": body.SHA256, "sizeBytes": body.SizeBytes, "storageKey": key})
	case r.Method == http.MethodGet && path == "/artifacts/store":
		data, ok := plane.stored[r.URL.Query().Get("key")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	case r.Method == http.MethodPost && path == "/complete":
		var body struct {
			Result map[string]any `json:"result"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		plane.completions = append(plane.completions, body.Result)
		writeEnvelope(w, map[string]any{"job": map[string]any{"id": "pfjob_store", "status": "completed"}})
	case strings.HasSuffix(path, "/heartbeat") || strings.HasSuffix(r.URL.Path, "/logs"):
		writeEnvelope(w, map[string]any{"job": map[string]any{"id": "pfjob_store"}})
	default:
		plane.t.Errorf("unexpected route %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func (plane *fakeStoreControlPlane) client() *storeArtifactClient {
	return &storeArtifactClient{client: plane.server.Client(), baseURL: plane.server.URL, runnerID: "pfrun_store", jobID: "pfjob_store", token: "runner_token"}
}

func b64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func TestExpandStorePlanEnvironmentResolvesEASStyleReferences(t *testing.T) {
	got, err := expandStorePlanEnvironment(
		map[string]string{
			"SENTRY_DSN":  "${EXPO_PUBLIC_SENTRY_DSN_PROD}",
			"API_URL":     "https://${API_HOST}/v1",
			"APP_VARIANT": "production",
		},
		map[string]string{"EXPO_PUBLIC_SENTRY_DSN_PROD": "https://dsn.example", "API_HOST": "api.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got["SENTRY_DSN"] != "https://dsn.example" || got["API_URL"] != "https://api.example.com/v1" || got["APP_VARIANT"] != "production" {
		t.Fatalf("unexpected expansion: %#v", got)
	}
}

func TestExpandStorePlanEnvironmentFailsOnUnresolvedReference(t *testing.T) {
	_, err := expandStorePlanEnvironment(
		map[string]string{"SENTRY_DSN": "${EXPO_PUBLIC_SENTRY_DSN_PROD}", "B": "${A_MISSING}"},
		map[string]string{},
	)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "build_environment_unresolved" {
		t.Fatalf("want build_environment_unresolved, got %v", err)
	}
	if !strings.Contains(failure.message, "A_MISSING, EXPO_PUBLIC_SENTRY_DSN_PROD") {
		t.Fatalf("message should list missing names sorted: %q", failure.message)
	}
}
