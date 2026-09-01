package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVersionPrintsContractVersion(t *testing.T) {
	var stdout bytes.Buffer
	code := run([]string{"version"}, &stdout, &bytes.Buffer{}, http.DefaultClient)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "preflight") {
		t.Fatalf("expected preflight in version output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "contract 2026-05-20") {
		t.Fatalf("expected contract version in output, got %q", stdout.String())
	}
}

func TestSubcommandHelpDoesNotCreateWorkflow(t *testing.T) {
	for _, args := range [][]string{
		{"login", "--help"},
		{"prove-app", "--help"},
		{"runner", "--help"},
	} {
		var stdout bytes.Buffer
		code := run(args, &stdout, &bytes.Buffer{}, http.DefaultClient)

		if code != 0 {
			t.Fatalf("run(%v) exit = %d, want 0", args, code)
		}
		if !strings.Contains(stdout.String(), "Usage: preflight "+args[0]) {
			t.Fatalf("run(%v) help output = %q", args, stdout.String())
		}
	}
}

func TestCapabilitiesProbePrintsSharedContractFixture(t *testing.T) {
	fixture := readCapabilitiesFixture(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/preflight/v1/capabilities" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	code := run(
		[]string{"capabilities", "--api-url", server.URL},
		&stdout,
		&bytes.Buffer{},
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if strings.TrimSpace(stdout.String()) != strings.TrimSpace(string(fixture)) {
		t.Fatalf("capabilities output did not match shared fixture\nwant: %s\ngot: %s", fixture, stdout.String())
	}
}

func TestLoginStoresTokenInCLIConfigAndProveAppUsesSavedAuth(t *testing.T) {
	appDir := writeExpoFixture(t)
	configPath := filepath.Join(t.TempDir(), "preflight", "config.json")
	t.Setenv("PREFLIGHT_CONFIG_PATH", configPath)
	t.Setenv("PREFLIGHT_USER_TOKEN", "user_token_123")

	var workflowRequest map[string]any
	var sawWorkflow bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer user_token_123" {
			t.Fatalf("expected saved Preflight auth token, got %q for %s %s", r.Header.Get("Authorization"), r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			sawWorkflow = true
			if err := json.NewDecoder(r.Body).Decode(&workflowRequest); err != nil {
				t.Fatalf("decode workflow request: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_login_config","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var loginStdout bytes.Buffer
	var loginStderr bytes.Buffer
	loginCode := run(
		[]string{"login", "--api-url", server.URL, "--token-env", "PREFLIGHT_USER_TOKEN"},
		&loginStdout,
		&loginStderr,
		server.Client(),
	)

	if loginCode != 0 {
		t.Fatalf("login exit = %d\nstdout: %s\nstderr: %s", loginCode, loginStdout.String(), loginStderr.String())
	}
	if strings.Contains(loginStdout.String(), "user_token_123") || strings.Contains(loginStderr.String(), "user_token_123") {
		t.Fatal("login must not print the token")
	}
	if strings.HasPrefix(configPath, appDir) {
		t.Fatalf("test config path must not be inside app repo: %s", configPath)
	}
	configInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("expected login to write CLI config: %v", err)
	}
	if configInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected config permissions 0600, got %o", configInfo.Mode().Perm())
	}

	t.Setenv("PREFLIGHT_USER_TOKEN", "")
	var proveStdout bytes.Buffer
	var proveStderr bytes.Buffer
	proveCode := run(
		[]string{"prove-app", "--app-dir", appDir, "--json"},
		&proveStdout,
		&proveStderr,
		server.Client(),
	)

	if proveCode != 0 {
		t.Fatalf("prove-app exit = %d\nstdout: %s\nstderr: %s", proveCode, proveStdout.String(), proveStderr.String())
	}
	if !sawWorkflow {
		t.Fatal("expected prove-app to create workflow with saved config")
	}
	if workflowRequest["workspaceId"] != "local" {
		t.Fatalf("expected default workspace from config, got %#v", workflowRequest)
	}
}

func TestProveAppRequiresAuthBeforeRunnerCapacityOrWorkflowMutation(t *testing.T) {
	appDir := writeExpoFixture(t)
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))

	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(readCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity", "POST /api/preflight/v1/workflows/prove-app":
			mutated = true
			_, _ = w.Write([]byte(`{"data":{},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_unexpected"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--json"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code == 0 {
		t.Fatalf("expected auth_required failure\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if mutated {
		t.Fatal("prove-app must not check runner capacity or create workflows before auth succeeds")
	}
	if !strings.Contains(stderr.String(), "auth_required") {
		t.Fatalf("expected auth_required in stderr, got %q", stderr.String())
	}
}

func TestConfigBindWorkspacePersistsWorkspaceForAppPath(t *testing.T) {
	appDir := writeExpoFixture(t)
	configPath := filepath.Join(t.TempDir(), "preflight", "config.json")
	t.Setenv("PREFLIGHT_CONFIG_PATH", configPath)
	t.Setenv("PREFLIGHT_TOKEN", "user_token_456")

	var capacityWorkspaceID string
	var workflowRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer user_token_456" {
			t.Fatalf("expected Preflight auth token, got %q for %s %s", r.Header.Get("Authorization"), r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			capacityWorkspaceID = r.URL.Query().Get("workspaceId")
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"ws_mobile_bound","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			if err := json.NewDecoder(r.Body).Decode(&workflowRequest); err != nil {
				t.Fatalf("decode workflow request: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_bound_workspace","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	if code := run(
		[]string{"login", "--api-url", server.URL, "--token-env", "PREFLIGHT_TOKEN"},
		&bytes.Buffer{},
		&bytes.Buffer{},
		server.Client(),
	); code != 0 {
		t.Fatalf("login exit = %d", code)
	}

	var bindStdout bytes.Buffer
	var bindStderr bytes.Buffer
	bindCode := run(
		[]string{"config", "bind-workspace", "--app-dir", appDir, "--workspace-id", "ws_mobile_bound"},
		&bindStdout,
		&bindStderr,
		server.Client(),
	)

	if bindCode != 0 {
		t.Fatalf("config bind-workspace exit = %d\nstdout: %s\nstderr: %s", bindCode, bindStdout.String(), bindStderr.String())
	}

	var proveStdout bytes.Buffer
	var proveStderr bytes.Buffer
	proveCode := run(
		[]string{"prove-app", "--app-dir", appDir, "--json"},
		&proveStdout,
		&proveStderr,
		server.Client(),
	)

	if proveCode != 0 {
		t.Fatalf("prove-app exit = %d\nstdout: %s\nstderr: %s", proveCode, proveStdout.String(), proveStderr.String())
	}
	if capacityWorkspaceID != "ws_mobile_bound" {
		t.Fatalf("expected bound workspace for capacity probe, got %q", capacityWorkspaceID)
	}
	if workflowRequest["workspaceId"] != "ws_mobile_bound" {
		t.Fatalf("expected bound workspace on workflow request, got %#v", workflowRequest)
	}
}

func TestProveAppDoesNotUseSavedWorkspaceForDifferentExplicitAPIURL(t *testing.T) {
	appDir := writeExpoFixture(t)
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("PREFLIGHT_TOKEN", "explicit_api_token")

	bindingKey, err := preflightAppConfigBindingKey(appDir)
	if err != nil {
		t.Fatalf("resolve binding key: %v", err)
	}
	if err := savePreflightCLIConfig(preflightCLIConfig{
		APIURL:      "https://saved.preflight.example",
		Token:       "saved_token",
		WorkspaceID: "ws_saved_default",
		WorkspaceBindings: map[string]string{
			bindingKey: "ws_saved_binding",
		},
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var capacityWorkspaceID string
	var workflowRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer explicit_api_token" {
			t.Fatalf("expected explicit Preflight auth token, got %q for %s %s", r.Header.Get("Authorization"), r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			capacityWorkspaceID = r.URL.Query().Get("workspaceId")
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			if err := json.NewDecoder(r.Body).Decode(&workflowRequest); err != nil {
				t.Fatalf("decode workflow request: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_explicit_api","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--json"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("prove-app exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if capacityWorkspaceID != "local" {
		t.Fatalf("expected explicit API URL to keep local workspace for capacity probe, got %q", capacityWorkspaceID)
	}
	if workflowRequest["workspaceId"] != "local" {
		t.Fatalf("expected explicit API URL to keep local workspace for workflow request, got %#v", workflowRequest)
	}
}

func TestCredentialsCreateReadsSecretFromEnvAndDoesNotPrintValue(t *testing.T) {
	const secretValue = "expo_cli_secret_token_123"
	t.Setenv("EXPO_TOKEN", secretValue)

	var requestBody map[string]any
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/secret-refs" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"secretReference":{"id":"pfsec_cli","workspaceId":"local","appId":"pfapp_mobile","provider":"expo","purpose":"api_token","key":"EXPO_TOKEN","laneScope":"development","status":"active"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_credential_create"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"credentials",
			"create",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"expo",
			"--purpose",
			"api_token",
			"--key",
			"EXPO_TOKEN",
			"--lane",
			"development",
			"--value-env",
			"EXPO_TOKEN",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if requestBody["value"] != secretValue {
		t.Fatalf("expected request to carry env secret value, got %#v", requestBody)
	}
	if strings.Contains(stdout.String(), secretValue) || strings.Contains(stderr.String(), secretValue) {
		t.Fatalf("CLI output leaked secret\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "created credential pfsec_cli expo EXPO_TOKEN development") {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
}

func TestManagementCommandsUseSavedPreflightLoginConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "preflight", "config.json")
	t.Setenv("PREFLIGHT_CONFIG_PATH", configPath)
	t.Setenv("EXPO_TOKEN", "saved_config_expo_token")

	var workspaces []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer management_token_123" {
			t.Fatalf("expected saved Preflight auth token, got %q for %s %s", r.Header.Get("Authorization"), r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/secret-refs":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode credential body: %v", err)
			}
			workspaces = append(workspaces, fmt.Sprint(body["workspaceId"]))
			_, _ = w.Write([]byte(`{"data":{"secretReference":{"id":"pfsec_saved","workspaceId":"ws_management_saved","appId":"pfapp_mobile","provider":"expo","purpose":"api_token","key":"EXPO_TOKEN","laneScope":"development","status":"active"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_credential_create"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/secret-refs":
			workspaces = append(workspaces, r.URL.Query().Get("workspaceId"))
			_, _ = w.Write([]byte(`{"data":{"secretReferences":[{"id":"pfsec_saved","workspaceId":"ws_management_saved","appId":"pfapp_mobile","provider":"expo","key":"EXPO_TOKEN","laneScope":"development","status":"active"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_credential_list"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			workspaces = append(workspaces, fmt.Sprint(body["workspaceId"]))
			_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_saved","workspaceId":"ws_management_saved","appId":"pfapp_mobile","provider":"expo","displayName":"Expo","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_provider_upsert"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/provider-accounts":
			workspaces = append(workspaces, r.URL.Query().Get("workspaceId"))
			_, _ = w.Write([]byte(`{"data":{"providerAccounts":[{"id":"pfprov_saved","workspaceId":"ws_management_saved","appId":"pfapp_mobile","provider":"expo","displayName":"Expo","status":"connected"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_provider_list"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			workspaces = append(workspaces, fmt.Sprint(body["workspaceId"]))
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_saved","workspaceId":"ws_management_saved","appId":"pfapp_mobile","provider":"expo","capability":"eas.api.auth","status":"ready"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_readiness_record"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			workspaces = append(workspaces, r.URL.Query().Get("workspaceId"))
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":[{"id":"pfready_saved","workspaceId":"ws_management_saved","appId":"pfapp_mobile","provider":"expo","capability":"eas.api.auth","status":"ready"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_readiness_list"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	if err := savePreflightCLIConfig(preflightCLIConfig{
		APIVersion:        "v1",
		APIURL:            server.URL,
		Token:             "management_token_123",
		WorkspaceID:       "ws_management_saved",
		WorkspaceBindings: map[string]string{},
	}); err != nil {
		t.Fatalf("save CLI config: %v", err)
	}

	commands := [][]string{
		{"credentials", "create", "--app-id", "pfapp_mobile", "--provider", "expo", "--purpose", "api_token", "--key", "EXPO_TOKEN", "--lane", "development", "--value-env", "EXPO_TOKEN"},
		{"credentials", "list", "--app-id", "pfapp_mobile", "--provider", "expo"},
		{"providers", "upsert", "--app-id", "pfapp_mobile", "--provider", "expo", "--display-name", "Expo", "--status", "connected"},
		{"providers", "list", "--app-id", "pfapp_mobile", "--provider", "expo"},
		{"provider-readiness", "record", "--app-id", "pfapp_mobile", "--provider", "expo", "--capability", "eas.api.auth", "--status", "ready"},
		{"provider-readiness", "list", "--app-id", "pfapp_mobile", "--provider", "expo"},
	}
	for _, command := range commands {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(command, &stdout, &stderr, server.Client())
		if code != 0 {
			t.Fatalf("run(%v) exit = %d\nstdout: %s\nstderr: %s", command, code, stdout.String(), stderr.String())
		}
	}

	if len(workspaces) != len(commands) {
		t.Fatalf("expected workspace capture for every command, got %#v", workspaces)
	}
	for _, workspaceID := range workspaces {
		if workspaceID != "ws_management_saved" {
			t.Fatalf("expected saved workspace for all management commands, got %#v", workspaces)
		}
	}
}

func TestProvidersUpsertAndListUsePreflightAPI(t *testing.T) {
	var calls []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			if body["provider"] != "app_store_connect" || body["displayName"] != "Apple Developer Team" {
				t.Fatalf("unexpected provider body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_cli","workspaceId":"local","appId":"pfapp_mobile","provider":"app_store_connect","displayName":"Apple Developer Team","externalIds":{"teamId":"TEAM123","ascAppId":"1234567890"},"capabilities":["asc.testflight.submit"],"credentialReferenceIds":["pfsec_asc"],"status":"connected","metadata":{}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_provider_upsert"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/provider-accounts":
			_, _ = w.Write([]byte(`{"data":{"providerAccounts":[{"id":"pfprov_cli","workspaceId":"local","appId":"pfapp_mobile","provider":"app_store_connect","displayName":"Apple Developer Team","externalIds":{"teamId":"TEAM123"},"capabilities":["asc.testflight.submit"],"credentialReferenceIds":["pfsec_asc"],"status":"connected","metadata":{}}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_provider_list"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var upsertOut bytes.Buffer
	code := run(
		[]string{
			"providers",
			"upsert",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"app_store_connect",
			"--display-name",
			"Apple Developer Team",
			"--external-id",
			"teamId=TEAM123",
			"--external-id",
			"ascAppId=1234567890",
			"--capability",
			"asc.testflight.submit",
			"--credential-ref",
			"pfsec_asc",
			"--status",
			"connected",
		},
		&upsertOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("upsert exit = %d, stdout = %s", code, upsertOut.String())
	}
	if !strings.Contains(upsertOut.String(), "provider account pfprov_cli app_store_connect connected") {
		t.Fatalf("unexpected upsert output %q", upsertOut.String())
	}

	var listOut bytes.Buffer
	code = run(
		[]string{
			"providers",
			"list",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"app_store_connect",
		},
		&listOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("list exit = %d, stdout = %s", code, listOut.String())
	}
	if !strings.Contains(listOut.String(), "pfprov_cli app_store_connect connected Apple Developer Team") {
		t.Fatalf("unexpected list output %q", listOut.String())
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 API calls, got %v", calls)
	}
	if !strings.Contains(calls[1], "workspaceId=local") || !strings.Contains(calls[1], "provider=app_store_connect") {
		t.Fatalf("list call did not include filters: %s", calls[1])
	}
}

func TestOAuthClientsUpsertAndListUsePreflightAPI(t *testing.T) {
	var upsertBody map[string]any
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/oauth-clients":
			if err := json.NewDecoder(r.Body).Decode(&upsertBody); err != nil {
				t.Fatalf("decode OAuth client body: %v", err)
			}
			if upsertBody["provider"] != "google_oauth" || upsertBody["clientKind"] != "google_android" {
				t.Fatalf("unexpected OAuth client body %#v", upsertBody)
			}
			_, _ = w.Write([]byte(`{"data":{"oauthClient":{"id":"pfoauth_cli","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google","provider":"google_oauth","clientKind":"google_android","displayName":"ForgeGraph Android OAuth","externalClientId":"123-android.apps.googleusercontent.com","androidPackage":"com.gmacko.forgegraph.dev","androidSha1Fingerprint":"AA:BB","status":"configured","secretReferenceIds":[]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_upsert"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/oauth-clients":
			_, _ = w.Write([]byte(`{"data":{"oauthClients":[{"id":"pfoauth_cli","workspaceId":"local","appId":"pfapp_mobile","provider":"google_oauth","clientKind":"google_android","displayName":"ForgeGraph Android OAuth","status":"configured"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_list"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var upsertOut bytes.Buffer
	code := run(
		[]string{
			"oauth-clients",
			"upsert",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider-account-id",
			"pfprov_google",
			"--provider",
			"google_oauth",
			"--client-kind",
			"google_android",
			"--display-name",
			"ForgeGraph Android OAuth",
			"--external-client-id",
			"123-android.apps.googleusercontent.com",
			"--android-package",
			"com.gmacko.forgegraph.dev",
			"--android-sha1",
			"AA:BB",
			"--scope",
			"openid",
			"--scope",
			"email",
			"--status",
			"configured",
		},
		&upsertOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("oauth upsert exit = %d, stdout = %s", code, upsertOut.String())
	}
	if !strings.Contains(upsertOut.String(), "oauth client pfoauth_cli google_oauth google_android configured") {
		t.Fatalf("unexpected upsert output %q", upsertOut.String())
	}
	scopes, ok := upsertBody["scopes"].([]any)
	if !ok || fmt.Sprint(scopes) != "[openid email]" {
		t.Fatalf("unexpected scopes %#v", upsertBody["scopes"])
	}

	var listOut bytes.Buffer
	code = run(
		[]string{
			"oauth-clients",
			"list",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"google_oauth",
		},
		&listOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("oauth list exit = %d, stdout = %s", code, listOut.String())
	}
	if !strings.Contains(listOut.String(), "pfoauth_cli google_oauth google_android configured ForgeGraph Android OAuth") {
		t.Fatalf("unexpected list output %q", listOut.String())
	}
	if len(calls) != 2 || !strings.Contains(calls[1], "provider=google_oauth") {
		t.Fatalf("unexpected OAuth client API calls %v", calls)
	}
}

func TestTargetsUpsertAndListUseStandalonePreflightAPI(t *testing.T) {
	var upsertBody map[string]any
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer target_token" {
			t.Fatalf("expected bearer token, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-preflight-workspace-id") != "ws_targets" {
			t.Fatalf("expected workspace header, got %q", r.Header.Get("x-preflight-workspace-id"))
		}
		if r.Header.Get("x-preflight-user-id") != "preflight-cli" {
			t.Fatalf("expected CLI user header, got %q", r.Header.Get("x-preflight-user-id"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/targets":
			if err := json.NewDecoder(r.Body).Decode(&upsertBody); err != nil {
				t.Fatalf("decode target body: %v", err)
			}
			if upsertBody["workspaceId"] != "ws_targets" ||
				upsertBody["runnerId"] != "pfrun_cli" ||
				upsertBody["platform"] != "ios" ||
				upsertBody["kind"] != "ios_simulator" ||
				upsertBody["targetKey"] != "ios-sim:SIM-UDID" ||
				upsertBody["providerIdentity"] != "SIM-UDID" {
				t.Fatalf("unexpected target body %#v", upsertBody)
			}
			capabilities := upsertBody["capabilities"].(map[string]any)
			if capabilities["runtime"] != "iOS 19.0" || capabilities["source"] != "simctl" {
				t.Fatalf("unexpected target capabilities %#v", capabilities)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pftgt_ios_sim","workspaceId":"ws_targets","runnerId":"pfrun_cli","platform":"ios","kind":"ios_simulator","targetKey":"ios-sim:SIM-UDID","displayName":"iPhone 16 Pro","providerIdentity":"SIM-UDID","availability":"available"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/targets":
			if r.URL.Query().Get("platform") != "ios" ||
				r.URL.Query().Get("kind") != "ios_simulator" ||
				r.URL.Query().Get("runnerId") != "pfrun_cli" {
				t.Fatalf("unexpected target list query %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"pftgt_ios_sim","workspaceId":"ws_targets","runnerId":"pfrun_cli","platform":"ios","kind":"ios_simulator","targetKey":"ios-sim:SIM-UDID","displayName":"iPhone 16 Pro","providerIdentity":"SIM-UDID","availability":"available"}]}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("PREFLIGHT_TOKEN", "target_token")

	var upsertOut bytes.Buffer
	code := run(
		[]string{
			"targets",
			"upsert",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_targets",
			"--runner-id",
			"pfrun_cli",
			"--platform",
			"ios",
			"--kind",
			"ios_simulator",
			"--target-key",
			"ios-sim:SIM-UDID",
			"--display-name",
			"iPhone 16 Pro",
			"--provider-identity",
			"SIM-UDID",
			"--availability",
			"available",
			"--capability",
			"runtime=iOS 19.0",
			"--capability",
			"source=simctl",
		},
		&upsertOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("target upsert exit = %d, stdout = %s", code, upsertOut.String())
	}
	if !strings.Contains(upsertOut.String(), "target pftgt_ios_sim ios ios_simulator available iPhone 16 Pro") {
		t.Fatalf("unexpected target upsert output %q", upsertOut.String())
	}

	var listOut bytes.Buffer
	code = run(
		[]string{
			"targets",
			"list",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_targets",
			"--platform",
			"ios",
			"--kind",
			"ios_simulator",
			"--runner-id",
			"pfrun_cli",
		},
		&listOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("target list exit = %d, stdout = %s", code, listOut.String())
	}
	if !strings.Contains(listOut.String(), "pftgt_ios_sim ios ios_simulator available iPhone 16 Pro") {
		t.Fatalf("unexpected target list output %q", listOut.String())
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 API calls, got %v", calls)
	}
}

func TestProveAppStandaloneSimulatorPlanUsesDerivedAppAndPreflightAPI(t *testing.T) {
	appDir := writeExpoFixture(t)
	t.Setenv("PREFLIGHT_TOKEN", "standalone_token")

	var planBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/apps/pfapp_forgegraph_mobile/simulator-proof-plans" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer standalone_token" {
			t.Fatalf("expected bearer token, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-preflight-workspace-id") != "ws_standalone" {
			t.Fatalf("expected workspace header, got %q", r.Header.Get("x-preflight-workspace-id"))
		}
		if err := json.NewDecoder(r.Body).Decode(&planBody); err != nil {
			t.Fatalf("decode simulator plan body: %v", err)
		}
		if planBody["workspaceId"] != "ws_standalone" ||
			planBody["workflowId"] != "pfw_cli_sim" ||
			planBody["platform"] != "ios" ||
			planBody["targetKind"] != "ios_simulator" ||
			planBody["targetKey"] != "SIM-UDID" ||
			planBody["appScheme"] != "forgegraph" ||
			planBody["port"] != float64(19000) {
			t.Fatalf("unexpected simulator plan body %#v", planBody)
		}
		if planBody["flowPath"] != filepath.Join(appDir, ".maestro", "01-app-launches.yaml") {
			t.Fatalf("unexpected flowPath %#v", planBody["flowPath"])
		}
		_, _ = w.Write([]byte(`{"data":{"workflowId":"pfw_cli_sim","platform":"ios","targetKind":"ios_simulator","targetKey":"SIM-UDID","advertisedUrl":"http://127.0.0.1:19000","commands":[{"id":"expo_start","title":"Start Expo development server","kind":"long_running","command":"npx","args":["expo","start","--localhost","--dev-client","--port","19000"],"cwd":"/app"},{"id":"open_development_client","title":"Open development client on iOS simulator","kind":"one_shot","command":"xcrun","args":["simctl","openurl","SIM-UDID","forgegraph://expo-development-client/?url=http%3A%2F%2F127.0.0.1%3A19000"]},{"id":"maestro","title":"Run Maestro flow","kind":"one_shot","command":"maestro","args":["--device","SIM-UDID","test","--format","junit","--output","/runtime-artifacts/maestro/report.xml","--test-output-dir","/runtime-artifacts/maestro/output","/app/.maestro/01-app-launches.yaml"]}]}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--standalone-plan",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_standalone",
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--target-kind",
			"ios_simulator",
			"--target-key",
			"SIM-UDID",
			"--workflow-id",
			"pfw_cli_sim",
			"--port",
			"19000",
		},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("standalone prove-app exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "simulator proof plan pfw_cli_sim ios ios_simulator") ||
		!strings.Contains(stdout.String(), "npx expo start --localhost --dev-client --port 19000") ||
		!strings.Contains(stdout.String(), "maestro --device SIM-UDID test --format junit") {
		t.Fatalf("unexpected standalone plan output %q", stdout.String())
	}
}

func TestProveAppStandaloneRunExecutesPlanAndPostsRuntimeState(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	for name, script := range map[string]string{
		"npx": `#!/usr/bin/env sh
printf 'npx %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
sleep 30
`,
		"xcrun": `#!/usr/bin/env sh
printf 'xcrun %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
`,
		"maestro": `#!/usr/bin/env sh
printf 'maestro %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
`,
	} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_COMMAND_LOG", commandLog)
	t.Setenv("PREFLIGHT_TOKEN", "standalone_run_token")

	var calls []string
	var devSessionBody map[string]any
	var targetSessionBody map[string]any
	var targetRunBodies []map[string]any
	var artifactBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer standalone_run_token" {
			t.Fatalf("expected bearer token, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-preflight-workspace-id") != "ws_run" {
			t.Fatalf("expected workspace header, got %q", r.Header.Get("x-preflight-workspace-id"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/simulator-proof-plans":
			_, _ = fmt.Fprintf(w, `{"data":{"workflowId":"pfw_run","platform":"ios","targetKind":"ios_simulator","targetKey":"SIM-UDID","advertisedUrl":"http://127.0.0.1:19000","devSession":{"id":"pfds_run","workspaceId":"ws_run","appId":"pfapp_forgegraph_mobile","workflowId":"pfw_run","platform":"ios","lane":"simulator","targetKind":"ios_simulator","hostMode":"localhost","status":"starting","appScheme":"forgegraph","advertisedUrl":"http://127.0.0.1:19000","port":19000,"metadata":{}},"targetSession":{"id":"pftsess_run","workspaceId":"ws_run","appId":"pfapp_forgegraph_mobile","targetId":"SIM-UDID","devSessionId":"pfds_run","workflowId":"pfw_run","status":"opening","openedUrl":"forgegraph://expo-development-client/?url=http%%3A%%2F%%2F127.0.0.1%%3A19000","metadata":{}},"targetRun":{"id":"pftrun_run","workspaceId":"ws_run","appId":"pfapp_forgegraph_mobile","targetId":"SIM-UDID","workflowId":"pfw_run","targetSessionId":"pftsess_run","status":"queued","flowPath":%q,"resultSummary":{},"metadata":{"format":"junit"}},"commands":[{"id":"expo_start","title":"Start Expo development server","kind":"long_running","command":"npx","args":["expo","start","--localhost","--dev-client","--port","19000"],"cwd":%q},{"id":"open_development_client","title":"Open development client on iOS simulator","kind":"one_shot","command":"xcrun","args":["simctl","openurl","SIM-UDID","forgegraph://expo-development-client/?url=http%%3A%%2F%%2F127.0.0.1%%3A19000"]},{"id":"maestro","title":"Run Maestro flow","kind":"one_shot","command":"maestro","args":["--device","SIM-UDID","test","--format","junit","--output","%s","%s"]}]}}`, filepath.Join(appDir, ".maestro", "01-app-launches.yaml"), appDir, filepath.Join(appDir, ".preflight", "simulator-proofs", "pfw_run", "maestro", "report.xml"), filepath.Join(appDir, ".maestro", "01-app-launches.yaml"))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/dev-sessions":
			if err := json.NewDecoder(r.Body).Decode(&devSessionBody); err != nil {
				t.Fatalf("decode dev session body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pfds_run","status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/target-sessions":
			if err := json.NewDecoder(r.Body).Decode(&targetSessionBody); err != nil {
				t.Fatalf("decode target session body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pftsess_run","status":"open"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/target-runs":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode target run body: %v", err)
			}
			targetRunBodies = append(targetRunBodies, body)
			_, _ = w.Write([]byte(`{"data":{"id":"pftrun_run"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/runtime-artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact body: %v", err)
			}
			artifactBodies = append(artifactBodies, body)
			_, _ = w.Write([]byte(`{"data":{"id":"pfart_run"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--standalone-run",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_run",
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--target-kind",
			"ios_simulator",
			"--target-key",
			"SIM-UDID",
			"--workflow-id",
			"pfw_run",
			"--port",
			"19000",
		},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("standalone run exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if devSessionBody["status"] != "running" || devSessionBody["pid"] == nil {
		t.Fatalf("expected running dev session with pid, got %#v", devSessionBody)
	}
	if targetSessionBody["status"] != "open" {
		t.Fatalf("expected open target session, got %#v", targetSessionBody)
	}
	if len(targetRunBodies) != 2 || targetRunBodies[0]["status"] != "running" || targetRunBodies[1]["status"] != "passed" {
		t.Fatalf("expected running and passed target run updates, got %#v", targetRunBodies)
	}
	if len(artifactBodies) == 0 || artifactBodies[0]["redacted"] != true {
		t.Fatalf("expected redacted artifact posts, got %#v", artifactBodies)
	}
	logContent, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	for _, expected := range []string{
		"npx expo start --localhost --dev-client --port 19000",
		"xcrun simctl openurl SIM-UDID",
		"maestro --device SIM-UDID test --format junit",
	} {
		if !strings.Contains(string(logContent), expected) {
			t.Fatalf("expected command log to contain %q, got %q", expected, string(logContent))
		}
	}
	if countCalls(calls, "POST /api/preflight/v1/apps/pfapp_forgegraph_mobile/target-runs") != 2 {
		t.Fatalf("expected two target run posts, got calls %v", calls)
	}
}

func TestProveAppStandaloneSimulatorRunPostsMaestroArtifactMetadata(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	reportPath := filepath.Join(appDir, ".preflight", "simulator-proofs", "pfw_artifacts", "maestro", "report.xml")
	outputDir := filepath.Join(appDir, ".preflight", "simulator-proofs", "pfw_artifacts", "maestro", "output")
	for name, script := range map[string]string{
		"npx": `#!/usr/bin/env sh
printf 'npx %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
sleep 30
`,
		"xcrun": `#!/usr/bin/env sh
printf 'xcrun %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
`,
		"maestro": `#!/usr/bin/env sh
printf 'maestro %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
printf 'maestro stdout line\n'
printf 'maestro stderr line\n' >&2
report=""
output_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      report="$2"
      shift 2
      ;;
    --test-output-dir)
      output_dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$report")" "$output_dir"
printf '<testsuite tests="2" failures="0"></testsuite>\n' > "$report"
printf '{"commands":[]}\n' > "$output_dir/commands-1.json"
printf 'png\n' > "$output_dir/screenshot-1.png"
printf 'mp4\n' > "$output_dir/video-1.mp4"
`,
	} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_COMMAND_LOG", commandLog)
	t.Setenv("PREFLIGHT_TOKEN", "standalone_artifact_token")

	var targetRunBodies []map[string]any
	var artifactBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/simulator-proof-plans":
			_, _ = fmt.Fprintf(w, `{"data":{"workflowId":"pfw_artifacts","platform":"ios","targetKind":"ios_simulator","targetKey":"SIM-UDID","advertisedUrl":"http://127.0.0.1:19000","devSession":{"id":"pfds_artifacts","workspaceId":"ws_artifacts","appId":"pfapp_forgegraph_mobile","workflowId":"pfw_artifacts","platform":"ios","lane":"simulator","targetKind":"ios_simulator","hostMode":"localhost","status":"starting","appScheme":"forgegraph","advertisedUrl":"http://127.0.0.1:19000","port":19000,"metadata":{}},"targetSession":{"id":"pftsess_artifacts","workspaceId":"ws_artifacts","appId":"pfapp_forgegraph_mobile","targetId":"SIM-UDID","devSessionId":"pfds_artifacts","workflowId":"pfw_artifacts","status":"opening","openedUrl":"forgegraph://expo-development-client/?url=http%%3A%%2F%%2F127.0.0.1%%3A19000","metadata":{}},"targetRun":{"id":"pftrun_artifacts","workspaceId":"ws_artifacts","appId":"pfapp_forgegraph_mobile","targetId":"SIM-UDID","workflowId":"pfw_artifacts","targetSessionId":"pftsess_artifacts","status":"queued","flowPath":%q,"reportArtifactId":%q,"resultSummary":{},"metadata":{"format":"junit","testOutputDirectory":%q}},"commands":[{"id":"expo_start","kind":"long_running","command":"npx","args":["expo","start","--localhost","--dev-client","--port","19000"],"cwd":%q},{"id":"open_development_client","kind":"one_shot","command":"xcrun","args":["simctl","openurl","SIM-UDID","forgegraph://expo-development-client/?url=http%%3A%%2F%%2F127.0.0.1%%3A19000"]},{"id":"maestro","kind":"one_shot","command":"maestro","args":["--device","SIM-UDID","test","--format","junit","--output",%q,"--test-output-dir",%q,"%s"]}]}}`,
				filepath.Join(appDir, ".maestro", "01-app-launches.yaml"),
				reportPath,
				outputDir,
				appDir,
				reportPath,
				outputDir,
				filepath.Join(appDir, ".maestro", "01-app-launches.yaml"),
			)
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/dev-sessions":
			_, _ = w.Write([]byte(`{"data":{"id":"pfds_artifacts","status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/target-sessions":
			_, _ = w.Write([]byte(`{"data":{"id":"pftsess_artifacts","status":"open"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/target-runs":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode target run body: %v", err)
			}
			targetRunBodies = append(targetRunBodies, body)
			_, _ = w.Write([]byte(`{"data":{"id":"pftrun_artifacts"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/runtime-artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact body: %v", err)
			}
			artifactBodies = append(artifactBodies, body)
			_, _ = w.Write([]byte(`{"data":{"id":"pfart_recorded"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--standalone-run",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_artifacts",
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--target-kind",
			"ios_simulator",
			"--target-key",
			"SIM-UDID",
			"--workflow-id",
			"pfw_artifacts",
			"--port",
			"19000",
		},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("standalone simulator artifact run exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if len(targetRunBodies) != 2 {
		t.Fatalf("expected two target run posts, got %#v", targetRunBodies)
	}
	completed := targetRunBodies[1]
	if completed["reportArtifactId"] != reportPath {
		t.Fatalf("expected reportArtifactId %q, got %#v", reportPath, completed)
	}
	if len(artifactBodies) != 5 {
		t.Fatalf("expected five artifact posts, got %#v", artifactBodies)
	}
	if artifactBodies[0]["kind"] != "maestro_report" ||
		artifactBodies[0]["targetRunId"] != "pftrun_artifacts" ||
		artifactBodies[0]["uri"] != reportPath ||
		artifactBodies[0]["redacted"] != true {
		t.Fatalf("expected redacted Maestro report artifact, got %#v", artifactBodies[0])
	}
	resultSummary := completed["resultSummary"].(map[string]any)
	if resultSummary["reportPath"] != reportPath {
		t.Fatalf("expected result summary report path, got %#v", resultSummary)
	}
	metadata := completed["metadata"].(map[string]any)
	if metadata["testOutputDirectory"] != outputDir {
		t.Fatalf("expected output dir metadata, got %#v", metadata)
	}
	if len(metadata["screenshotPaths"].([]any)) != 1 ||
		len(metadata["videoPaths"].([]any)) != 1 ||
		len(metadata["commandPaths"].([]any)) != 1 {
		t.Fatalf("expected discovered artifact paths in metadata, got %#v", metadata)
	}
	logPath, ok := metadata["logPath"].(string)
	if !ok || logPath == "" {
		t.Fatalf("expected maestro log path in metadata, got %#v", metadata)
	}
	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read maestro log path: %v", err)
	}
	if !strings.Contains(string(logContent), "maestro stdout line") ||
		!strings.Contains(string(logContent), "maestro stderr line") {
		t.Fatalf("expected maestro stdout/stderr in log, got %q", string(logContent))
	}
}

func writeMaestroLaunchFixture(t *testing.T, appDir string) {
	t.Helper()
	maestroDir := filepath.Join(appDir, ".maestro")
	if err := os.MkdirAll(maestroDir, 0o755); err != nil {
		t.Fatalf("create Maestro fixture directory: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(maestroDir, "01-app-launches.yaml"),
		[]byte("appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n"),
		0o644,
	); err != nil {
		t.Fatalf("write Maestro fixture: %v", err)
	}
}

func TestProveAppStandaloneRunExecutesDevelopmentBuildPlanAndPostsResult(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeMaestroLaunchFixture(t, appDir)
	commandLog := filepath.Join(t.TempDir(), "eas-commands.log")
	artifactDir := filepath.Join(t.TempDir(), "runtime-artifacts")
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'eas %s EXPO_TOKEN=%s\n' "$*" "$EXPO_TOKEN" >> "$PREFLIGHT_COMMAND_LOG"
case "$1" in
  config)
    printf '{"projectId":"eas_project_123"}\n'
    ;;
  build)
    printf '{"id":"eas_build_123","status":"in-progress","platform":"ios","url":"https://expo.dev/accounts/acme/projects/mobile/builds/eas_build_123"}\n'
    ;;
  build:view)
    if [ "$2" != "eas_build_123" ]; then
      printf 'unexpected build id %s\n' "$2" >&2
      exit 2
    fi
    printf '{"id":"eas_build_123","status":"finished","platform":"ios","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/eas_build_123.ipa"},"logsUrl":"https://expo.dev/builds/eas_build_123/logs"}\n'
    ;;
  *)
    printf 'unexpected eas command %s\n' "$*" >&2
    exit 2
    ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf 'npx %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
printf 'npx %s\n' "$*"
printf 'exp+forgegraf://expo-development-client/?url=https%%3A%%2F%%2Fpreflight-tunnel.ngrok-free.app\n'
sleep 30
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_COMMAND_LOG", commandLog)
	t.Setenv("PREFLIGHT_TOKEN", "standalone_dev_token")
	t.Setenv("EXPO_TOKEN", "expo_token_123")

	var planBody map[string]any
	var sessionPlanBody map[string]any
	var resultBody map[string]any
	var devSessionBody map[string]any
	var targetSessionBody map[string]any
	var artifactBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer standalone_dev_token" {
			t.Fatalf("expected bearer token, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-preflight-workspace-id") != "ws_dev" {
			t.Fatalf("expected workspace header, got %q", r.Header.Get("x-preflight-workspace-id"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-plans":
			if err := json.NewDecoder(r.Body).Decode(&planBody); err != nil {
				t.Fatalf("decode plan body: %v", err)
			}
			buildProfile := fmt.Sprint(planBody["buildProfile"])
			_, _ = fmt.Fprintf(w, `{"data":{"workflowId":"pfw_dev","platform":"ios","targetKind":"iphone","requiredSecrets":["expoToken"],"build":{"id":"pfbuild_pfw_dev","appId":"pfapp_forgegraph_mobile","platform":"ios","profile":%q,"version":"1.2.3","environment":"development","status":"queued"},"installation":{"id":"pfinstall_pfw_dev","workspaceId":"ws_dev","appId":"pfapp_forgegraph_mobile","targetId":"pftarget_iphone","buildId":"pfbuild_pfw_dev","workflowId":"pfw_dev","status":"installing","installUrl":"","metadata":{}},"commands":[{"id":"eas_config","title":"Read EAS project configuration","kind":"one_shot","command":"eas","args":["config","--platform","ios","--profile",%q,"--json","--non-interactive"],"cwd":%q,"env":{"EXPO_NO_TELEMETRY":"1","EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q},{"id":"eas_build","title":"Create EAS development build","kind":"one_shot","command":"eas","args":["build","--platform","ios","--profile",%q,"--message","Preflight iOS development build","--json","--non-interactive"],"cwd":%q,"env":{"EXPO_NO_TELEMETRY":"1","EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q},{"id":"eas_build_view","title":"Refresh EAS build status","kind":"one_shot","command":"eas","args":["build:view","${EAS_BUILD_ID}","--json"],"cwd":%q,"env":{"EXPO_NO_TELEMETRY":"1","EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q}]}}`,
				buildProfile,
				buildProfile,
				appDir,
				filepath.Join(artifactDir, "eas", "config.json"),
				buildProfile,
				appDir,
				filepath.Join(artifactDir, "eas", "build.json"),
				appDir,
				filepath.Join(artifactDir, "eas", "build-view.json"),
			)
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-results":
			if err := json.NewDecoder(r.Body).Decode(&resultBody); err != nil {
				t.Fatalf("decode result body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"build":{"id":"pfbuild_pfw_dev","status":"completed"},"installation":{"id":"pfinstall_pfw_dev","status":"installed"}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-session-plans":
			if err := json.NewDecoder(r.Body).Decode(&sessionPlanBody); err != nil {
				t.Fatalf("decode development session plan body: %v", err)
			}
			_, _ = fmt.Fprintf(w, `{"data":{"workflowId":"pfw_dev","platform":"ios","targetKind":"iphone","targetId":"pftarget_iphone","advertisedUrl":"${EXPO_TUNNEL_URL}","deepLinkUrl":"forgegraph://expo-development-client/?url=%%24%%7BEXPO_TUNNEL_URL%%7D","qrUrl":"https://qr.expo.dev/development-client?appScheme=forgegraph&url=%%24%%7BEXPO_TUNNEL_URL%%7D","devSession":{"id":"pfds_pfw_dev","workspaceId":"ws_dev","appId":"pfapp_forgegraph_mobile","buildId":"pfbuild_pfw_dev","workflowId":"pfw_dev","platform":"ios","lane":"development","targetKind":"iphone","hostMode":"tunnel","status":"starting","appScheme":"forgegraph","advertisedUrl":"${EXPO_TUNNEL_URL}","deepLinkUrl":"forgegraph://expo-development-client/?url=%%24%%7BEXPO_TUNNEL_URL%%7D","qrUrl":"https://qr.expo.dev/development-client?appScheme=forgegraph&url=%%24%%7BEXPO_TUNNEL_URL%%7D","installUrl":"https://expo.dev/runtime-artifacts/eas_build_123.ipa","port":19000,"metadata":{}},"targetSession":{"id":"pftsess_pfw_dev","workspaceId":"ws_dev","appId":"pfapp_forgegraph_mobile","targetId":"pftarget_iphone","devSessionId":"pfds_pfw_dev","workflowId":"pfw_dev","status":"opening","openedUrl":"forgegraph://expo-development-client/?url=%%24%%7BEXPO_TUNNEL_URL%%7D","metadata":{}},"commands":[{"id":"expo_start_tunnel","kind":"long_running","command":"npx","args":["expo","start","--tunnel","--dev-client","--port","19000"],"cwd":%q,"env":{"EXPO_NO_TELEMETRY":"1"}}]}}`, appDir)
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/dev-sessions":
			if err := json.NewDecoder(r.Body).Decode(&devSessionBody); err != nil {
				t.Fatalf("decode dev session body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pfds_pfw_dev","status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/target-sessions":
			if err := json.NewDecoder(r.Body).Decode(&targetSessionBody); err != nil {
				t.Fatalf("decode target session body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pftsess_pfw_dev","status":"opening"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/runtime-artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact body: %v", err)
			}
			artifactBodies = append(artifactBodies, body)
			if body["kind"] == "qr_code" {
				_, _ = w.Write([]byte(`{"data":{"id":"pfart_qr"}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"id":"pfart_eas"}}`))
			}
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--standalone-run",
			"--lane",
			"development",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_dev",
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--target-kind",
			"iphone",
			"--target-id",
			"pftarget_iphone",
			"--workflow-id",
			"pfw_dev",
			"--version",
			"1.2.3",
			"--artifact-dir",
			artifactDir,
		},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("standalone development run exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if planBody["targetId"] != "pftarget_iphone" || planBody["version"] != "1.2.3" || planBody["buildProfile"] != "development-device" {
		t.Fatalf("unexpected development build plan body %#v", planBody)
	}
	if resultBody["planBuildId"] != "pfbuild_pfw_dev" ||
		resultBody["planInstallationId"] != "pfinstall_pfw_dev" ||
		resultBody["targetId"] != "pftarget_iphone" ||
		resultBody["version"] != "1.2.3" {
		t.Fatalf("unexpected development build result body %#v", resultBody)
	}
	if sessionPlanBody["buildId"] != "pfbuild_pfw_dev" ||
		sessionPlanBody["targetId"] != "pftarget_iphone" ||
		sessionPlanBody["targetKind"] != "iphone" {
		t.Fatalf("unexpected development session plan body %#v", sessionPlanBody)
	}
	if devSessionBody["status"] != "running" ||
		devSessionBody["pid"] == nil ||
		devSessionBody["hostMode"] != "tunnel" {
		t.Fatalf("expected running tunnel dev session, got %#v", devSessionBody)
	}
	if devSessionBody["advertisedUrl"] != "https://preflight-tunnel.ngrok-free.app" ||
		devSessionBody["deepLinkUrl"] != "forgegraph://expo-development-client/?url=https%3A%2F%2Fpreflight-tunnel.ngrok-free.app" ||
		devSessionBody["qrUrl"] != "https://qr.expo.dev/development-client?appScheme=forgegraph&url=https%3A%2F%2Fpreflight-tunnel.ngrok-free.app" {
		t.Fatalf("expected observed Expo tunnel URL in dev session, got %#v", devSessionBody)
	}
	if devSessionBody["qrArtifactId"] != "pfart_qr" || devSessionBody["qrPayloadPath"] == "" {
		t.Fatalf("expected QR artifact evidence on development dev session, got %#v", devSessionBody)
	}
	if devSessionBody["logPath"] == "" {
		t.Fatalf("expected Expo tunnel log evidence on development dev session, got %#v", devSessionBody)
	}
	if targetSessionBody["status"] != "opening" ||
		targetSessionBody["targetId"] != "pftarget_iphone" {
		t.Fatalf("expected target session opening for physical device, got %#v", targetSessionBody)
	}
	easBuild := resultBody["easBuild"].(map[string]any)
	if easBuild["id"] != "eas_build_123" || easBuild["status"] != "finished" {
		t.Fatalf("expected final EAS build:view JSON, got %#v", easBuild)
	}
	if len(artifactBodies) != 5 {
		t.Fatalf("expected three EAS artifact posts plus QR and log artifact posts, got %#v", artifactBodies)
	}
	for index, expectedURI := range []string{
		filepath.Join(artifactDir, "eas", "config.json"),
		filepath.Join(artifactDir, "eas", "build.json"),
		filepath.Join(artifactDir, "eas", "build-view.json"),
	} {
		artifact := artifactBodies[index]
		if artifact["kind"] != "tool_output" ||
			artifact["workflowId"] != "pfw_dev" ||
			artifact["buildId"] != "pfbuild_pfw_dev" ||
			artifact["uri"] != expectedURI ||
			artifact["contentType"] != "application/json" ||
			artifact["redacted"] != true {
			t.Fatalf("expected redacted EAS artifact %d for %q, got %#v", index, expectedURI, artifact)
		}
	}
	qrArtifact := artifactBodies[3]
	if qrArtifact["kind"] != "qr_code" ||
		qrArtifact["workflowId"] != "pfw_dev" ||
		qrArtifact["buildId"] != "pfbuild_pfw_dev" ||
		qrArtifact["targetId"] != "pftarget_iphone" ||
		qrArtifact["contentType"] != "application/json" ||
		qrArtifact["redacted"] != true {
		t.Fatalf("expected redacted QR runtime artifact, got %#v", qrArtifact)
	}
	qrMetadata := qrArtifact["metadata"].(map[string]any)
	if qrMetadata["qrUrl"] != "https://qr.expo.dev/development-client?appScheme=forgegraph&url=https%3A%2F%2Fpreflight-tunnel.ngrok-free.app" ||
		qrMetadata["deepLinkUrl"] != "forgegraph://expo-development-client/?url=https%3A%2F%2Fpreflight-tunnel.ngrok-free.app" ||
		qrMetadata["installUrl"] != "https://expo.dev/runtime-artifacts/eas_build_123.ipa" {
		t.Fatalf("unexpected QR metadata %#v", qrMetadata)
	}
	qrPayload, err := os.ReadFile(fmt.Sprint(qrArtifact["uri"]))
	if err != nil {
		t.Fatalf("read QR payload artifact: %v", err)
	}
	if !strings.Contains(string(qrPayload), "https://qr.expo.dev/development-client") ||
		!strings.Contains(string(qrPayload), "forgegraph://expo-development-client/") ||
		!strings.Contains(string(qrPayload), "https://preflight-tunnel.ngrok-free.app") {
		t.Fatalf("expected QR payload to preserve Expo QR/deep-link evidence, got %q", string(qrPayload))
	}
	logArtifact := artifactBodies[4]
	if logArtifact["kind"] != "log" ||
		logArtifact["workflowId"] != "pfw_dev" ||
		logArtifact["buildId"] != "pfbuild_pfw_dev" ||
		logArtifact["targetId"] != "pftarget_iphone" ||
		logArtifact["contentType"] != "text/plain" ||
		logArtifact["redacted"] != true {
		t.Fatalf("expected redacted Expo tunnel log artifact, got %#v", logArtifact)
	}
	logPayload, err := os.ReadFile(fmt.Sprint(logArtifact["uri"]))
	if err != nil {
		t.Fatalf("read Expo tunnel log artifact: %v", err)
	}
	if !strings.Contains(string(logPayload), "expo-development-client") ||
		!strings.Contains(string(logPayload), "https%3A%2F%2Fpreflight-tunnel.ngrok-free.app") {
		t.Fatalf("expected Expo tunnel log to preserve startup output, got %q", string(logPayload))
	}
	logContent, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	for _, expected := range []string{
		"eas config --platform ios --profile development-device --json --non-interactive EXPO_TOKEN=expo_token_123",
		"eas build --platform ios --profile development-device --message Preflight iOS development build --json --non-interactive EXPO_TOKEN=expo_token_123",
		"eas build:view eas_build_123 --json EXPO_TOKEN=expo_token_123",
		"npx expo start --tunnel --dev-client --port 19000",
	} {
		if !strings.Contains(string(logContent), expected) {
			t.Fatalf("expected command log to contain %q, got %q", expected, string(logContent))
		}
	}
	buildArtifact, err := os.ReadFile(filepath.Join(artifactDir, "eas", "build-view.json"))
	if err != nil {
		t.Fatalf("read EAS build-view artifact: %v", err)
	}
	if !strings.Contains(string(buildArtifact), `"status":"finished"`) {
		t.Fatalf("expected build-view artifact to contain finished JSON, got %q", string(buildArtifact))
	}
	if !strings.Contains(stdout.String(), "development build run pfw_dev posted eas_build_123") {
		t.Fatalf("expected run summary, got stdout %q", stdout.String())
	}
}

func TestProveAppStandaloneRunPostsPreviewBuildWithoutDevelopmentSession(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeMaestroLaunchFixture(t, appDir)
	artifactDir := filepath.Join(t.TempDir(), "runtime-artifacts")
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s\n' "$*" >> "$COMMAND_LOG"
case "$1" in
  config)
    printf '{"projectId":"eas_project_preview"}\n'
    ;;
  build)
    printf 'build-env CI=%s EXPO_NO_INTERACTIVE=%s\n' "${CI-unset}" "${EXPO_NO_INTERACTIVE-unset}" >> "$COMMAND_LOG"
    printf '{"id":"eas_build_preview","status":"in-progress","platform":"ios"}\n'
    ;;
  build:list)
    printf '[{"id":"eas_build_preview","status":"in-progress","platform":"ios"}]\n'
    ;;
  build:view)
    printf '{"id":"eas_build_preview","status":"finished","platform":"ios","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/eas_build_preview.ipa"}}\n'
    ;;
  *)
    exit 2
    ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_TOKEN", "standalone_preview_token")
	t.Setenv("EXPO_TOKEN", "expo_token_preview")
	t.Setenv("COMMAND_LOG", commandLog)

	var resultBody map[string]any
	sessionPlanCalls := 0
	resultPosted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-plans":
			_, _ = fmt.Fprintf(w, `{"data":{"plan":{"workflowId":"pfw_preview","platform":"ios","targetKind":"iphone","build":{"id":"pfbuild_pfw_preview","appId":"pfapp_forgegraph_mobile","platform":"ios","profile":"preview","version":"1.2.3","environment":"preview","status":"queued"},"installation":{"id":"pfinstall_pfw_preview","workspaceId":"ws_preview","appId":"pfapp_forgegraph_mobile","targetId":"pftarget_iphone","buildId":"pfbuild_pfw_preview","workflowId":"pfw_preview","status":"installing","installUrl":"","metadata":{"buildProfile":"preview"}},"commands":[{"id":"eas_config","kind":"one_shot","command":"eas","args":["config","--platform","ios","--profile","preview","--json","--non-interactive"],"cwd":%q,"env":{"EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q},{"id":"eas_build","kind":"one_shot","command":"eas","args":["build","--platform","ios","--profile","preview","--json","--non-interactive"],"cwd":%q,"env":{"EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q},{"id":"eas_build_view","kind":"one_shot","command":"eas","args":["build:view","${EAS_BUILD_ID}","--json"],"cwd":%q,"env":{"EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q}]}}}`,
				appDir,
				filepath.Join(artifactDir, "eas", "config.json"),
				appDir,
				filepath.Join(artifactDir, "eas", "build.json"),
				appDir,
				filepath.Join(artifactDir, "eas", "build-view.json"),
			)
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-results":
			if err := json.NewDecoder(r.Body).Decode(&resultBody); err != nil {
				t.Fatalf("decode result body: %v", err)
			}
			resultPosted = true
			_, _ = w.Write([]byte(`{"data":{"build":{"id":"pfbuild_pfw_preview","status":"completed"},"installation":{"id":"pfinstall_pfw_preview","status":"installed"}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/runtime-artifacts":
			if !resultPosted {
				http.Error(w, "build result must be persisted before artifacts", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"id":"pfart_preview"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-session-plans":
			sessionPlanCalls++
			http.Error(w, "preview must not start a development session", http.StatusBadRequest)
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app", "--standalone-run", "--lane", "development",
			"--interactive-setup",
			"--api-url", server.URL, "--workspace-id", "ws_preview",
			"--app-dir", appDir, "--platform", "ios", "--target-kind", "iphone",
			"--target-id", "pftarget_iphone", "--workflow-id", "pfw_preview",
			"--build-profile", "preview", "--version", "1.2.3",
			"--artifact-dir", artifactDir,
		},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("standalone preview run exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if resultBody["buildProfile"] != "preview" {
		t.Fatalf("expected preview result profile, got %#v", resultBody)
	}
	if sessionPlanCalls != 0 {
		t.Fatalf("expected no development session for preview, got %d calls", sessionPlanCalls)
	}
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if strings.Contains(string(commands), "build --platform ios --profile preview --json") ||
		strings.Contains(string(commands), "build --platform ios --profile preview --non-interactive") {
		t.Fatalf("interactive setup must remove JSON and non-interactive flags from EAS build, got %q", string(commands))
	}
	if !strings.Contains(string(commands), "build --platform ios --profile preview") {
		t.Fatalf("expected interactive EAS preview build command, got %q", string(commands))
	}
	if !strings.Contains(string(commands), "build:list --platform ios --limit 1 --json --non-interactive") {
		t.Fatalf("expected build lookup after interactive setup, got %q", string(commands))
	}
	if !strings.Contains(string(commands), "build-env CI=unset EXPO_NO_INTERACTIVE=unset") {
		t.Fatalf("interactive setup must remove forced non-interactive environment, got %q", string(commands))
	}
}

func TestRunInteractiveCommandWithTimeoutDoesNotUseBackgroundProcessGroup(t *testing.T) {
	command := exec.Command("sh", "-c", "exit 0")
	if err := runInteractiveCommandWithTimeout(command, time.Second); err != nil {
		t.Fatalf("run interactive command: %v", err)
	}
	if command.SysProcAttr != nil && command.SysProcAttr.Setpgid {
		t.Fatal("interactive command must remain in the terminal foreground process group")
	}
}

func TestResolveStandalonePlanEnvAllowsLocalEASSessionWithoutExpoToken(t *testing.T) {
	t.Setenv("EXPO_TOKEN", "")
	t.Setenv("PREFLIGHT_SECRET_EXPO_TOKEN", "")

	resolved, err := resolveStandalonePlanEnv(map[string]string{
		"EXPO_NO_TELEMETRY": "1",
		"EXPO_TOKEN":        "${PREFLIGHT_SECRET:expoToken}",
	})
	if err != nil {
		t.Fatalf("resolve standalone plan env: %v", err)
	}
	if resolved["EXPO_NO_TELEMETRY"] != "1" {
		t.Fatalf("expected non-secret plan env to be preserved, got %#v", resolved)
	}
	if _, ok := resolved["EXPO_TOKEN"]; ok {
		t.Fatalf("expected missing Expo token to defer to the local EAS session, got %#v", resolved)
	}
}

func TestProveAppStandaloneDevelopmentBuildPollsBuildViewUntilTerminal(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeMaestroLaunchFixture(t, appDir)
	commandLog := filepath.Join(t.TempDir(), "eas-commands.log")
	stateFile := filepath.Join(t.TempDir(), "build-view-count")
	artifactDir := filepath.Join(t.TempDir(), "runtime-artifacts")
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'eas %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
case "$1" in
  config)
    printf '{"projectId":"eas_project_123"}\n'
    ;;
  build)
    printf '{"id":"eas_build_poll","status":"in-progress","platform":"ios"}\n'
    ;;
  build:view)
    count=0
    if [ -f "$PREFLIGHT_BUILD_VIEW_COUNT_FILE" ]; then
      count=$(cat "$PREFLIGHT_BUILD_VIEW_COUNT_FILE")
    fi
    count=$((count + 1))
    printf '%s' "$count" > "$PREFLIGHT_BUILD_VIEW_COUNT_FILE"
    if [ "$count" -lt 3 ]; then
      printf '{"id":"eas_build_poll","status":"in-progress","platform":"ios"}\n'
    else
      printf '{"id":"eas_build_poll","status":"finished","platform":"ios","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/eas_build_poll.ipa"}}\n'
    fi
    ;;
  *)
    printf 'unexpected eas command %s\n' "$*" >&2
    exit 2
    ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf 'npx %s\n' "$*" >> "$PREFLIGHT_COMMAND_LOG"
printf 'npx %s\n' "$*"
sleep 30
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_COMMAND_LOG", commandLog)
	t.Setenv("PREFLIGHT_BUILD_VIEW_COUNT_FILE", stateFile)
	t.Setenv("PREFLIGHT_TOKEN", "standalone_poll_token")
	t.Setenv("EXPO_TOKEN", "expo_token_123")
	t.Setenv("PREFLIGHT_EAS_BUILD_POLL_INTERVAL", "1ms")

	var resultBody map[string]any
	var sessionPlanBody map[string]any
	var artifactBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-plans":
			_, _ = fmt.Fprintf(w, `{"data":{"workflowId":"pfw_poll","platform":"ios","targetKind":"iphone","build":{"id":"pfbuild_pfw_poll","appId":"pfapp_forgegraph_mobile","platform":"ios","profile":"development","version":"1.2.3","environment":"development","status":"queued"},"installation":{"id":"pfinstall_pfw_poll","workspaceId":"ws_poll","appId":"pfapp_forgegraph_mobile","targetId":"pftarget_iphone","buildId":"pfbuild_pfw_poll","workflowId":"pfw_poll","status":"installing","installUrl":"","metadata":{}},"commands":[{"id":"eas_config","kind":"one_shot","command":"eas","args":["config","--platform","ios","--profile","development","--json","--non-interactive"],"cwd":%q,"env":{"EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q},{"id":"eas_build","kind":"one_shot","command":"eas","args":["build","--platform","ios","--profile","development","--json","--non-interactive"],"cwd":%q,"env":{"EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q},{"id":"eas_build_view","kind":"one_shot","command":"eas","args":["build:view","${EAS_BUILD_ID}","--json"],"cwd":%q,"env":{"EXPO_TOKEN":"${PREFLIGHT_SECRET:expoToken}"},"stdoutArtifactPath":%q}]}}`,
				appDir,
				filepath.Join(artifactDir, "eas", "config.json"),
				appDir,
				filepath.Join(artifactDir, "eas", "build.json"),
				appDir,
				filepath.Join(artifactDir, "eas", "build-view.json"),
			)
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-results":
			if err := json.NewDecoder(r.Body).Decode(&resultBody); err != nil {
				t.Fatalf("decode result body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"build":{"id":"pfbuild_pfw_poll","status":"completed"},"installation":{"id":"pfinstall_pfw_poll","status":"installed"}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-session-plans":
			if err := json.NewDecoder(r.Body).Decode(&sessionPlanBody); err != nil {
				t.Fatalf("decode development session plan body: %v", err)
			}
			_, _ = fmt.Fprintf(w, `{"data":{"workflowId":"pfw_poll","platform":"ios","targetKind":"iphone","targetId":"pftarget_iphone","advertisedUrl":"${EXPO_TUNNEL_URL}","devSession":{"id":"pfds_pfw_poll","workspaceId":"ws_poll","appId":"pfapp_forgegraph_mobile","buildId":"pfbuild_pfw_poll","workflowId":"pfw_poll","platform":"ios","lane":"development","targetKind":"iphone","hostMode":"tunnel","status":"starting","port":19000,"metadata":{}},"targetSession":{"id":"pftsess_pfw_poll","workspaceId":"ws_poll","appId":"pfapp_forgegraph_mobile","targetId":"pftarget_iphone","devSessionId":"pfds_pfw_poll","workflowId":"pfw_poll","status":"opening","metadata":{}},"commands":[{"id":"expo_start_tunnel","kind":"long_running","command":"npx","args":["expo","start","--tunnel","--dev-client","--port","19000"],"cwd":%q,"env":{"EXPO_NO_TELEMETRY":"1"}}]}}`, appDir)
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/dev-sessions":
			_, _ = w.Write([]byte(`{"data":{"id":"pfds_pfw_poll","status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/target-sessions":
			_, _ = w.Write([]byte(`{"data":{"id":"pftsess_pfw_poll","status":"opening"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_forgegraph_mobile/runtime-artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact body: %v", err)
			}
			artifactBodies = append(artifactBodies, body)
			_, _ = w.Write([]byte(`{"data":{"id":"pfart_poll"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--standalone-run",
			"--lane",
			"development",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_poll",
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--target-kind",
			"iphone",
			"--target-id",
			"pftarget_iphone",
			"--workflow-id",
			"pfw_poll",
			"--version",
			"1.2.3",
			"--artifact-dir",
			artifactDir,
		},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("standalone development poll exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	easBuild := resultBody["easBuild"].(map[string]any)
	if easBuild["status"] != "finished" {
		t.Fatalf("expected terminal EAS build result, got %#v", easBuild)
	}
	if len(artifactBodies) != 4 {
		t.Fatalf("expected config, build, terminal build-view, and Expo log artifacts, got %#v", artifactBodies)
	}
	logArtifact := artifactBodies[3]
	if logArtifact["kind"] != "log" ||
		logArtifact["workflowId"] != "pfw_poll" ||
		logArtifact["buildId"] != "pfbuild_pfw_poll" ||
		logArtifact["targetId"] != "pftarget_iphone" ||
		logArtifact["contentType"] != "text/plain" ||
		logArtifact["redacted"] != true {
		t.Fatalf("expected redacted Expo log artifact, got %#v", logArtifact)
	}
	logPayload, err := os.ReadFile(fmt.Sprint(logArtifact["uri"]))
	if err != nil {
		t.Fatalf("read Expo log artifact: %v", err)
	}
	if !strings.Contains(string(logPayload), "npx expo start --tunnel --dev-client --port 19000") {
		t.Fatalf("expected Expo log artifact to preserve startup output, got %q", string(logPayload))
	}
	if sessionPlanBody["buildId"] != "pfbuild_pfw_poll" || sessionPlanBody["targetId"] != "pftarget_iphone" {
		t.Fatalf("expected terminal build to feed development session plan, got %#v", sessionPlanBody)
	}
	countContent, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read build-view count: %v", err)
	}
	if strings.TrimSpace(string(countContent)) != "3" {
		t.Fatalf("expected three build:view polls, got %q", string(countContent))
	}
	artifact, err := os.ReadFile(filepath.Join(artifactDir, "eas", "build-view.json"))
	if err != nil {
		t.Fatalf("read build-view artifact: %v", err)
	}
	if !strings.Contains(string(artifact), `"status":"finished"`) {
		t.Fatalf("expected final artifact to contain finished status, got %q", string(artifact))
	}
}

func TestProveAppStandaloneDevelopmentPlanUsesDerivedEASProfile(t *testing.T) {
	appDir := writeExpoFixture(t)
	maestroDir := filepath.Join(appDir, ".maestro")
	if err := os.MkdirAll(maestroDir, 0o755); err != nil {
		t.Fatalf("create Maestro fixture directory: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(maestroDir, "01-app-launches.yaml"),
		[]byte("appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n"),
		0o644,
	); err != nil {
		t.Fatalf("write Maestro fixture: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(appDir, "eas.json"),
		[]byte(`{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":true}},"development-device":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":false}},"development-android":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"android":{"buildType":"apk"}}}}`),
		0o644,
	); err != nil {
		t.Fatalf("write eas json: %v", err)
	}
	var iosPlanBody map[string]any
	var androidPlanBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/apps/pfapp_forgegraph_mobile/development-build-plans" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode development build plan body: %v", err)
		}
		if body["platform"] == "android" {
			androidPlanBody = body
		} else {
			iosPlanBody = body
		}
		_, _ = w.Write([]byte(`{"data":{"workflowId":"pfw_profile","platform":"ios","targetKind":"iphone","build":{"id":"pfbuild_profile","profile":"unused"},"installation":{"id":"pfinstall_profile"},"commands":[]}}`))
	}))
	t.Cleanup(server.Close)

	for _, platform := range []string{"ios", "android"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(
			[]string{
				"prove-app",
				"--standalone-plan",
				"--lane",
				"development",
				"--api-url",
				server.URL,
				"--workspace-id",
				"ws_profile",
				"--app-dir",
				appDir,
				"--platform",
				platform,
				"--target-id",
				"pftarget_profile",
				"--workflow-id",
				"pfw_profile",
				"--version",
				"1.2.3",
			},
			&stdout,
			&stderr,
			server.Client(),
		)
		if code != 0 {
			t.Fatalf("standalone development plan for %s exit = %d\nstdout: %s\nstderr: %s", platform, code, stdout.String(), stderr.String())
		}
	}

	if iosPlanBody["buildProfile"] != "development-device" {
		t.Fatalf("expected iOS development-device profile from source binding, got %#v", iosPlanBody)
	}
	if androidPlanBody["buildProfile"] != "development-android" {
		t.Fatalf("expected Android development profile from source binding, got %#v", androidPlanBody)
	}
	for platform, body := range map[string]map[string]any{
		"ios":     iosPlanBody,
		"android": androidPlanBody,
	} {
		readiness, ok := body["developmentReadiness"].(map[string]any)
		if !ok {
			t.Fatalf("expected %s plan body to include development readiness, got %#v", platform, body)
		}
		if readiness["packageJson"] == nil || readiness["easJson"] == nil {
			t.Fatalf("expected %s development readiness to include package and EAS config, got %#v", platform, readiness)
		}
		flows, ok := readiness["maestroFlows"].([]any)
		if !ok || len(flows) == 0 {
			t.Fatalf("expected %s development readiness to include Maestro flows, got %#v", platform, readiness)
		}
	}
}

func TestStartStandaloneObservedPlannedCommandFailsWhenCommandExitsWithoutStartupOutput(t *testing.T) {
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
exit 7
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	command, err := startStandaloneObservedPlannedCommand(simulatorProofPlanCommand{
		ID:      "expo_start_tunnel",
		Kind:    "long_running",
		Command: "npx",
		Args:    []string{"expo", "start", "--tunnel", "--dev-client"},
	}, &bytes.Buffer{}, time.Second)

	if command != nil {
		terminateProcessGroup(command)
		t.Fatal("expected no running command after silent startup failure")
	}
	if err == nil || !strings.Contains(err.Error(), "exited before emitting startup output") {
		t.Fatalf("expected silent startup failure, got %v", err)
	}
}

func TestOAuthClientsUseSavedPreflightLoginConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "preflight", "config.json")
	t.Setenv("PREFLIGHT_CONFIG_PATH", configPath)

	var configureBody map[string]any
	var listWorkspaceID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer oauth_token_123" {
			t.Fatalf("expected saved Preflight auth token, got %q for %s %s", r.Header.Get("Authorization"), r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/oauth-clients":
			listWorkspaceID = r.URL.Query().Get("workspaceId")
			_, _ = w.Write([]byte(`{"data":{"oauthClients":[{"id":"pfoauth_saved","workspaceId":"ws_oauth_saved","appId":"pfapp_mobile","provider":"google_oauth","clientKind":"google_ios","displayName":"ForgeGraph iOS OAuth","status":"configured"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_list"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/oauth-clients/configure":
			if err := json.NewDecoder(r.Body).Decode(&configureBody); err != nil {
				t.Fatalf("decode OAuth configure body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_google_oauth","workspaceId":"ws_oauth_saved","appId":"pfapp_mobile","provider":"google_oauth","displayName":"Google Auth Platform","status":"needs_setup"},"credentialFlow":{"id":"pfcredflow_google_oauth","status":"waiting_for_human","nextAction":"complete_provider_console_setup"},"oauthClient":{"id":"pfoauth_saved_configure","provider":"google_oauth","clientKind":"google_ios","status":"needs_human"},"providerReadiness":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_configure"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	if err := savePreflightCLIConfig(preflightCLIConfig{
		APIVersion:        "v1",
		APIURL:            server.URL,
		Token:             "oauth_token_123",
		WorkspaceID:       "ws_oauth_saved",
		WorkspaceBindings: map[string]string{},
	}); err != nil {
		t.Fatalf("save CLI config: %v", err)
	}

	var listOut bytes.Buffer
	listCode := run(
		[]string{"oauth-clients", "list", "--app-id", "pfapp_mobile", "--provider", "google_oauth"},
		&listOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if listCode != 0 {
		t.Fatalf("oauth list exit = %d, stdout = %s", listCode, listOut.String())
	}
	if listWorkspaceID != "ws_oauth_saved" {
		t.Fatalf("expected workspace from saved config, got %q", listWorkspaceID)
	}

	var configureOut bytes.Buffer
	var configureErr bytes.Buffer
	configureCode := run(
		[]string{
			"oauth-clients",
			"configure",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"google_oauth",
			"--client-kind",
			"google_ios",
			"--display-name",
			"ForgeGraph iOS OAuth",
			"--bundle-id",
			"com.gmacko.forgegraph.dev",
		},
		&configureOut,
		&configureErr,
		server.Client(),
	)
	if configureCode != 0 {
		t.Fatalf("oauth configure exit = %d\nstdout: %s\nstderr: %s", configureCode, configureOut.String(), configureErr.String())
	}
	if configureBody["workspaceId"] != "ws_oauth_saved" {
		t.Fatalf("expected configure workspace from saved config, got %#v", configureBody)
	}
}

func TestOAuthClientsDescribePrintsExternalClientDetail(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_WORKSPACE_ID", "")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/preflight/v1/oauth-clients" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"oauthClients":[` +
			`{"id":"pfoauth_other","appId":"pfapp_other","provider":"google_oauth","clientKind":"google_web","displayName":"Other","status":"configured","externalClientId":"other.apps.googleusercontent.com"},` +
			`{"id":"pfoauth_playtrek","appId":"playtrek","provider":"apple_oauth","clientKind":"apple_services_id","displayName":"PlayTrek — Sign in with Apple","status":"configured","externalClientId":"com.gmacko.playtrek.signin","appleTeamId":"P4SWQXAB5H","appleServicesId":"com.gmacko.playtrek.signin","redirectUris":["https://playtrek.ai/api/auth/callback/apple"],"secretReferenceIds":["pfsecret_apple_key"]}` +
			`]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_describe"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"oauth-clients", "describe", "pfoauth_playtrek", "--workspace-id", "ws-1", "--api-url", server.URL},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{
		"com.gmacko.playtrek.signin",
		"P4SWQXAB5H",
		"pfsecret_apple_key",
		"https://playtrek.ai/api/auth/callback/apple",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q: %s", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "pfoauth_other") {
		t.Fatalf("stdout should only describe the requested client: %s", stdout.String())
	}
}

func TestOAuthClientsDescribeUnknownIDFails(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"oauthClients":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_missing"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"oauth-clients", "describe", "pfoauth_nope", "--workspace-id", "ws-1", "--api-url", server.URL},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "pfoauth_nope") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestOAuthClientsListJSONPrintsFullRecords(t *testing.T) {
	t.Setenv("PREFLIGHT_TOKEN", "token-123")
	t.Setenv("PREFLIGHT_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"oauthClients":[{"id":"pfoauth_playtrek","appId":"playtrek","provider":"apple_oauth","clientKind":"apple_services_id","displayName":"PlayTrek","status":"configured","externalClientId":"com.gmacko.playtrek.signin","secretReferenceIds":["pfsecret_apple_key"]}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_json"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"oauth-clients", "list", "--workspace-id", "ws-1", "--api-url", server.URL, "--json"},
		&stdout,
		&stderr,
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr.String())
	}
	var decoded []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if len(decoded) != 1 || decoded[0]["externalClientId"] != "com.gmacko.playtrek.signin" {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestOAuthClientsConfigureUsesPreflightAPI(t *testing.T) {
	var configureBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/oauth-clients/configure" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		if err := json.NewDecoder(r.Body).Decode(&configureBody); err != nil {
			t.Fatalf("decode OAuth configure body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_google_oauth","workspaceId":"local","appId":"pfapp_mobile","provider":"google_oauth","displayName":"Google Auth Platform","externalIds":{"googleCloudProjectId":"forgegraph-mobile"},"capabilities":["google_oauth.management","oauth.google.android"],"credentialReferenceIds":[],"status":"needs_setup","metadata":{}},"credentialFlow":{"id":"pfcredflow_google_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","capability":"oauth.google.android","action":"apply","status":"waiting_for_human","secretReferenceIds":[],"prompt":"Create the Android OAuth client in Google Auth Platform.","nextAction":"complete_provider_console_setup","metadata":{}},"oauthClient":{"id":"pfoauth_google_android","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","clientKind":"google_android","displayName":"ForgeGraph Android OAuth","androidPackage":"com.gmacko.forgegraph.dev","androidSha1Fingerprint":"AA:BB","status":"needs_human","secretReferenceIds":[]},"providerReadiness":[{"id":"pfready_google_android","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","platform":"android","capability":"oauth.google.android","status":"blocked","blockerCode":"oauth_client_needs_human","adapterVersion":"preflight-api@oauth.v1"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_configure"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"oauth-clients",
			"configure",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"google_oauth",
			"--client-kind",
			"google_android",
			"--display-name",
			"ForgeGraph Android OAuth",
			"--google-cloud-project-id",
			"forgegraph-mobile",
			"--android-package",
			"com.gmacko.forgegraph.dev",
			"--android-sha1",
			"AA:BB",
			"--scope",
			"openid",
			"--scope",
			"email",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("oauth configure exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if configureBody["googleCloudProjectId"] != "forgegraph-mobile" {
		t.Fatalf("unexpected OAuth configure body %#v", configureBody)
	}
	if !strings.Contains(stdout.String(), "oauth client pfoauth_google_android google_oauth google_android needs_human") {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "credential flow pfcredflow_google_oauth waiting_for_human") {
		t.Fatalf("expected credential flow output, got %q", stdout.String())
	}
}

func TestOAuthClientsConfigureHelpDocumentsExpoAppDerivation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"oauth-clients", "configure", "--help"},
		&stdout,
		&stderr,
		http.DefaultClient,
	)

	if code != 0 {
		t.Fatalf("expected help exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{
		"Usage: preflight oauth-clients configure",
		"--app-dir <path>",
		"--platform ios|android",
		"Derives app ID and native identifiers from an Expo app",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected help to contain %q, got %q", expected, stdout.String())
		}
	}
}

func TestOAuthClientsConfigureDerivesGoogleAndroidAppDefaultsFromExpoApp(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeExpoConfigIdentity(t, appDir)

	var configureBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/oauth-clients/configure" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		if err := json.NewDecoder(r.Body).Decode(&configureBody); err != nil {
			t.Fatalf("decode OAuth configure body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_google_oauth","workspaceId":"local","appId":"pfapp_forgegraph_mobile","provider":"google_oauth","displayName":"Google Auth Platform","status":"needs_setup"},"credentialFlow":{"id":"pfcredflow_google_oauth","status":"waiting_for_human","nextAction":"complete_provider_console_setup"},"oauthClient":{"id":"pfoauth_google_android","provider":"google_oauth","clientKind":"google_android","status":"needs_human"},"providerReadiness":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_configure"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"oauth-clients",
			"configure",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--provider",
			"google_oauth",
			"--platform",
			"android",
			"--google-cloud-project-id",
			"forgegraph-mobile",
			"--android-sha1",
			"AA:BB",
			"--scope",
			"openid",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("oauth configure exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if configureBody["workspaceId"] != "local" || configureBody["appId"] != "pfapp_forgegraph_mobile" {
		t.Fatalf("expected derived workspace/app IDs, got %#v", configureBody)
	}
	if configureBody["clientKind"] != "google_android" || configureBody["displayName"] != "ForgeGraph Mobile Google Android OAuth" {
		t.Fatalf("expected derived Google Android defaults, got %#v", configureBody)
	}
	if configureBody["androidPackage"] != "com.gmacko.forgegraph.dev" || configureBody["androidSha1Fingerprint"] != "AA:BB" {
		t.Fatalf("expected derived Android package plus supplied SHA-1, got %#v", configureBody)
	}
}

func TestOAuthClientsConfigureDerivesAppleIOSAppDefaultsFromExpoApp(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeExpoConfigIdentity(t, appDir)

	var configureBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/oauth-clients/configure" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		if err := json.NewDecoder(r.Body).Decode(&configureBody); err != nil {
			t.Fatalf("decode OAuth configure body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_apple_oauth","workspaceId":"local","appId":"pfapp_forgegraph_mobile","provider":"apple_oauth","displayName":"Apple Sign in","status":"connected"},"credentialFlow":{"id":"pfcredflow_apple_oauth","status":"completed","nextAction":"ready"},"oauthClient":{"id":"pfoauth_apple_app_id","provider":"apple_oauth","clientKind":"apple_app_id","status":"configured"},"providerReadiness":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_oauth_configure"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"oauth-clients",
			"configure",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--provider",
			"apple_oauth",
			"--platform",
			"ios",
			"--apple-team-id",
			"TEAM123",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("oauth configure exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if configureBody["workspaceId"] != "local" || configureBody["appId"] != "pfapp_forgegraph_mobile" {
		t.Fatalf("expected derived workspace/app IDs, got %#v", configureBody)
	}
	if configureBody["clientKind"] != "apple_app_id" || configureBody["displayName"] != "ForgeGraph Mobile Apple App ID" {
		t.Fatalf("expected derived Apple iOS defaults, got %#v", configureBody)
	}
	if configureBody["bundleId"] != "com.gmacko.forgegraph.dev" || configureBody["appleTeamId"] != "TEAM123" {
		t.Fatalf("expected derived iOS bundle plus supplied Apple team, got %#v", configureBody)
	}
}

func TestOAuthClientsConfigureAllRequiredDerivesExpoClients(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeExpoConfigIdentity(t, appDir)

	var configureBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/preflight/v1/oauth-clients/configure" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode OAuth configure body: %v", err)
		}
		configureBodies = append(configureBodies, body)
		clientKind := body["clientKind"].(string)
		provider := body["provider"].(string)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"providerAccount": map[string]any{
					"id":       "pfprov_" + provider,
					"provider": provider,
					"status":   "needs_setup",
				},
				"credentialFlow": map[string]any{
					"id":         "pfcredflow_" + clientKind,
					"status":     "waiting_for_human",
					"nextAction": "complete_provider_console_setup",
				},
				"oauthClient": map[string]any{
					"id":         "pfoauth_" + clientKind,
					"provider":   provider,
					"clientKind": clientKind,
					"status":     "needs_human",
				},
				"providerReadiness": []map[string]any{},
			},
			"meta": map[string]any{
				"apiVersion":      "v1",
				"contractVersion": contractVersion,
				"requestId":       "req_oauth_configure_all",
			},
		}); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"oauth-clients",
			"configure",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--all-required",
			"--google-cloud-project-id",
			"forgegraph-mobile",
			"--android-sha1",
			"AA:BB",
			"--apple-team-id",
			"TEAM123",
			"--apple-services-id",
			"com.gmacko.forgegraph.web",
			"--redirect-uri",
			"https://forgegraph.dev/api/auth/callback/apple",
			"--javascript-origin",
			"https://forgegraph.dev",
			"--scope",
			"openid",
			"--scope",
			"email",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("oauth configure all exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if len(configureBodies) != 5 {
		t.Fatalf("expected 5 OAuth configure calls, got %#v", configureBodies)
	}
	expectedKinds := []string{"google_ios", "apple_app_id", "google_android", "google_web", "apple_services_id"}
	for index, expectedKind := range expectedKinds {
		body := configureBodies[index]
		if body["workspaceId"] != "local" || body["appId"] != "pfapp_forgegraph_mobile" {
			t.Fatalf("expected derived app scope at %d, got %#v", index, body)
		}
		if body["clientKind"] != expectedKind {
			t.Fatalf("expected client kind %q at %d, got %#v", expectedKind, index, body)
		}
	}
	if configureBodies[0]["provider"] != "google_oauth" || configureBodies[0]["bundleId"] != "com.gmacko.forgegraph.dev" {
		t.Fatalf("expected Google iOS defaults, got %#v", configureBodies[0])
	}
	if configureBodies[1]["provider"] != "apple_oauth" || configureBodies[1]["bundleId"] != "com.gmacko.forgegraph.dev" || configureBodies[1]["appleTeamId"] != "TEAM123" {
		t.Fatalf("expected Apple App ID defaults, got %#v", configureBodies[1])
	}
	if configureBodies[2]["provider"] != "google_oauth" || configureBodies[2]["androidPackage"] != "com.gmacko.forgegraph.dev" || configureBodies[2]["androidSha1Fingerprint"] != "AA:BB" {
		t.Fatalf("expected Google Android defaults, got %#v", configureBodies[2])
	}
	if configureBodies[3]["provider"] != "google_oauth" || len(configureBodies[3]["redirectUris"].([]any)) != 1 || len(configureBodies[3]["javascriptOrigins"].([]any)) != 1 {
		t.Fatalf("expected Google web defaults, got %#v", configureBodies[3])
	}
	if configureBodies[4]["provider"] != "apple_oauth" || configureBodies[4]["appleServicesId"] != "com.gmacko.forgegraph.web" || len(configureBodies[4]["redirectUris"].([]any)) != 1 {
		t.Fatalf("expected Apple Services ID defaults, got %#v", configureBodies[4])
	}
	for _, expected := range expectedKinds {
		if !strings.Contains(stdout.String(), "oauth client pfoauth_"+expected) {
			t.Fatalf("expected output for %s, got %q", expected, stdout.String())
		}
	}
}

func TestProvidersVerifyAppStoreConnectCallsAPIAndRecordsReadiness(t *testing.T) {
	privateKey, privateKeyPEM := generateTestAppStoreConnectKey(t)
	t.Setenv("ASC_PRIVATE_KEY", privateKeyPEM)

	var providerBody map[string]any
	var readinessBody map[string]any
	var credentialFlowBody map[string]any
	var sawASCRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/apps":
			sawASCRequest = true
			if r.URL.Query().Get("limit") != "1" {
				t.Fatalf("expected App Store Connect probe to use limit=1, got %s", r.URL.RawQuery)
			}
			assertValidAppStoreConnectJWT(t, r.Header.Get("Authorization"), privateKey)
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			if err := json.NewDecoder(r.Body).Decode(&providerBody); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_asc","workspaceId":"local","appId":"pfapp_mobile","provider":"app_store_connect","displayName":"Apple Developer Team","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_provider_verify"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts/pfprov_asc/credential-flows":
			if err := json.NewDecoder(r.Body).Decode(&credentialFlowBody); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_asc","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_asc","provider":"app_store_connect","capability":"asc.api.auth","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":["pfsec_asc_key"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_asc_flow"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			if err := json.NewDecoder(r.Body).Decode(&readinessBody); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_asc","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_asc","provider":"app_store_connect","platform":"ios","capability":"asc.api.auth","status":"ready","adapterVersion":"preflight-cli@app-store-connect.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_readiness_verify"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"providers",
			"verify",
			"--provider",
			"app_store_connect",
			"--api-url",
			server.URL,
			"--asc-api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--display-name",
			"Apple Developer Team",
			"--issuer-id",
			"00000000-1111-2222-3333-444444444444",
			"--key-id",
			"ASC1234567",
			"--private-key-env",
			"ASC_PRIVATE_KEY",
			"--credential-ref",
			"pfsec_asc_key",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !sawASCRequest {
		t.Fatal("expected App Store Connect API probe")
	}
	if strings.Contains(stdout.String(), privateKeyPEM) || strings.Contains(stderr.String(), privateKeyPEM) {
		t.Fatalf("provider verify leaked private key\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if providerBody["provider"] != "app_store_connect" || providerBody["status"] != "connected" {
		t.Fatalf("unexpected provider body %#v", providerBody)
	}
	externalIDs := providerBody["externalIds"].(map[string]any)
	if externalIDs["issuerId"] != "00000000-1111-2222-3333-444444444444" || externalIDs["keyId"] != "ASC1234567" {
		t.Fatalf("unexpected external IDs %#v", externalIDs)
	}
	if readinessBody["providerAccountId"] != "pfprov_asc" || readinessBody["status"] != "ready" {
		t.Fatalf("unexpected readiness body %#v", readinessBody)
	}
	if credentialFlowBody["provider"] != "app_store_connect" ||
		credentialFlowBody["capability"] != "asc.api.auth" ||
		credentialFlowBody["action"] != "inspect" ||
		credentialFlowBody["status"] != "completed" ||
		credentialFlowBody["nextAction"] != "ready" {
		t.Fatalf("unexpected App Store Connect credential flow body %#v", credentialFlowBody)
	}
	ascSecretRefs := credentialFlowBody["secretReferenceIds"].([]any)
	if !containsAny(ascSecretRefs, "pfsec_asc_key") {
		t.Fatalf("expected ASC secret reference in credential flow body %#v", credentialFlowBody)
	}
	if !strings.Contains(stdout.String(), "verified provider pfprov_asc app_store_connect ready") {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
}

func TestProvidersVerifyGoogleCloudAndAndroidLocalUseManagedCommands(t *testing.T) {
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "provider-verify.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "gcloud"), []byte(`#!/usr/bin/env sh
printf 'gcloud :: %s\n' "$*" >> "$PROVIDER_VERIFY_LOG"
case "$*" in
  "auth list --filter=status:ACTIVE --format=value(account)") printf 'mobile-admin@example.com\n' ;;
  "config get-value project") printf 'fg-mobile-prod\n' ;;
  *) exit 7 ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake gcloud: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "adb"), []byte(`#!/usr/bin/env sh
printf 'adb :: %s\n' "$*" >> "$PROVIDER_VERIFY_LOG"
printf 'List of devices attached\nemulator-5554\tdevice\n'
`), 0o755); err != nil {
		t.Fatalf("write fake adb: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "emulator"), []byte(`#!/usr/bin/env sh
printf 'emulator :: %s\n' "$*" >> "$PROVIDER_VERIFY_LOG"
printf 'Pixel_6_API_35\n'
`), 0o755); err != nil {
		t.Fatalf("write fake emulator: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROVIDER_VERIFY_LOG", commandLog)

	var providerBodies []map[string]any
	var readinessBodies []map[string]any
	var credentialFlowBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			providerBodies = append(providerBodies, body)
			switch body["provider"] {
			case "google_cloud":
				_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_gcloud","workspaceId":"local","appId":"pfapp_mobile","provider":"google_cloud","displayName":"Google Cloud Project","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_gcloud_provider"}}`))
			case "android_local":
				_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_android","workspaceId":"local","appId":"pfapp_mobile","provider":"android_local","displayName":"Local Android SDK","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_android_provider"}}`))
			default:
				t.Fatalf("unexpected provider body %#v", body)
			}
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/preflight/v1/provider-accounts/") && strings.HasSuffix(r.URL.Path, "/credential-flows"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			credentialFlowBodies = append(credentialFlowBodies, body)
			switch body["provider"] {
			case "google_cloud":
				_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_gcloud","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_gcloud","provider":"google_cloud","capability":"gcloud.cli.auth","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":[]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_gcloud_flow"}}`))
			case "android_local":
				_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_android","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_android","provider":"android_local","capability":"android.local.management","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":[]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_android_flow"}}`))
			default:
				t.Fatalf("unexpected credential flow body %#v", body)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			readinessBodies = append(readinessBodies, body)
			switch body["provider"] {
			case "google_cloud":
				_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_gcloud","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_gcloud","provider":"google_cloud","capability":"gcloud.cli.auth","status":"ready","adapterVersion":"preflight-cli@google-cloud.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_gcloud_ready"}}`))
			case "android_local":
				_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_android","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_android","provider":"android_local","platform":"android","capability":"android.local.management","status":"ready","adapterVersion":"preflight-cli@android-local.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_android_ready"}}`))
			default:
				t.Fatalf("unexpected readiness body %#v", body)
			}
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	for _, provider := range []struct {
		name        string
		displayName string
		expected    string
	}{
		{name: "google_cloud", displayName: "Google Cloud Project", expected: "verified provider pfprov_gcloud google_cloud ready"},
		{name: "android_local", displayName: "Local Android SDK", expected: "verified provider pfprov_android android_local ready"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(
			[]string{
				"providers",
				"verify",
				"--provider",
				provider.name,
				"--api-url",
				server.URL,
				"--workspace-id",
				"local",
				"--app-id",
				"pfapp_mobile",
				"--display-name",
				provider.displayName,
			},
			&stdout,
			&stderr,
			server.Client(),
		)
		if code != 0 {
			t.Fatalf("%s verify exit = %d\nstdout: %s\nstderr: %s", provider.name, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), provider.expected) {
			t.Fatalf("unexpected stdout %q", stdout.String())
		}
	}

	output, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read provider command log: %v", err)
	}
	for _, expected := range []string{
		"gcloud :: auth list --filter=status:ACTIVE --format=value(account)",
		"gcloud :: config get-value project",
		"adb :: devices",
		"emulator :: -list-avds",
	} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("expected command log to contain %q, got %q", expected, string(output))
		}
	}
	if len(providerBodies) != 2 || len(readinessBodies) != 2 {
		t.Fatalf("expected provider/readiness writes, got provider=%#v readiness=%#v", providerBodies, readinessBodies)
	}
	if len(credentialFlowBodies) != 2 {
		t.Fatalf("expected provider credential flow writes, got %#v", credentialFlowBodies)
	}
	for _, body := range credentialFlowBodies {
		if body["action"] != "inspect" || body["status"] != "completed" || body["nextAction"] != "ready" {
			t.Fatalf("unexpected provider credential flow body %#v", body)
		}
	}
}

func TestProviderVerificationBlockedNextActionsStayOnPreflightSurface(t *testing.T) {
	for _, provider := range []string{
		"expo",
		"eas",
		"app_store_connect",
		"google_play",
		"google_cloud",
		"google_oauth",
		"apple_oauth",
		"sentry",
	} {
		nextAction := providerVerificationCredentialFlowNextAction(providerVerificationRecord{
			Provider: provider,
			Readiness: providerProbeResult{
				Status:      "blocked",
				BlockerCode: provider + "_blocked",
			},
		})
		if strings.HasPrefix(nextAction, "gcloud ") || strings.HasPrefix(nextAction, "eas ") || strings.HasPrefix(nextAction, "adb ") {
			t.Fatalf("%s nextAction exposed raw external command %q", provider, nextAction)
		}
		if provider == "google_cloud" && !strings.HasPrefix(nextAction, "preflight providers verify --provider google_cloud") {
			t.Fatalf("google_cloud nextAction should use Preflight provider adapter, got %q", nextAction)
		}
	}
}

func TestProvidersVerifyExpoAndEASUsePreflightOwnedTokenAndManagedCommands(t *testing.T) {
	appDir := t.TempDir()
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "expo-eas-provider-verify.log")
	rawToken := "expo-token-value-that-must-not-leak"
	t.Setenv("EXPO_TOKEN", rawToken)
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
if [ -n "$EXPO_TOKEN" ]; then token_state=present; else token_state=missing; fi
printf 'eas :: %s :: token=%s :: cwd=%s\n' "$*" "$token_state" "$(pwd)" >> "$EXPO_EAS_PROVIDER_VERIFY_LOG"
case "$*" in
  "whoami") printf '@forgegraph-bot\n' ;;
  "config --json --non-interactive") printf '{"expo":{"name":"ForgeGraph Mobile","slug":"forgegraph-mobile","owner":"forgegraph","extra":{"eas":{"projectId":"expo-project-123"}}},"eas":{"build":{"development":{"developmentClient":true},"preview":{"distribution":"internal"}}}}\n' ;;
  *) exit 7 ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("EXPO_EAS_PROVIDER_VERIFY_LOG", commandLog)

	var providerBodies []map[string]any
	var readinessBodies []map[string]any
	var credentialFlowBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			providerBodies = append(providerBodies, body)
			switch body["provider"] {
			case "expo":
				_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_expo","workspaceId":"local","appId":"pfapp_mobile","provider":"expo","displayName":"Expo Account","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_expo_provider"}}`))
			case "eas":
				_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_eas","workspaceId":"local","appId":"pfapp_mobile","provider":"eas","displayName":"EAS Project","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_eas_provider"}}`))
			default:
				t.Fatalf("unexpected provider body %#v", body)
			}
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/preflight/v1/provider-accounts/") && strings.HasSuffix(r.URL.Path, "/credential-flows"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			credentialFlowBodies = append(credentialFlowBodies, body)
			switch body["provider"] {
			case "expo":
				_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_expo","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_expo","provider":"expo","capability":"expo.api.auth","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":["pfsec_expo_token"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_expo_flow"}}`))
			case "eas":
				_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_eas","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_eas","provider":"eas","capability":"eas.project.config","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":["pfsec_expo_token"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_eas_flow"}}`))
			default:
				t.Fatalf("unexpected credential flow body %#v", body)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			readinessBodies = append(readinessBodies, body)
			switch body["provider"] {
			case "expo":
				_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_expo","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_expo","provider":"expo","capability":"expo.api.auth","status":"ready","adapterVersion":"preflight-cli@expo.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_expo_ready"}}`))
			case "eas":
				_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_eas","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_eas","provider":"eas","capability":"eas.project.config","status":"ready","adapterVersion":"preflight-cli@eas.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_eas_ready"}}`))
			default:
				t.Fatalf("unexpected readiness body %#v", body)
			}
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	for _, provider := range []struct {
		name        string
		displayName string
		args        []string
		expected    string
	}{
		{
			name:        "expo",
			displayName: "Expo Account",
			args: []string{
				"providers",
				"verify",
				"--provider",
				"expo",
				"--api-url",
				server.URL,
				"--workspace-id",
				"local",
				"--app-id",
				"pfapp_mobile",
				"--display-name",
				"Expo Account",
				"--token-env",
				"EXPO_TOKEN",
				"--credential-ref",
				"pfsec_expo_token",
			},
			expected: "verified provider pfprov_expo expo ready",
		},
		{
			name:        "eas",
			displayName: "EAS Project",
			args: []string{
				"providers",
				"verify",
				"--provider",
				"eas",
				"--api-url",
				server.URL,
				"--workspace-id",
				"local",
				"--app-id",
				"pfapp_mobile",
				"--display-name",
				"EAS Project",
				"--token-env",
				"EXPO_TOKEN",
				"--credential-ref",
				"pfsec_expo_token",
				"--app-dir",
				appDir,
			},
			expected: "verified provider pfprov_eas eas ready",
		},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(provider.args, &stdout, &stderr, server.Client())
		if code != 0 {
			t.Fatalf("%s verify exit = %d\nstdout: %s\nstderr: %s", provider.name, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), provider.expected) {
			t.Fatalf("unexpected stdout %q", stdout.String())
		}
		if strings.Contains(stdout.String(), rawToken) || strings.Contains(stderr.String(), rawToken) {
			t.Fatalf("%s verify leaked Expo token\nstdout: %s\nstderr: %s", provider.name, stdout.String(), stderr.String())
		}
	}

	output, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	resolvedAppDir, err := filepath.EvalSymlinks(appDir)
	if err != nil {
		t.Fatalf("resolve app dir: %v", err)
	}
	for _, expected := range []string{
		"eas :: whoami :: token=present",
		"eas :: config --json --non-interactive :: token=present :: cwd=" + resolvedAppDir,
	} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("expected command log to contain %q, got %q", expected, string(output))
		}
	}
	if strings.Contains(string(output), rawToken) {
		t.Fatalf("managed EAS command log leaked Expo token: %q", string(output))
	}
	if len(providerBodies) != 2 || len(readinessBodies) != 2 || len(credentialFlowBodies) != 2 {
		t.Fatalf("expected provider/readiness/credential-flow writes, got provider=%#v readiness=%#v flow=%#v", providerBodies, readinessBodies, credentialFlowBodies)
	}
	serializedBodies := fmt.Sprintf("%#v %#v %#v", providerBodies, readinessBodies, credentialFlowBodies)
	if strings.Contains(serializedBodies, rawToken) {
		t.Fatalf("Preflight API payloads leaked Expo token: %s", serializedBodies)
	}

	expoProvider := providerBodies[0]
	if expoProvider["provider"] != "expo" || expoProvider["status"] != "connected" {
		t.Fatalf("unexpected Expo provider body %#v", expoProvider)
	}
	expoExternalIDs := expoProvider["externalIds"].(map[string]any)
	if expoExternalIDs["accountName"] != "@forgegraph-bot" {
		t.Fatalf("unexpected Expo external IDs %#v", expoExternalIDs)
	}
	easProvider := providerBodies[1]
	if easProvider["provider"] != "eas" || easProvider["status"] != "connected" {
		t.Fatalf("unexpected EAS provider body %#v", easProvider)
	}
	easExternalIDs := easProvider["externalIds"].(map[string]any)
	if easExternalIDs["projectId"] != "expo-project-123" || easExternalIDs["owner"] != "forgegraph" || easExternalIDs["slug"] != "forgegraph-mobile" {
		t.Fatalf("unexpected EAS external IDs %#v", easExternalIDs)
	}

	expoReadiness := readinessBodies[0]
	if expoReadiness["provider"] != "expo" || expoReadiness["capability"] != "expo.api.auth" || expoReadiness["status"] != "ready" {
		t.Fatalf("unexpected Expo readiness body %#v", expoReadiness)
	}
	easReadiness := readinessBodies[1]
	if easReadiness["provider"] != "eas" || easReadiness["capability"] != "eas.project.config" || easReadiness["status"] != "ready" {
		t.Fatalf("unexpected EAS readiness body %#v", easReadiness)
	}
	easFacts := easReadiness["facts"].(map[string]any)
	if easFacts["projectId"] != "expo-project-123" || easFacts["buildProfileCount"] != float64(2) {
		t.Fatalf("unexpected EAS facts %#v", easFacts)
	}
	for _, flow := range credentialFlowBodies {
		if flow["action"] != "inspect" || flow["status"] != "completed" || flow["nextAction"] != "ready" {
			t.Fatalf("unexpected credential flow body %#v", flow)
		}
		secretRefs := flow["secretReferenceIds"].([]any)
		if !containsAny(secretRefs, "pfsec_expo_token") {
			t.Fatalf("expected Expo token secret reference in credential flow %#v", flow)
		}
	}
}

func TestProvidersVerifyGoogleAndAppleOAuthRecordManagementReadiness(t *testing.T) {
	privateKey, privateKeyPEM := generateTestAppStoreConnectKey(t)
	t.Setenv("APPLE_OAUTH_PRIVATE_KEY", privateKeyPEM)

	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "oauth-provider-verify.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "gcloud"), []byte(`#!/usr/bin/env sh
printf 'gcloud :: %s\n' "$*" >> "$OAUTH_PROVIDER_VERIFY_LOG"
case "$*" in
  "config get-value project") printf 'fg-mobile-prod\n' ;;
  "iam oauth-clients list --location=global --format=json") printf 'IAM OAuth clients are not Google Auth Platform clients\n' >&2; exit 9 ;;
  *) exit 7 ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake gcloud: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OAUTH_PROVIDER_VERIFY_LOG", commandLog)

	var providerBodies []map[string]any
	var readinessBodies []map[string]any
	var credentialFlowBodies []map[string]any
	var sawBundleIDs bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/bundleIds":
			sawBundleIDs = true
			if r.URL.Query().Get("limit") != "1" {
				t.Fatalf("expected Bundle IDs probe to use limit=1, got %s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("include") != "bundleIdCapabilities" {
				t.Fatalf("expected Bundle IDs probe to include capabilities, got %s", r.URL.RawQuery)
			}
			assertValidAppStoreConnectJWT(t, r.Header.Get("Authorization"), privateKey)
			_, _ = w.Write([]byte(`{"data":[{"id":"bundle_123","type":"bundleIds","attributes":{"identifier":"com.gmacko.forgegraph.dev","name":"ForgeGraph Dev","platform":"IOS"}}],"included":[{"id":"cap_123","type":"bundleIdCapabilities","attributes":{"capabilityType":"SIGN_IN_WITH_APPLE"}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			providerBodies = append(providerBodies, body)
			switch body["provider"] {
			case "google_oauth":
				_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_google_oauth","workspaceId":"local","appId":"pfapp_mobile","provider":"google_oauth","displayName":"Google OAuth Platform","status":"needs_setup"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_google_oauth_provider"}}`))
			case "apple_oauth":
				_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_apple_oauth","workspaceId":"local","appId":"pfapp_mobile","provider":"apple_oauth","displayName":"Apple Sign in","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_apple_oauth_provider"}}`))
			default:
				t.Fatalf("unexpected provider body %#v", body)
			}
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/preflight/v1/provider-accounts/") && strings.HasSuffix(r.URL.Path, "/credential-flows"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			credentialFlowBodies = append(credentialFlowBodies, body)
			switch body["provider"] {
			case "google_oauth":
				_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_google_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","capability":"google_oauth.management","action":"inspect","status":"waiting_for_human","nextAction":"preflight oauth-clients configure --app-dir <APP_DIR> --all-required","secretReferenceIds":[]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_google_oauth_flow"}}`))
			case "apple_oauth":
				_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_apple_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_apple_oauth","provider":"apple_oauth","capability":"apple_oauth.management","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":["pfsec_apple_sign_in_key"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_apple_oauth_flow"}}`))
			default:
				t.Fatalf("unexpected credential flow body %#v", body)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			readinessBodies = append(readinessBodies, body)
			switch body["provider"] {
			case "google_oauth":
				_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_google_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","capability":"google_oauth.management","status":"blocked","blockerCode":"google_auth_platform_clients_require_import","adapterVersion":"preflight-cli@google-oauth.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_google_oauth_ready"}}`))
			case "apple_oauth":
				_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_apple_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_apple_oauth","provider":"apple_oauth","capability":"apple_oauth.management","status":"ready","adapterVersion":"preflight-cli@apple-oauth.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_apple_oauth_ready"}}`))
			default:
				t.Fatalf("unexpected readiness body %#v", body)
			}
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	for _, provider := range []struct {
		args     []string
		expected string
	}{
		{
			args: []string{
				"providers",
				"verify",
				"--provider",
				"google_oauth",
				"--api-url",
				server.URL,
				"--workspace-id",
				"local",
				"--app-id",
				"pfapp_mobile",
				"--display-name",
				"Google OAuth Platform",
			},
			expected: "verified provider pfprov_google_oauth google_oauth blocked",
		},
		{
			args: []string{
				"providers",
				"verify",
				"--provider",
				"apple_oauth",
				"--api-url",
				server.URL,
				"--asc-api-url",
				server.URL,
				"--workspace-id",
				"local",
				"--app-id",
				"pfapp_mobile",
				"--display-name",
				"Apple Sign in",
				"--issuer-id",
				"00000000-1111-2222-3333-444444444444",
				"--key-id",
				"ASC1234567",
				"--private-key-env",
				"APPLE_OAUTH_PRIVATE_KEY",
				"--credential-ref",
				"pfsec_apple_sign_in_key",
			},
			expected: "verified provider pfprov_apple_oauth apple_oauth ready",
		},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := run(provider.args, &stdout, &stderr, server.Client())
		expectedCode := 0
		if strings.Contains(provider.expected, "google_oauth blocked") {
			expectedCode = 1
		}
		if code != expectedCode {
			t.Fatalf("verify exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), provider.expected) {
			t.Fatalf("unexpected stdout %q", stdout.String())
		}
	}

	if !sawBundleIDs {
		t.Fatal("expected App Store Connect Bundle IDs probe")
	}
	output, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	for _, expected := range []string{
		"gcloud :: config get-value project",
	} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("expected command log to contain %q, got %q", expected, string(output))
		}
	}
	if strings.Contains(string(output), "iam oauth-clients") {
		t.Fatalf("Google OAuth verifier must not treat IAM OAuth clients as Google Auth Platform clients; got log %q", string(output))
	}
	if len(providerBodies) != 2 || len(readinessBodies) != 2 {
		t.Fatalf("expected two provider/readiness writes, got provider=%#v readiness=%#v", providerBodies, readinessBodies)
	}
	if len(credentialFlowBodies) != 2 {
		t.Fatalf("expected two credential flow writes, got %#v", credentialFlowBodies)
	}
	googleProvider := providerBodies[0]
	if googleProvider["provider"] != "google_oauth" || googleProvider["status"] != "needs_setup" {
		t.Fatalf("unexpected Google OAuth provider body %#v", googleProvider)
	}
	googleExternalIDs := googleProvider["externalIds"].(map[string]any)
	if googleExternalIDs["projectId"] != "fg-mobile-prod" {
		t.Fatalf("unexpected Google OAuth external IDs %#v", googleExternalIDs)
	}
	googleReadiness := readinessBodies[0]
	if googleReadiness["provider"] != "google_oauth" ||
		googleReadiness["capability"] != "google_oauth.management" ||
		googleReadiness["status"] != "blocked" ||
		googleReadiness["blockerCode"] != "google_auth_platform_clients_require_import" {
		t.Fatalf("unexpected Google OAuth readiness %#v", googleReadiness)
	}
	googleFacts := googleReadiness["facts"].(map[string]any)
	if googleFacts["projectId"] != "fg-mobile-prod" || googleFacts["clientSource"] != "preflight_oauth_client_records" {
		t.Fatalf("unexpected Google OAuth facts %#v", googleFacts)
	}
	googleFlow := credentialFlowBodies[0]
	if googleFlow["provider"] != "google_oauth" ||
		googleFlow["capability"] != "google_oauth.management" ||
		googleFlow["action"] != "inspect" ||
		googleFlow["status"] != "waiting_for_human" ||
		googleFlow["nextAction"] != "preflight oauth-clients configure --app-dir <APP_DIR> --all-required" {
		t.Fatalf("unexpected Google OAuth credential flow %#v", googleFlow)
	}
	if !strings.Contains(googleFlow["prompt"].(string), "Google Sign-In OAuth clients") {
		t.Fatalf("expected Google OAuth prompt to explain required clients, got %#v", googleFlow)
	}
	appleProvider := providerBodies[1]
	if appleProvider["provider"] != "apple_oauth" || appleProvider["status"] != "connected" {
		t.Fatalf("unexpected Apple OAuth provider body %#v", appleProvider)
	}
	appleReadiness := readinessBodies[1]
	if appleReadiness["provider"] != "apple_oauth" ||
		appleReadiness["capability"] != "apple_oauth.management" ||
		appleReadiness["status"] != "ready" {
		t.Fatalf("unexpected Apple OAuth readiness %#v", appleReadiness)
	}
	appleFacts := appleReadiness["facts"].(map[string]any)
	if appleFacts["bundleIdCount"] != float64(1) || appleFacts["signInWithAppleCapabilityCount"] != float64(1) {
		t.Fatalf("unexpected Apple OAuth facts %#v", appleFacts)
	}
	appleFlow := credentialFlowBodies[1]
	if appleFlow["provider"] != "apple_oauth" ||
		appleFlow["capability"] != "apple_oauth.management" ||
		appleFlow["action"] != "inspect" ||
		appleFlow["status"] != "completed" ||
		appleFlow["nextAction"] != "ready" {
		t.Fatalf("unexpected Apple OAuth credential flow %#v", appleFlow)
	}
	appleSecretRefs := appleFlow["secretReferenceIds"].([]any)
	if !containsAny(appleSecretRefs, "pfsec_apple_sign_in_key") {
		t.Fatalf("expected Apple OAuth secret reference in credential flow %#v", appleFlow)
	}
}

func TestProvidersVerifyGooglePlayUsesServiceAccountAndRecordsReadiness(t *testing.T) {
	privateKey, serviceAccountJSON := generateTestGooglePlayServiceAccount(t)
	t.Setenv("GOOGLE_PLAY_SERVICE_ACCOUNT", serviceAccountJSON)

	var providerBody map[string]any
	var readinessBody map[string]any
	var credentialFlowBody map[string]any
	var sawTokenRequest bool
	var sawEditInsert bool
	var sawTrackList bool
	var sawEditDelete bool

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			sawTokenRequest = true
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				t.Fatalf("unexpected grant type %q", r.Form.Get("grant_type"))
			}
			assertValidGoogleServiceAccountJWT(
				t,
				r.Form.Get("assertion"),
				privateKey,
				"play-publisher@fg-mobile-prod.iam.gserviceaccount.com",
				"play-key-123",
				server.URL+"/token",
				"https://www.googleapis.com/auth/androidpublisher",
			)
			_, _ = w.Write([]byte(`{"access_token":"ya29.play-token","token_type":"Bearer","expires_in":3600}`))
		case r.Method == http.MethodPost && r.URL.Path == "/androidpublisher/v3/applications/com.gmacko.forgegraph.dev/edits":
			sawEditInsert = true
			if r.Header.Get("Authorization") != "Bearer ya29.play-token" {
				t.Fatalf("unexpected Play auth header %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"id":"pfedit_123","expiryTimeSeconds":"1700000000"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/androidpublisher/v3/applications/com.gmacko.forgegraph.dev/edits/pfedit_123/tracks":
			sawTrackList = true
			if r.Header.Get("Authorization") != "Bearer ya29.play-token" {
				t.Fatalf("unexpected Play auth header %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"kind":"androidpublisher#tracksListResponse","tracks":[{"track":"internal"},{"track":"production"}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/androidpublisher/v3/applications/com.gmacko.forgegraph.dev/edits/pfedit_123":
			sawEditDelete = true
			if r.Header.Get("Authorization") != "Bearer ya29.play-token" {
				t.Fatalf("unexpected Play auth header %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			if err := json.NewDecoder(r.Body).Decode(&providerBody); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_play","workspaceId":"local","appId":"pfapp_mobile","provider":"google_play","displayName":"Google Play Console","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_play_provider"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts/pfprov_play/credential-flows":
			if err := json.NewDecoder(r.Body).Decode(&credentialFlowBody); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_play","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_play","provider":"google_play","capability":"play.publisher.api","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":["pfsec_play_service_account"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_play_flow"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			if err := json.NewDecoder(r.Body).Decode(&readinessBody); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_play","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_play","provider":"google_play","platform":"android","capability":"play.publisher.api","status":"ready","adapterVersion":"preflight-cli@google-play.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_play_ready"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	serviceAccountJSON = strings.ReplaceAll(serviceAccountJSON, "__TOKEN_URI__", server.URL+"/token")
	t.Setenv("GOOGLE_PLAY_SERVICE_ACCOUNT", serviceAccountJSON)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"providers",
			"verify",
			"--provider",
			"google_play",
			"--api-url",
			server.URL,
			"--play-api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--display-name",
			"Google Play Console",
			"--package-name",
			"com.gmacko.forgegraph.dev",
			"--service-account-json-env",
			"GOOGLE_PLAY_SERVICE_ACCOUNT",
			"--credential-ref",
			"pfsec_play_service_account",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for name, saw := range map[string]bool{
		"token request": sawTokenRequest,
		"edit insert":   sawEditInsert,
		"track list":    sawTrackList,
		"edit delete":   sawEditDelete,
	} {
		if !saw {
			t.Fatalf("expected %s", name)
		}
	}
	if strings.Contains(stdout.String(), serviceAccountJSON) || strings.Contains(stderr.String(), serviceAccountJSON) || strings.Contains(stdout.String(), "ya29.play-token") {
		t.Fatalf("provider verify leaked Play credentials\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if providerBody["provider"] != "google_play" || providerBody["status"] != "connected" {
		t.Fatalf("unexpected provider body %#v", providerBody)
	}
	externalIDs := providerBody["externalIds"].(map[string]any)
	if externalIDs["clientEmail"] != "play-publisher@fg-mobile-prod.iam.gserviceaccount.com" ||
		externalIDs["packageName"] != "com.gmacko.forgegraph.dev" ||
		externalIDs["projectId"] != "fg-mobile-prod" {
		t.Fatalf("unexpected external IDs %#v", externalIDs)
	}
	if readinessBody["providerAccountId"] != "pfprov_play" ||
		readinessBody["provider"] != "google_play" ||
		readinessBody["platform"] != "android" ||
		readinessBody["status"] != "ready" ||
		readinessBody["capability"] != "play.publisher.api" {
		t.Fatalf("unexpected readiness body %#v", readinessBody)
	}
	if credentialFlowBody["provider"] != "google_play" ||
		credentialFlowBody["capability"] != "play.publisher.api" ||
		credentialFlowBody["action"] != "inspect" ||
		credentialFlowBody["status"] != "completed" ||
		credentialFlowBody["nextAction"] != "ready" {
		t.Fatalf("unexpected Google Play credential flow body %#v", credentialFlowBody)
	}
	playSecretRefs := credentialFlowBody["secretReferenceIds"].([]any)
	if !containsAny(playSecretRefs, "pfsec_play_service_account") {
		t.Fatalf("expected Play secret reference in credential flow body %#v", credentialFlowBody)
	}
	if !strings.Contains(stdout.String(), "verified provider pfprov_play google_play ready") {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
}

func TestProvidersVerifySentryUsesBearerTokenAndRecordsSourceMapReadiness(t *testing.T) {
	sentryToken := "sntrys_secret_provider_token"
	t.Setenv("SENTRY_AUTH_TOKEN", sentryToken)

	var providerBody map[string]any
	var readinessBody map[string]any
	var credentialFlowBody map[string]any
	var sawProjectRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/0/projects/gmacko/forgegraph-mobile/":
			sawProjectRequest = true
			if r.Header.Get("Authorization") != "Bearer "+sentryToken {
				t.Fatalf("unexpected Sentry auth header %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"id":"4505278496","slug":"forgegraph-mobile","name":"ForgeGraph Mobile","platform":"react-native","access":["project:read","project:releases","event:read"]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts":
			if err := json.NewDecoder(r.Body).Decode(&providerBody); err != nil {
				t.Fatalf("decode provider body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerAccount":{"id":"pfprov_sentry","workspaceId":"local","appId":"pfapp_mobile","provider":"sentry","displayName":"Sentry Mobile","status":"connected"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_sentry_provider"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts/pfprov_sentry/credential-flows":
			if err := json.NewDecoder(r.Body).Decode(&credentialFlowBody); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_sentry","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_sentry","provider":"sentry","capability":"sentry.source_maps.upload","action":"inspect","status":"completed","nextAction":"ready","secretReferenceIds":["pfsec_sentry_token"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_sentry_flow"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			if err := json.NewDecoder(r.Body).Decode(&readinessBody); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_sentry","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_sentry","provider":"sentry","capability":"sentry.source_maps.upload","status":"ready","adapterVersion":"preflight-cli@sentry.v1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_sentry_ready"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"providers",
			"verify",
			"--provider",
			"sentry",
			"--api-url",
			server.URL,
			"--sentry-api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--display-name",
			"Sentry Mobile",
			"--org-slug",
			"gmacko",
			"--project-slug",
			"forgegraph-mobile",
			"--auth-token-env",
			"SENTRY_AUTH_TOKEN",
			"--credential-ref",
			"pfsec_sentry_token",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected Sentry verify exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !sawProjectRequest {
		t.Fatal("expected Sentry project probe")
	}
	if strings.Contains(stdout.String(), sentryToken) || strings.Contains(stderr.String(), sentryToken) {
		t.Fatalf("provider verify leaked Sentry token\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if providerBody["provider"] != "sentry" || providerBody["status"] != "connected" {
		t.Fatalf("unexpected provider body %#v", providerBody)
	}
	externalIDs := providerBody["externalIds"].(map[string]any)
	if externalIDs["orgSlug"] != "gmacko" || externalIDs["projectSlug"] != "forgegraph-mobile" || externalIDs["projectId"] != "4505278496" {
		t.Fatalf("unexpected Sentry external IDs %#v", externalIDs)
	}
	if readinessBody["providerAccountId"] != "pfprov_sentry" ||
		readinessBody["provider"] != "sentry" ||
		readinessBody["capability"] != "sentry.source_maps.upload" ||
		readinessBody["status"] != "ready" {
		t.Fatalf("unexpected Sentry readiness body %#v", readinessBody)
	}
	facts := readinessBody["facts"].(map[string]any)
	if facts["orgSlug"] != "gmacko" || facts["projectSlug"] != "forgegraph-mobile" || facts["projectPlatform"] != "react-native" {
		t.Fatalf("unexpected Sentry readiness facts %#v", facts)
	}
	requiredScopes := facts["requiredScopes"].([]any)
	if !containsAny(requiredScopes, "project:read") || !containsAny(requiredScopes, "project:releases") {
		t.Fatalf("expected Sentry required scopes in facts, got %#v", facts)
	}
	if credentialFlowBody["provider"] != "sentry" ||
		credentialFlowBody["capability"] != "sentry.source_maps.upload" ||
		credentialFlowBody["action"] != "inspect" ||
		credentialFlowBody["status"] != "completed" ||
		credentialFlowBody["nextAction"] != "ready" {
		t.Fatalf("unexpected Sentry credential flow body %#v", credentialFlowBody)
	}
	sentrySecretRefs := credentialFlowBody["secretReferenceIds"].([]any)
	if !containsAny(sentrySecretRefs, "pfsec_sentry_token") {
		t.Fatalf("expected Sentry secret reference in credential flow body %#v", credentialFlowBody)
	}
	if !strings.Contains(stdout.String(), "verified provider pfprov_sentry sentry ready") {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
}

func TestProviderReadinessRecordAndListUseAppScopedAPI(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness body: %v", err)
			}
			if body["provider"] != "google_play" || body["capability"] != "play.internal.submit" {
				t.Fatalf("unexpected readiness body %#v", body)
			}
			if body["nextAction"] != "preflight oauth-clients configure --app-dir apps/mobile --provider google_oauth --client-kind google_android --platform android --android-sha1 AA:BB --external-client-id <CLIENT_ID>" ||
				body["requiredHumanRole"] != "Google Auth Platform administrator" {
				t.Fatalf("expected next action and role in readiness body, got %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":{"id":"pfready_cli","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_play","provider":"google_play","platform":"android","lane":"store","capability":"play.internal.submit","status":"blocked","blockerCode":"play_track_permission_missing","nextAction":"preflight oauth-clients configure --app-dir apps/mobile --provider google_oauth --client-kind google_android --platform android --android-sha1 AA:BB --external-client-id <CLIENT_ID>","requiredHumanRole":"Google Auth Platform administrator","credentialReferenceIds":[],"facts":{},"adapterVersion":"fake-play-adapter@1"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_readiness_record"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-readiness":
			_, _ = w.Write([]byte(`{"data":{"providerReadiness":[{"id":"pfready_cli","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_play","provider":"google_play","platform":"android","lane":"store","capability":"play.internal.submit","status":"blocked","blockerCode":"play_track_permission_missing","nextAction":"preflight oauth-clients configure --app-dir apps/mobile --provider google_oauth --client-kind google_android --platform android --android-sha1 AA:BB --external-client-id <CLIENT_ID>","requiredHumanRole":"Google Auth Platform administrator","credentialReferenceIds":[],"facts":{},"adapterVersion":"fake-play-adapter@1"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_readiness_list"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var recordOut bytes.Buffer
	code := run(
		[]string{
			"provider-readiness",
			"record",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider-account-id",
			"pfprov_play",
			"--provider",
			"google_play",
			"--platform",
			"android",
			"--lane",
			"store",
			"--capability",
			"play.internal.submit",
			"--status",
			"blocked",
			"--blocker-code",
			"play_track_permission_missing",
			"--next-action",
			"preflight oauth-clients configure --app-dir apps/mobile --provider google_oauth --client-kind google_android --platform android --android-sha1 AA:BB --external-client-id <CLIENT_ID>",
			"--required-human-role",
			"Google Auth Platform administrator",
			"--adapter-version",
			"fake-play-adapter@1",
		},
		&recordOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("record exit = %d, stdout = %s", code, recordOut.String())
	}
	if !strings.Contains(recordOut.String(), "provider readiness pfready_cli google_play play.internal.submit blocked") {
		t.Fatalf("unexpected record output %q", recordOut.String())
	}

	var listOut bytes.Buffer
	code = run(
		[]string{
			"provider-readiness",
			"list",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider",
			"google_play",
			"--capability",
			"play.internal.submit",
		},
		&listOut,
		&bytes.Buffer{},
		server.Client(),
	)
	if code != 0 {
		t.Fatalf("list exit = %d, stdout = %s", code, listOut.String())
	}
	if !strings.Contains(listOut.String(), "pfready_cli google_play play.internal.submit blocked play_track_permission_missing") {
		t.Fatalf("unexpected list output %q", listOut.String())
	}
	if !strings.Contains(listOut.String(), "next_action=\"preflight oauth-clients configure --app-dir apps/mobile --provider google_oauth --client-kind google_android --platform android --android-sha1 AA:BB --external-client-id <CLIENT_ID>\"") ||
		!strings.Contains(listOut.String(), "required_human_role=\"Google Auth Platform administrator\"") {
		t.Fatalf("expected next action and role in list output, got %q", listOut.String())
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 API calls, got %v", calls)
	}
}

func TestProviderReadinessPlanUsesAppScopedSetupPlanAPI(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/apps/pfapp_mobile/provider-setup-plan":
			if r.URL.Query().Get("workspaceId") != "local" ||
				r.URL.Query().Get("platform") != "ios" ||
				r.URL.Query().Get("lane") != "development" {
				t.Fatalf("unexpected setup plan query %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":{"providerSetupPlan":{"workspaceId":"local","appId":"pfapp_mobile","platform":"ios","lane":"development","ready":false,"requirements":[{"provider":"expo","capability":"expo.api.auth","status":"ready","credentialReferenceIds":[],"source":"readiness"},{"provider":"eas","capability":"eas.project.config","status":"blocked","blockerCode":"eas_project_id_missing","nextAction":"preflight providers verify --provider eas --credential-ref <EXPO_TOKEN_SECRET_REF> --app-dir <APP_DIR>","credentialReferenceIds":[],"source":"readiness"},{"provider":"google_oauth","capability":"oauth.google.ios","status":"blocked","blockerCode":"provider_readiness_missing","nextAction":"preflight oauth-clients configure --app-dir <APP_DIR> --provider google_oauth --client-kind google_ios","requiredHumanRole":"Google Auth Platform administrator","credentialReferenceIds":[],"source":"synthesized"}],"nextActions":["preflight providers verify --provider eas --credential-ref <EXPO_TOKEN_SECRET_REF> --app-dir <APP_DIR>","preflight oauth-clients configure --app-dir <APP_DIR> --provider google_oauth --client-kind google_ios"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_provider_setup_plan"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"provider-readiness",
			"plan",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--platform",
			"ios",
			"--lane",
			"development",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 1 {
		t.Fatalf("plan exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "provider setup plan pfapp_mobile ios development blocked") ||
		!strings.Contains(stdout.String(), "eas eas.project.config blocked eas_project_id_missing") ||
		!strings.Contains(stdout.String(), "next_action=\"preflight providers verify --provider eas --credential-ref <EXPO_TOKEN_SECRET_REF> --app-dir <APP_DIR>\"") ||
		!strings.Contains(stdout.String(), "google_oauth oauth.google.ios blocked provider_readiness_missing") ||
		!strings.Contains(stdout.String(), "required_human_role=\"Google Auth Platform administrator\"") {
		t.Fatalf("unexpected setup plan output %q", stdout.String())
	}
	if len(calls) != 1 {
		t.Fatalf("expected one setup plan API call, got %v", calls)
	}
}

func TestCredentialFlowsListUsesProviderAccountScopedAPI(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/provider-accounts/pfprov_google_oauth/credential-flows":
			if r.URL.Query().Get("workspaceId") != "local" ||
				r.URL.Query().Get("appId") != "pfapp_mobile" ||
				r.URL.Query().Get("provider") != "google_oauth" ||
				r.URL.Query().Get("status") != "waiting_for_human" {
				t.Fatalf("unexpected credential flow query %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":{"credentialFlows":[{"id":"pfcredflow_google_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","capability":"google_oauth.management","action":"inspect","status":"waiting_for_human","nextAction":"preflight oauth-clients configure --app-dir <APP_DIR> --all-required","secretReferenceIds":[]}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_credential_flow_list"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"credential-flows",
			"list",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider-account-id",
			"pfprov_google_oauth",
			"--provider",
			"google_oauth",
			"--status",
			"waiting_for_human",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("credential-flows list exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "pfcredflow_google_oauth google_oauth google_oauth.management inspect waiting_for_human") ||
		!strings.Contains(stdout.String(), "next_action=\"preflight oauth-clients configure --app-dir <APP_DIR> --all-required\"") {
		t.Fatalf("unexpected credential-flows list output %q", stdout.String())
	}
	if len(calls) != 1 {
		t.Fatalf("expected one credential-flow API call, got %v", calls)
	}
}

func TestCredentialFlowsCreateUsesProviderAccountScopedAPI(t *testing.T) {
	var credentialFlowBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/provider-accounts/pfprov_google_oauth/credential-flows":
			if err := json.NewDecoder(r.Body).Decode(&credentialFlowBody); err != nil {
				t.Fatalf("decode credential flow body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"credentialFlow":{"id":"pfcredflow_google_oauth","workspaceId":"local","appId":"pfapp_mobile","providerAccountId":"pfprov_google_oauth","provider":"google_oauth","capability":"google_oauth.management","action":"inspect","status":"waiting_for_human","nextAction":"preflight oauth-clients configure --app-dir apps/mobile --all-required","secretReferenceIds":["pfsec_google_admin"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_credential_flow_create"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"credential-flows",
			"create",
			"--api-url",
			server.URL,
			"--workspace-id",
			"local",
			"--app-id",
			"pfapp_mobile",
			"--provider-account-id",
			"pfprov_google_oauth",
			"--provider",
			"google_oauth",
			"--capability",
			"google_oauth.management",
			"--action",
			"inspect",
			"--status",
			"waiting_for_human",
			"--prompt",
			"Create or import required Google Auth Platform clients.",
			"--next-action",
			"preflight oauth-clients configure --app-dir apps/mobile --all-required",
			"--credential-ref",
			"pfsec_google_admin",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("credential-flows create exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if credentialFlowBody["workspaceId"] != "local" ||
		credentialFlowBody["appId"] != "pfapp_mobile" ||
		credentialFlowBody["provider"] != "google_oauth" ||
		credentialFlowBody["capability"] != "google_oauth.management" ||
		credentialFlowBody["action"] != "inspect" ||
		credentialFlowBody["status"] != "waiting_for_human" ||
		credentialFlowBody["prompt"] != "Create or import required Google Auth Platform clients." ||
		credentialFlowBody["nextAction"] != "preflight oauth-clients configure --app-dir apps/mobile --all-required" {
		t.Fatalf("unexpected credential flow create body %#v", credentialFlowBody)
	}
	secretRefs := credentialFlowBody["secretReferenceIds"].([]any)
	if !containsAny(secretRefs, "pfsec_google_admin") {
		t.Fatalf("expected credential ref in create body %#v", credentialFlowBody)
	}
	if !strings.Contains(stdout.String(), "credential flow pfcredflow_google_oauth google_oauth google_oauth.management inspect waiting_for_human") ||
		!strings.Contains(stdout.String(), "next_action=\"preflight oauth-clients configure --app-dir apps/mobile --all-required\"") {
		t.Fatalf("unexpected credential-flows create output %q", stdout.String())
	}
}

func TestDefaultRunnerCapabilitiesAdvertiseOnlyWhatTheHostHas(t *testing.T) {
	// This used to assert a fixed list, which passed everywhere because the
	// list was hardcoded — that is exactly the bug: labnuc (Linux) advertised
	// xcrun/simctl/fastlane/adb while having none of them, so it could be
	// handed iOS work it could not run. Assert the invariant instead, so the
	// test means something on a Mac, on Linux CI, and on a bare container.
	capabilities := defaultRunnerCapabilities("lan")

	localTools, ok := capabilities["localTools"].([]string)
	if !ok {
		t.Fatalf("expected localTools capability list, got %#v", capabilities["localTools"])
	}
	for _, tool := range localTools {
		if !localToolAvailable(tool) {
			t.Errorf("advertised %q but it is not available on this host", tool)
		}
	}

	platforms, ok := capabilities["platforms"].([]string)
	if !ok {
		t.Fatalf("expected platforms capability list, got %#v", capabilities["platforms"])
	}
	for _, platform := range platforms {
		switch platform {
		case "ios":
			if !localToolAvailable("xcrun") {
				t.Error("advertised ios without xcrun")
			}
		case "android":
			if resolveAndroidSdkTool("adb") == "" {
				t.Error("advertised android without a resolvable adb")
			}
		default:
			t.Errorf("unexpected platform %q", platform)
		}
	}

	// Platform-specific adapters must not outlive their platform.
	adapters, ok := capabilities["adapters"].([]string)
	if !ok {
		t.Fatalf("expected adapters capability list, got %#v", capabilities["adapters"])
	}
	have := map[string]bool{}
	for _, platform := range platforms {
		have[platform] = true
	}
	for _, adapter := range adapters {
		if required, gated := adapterRequirements[adapter]; gated && !have[required] {
			t.Errorf("advertised adapter %q without platform %q", adapter, required)
		}
	}
}

func TestSetupRunsAllowlistedProviderManagementCommands(t *testing.T) {
	appDir := t.TempDir()
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "provider-setup.log")

	for _, name := range []string{"gcloud", "adb", "emulator", "sdkmanager", "avdmanager"} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$(basename "$0")" "$*" >> "$PROVIDER_SETUP_LOG"
exit 0
`), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROVIDER_SETUP_LOG", commandLog)

	for _, commandLine := range []string{
		"gcloud auth application-default login --no-launch-browser",
		"gcloud services enable androidpublisher.googleapis.com",
		"adb devices",
		"emulator -list-avds",
		"sdkmanager --list",
		"avdmanager list avd",
	} {
		t.Run(commandLine, func(t *testing.T) {
			if _, err := runGuidedSetupCommand(commandLine, appDir, &bytes.Buffer{}); err != nil {
				t.Fatalf("expected provider setup command to be allowed: %v", err)
			}
		})
	}

	output, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read provider setup log: %v", err)
	}
	for _, expected := range []string{
		"gcloud :: auth application-default login --no-launch-browser",
		"gcloud :: services enable androidpublisher.googleapis.com",
		"adb :: devices",
		"emulator :: -list-avds",
		"sdkmanager :: --list",
		"avdmanager :: list avd",
	} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("expected provider setup log to contain %q, got %q", expected, string(output))
		}
	}
}

func TestSetupRejectsGoogleIAMOAuthClientCommandsForGoogleAuthPlatform(t *testing.T) {
	_, err := runGuidedSetupCommand(
		"gcloud iam oauth-clients list --location=global",
		t.TempDir(),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("expected Google IAM OAuth client setup command to be rejected")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestSetupUsesSavedPreflightLoginConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "preflight", "config.json")
	t.Setenv("PREFLIGHT_CONFIG_PATH", configPath)
	workspaceRoot := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer setup_token_123" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/preflight/v1/workflows/pfw_setup_auth" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_setup_auth","workspaceId":"ws_setup_saved","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_auth","status":"waiting","phase":"eas_setup_required","blockerCode":"eas_setup_required"},"runnerJobs":[{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","payload":{"sourceBinding":{"id":"pfsrc_setup_auth","workspaceRoot":%q,"packagePath":"apps/mobile"}},"result":{"status":"setup_required","setupRequired":{"code":"expo_token_secret_required","commands":["preflight credentials create --provider expo --purpose api_token --key EXPO_TOKEN --value-env EXPO_TOKEN"]}}}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_setup_auth"}}`, workspaceRoot)
	}))
	t.Cleanup(server.Close)

	if err := savePreflightCLIConfig(preflightCLIConfig{
		APIVersion:        "v1",
		APIURL:            server.URL,
		Token:             "setup_token_123",
		WorkspaceID:       "ws_setup_saved",
		WorkspaceBindings: map[string]string{},
	}); err != nil {
		t.Fatalf("save CLI config: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"setup", "--workflow-id", "pfw_setup_auth"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "setup required pfw_setup_auth expo_token_secret_required") {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
}

func TestSetupRunsGuidedEASCommandRecordsTranscriptAndResumesWorkflow(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$EAS_LOG"
printf 'configured with EAS_TOKEN=super_secret_token\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("EAS_LOG", commandLog)

	var transcriptID string
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/preflight/v1/workflows/pfw_setup":
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_setup","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup","status":"waiting","phase":"eas_setup_required","blockerCode":"eas_setup_required","blockerMessage":"Run EAS build interactively so Expo can configure iOS internal-distribution credentials."},"runnerJobs":[{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"id":"pfsrc_initial","workspaceRoot":%q,"packagePath":"apps/mobile"}},"result":{"status":"setup_required","setupRequired":{"code":"eas_credentials_setup_required","message":"Run EAS build interactively so Expo can configure iOS internal-distribution credentials.","commands":["eas build --platform ios --profile development-device"]},"easBuild":{"platform":"ios","profile":"development-device","targetClass":"device"}}}],"events":[],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`, workspaceRoot)
		case "/api/preflight/v1/setup-transcripts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transcript body: %v", err)
			}
			if body["workflowId"] != "pfw_setup" || body["sourceBindingId"] != "pfsrc_initial" {
				t.Fatalf("unexpected transcript body %#v", body)
			}
			if body["status"] != "completed" {
				t.Fatalf("expected completed transcript, got %#v", body)
			}
			redactedContent, _ := body["redactedContent"].(string)
			if strings.Contains(redactedContent, "super_secret_token") {
				t.Fatalf("transcript leaked setup command output: %s", redactedContent)
			}
			transcriptID = "pfsetup_cli"
			_, _ = w.Write([]byte(`{"data":{"setupTranscript":{"id":"pfsetup_cli","workflowId":"pfw_setup","sourceBindingId":"pfsrc_initial","status":"completed","summary":"EAS setup command completed.","commands":["eas build --platform ios --profile development-device"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_transcript"}}`))
		case "/api/preflight/v1/workflows/pfw_setup/resume-setup":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode resume body: %v", err)
			}
			if body["workspaceId"] != "ws_setup" || body["setupTranscriptId"] != transcriptID {
				t.Fatalf("unexpected resume body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_setup","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup","status":"waiting","phase":"eas_readiness_queued","blockerCode":"waiting_for_eas_setup"},"runnerJobs":[],"events":[{"eventType":"eas.setup.resumed"}],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_resume"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"setup",
			"--api-url",
			server.URL,
			"--workflow-id",
			"pfw_setup",
			"--run",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{
		"setup required pfw_setup eas_credentials_setup_required",
		"running setup command: eas build --platform ios --profile development-device",
		"recorded setup transcript pfsetup_cli completed",
		"resumed workflow pfw_setup eas_readiness_queued",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected stdout to contain %q, got %q", expected, stdout.String())
		}
	}
	waitForFileContains(t, commandLog, "apps/mobile :: build --platform ios --profile development-device")
	if strings.Join(calls, "\n") != strings.Join([]string{
		"GET /api/preflight/v1/workflows/pfw_setup",
		"POST /api/preflight/v1/setup-transcripts",
		"POST /api/preflight/v1/workflows/pfw_setup/resume-setup",
	}, "\n") {
		t.Fatalf("unexpected API calls %v", calls)
	}
}

func TestSetupRecordsChangedSourceBoundFiles(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	writeExpoConfigIdentity(t, appDir)
	if err := os.WriteFile(filepath.Join(appDir, "eas.json"), []byte(`{"build":{"development-device":{"developmentClient":true,"distribution":"internal"}}}`), 0o644); err != nil {
		t.Fatalf("write eas.json: %v", err)
	}

	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '{"build":{"development-device":{"developmentClient":true,"distribution":"internal","ios":{"simulator":false}}}}' > eas.json
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var changedFiles []any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/preflight/v1/workflows/pfw_setup_changed":
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_setup_changed","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_changed","status":"waiting","phase":"eas_setup_required","blockerCode":"eas_setup_required","blockerMessage":"Run EAS build interactively so Expo can configure iOS internal-distribution credentials."},"runnerJobs":[{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"id":"pfsrc_initial","workspaceRoot":%q,"packagePath":"apps/mobile"}},"result":{"status":"setup_required","setupRequired":{"code":"eas_credentials_setup_required","message":"Run EAS build interactively so Expo can configure iOS internal-distribution credentials.","commands":["eas build --platform ios --profile development-device"]},"easBuild":{"platform":"ios","profile":"development-device","targetClass":"device"}}}],"events":[],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`, workspaceRoot)
		case "/api/preflight/v1/setup-transcripts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transcript body: %v", err)
			}
			changedFiles, _ = body["changedFiles"].([]any)
			_, _ = w.Write([]byte(`{"data":{"setupTranscript":{"id":"pfsetup_changed","workflowId":"pfw_setup_changed","sourceBindingId":"pfsrc_initial","status":"completed","summary":"EAS setup command completed.","commands":["eas build --platform ios --profile development-device"],"changedFiles":["apps/mobile/eas.json"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_transcript"}}`))
		case "/api/preflight/v1/workflows/pfw_setup_changed/resume-setup":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode resume body: %v", err)
			}
			sourceBinding, ok := body["sourceBinding"].(map[string]any)
			if !ok {
				t.Fatalf("expected resume setup to include successor source binding, got %#v", body)
			}
			if sourceBinding["packagePath"] != "apps/mobile" || sourceBinding["easJsonDigest"] == "" {
				t.Fatalf("unexpected successor source binding %#v", sourceBinding)
			}
			changedSetupFiles, _ := sourceBinding["changedSetupFiles"].([]any)
			if len(changedSetupFiles) != 1 || changedSetupFiles[0] != "apps/mobile/eas.json" {
				t.Fatalf("expected successor binding changed setup files, got %#v", sourceBinding)
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_setup_changed","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_changed","status":"waiting","phase":"eas_readiness_queued","blockerCode":"waiting_for_eas_setup"},"runnerJobs":[],"events":[{"eventType":"setup.source_rebound"},{"eventType":"eas.setup.resumed"}],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_resume"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"setup",
			"--api-url",
			server.URL,
			"--workflow-id",
			"pfw_setup_changed",
			"--run",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if len(changedFiles) != 1 || changedFiles[0] != "apps/mobile/eas.json" {
		t.Fatalf("expected setup transcript to include changed eas.json, got %#v", changedFiles)
	}
	if !strings.Contains(stdout.String(), "resumed workflow pfw_setup_changed eas_readiness_queued") {
		t.Fatalf("expected setup to resume with successor source binding, got %q", stdout.String())
	}
}

func TestSetupRecordsCreatedCredentialReferencesFromGuidedOutput(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "preflight"), []byte(`#!/usr/bin/env sh
printf 'created credential pfsec_expo_setup expo EXPO_TOKEN development\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake preflight: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/preflight/v1/workflows/pfw_setup_secret":
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_setup_secret","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_secret","status":"waiting","phase":"eas_setup_required","blockerCode":"eas_setup_required","blockerMessage":"Create a Preflight-owned Expo API token before EAS runs."},"runnerJobs":[{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"id":"pfsrc_initial","workspaceRoot":%q,"packagePath":"apps/mobile"}},"result":{"status":"setup_required","setupRequired":{"code":"expo_token_secret_required","message":"Create a Preflight-owned Expo API token before EAS runs.","commands":["preflight credentials create --api-url http://localhost:3031 --workspace-id ws_setup --app-id pfapp_mobile --provider expo --purpose api_token --key EXPO_TOKEN --lane development --value-env EXPO_TOKEN"]}}}],"events":[],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`, workspaceRoot)
		case "/api/preflight/v1/setup-transcripts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transcript body: %v", err)
			}
			secretRefs, _ := body["secretReferenceIds"].([]any)
			if len(secretRefs) != 1 || secretRefs[0] != "pfsec_expo_setup" {
				t.Fatalf("expected setup transcript to include created secret reference, got %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"setupTranscript":{"id":"pfsetup_secret","workflowId":"pfw_setup_secret","sourceBindingId":"pfsrc_initial","status":"completed","summary":"EAS setup command completed.","commands":["preflight credentials create --api-url http://localhost:3031 --workspace-id ws_setup --app-id pfapp_mobile --provider expo --purpose api_token --key EXPO_TOKEN --lane development --value-env EXPO_TOKEN"],"secretReferenceIds":["pfsec_expo_setup"],"changedFiles":[]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_transcript"}}`))
		case "/api/preflight/v1/workflows/pfw_setup_secret/resume-setup":
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_setup_secret","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_secret","status":"waiting","phase":"eas_readiness_queued","blockerCode":"waiting_for_eas_setup"},"runnerJobs":[],"events":[{"eventType":"eas.setup.resumed"}],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_resume"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"setup",
			"--api-url",
			server.URL,
			"--workflow-id",
			"pfw_setup_secret",
			"--run",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "resumed workflow pfw_setup_secret eas_readiness_queued") {
		t.Fatalf("expected setup to resume workflow, got %q", stdout.String())
	}
}

func TestSetupStreamsGuidedCommandOutputWithRedaction(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'Select credentials for internal distribution\n'
printf 'EAS_TOKEN=super_secret_token\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/preflight/v1/workflows/pfw_setup_stream":
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_setup_stream","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_stream","status":"waiting","phase":"eas_setup_required","blockerCode":"eas_setup_required"},"runnerJobs":[{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"id":"pfsrc_initial","workspaceRoot":%q,"packagePath":"apps/mobile"}},"result":{"status":"setup_required","setupRequired":{"code":"eas_credentials_setup_required","commands":["eas build --platform ios --profile development-device"]},"easBuild":{"platform":"ios","profile":"development-device","targetClass":"device"}}}],"events":[],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`, workspaceRoot)
		case "/api/preflight/v1/setup-transcripts":
			_, _ = w.Write([]byte(`{"data":{"setupTranscript":{"id":"pfsetup_stream","workflowId":"pfw_setup_stream","sourceBindingId":"pfsrc_initial","status":"completed","summary":"EAS setup command completed.","commands":["eas build --platform ios --profile development-device"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_transcript"}}`))
		case "/api/preflight/v1/workflows/pfw_setup_stream/resume-setup":
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_setup_stream","workspaceId":"ws_setup","appId":"pfapp_mobile","platform":"ios","lane":"development","status":"waiting"},"workflowProjection":{"workflowId":"pfw_setup_stream","status":"waiting","phase":"eas_readiness_queued","blockerCode":"waiting_for_eas_setup"},"runnerJobs":[],"events":[{"eventType":"eas.setup.resumed"}],"runtime-artifacts":[],"setupTranscripts":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_resume"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"setup",
			"--api-url",
			server.URL,
			"--workflow-id",
			"pfw_setup_stream",
			"--run",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Select credentials for internal distribution") {
		t.Fatalf("expected setup command output to stream, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "super_secret_token") {
		t.Fatalf("expected streamed setup output to be redacted, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "EAS_TOKEN=[REDACTED]") {
		t.Fatalf("expected redacted token marker in streamed output, got %q", stdout.String())
	}
}

func TestSetupStreamsPromptFragmentsBeforeCommandExits(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	allowExit := filepath.Join(t.TempDir(), "allow-exit")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '? Do you want to log in to your Apple account? (Y/n)'
while [ ! -f "$ALLOW_EXIT" ]; do
  sleep 0.02
done
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ALLOW_EXIT", allowExit)

	var stdout lockedBuffer
	done := make(chan struct{})
	var transcript string
	var runErr error
	go func() {
		transcript, runErr = runGuidedSetupCommand("eas build --platform ios --profile development-device", appDir, &stdout)
		close(done)
	}()

	defer func() {
		_ = os.WriteFile(allowExit, []byte("ok"), 0o644)
		<-done
	}()

	waitForBufferContains(t, &stdout, "Do you want to log in to your Apple account?")

	_ = os.WriteFile(allowExit, []byte("ok"), 0o644)
	<-done
	if runErr != nil {
		t.Fatalf("expected prompt command to exit cleanly: %v", runErr)
	}
	if !strings.Contains(transcript, "Do you want to log in to your Apple account?") {
		t.Fatalf("expected prompt fragment in transcript, got %q", transcript)
	}
}

func TestSetupRunsAllowlistedNpxExpoAndEASCommands(t *testing.T) {
	appDir := t.TempDir()
	fakeBin := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NPX_LOG", commandLog)

	for _, commandLine := range []string{
		"npx expo install expo-dev-client",
		"npx eas-cli build:configure --platform ios",
	} {
		t.Run(commandLine, func(t *testing.T) {
			if _, err := runGuidedSetupCommand(commandLine, appDir, &bytes.Buffer{}); err != nil {
				t.Fatalf("expected setup command to be allowed: %v", err)
			}
		})
	}

	output, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	for _, expected := range []string{
		"expo install expo-dev-client",
		"eas-cli build:configure --platform ios",
	} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("expected npx log to contain %q, got %q", expected, string(output))
		}
	}
}

func TestSetupAllowsPreflightCredentialCreateAndRejectsEASLogin(t *testing.T) {
	if err := validateGuidedSetupCommand(strings.Fields("preflight credentials create --provider expo --purpose api_token --key EXPO_TOKEN --lane development --value-env EXPO_TOKEN")); err != nil {
		t.Fatalf("expected Preflight credential setup command to be allowed: %v", err)
	}
	if err := validateGuidedSetupCommand(strings.Fields("npx eas-cli login")); err == nil {
		t.Fatal("expected EAS login setup command to be rejected")
	}
	if err := validateGuidedSetupCommand(strings.Fields("eas login")); err == nil {
		t.Fatal("expected raw EAS login setup command to be rejected")
	}
}

func TestSetupRejectsUntrustedNpxCommands(t *testing.T) {
	_, err := runGuidedSetupCommand("npx arbitrary-tool login", t.TempDir(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected untrusted npx setup command to be rejected")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestProveAppDiscoversExpoPackageAndCreatesWorkflow(t *testing.T) {
	appDir := writeExpoFixture(t)
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--json"},
		&stdout,
		&bytes.Buffer{},
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	sourceBinding := received["sourceBinding"].(map[string]any)
	if sourceBinding["packageName"] != "@forgegraph/mobile" {
		t.Fatalf("unexpected packageName %v", sourceBinding["packageName"])
	}
	if sourceBinding["packagePath"] != "." {
		t.Fatalf("unexpected packagePath %v", sourceBinding["packagePath"])
	}
	if sourceBinding["platform"] != "ios" || sourceBinding["lane"] != "simulator" {
		t.Fatalf("unexpected lane: %v/%v", sourceBinding["platform"], sourceBinding["lane"])
	}
	if !strings.Contains(stdout.String(), `"pfw_test"`) {
		t.Fatalf("expected workflow response on stdout, got %q", stdout.String())
	}
}

func TestProveAppProbesCapabilitiesBeforeCreatingWorkflow(t *testing.T) {
	appDir := writeExpoFixture(t)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--json"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if got := strings.Join(calls, ","); got != "GET /api/preflight/v1/capabilities,GET /api/preflight/v1/runners/capacity,POST /api/preflight/v1/workflows/prove-app" {
		t.Fatalf("prove-app must probe capabilities before workflow creation, got %s", got)
	}
}

func TestProveAppRequiresRunnerCapacityBeforeCreatingWorkflow(t *testing.T) {
	appDir := writeExpoFixture(t)
	createdWorkflow := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			if r.URL.Query().Get("workspaceId") != "local" {
				t.Fatalf("unexpected workspaceId %q", r.URL.Query().Get("workspaceId"))
			}
			if r.URL.Query().Get("workspaceRoot") != appDir {
				t.Fatalf("unexpected workspaceRoot %q", r.URL.Query().Get("workspaceRoot"))
			}
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"runner_required","workspaceId":"local","matchingRunnerCount":0}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_runner_capacity"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			createdWorkflow = true
			t.Fatalf("prove-app must not create a workflow before runner capacity is ready")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--json"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code == 0 {
		t.Fatalf("expected non-zero exit when runner capacity is missing\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if createdWorkflow {
		t.Fatal("workflow should not have been created")
	}
	if !strings.Contains(stderr.String(), "runner_required") {
		t.Fatalf("expected runner_required failure, got %q", stderr.String())
	}
	expectedCommand := fmt.Sprintf(
		"preflight runner --api-url %s --workspace-id local --workspace-root %s",
		server.URL,
		appDir,
	)
	if !strings.Contains(stderr.String(), expectedCommand) {
		t.Fatalf("expected runner start command %q, got %q", expectedCommand, stderr.String())
	}
}

func TestProveAppCanExplicitlyWaitForRunnerCapacity(t *testing.T) {
	appDir := writeExpoFixture(t)
	var calls []string
	var workflowRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"runner_required","workspaceId":"local","matchingRunnerCount":0,"nextAction":"preflight runner --api-url http://preflight.test --workspace-id local --workspace-root /workspace"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_runner_capacity"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			if err := json.NewDecoder(r.Body).Decode(&workflowRequest); err != nil {
				t.Fatalf("decode workflow request: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_wait_runner","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_workflow"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--wait-for-runner", "--json"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if got := strings.Join(calls, ","); got != "GET /api/preflight/v1/capabilities,GET /api/preflight/v1/runners/capacity,POST /api/preflight/v1/workflows/prove-app" {
		t.Fatalf("unexpected calls: %s", got)
	}
	if workflowRequest["workspaceId"] != "local" {
		t.Fatalf("expected workflow request even without runner capacity, got %#v", workflowRequest)
	}
	if !strings.Contains(stdout.String(), `"pfw_wait_runner"`) {
		t.Fatalf("expected workflow response on stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "runner_required") {
		t.Fatalf("expected explicit runner wait note, got %q", stderr.String())
	}
}

func TestProveAppDevelopmentLaneSelectsDeviceEASProfile(t *testing.T) {
	appDir := writeExpoFixture(t)
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"development",
			"--build-strategy",
			"eas",
			"--json",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if received["targetClass"] != "device" {
		t.Fatalf("expected development workflow to request a physical device, got %#v", received)
	}
	sourceBinding := received["sourceBinding"].(map[string]any)
	if sourceBinding["buildStrategy"] != "eas" {
		t.Fatalf("expected EAS build strategy in source binding, got %#v", sourceBinding)
	}
	if sourceBinding["platform"] != "ios" || sourceBinding["lane"] != "development" {
		t.Fatalf("unexpected source binding lane %#v", sourceBinding)
	}
	if sourceBinding["easProfileName"] != "development-device" {
		t.Fatalf("expected iOS device profile, got %#v", sourceBinding)
	}
	if sourceBinding["easProfileEnvDigest"] == "" {
		t.Fatalf("expected profile env digest, got %#v", sourceBinding)
	}
	if sourceBinding["appScheme"] != "forgegraph" || sourceBinding["expoSlug"] != "forgegraf" {
		t.Fatalf("expected app scheme and slug, got %#v", sourceBinding)
	}
}

func TestProveAppSendsSecretReferenceIdsForDevelopmentLane(t *testing.T) {
	appDir := writeExpoFixture(t)
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"development",
			"--secret-ref",
			"pfsec_expo",
			"--secret-ref",
			"pfsec_asc",
			"--json",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	secretReferenceIds, ok := received["secretReferenceIds"].([]any)
	if !ok {
		t.Fatalf("expected secretReferenceIds on workflow request, got %#v", received)
	}
	if fmt.Sprint(secretReferenceIds) != "[pfsec_expo pfsec_asc]" {
		t.Fatalf("unexpected secret refs %#v", secretReferenceIds)
	}
}

func TestProveAppLocalReadinessPrintsSourceBindingWithoutAPI(t *testing.T) {
	appDir := writeExpoFixture(t)
	writeExpoConfigIdentity(t, appDir)
	if err := os.WriteFile(
		filepath.Join(appDir, "app.config.ts"),
		[]byte(`export default { name: "ForgeGraph Mobile", slug: "forgegraf", scheme: "forgegraph", ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" }, android: { package: "com.gmacko.forgegraph.dev" }, extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } } }`),
		0o644,
	); err != nil {
		t.Fatalf("write app config identity: %v", err)
	}
	maestroDir := filepath.Join(appDir, ".maestro")
	if err := os.MkdirAll(maestroDir, 0o755); err != nil {
		t.Fatalf("create maestro dir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(maestroDir, "01-app-launches.yaml"),
		[]byte("appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n"),
		0o644,
	); err != nil {
		t.Fatalf("write maestro flow: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--local-readiness",
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"development",
			"--json",
		},
		&stdout,
		&stderr,
		http.DefaultClient,
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode local readiness JSON: %v\nstdout: %s", err, stdout.String())
	}
	if report["ready"] != true {
		t.Fatalf("expected local readiness to pass, got %#v", report)
	}
	sourceBinding := report["sourceBinding"].(map[string]any)
	if sourceBinding["appId"] != "pfapp_forgegraph_mobile" ||
		sourceBinding["easProfileName"] != "development-device" ||
		sourceBinding["iosBundleId"] != "com.gmacko.forgegraph.dev" {
		t.Fatalf("unexpected source binding %#v", sourceBinding)
	}
	if report["maestroFlowPath"] != filepath.Join(appDir, ".maestro", "01-app-launches.yaml") {
		t.Fatalf("unexpected maestro flow path %#v", report["maestroFlowPath"])
	}
	checks := report["checks"].([]any)
	if len(checks) == 0 {
		t.Fatalf("expected readiness checks, got %#v", report)
	}
}

func TestProveAppLocalReadinessInfersDevelopmentLaneForPhysicalTarget(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		platform        string
		targetKind      string
		expectedProfile string
	}{
		{name: "iphone", platform: "ios", targetKind: "iphone", expectedProfile: "development-device"},
		{name: "android phone", platform: "android", targetKind: "android-phone", expectedProfile: "development-android"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			appDir := writeExpoFixture(t)
			if err := os.WriteFile(
				filepath.Join(appDir, "app.config.ts"),
				[]byte(`export default { name: "ForgeGraph Mobile", slug: "forgegraf", scheme: "forgegraph", ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" }, android: { package: "com.gmacko.forgegraph.dev" }, extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } } }`),
				0o644,
			); err != nil {
				t.Fatalf("write app config identity: %v", err)
			}
			if err := os.WriteFile(
				filepath.Join(appDir, "eas.json"),
				[]byte(`{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":true}},"development-device":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":false}},"development-android":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"android":{"buildType":"apk"}}}}`),
				0o644,
			); err != nil {
				t.Fatalf("write eas json: %v", err)
			}
			maestroDir := filepath.Join(appDir, ".maestro")
			if err := os.MkdirAll(maestroDir, 0o755); err != nil {
				t.Fatalf("create maestro dir: %v", err)
			}
			if err := os.WriteFile(
				filepath.Join(maestroDir, "01-app-launches.yaml"),
				[]byte("appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n"),
				0o644,
			); err != nil {
				t.Fatalf("write maestro flow: %v", err)
			}

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := run(
				[]string{
					"prove-app",
					"--local-readiness",
					"--app-dir",
					appDir,
					"--platform",
					testCase.platform,
					"--target-kind",
					testCase.targetKind,
					"--json",
				},
				&stdout,
				&stderr,
				http.DefaultClient,
			)

			if code != 0 {
				t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
			}
			var report map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("decode local readiness JSON: %v\nstdout: %s", err, stdout.String())
			}
			sourceBinding := report["sourceBinding"].(map[string]any)
			if sourceBinding["lane"] != "development" || sourceBinding["easProfileName"] != testCase.expectedProfile {
				t.Fatalf("expected physical target to infer development lane/profile, got %#v", sourceBinding)
			}
		})
	}
}

func TestProveAppLocalReadinessPrefersAndroidDevelopmentProfile(t *testing.T) {
	appDir := writeExpoFixture(t)
	if err := os.WriteFile(
		filepath.Join(appDir, "app.config.ts"),
		[]byte(`export default { name: "ForgeGraph Mobile", slug: "forgegraf", scheme: "forgegraph", ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" }, android: { package: "com.gmacko.forgegraph.dev" }, extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } } }`),
		0o644,
	); err != nil {
		t.Fatalf("write app config identity: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(appDir, "eas.json"),
		[]byte(`{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":true}},"development-android":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"android":{"buildType":"apk"}}}}`),
		0o644,
	); err != nil {
		t.Fatalf("write eas json: %v", err)
	}
	maestroDir := filepath.Join(appDir, ".maestro")
	if err := os.MkdirAll(maestroDir, 0o755); err != nil {
		t.Fatalf("create maestro dir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(maestroDir, "01-app-launches.yaml"),
		[]byte("appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n"),
		0o644,
	); err != nil {
		t.Fatalf("write maestro flow: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--local-readiness",
			"--app-dir",
			appDir,
			"--platform",
			"android",
			"--lane",
			"development",
			"--json",
		},
		&stdout,
		&stderr,
		http.DefaultClient,
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode local readiness JSON: %v\nstdout: %s", err, stdout.String())
	}
	sourceBinding := report["sourceBinding"].(map[string]any)
	if sourceBinding["easProfileName"] != "development-android" {
		t.Fatalf("expected Android development profile, got %#v", sourceBinding)
	}
}

func TestProveAppSourceBindingRecordsDirtyWorkspaceAndChangedSetupFiles(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	for name, content := range map[string]string{
		"pnpm-workspace.yaml":             "packages:\n  - apps/*\n",
		"package.json":                    `{"name":"forgegraph-root","private":true,"workspaces":["apps/*"]}`,
		"apps/mobile/package.json":        `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15"}}`,
		"apps/mobile/app.config.ts":       `export default { slug: "forgegraf", scheme: "forgegraph" }`,
		"apps/mobile/eas.json":            `{"build":{"development":{"developmentClient":true,"distribution":"internal","ios":{"simulator":true}}}}`,
		"apps/mobile/src/unrelated.ts":    `export const unrelated = true;`,
		"apps/mobile/.maestro/smoke.yaml": "appId: forgegraph\n---\n",
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	runGit(t, workspaceRoot, "init")
	runGit(t, workspaceRoot, "checkout", "-b", "preflight-test")
	runGit(t, workspaceRoot, "remote", "add", "origin", "https://example.com/forgegraph.git")
	runGit(t, workspaceRoot, "add", ".")
	runGit(t, workspaceRoot, "-c", "user.email=preflight@example.com", "-c", "user.name=Preflight Test", "commit", "-m", "baseline")
	commitSHA := runGitOutput(t, workspaceRoot, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(appDir, "app.config.ts"), []byte(`export default { slug: "forgegraf-dev", scheme: "forgegraph" }`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "eas.json"), []byte(`{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":true}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "src", "unrelated.ts"), []byte(`export const unrelated = "changed";`), 0o644); err != nil {
		t.Fatal(err)
	}

	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"simulator",
			"--json",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	sourceBinding := received["sourceBinding"].(map[string]any)
	if sourceBinding["dirtyWorkspace"] != true {
		t.Fatalf("expected dirty workspace in source binding, got %#v", sourceBinding)
	}
	if sourceBinding["gitRemoteUrl"] != "https://example.com/forgegraph.git" {
		t.Fatalf("expected git remote URL, got %#v", sourceBinding)
	}
	if sourceBinding["gitBranch"] != "preflight-test" {
		t.Fatalf("expected git branch, got %#v", sourceBinding)
	}
	if sourceBinding["gitCommitSha"] != commitSHA {
		t.Fatalf("expected git commit %s, got %#v", commitSHA, sourceBinding)
	}
	changedSetupFiles, ok := sourceBinding["changedSetupFiles"].([]any)
	if !ok {
		t.Fatalf("expected changed setup files array, got %#v", sourceBinding["changedSetupFiles"])
	}
	if fmt.Sprint(changedSetupFiles) != "[apps/mobile/app.config.ts apps/mobile/eas.json]" {
		t.Fatalf("unexpected changed setup files %#v", changedSetupFiles)
	}
}

func TestProveAppSourceBindingSerializesEmptyChangedSetupFilesWhenDirtyOutsideSetup(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	for name, content := range map[string]string{
		"pnpm-workspace.yaml":      "packages:\n  - apps/*\n",
		"package.json":             `{"name":"forgegraph-root","private":true,"workspaces":["apps/*"]}`,
		"apps/mobile/package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15"}}`,
		"apps/mobile/app.config.ts": `export default {
			slug: "forgegraf",
			scheme: "forgegraph",
			ios: { bundleIdentifier: "com.gmacko.forgegraph" },
			android: { package: "com.gmacko.forgegraph" }
		}`,
		"apps/mobile/eas.json":         `{"build":{"development":{"developmentClient":true,"distribution":"internal","ios":{"simulator":true}}}}`,
		"apps/mobile/src/unrelated.ts": `export const unrelated = true;`,
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	runGit(t, workspaceRoot, "init")
	runGit(t, workspaceRoot, "checkout", "-b", "preflight-test")
	runGit(t, workspaceRoot, "add", ".")
	runGit(t, workspaceRoot, "-c", "user.email=preflight@example.com", "-c", "user.name=Preflight Test", "commit", "-m", "baseline")

	if err := os.WriteFile(filepath.Join(appDir, "src", "unrelated.ts"), []byte(`export const unrelated = "changed";`), 0o644); err != nil {
		t.Fatal(err)
	}

	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"simulator",
			"--json",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	sourceBinding := received["sourceBinding"].(map[string]any)
	changedSetupFiles, ok := sourceBinding["changedSetupFiles"].([]any)
	if !ok {
		t.Fatalf("expected changed setup files array, got %#v", sourceBinding["changedSetupFiles"])
	}
	if len(changedSetupFiles) != 0 {
		t.Fatalf("expected no changed setup files, got %#v", changedSetupFiles)
	}
}

func TestProveAppResolvesExpoConfigWithSelectedEASProfileEnv(t *testing.T) {
	appDir := t.TempDir()
	for name, content := range map[string]string{
		"package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"app.config.js": `module.exports = () => ({
			slug: "forgegraf-" + process.env.APP_VARIANT,
			scheme: "forgegraph-" + process.env.APP_VARIANT,
			ios: { bundleIdentifier: "com.gmacko.forgegraph." + process.env.BUNDLE_SUFFIX },
			android: { package: "com.gmacko.forgegraph." + process.env.BUNDLE_SUFFIX },
			extra: { eas: { projectId: process.env.EAS_PROJECT_ID } }
		})`,
		"eas.json": `{
			"build": {
				"development-device": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {
						"APP_VARIANT": "development",
						"EAS_PROJECT_ID": "05e5245e-6da8-4f7a-a557-324d36b02979"
					},
					"ios": {
						"simulator": false,
						"env": {
							"BUNDLE_SUFFIX": "dev"
						}
					}
				}
			}
		}`,
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf 'APP_VARIANT=%s BUNDLE_SUFFIX=%s :: %s\n' "$APP_VARIANT" "$BUNDLE_SUFFIX" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "config" ]; then
  printf '{"slug":"forgegraf-%s","scheme":"forgegraph-%s","ios":{"bundleIdentifier":"com.gmacko.forgegraph.%s"},"android":{"package":"com.gmacko.forgegraph.%s"},"extra":{"eas":{"projectId":"%s"}}}\n' "$APP_VARIANT" "$APP_VARIANT" "$BUNDLE_SUFFIX" "$BUNDLE_SUFFIX" "$EAS_PROJECT_ID"
  exit 0
fi
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("PREFLIGHT_FORCE_EXPO_CONFIG_CLI", "1")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"development",
			"--json",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	sourceBinding := received["sourceBinding"].(map[string]any)
	if sourceBinding["appScheme"] != "forgegraph-development" || sourceBinding["expoSlug"] != "forgegraf-development" {
		t.Fatalf("expected resolved app scheme and slug, got %#v", sourceBinding)
	}
	if sourceBinding["iosBundleId"] != "com.gmacko.forgegraph.dev" {
		t.Fatalf("expected profile-resolved iOS bundle ID, got %#v", sourceBinding)
	}
	if sourceBinding["androidPackage"] != "com.gmacko.forgegraph.dev" {
		t.Fatalf("expected profile-resolved Android package, got %#v", sourceBinding)
	}
	if sourceBinding["easProjectId"] != "05e5245e-6da8-4f7a-a557-324d36b02979" {
		t.Fatalf("expected resolved EAS project ID, got %#v", sourceBinding)
	}
	// resolveExpoConfig always digests the raw expo config file, even when the
	// Expo CLI resolution succeeds (see 1e5a641: digesting the evaluated JSON
	// let prove-app and runner-side validation compute different digests for
	// identical source when the CLI flaked, causing spurious
	// source_binding_mismatch failures). The evaluated config is only used to
	// resolve app identity (scheme/slug/bundle ids), not the digest.
	if sourceBinding["expoConfigDigest"] != digestIfExists(filepath.Join(appDir, "app.config.js")) {
		t.Fatalf("expected digest of raw app.config.js file, got %#v", sourceBinding["expoConfigDigest"])
	}
	expectedEnvDigest := digestJSON(map[string]string{
		"APP_VARIANT":    "development",
		"BUNDLE_SUFFIX":  "dev",
		"EAS_PROJECT_ID": "05e5245e-6da8-4f7a-a557-324d36b02979",
	})
	if sourceBinding["easProfileEnvDigest"] != expectedEnvDigest {
		t.Fatalf("expected merged profile env digest %s, got %#v", expectedEnvDigest, sourceBinding)
	}
	waitForFileContains(t, npxLog, "APP_VARIANT=development BUNDLE_SUFFIX=dev :: expo config --json --type public")
}

func TestProveAppResolvesExtendedEASProfileBeforeExpoConfig(t *testing.T) {
	appDir := t.TempDir()
	for name, content := range map[string]string{
		"package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"app.config.js": `module.exports = () => ({
			slug: "forgegraf-" + process.env.APP_VARIANT,
			scheme: "forgegraph-" + process.env.APP_VARIANT,
			ios: { bundleIdentifier: "com.gmacko.forgegraph." + process.env.BUNDLE_SUFFIX },
			android: { package: "com.gmacko.forgegraph." + process.env.BUNDLE_SUFFIX },
			extra: { eas: { projectId: process.env.EAS_PROJECT_ID } }
		})`,
		"eas.json": `{
			"build": {
				"base-development": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {
						"APP_VARIANT": "development",
						"EAS_PROJECT_ID": "05e5245e-6da8-4f7a-a557-324d36b02979"
					}
				},
				"development-device": {
					"extends": "base-development",
					"ios": {
						"simulator": false,
						"env": {
							"BUNDLE_SUFFIX": "dev"
						}
					}
				}
			}
		}`,
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf 'APP_VARIANT=%s BUNDLE_SUFFIX=%s :: %s\n' "$APP_VARIANT" "$BUNDLE_SUFFIX" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "config" ]; then
  printf '{"slug":"forgegraf-%s","scheme":"forgegraph-%s","ios":{"bundleIdentifier":"com.gmacko.forgegraph.%s"},"android":{"package":"com.gmacko.forgegraph.%s"},"extra":{"eas":{"projectId":"%s"}}}\n' "$APP_VARIANT" "$APP_VARIANT" "$BUNDLE_SUFFIX" "$BUNDLE_SUFFIX" "$EAS_PROJECT_ID"
  exit 0
fi
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("PREFLIGHT_FORCE_EXPO_CONFIG_CLI", "1")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCapabilitiesFixture(t, w, r) {
			return
		}
		if serveReadyRunnerCapacityFixture(t, w, r) {
			return
		}
		if r.URL.Path != "/api/preflight/v1/workflows/prove-app" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_test","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_test"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--platform",
			"ios",
			"--lane",
			"development",
			"--json",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	sourceBinding := received["sourceBinding"].(map[string]any)
	if sourceBinding["easProfileName"] != "development-device" {
		t.Fatalf("expected extended device profile, got %#v", sourceBinding)
	}
	if sourceBinding["appScheme"] != "forgegraph-development" || sourceBinding["expoSlug"] != "forgegraf-development" {
		t.Fatalf("expected resolved app scheme and slug from inherited profile env, got %#v", sourceBinding)
	}
	if sourceBinding["iosBundleId"] != "com.gmacko.forgegraph.dev" {
		t.Fatalf("expected inherited profile env to resolve iOS bundle ID, got %#v", sourceBinding)
	}
	if sourceBinding["easProjectId"] != "05e5245e-6da8-4f7a-a557-324d36b02979" {
		t.Fatalf("expected inherited EAS project ID, got %#v", sourceBinding)
	}
	expectedEnvDigest := digestJSON(map[string]string{
		"APP_VARIANT":    "development",
		"BUNDLE_SUFFIX":  "dev",
		"EAS_PROJECT_ID": "05e5245e-6da8-4f7a-a557-324d36b02979",
	})
	if sourceBinding["easProfileEnvDigest"] != expectedEnvDigest {
		t.Fatalf("expected inherited profile env digest %s, got %#v", expectedEnvDigest, sourceBinding)
	}
	waitForFileContains(t, npxLog, "APP_VARIANT=development BUNDLE_SUFFIX=dev :: expo config --json --type public")
}

func TestEASReadinessUsesExtendedProfileFields(t *testing.T) {
	appDir := t.TempDir()
	for name, content := range map[string]string{
		"package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"eas.json": `{
			"build": {
				"base-development": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {
						"APP_VARIANT": "development",
						"EAS_PROJECT_ID": "05e5245e-6da8-4f7a-a557-324d36b02979"
					}
				},
				"development-device": {
					"extends": "base-development",
					"ios": {
						"simulator": false,
						"env": {
							"BUNDLE_SUFFIX": "dev"
						}
					}
				}
			}
		}`,
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$EAS_LOG"
if [ "$1" = "whoami" ]; then
  printf 'forgegraph-bot\n'
  exit 0
fi
if [ "$1" = "build:list" ]; then
  printf '[]\n'
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	readiness, setupRequired := probeEASDevelopmentReadiness(
		appDir,
		runnerJobSourceBinding{EASJSONDigest: digestIfExists(filepath.Join(appDir, "eas.json"))},
		"development-device",
		"device",
		"ios",
	)

	if setupRequired != nil {
		t.Fatalf("expected inherited profile to be EAS-ready, got setup requirement %#v", setupRequired)
	}
	if readiness["developmentClient"] != true || readiness["distribution"] != "internal" {
		t.Fatalf("expected inherited development profile fields, got %#v", readiness)
	}
	if readiness["iosSimulator"] != false {
		t.Fatalf("expected extended device profile to target iOS devices, got %#v", readiness)
	}
	expectedEnvDigest := digestJSON(map[string]string{
		"APP_VARIANT":    "development",
		"BUNDLE_SUFFIX":  "dev",
		"EAS_PROJECT_ID": "05e5245e-6da8-4f7a-a557-324d36b02979",
	})
	if readiness["easProfileEnvDigest"] != expectedEnvDigest {
		t.Fatalf("expected inherited profile env digest %s, got %#v", expectedEnvDigest, readiness)
	}
	waitForFileContains(t, easLog, "build:list --platform ios --build-profile development-device --status finished --distribution internal --limit 1 --json --non-interactive")
}

func TestProveAppWatchPollsWorkflowUntilTerminal(t *testing.T) {
	appDir := writeExpoFixture(t)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_watch","status":"queued","appId":"pfapp_mobile","platform":"ios","lane":"simulator"},"runnerJob":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_create"}}`))
		case "GET /api/preflight/v1/workflows/pfw_watch/events":
			http.NotFound(w, r)
		case "GET /api/preflight/v1/workflows/pfw_watch":
			if countCalls(calls, "GET /api/preflight/v1/workflows/pfw_watch") == 1 {
				_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_watch","status":"running","appId":"pfapp_mobile","platform":"ios","lane":"simulator"},"workflowProjection":{"workflowId":"pfw_watch","status":"running","phase":"maestro_queued"},"runnerJobs":[],"events":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_watch_1"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_watch","status":"passed","appId":"pfapp_mobile","platform":"ios","lane":"simulator"},"workflowProjection":{"workflowId":"pfw_watch","status":"passed","phase":"maestro_smoke_passed"},"runnerJobs":[],"events":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_watch_2"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--watch",
			"--poll-interval",
			"1ms",
			"--watch-timeout",
			"1s",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "GET /api/preflight/v1/workflows/pfw_watch") != 2 {
		t.Fatalf("expected two workflow poll calls, got %v", calls)
	}
	for _, expected := range []string{
		"created workflow pfw_watch queued",
		"workflow pfw_watch running maestro_queued",
		"workflow pfw_watch passed maestro_smoke_passed",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected stdout to contain %q, got %q", expected, stdout.String())
		}
	}
}

func TestProveAppWatchPrefersSSEWorkflowEvents(t *testing.T) {
	appDir := writeExpoFixture(t)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_watch_sse","status":"queued","appId":"pfapp_mobile","platform":"ios","lane":"simulator"},"runnerJob":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_create"}}`))
		case "GET /api/preflight/v1/workflows/pfw_watch_sse/events":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(
				"id: 1\n" +
					"event: runner.job.queued\n" +
					`data: {"workflowId":"pfw_watch_sse","sequence":1,"eventType":"runner.job.queued","workflowProjection":{"workflowId":"pfw_watch_sse","status":"running","phase":"maestro_queued"}}` + "\n\n" +
					"id: 2\n" +
					"event: workflow.projection\n" +
					`data: {"workflowId":"pfw_watch_sse","sequence":2,"eventType":"workflow.projection","workflowProjection":{"workflowId":"pfw_watch_sse","status":"passed","phase":"maestro_smoke_passed"}}` + "\n\n",
			))
		case "GET /api/preflight/v1/workflows/pfw_watch_sse":
			t.Fatalf("polling endpoint should not be used when SSE reaches a terminal projection")
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"prove-app",
			"--api-url",
			server.URL,
			"--app-dir",
			appDir,
			"--watch",
			"--poll-interval",
			"1ms",
			"--watch-timeout",
			"1s",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Join(calls, "\n") != strings.Join([]string{
		"GET /api/preflight/v1/capabilities",
		"GET /api/preflight/v1/runners/capacity",
		"POST /api/preflight/v1/workflows/prove-app",
		"GET /api/preflight/v1/workflows/pfw_watch_sse/events",
	}, "\n") {
		t.Fatalf("expected create plus SSE watch calls, got %v", calls)
	}
	for _, expected := range []string{
		"created workflow pfw_watch_sse queued",
		"workflow pfw_watch_sse running maestro_queued",
		"workflow pfw_watch_sse passed maestro_smoke_passed",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected stdout to contain %q, got %q", expected, stdout.String())
		}
	}
}

func TestProveAppWatchUsesPreflightToken(t *testing.T) {
	appDir := writeExpoFixture(t)
	t.Setenv("PREFLIGHT_TOKEN", "watch_token_123")
	var missingAuth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer watch_token_123" {
			missingAuth = append(missingAuth, r.Method+" "+r.URL.Path)
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// `runner once` probes for a fleet signing identity on darwin; no cert is
		// configured for this fake, which is the 404 it treats as "nothing to
		// install".
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_watch_auth","status":"queued","appId":"pfapp_mobile","platform":"ios","lane":"simulator"},"runnerJob":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_create"}}`))
		case "GET /api/preflight/v1/workflows/pfw_watch_auth/events":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: workflow.projection\n" +
				`data: {"workflowId":"pfw_watch_auth","sequence":1,"eventType":"workflow.projection","workflowProjection":{"workflowId":"pfw_watch_auth","status":"passed","phase":"maestro_smoke_passed"}}` + "\n\n"))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--watch"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if len(missingAuth) != 0 {
		t.Fatalf("expected every prove-app watch request to carry auth, missing auth for %v", missingAuth)
	}
}

func TestRunnerOnceUsesSavedPreflightLoginForRegistration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "preflight", "config.json")
	t.Setenv("PREFLIGHT_CONFIG_PATH", configPath)
	workspaceRoot := t.TempDir()
	var registeredWorkspaceID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// `runner once` probes for a fleet signing identity on darwin; no cert is
		// configured for this fake, which is the 404 it treats as "nothing to install".
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/register":
			if r.Header.Get("Authorization") != "Bearer runner_register_token_123" {
				t.Fatalf("expected saved Preflight auth token on registration, got %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode registration body: %v", err)
			}
			registeredWorkspaceID = fmt.Sprint(body["workspaceId"])
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_saved","workspaceId":"ws_runner_saved","name":"Preflight Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"runnerJobStream":true}},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "POST /api/preflight/v1/runners/pfrun_saved/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("expected runner token on heartbeat, got %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_saved","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_saved/reconcile":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("expected runner token on reconcile, got %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "GET /api/preflight/v1/runners/pfrun_saved/jobs/stream":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("expected runner token on stream, got %q", r.Header.Get("Authorization"))
			}
			http.NotFound(w, r)
		case "POST /api/preflight/v1/runners/pfrun_saved/jobs/claim":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("expected runner token on claim, got %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_no_job"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	if err := savePreflightCLIConfig(preflightCLIConfig{
		APIVersion:        "v1",
		APIURL:            server.URL,
		Token:             "runner_register_token_123",
		WorkspaceID:       "ws_runner_saved",
		WorkspaceBindings: map[string]string{},
	}); err != nil {
		t.Fatalf("save CLI config: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{"runner", "once", "--workspace-root", workspaceRoot, "--host-identity", "macbook.local"},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	if registeredWorkspaceID != "ws_runner_saved" {
		t.Fatalf("expected runner registration workspace from saved config, got %q", registeredWorkspaceID)
	}
}

func TestRunnerOnceCleansExpiredLocalPreflightArtifactDirectories(t *testing.T) {
	workspaceRoot := t.TempDir()
	staleTime := time.Now().Add(-3 * time.Hour)
	freshTime := time.Now()
	staleDirs := []string{
		filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_stale_maestro"),
		filepath.Join(workspaceRoot, ".preflight", "eas", "pfjob_stale_eas"),
		filepath.Join(workspaceRoot, ".preflight", "dev-sessions", "pfjob_stale_devsession"),
		filepath.Join(workspaceRoot, ".preflight", "android-open", "pfjob_stale_android"),
	}
	for _, dir := range staleDirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create stale dir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "artifact.log"), []byte("stale"), 0o644); err != nil {
			t.Fatalf("write stale artifact: %v", err)
		}
		if err := os.Chtimes(dir, staleTime, staleTime); err != nil {
			t.Fatalf("age stale dir %s: %v", dir, err)
		}
	}
	freshDir := filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_fresh")
	if err := os.MkdirAll(freshDir, 0o755); err != nil {
		t.Fatalf("create fresh dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(freshDir, "artifact.log"), []byte("fresh"), 0o644); err != nil {
		t.Fatalf("write fresh artifact: %v", err)
	}
	if err := os.Chtimes(freshDir, freshTime, freshTime); err != nil {
		t.Fatalf("touch fresh dir: %v", err)
	}
	pidPath := filepath.Join(workspaceRoot, ".preflight", "expo-dev-session.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		t.Fatalf("write live pid file: %v", err)
	}
	stalePidPath := filepath.Join(workspaceRoot, "apps", "mobile", ".preflight", "expo-dev-session.pid")
	if err := os.MkdirAll(filepath.Dir(stalePidPath), 0o755); err != nil {
		t.Fatalf("create stale pid dir: %v", err)
	}
	if err := os.WriteFile(stalePidPath, []byte("not-a-pid"), 0o644); err != nil {
		t.Fatalf("write stale pid file: %v", err)
	}

	t.Setenv("PREFLIGHT_LOCAL_ARTIFACT_TTL", "1h")
	// cleanupStaleLocalPreflightProcessHandles only reconciles the workspace
	// root's own .preflight/expo-dev-session.pid by default (see 9053bf417,
	// which added the opt-in recursive variant to avoid a full workspace walk
	// on every runner tick). This test wants the nested
	// apps/mobile/.preflight/expo-dev-session.pid to be reconciled too, so it
	// must opt into the recursive walk explicitly.
	t.Setenv("PREFLIGHT_RECURSIVE_PROCESS_HANDLE_CLEANUP", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// `runner once` probes for a fleet signing identity on darwin; no cert is
		// configured for this fake, which is the 404 it treats as "nothing to
		// install".
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cleanup","workspaceId":"ws_cleanup","name":"Preflight Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"runnerJobStream":true}},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cleanup/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cleanup","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cleanup/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "GET /api/preflight/v1/runners/pfrun_cleanup/jobs/stream":
			http.NotFound(w, r)
		case "POST /api/preflight/v1/runners/pfrun_cleanup/jobs/claim":
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_no_job"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cleanup",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}
	for _, dir := range staleDirs {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("expected stale local artifact dir %s to be removed, stat err = %v", dir, err)
		}
	}
	if _, err := os.Stat(freshDir); err != nil {
		t.Fatalf("expected fresh local artifact dir to be retained: %v", err)
	}
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("expected live Expo dev-session pid file to be retained: %v", err)
	}
	if _, err := os.Stat(stalePidPath); !os.IsNotExist(err) {
		t.Fatalf("expected stale Expo dev-session pid file to be removed, stat err = %v", err)
	}
	if !strings.Contains(stdout.String(), "cleaned 4 expired Preflight local artifact directories") {
		t.Fatalf("expected cleanup summary in stdout, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "cleaned 1 stale Preflight local process handle") {
		t.Fatalf("expected stale process-handle cleanup summary in stdout, got %q", stdout.String())
	}
}

func TestProveAppIOSSimulatorProofLoopCoordinatesRunnerAndArtifacts(t *testing.T) {
	workspaceRoot := t.TempDir()
	// macOS puts TempDir under /var, a symlink to /private/var. The runner
	// reports the resolved path, so the fixture has to hold the same one or
	// every workspace-root comparison below fails on a Mac and passes on CI.
	if resolved, err := filepath.EvalSymlinks(workspaceRoot); err == nil {
		workspaceRoot = resolved
	}
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	for name, content := range map[string]string{
		"package.json":             `{"name":"forgegraph-root","private":true,"workspaces":["apps/*"]}`,
		"pnpm-workspace.yaml":      "packages:\n  - apps/*\n",
		"apps/mobile/package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"apps/mobile/app.config.ts": `export default {
			slug: "forgegraf",
			scheme: "forgegraph",
			ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" },
			android: { package: "com.gmacko.forgegraph.dev" },
			extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } }
		}`,
		"apps/mobile/eas.json":                        `{"build":{"development":{"developmentClient":true,"distribution":"internal","ios":{"simulator":true}}}}`,
		"apps/mobile/.maestro/01-app-launches.yaml":   "appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n",
		"apps/mobile/.preflight/expo-dev-session.pid": fmt.Sprint(os.Getpid()),
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}

	simctlJSON := filepath.Join(t.TempDir(), "simctl.json")
	if err := os.WriteFile(simctlJSON, []byte(`{
		"devices": {
			"com.apple.CoreSimulator.SimRuntime.iOS-26-4": [
				{
					"udid": "6BA8F38E-BF97-4830-98A6-E459E4312F29",
					"isAvailable": true,
					"deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17",
					"state": "Shutdown",
					"name": "iPhone 17"
				}
			]
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	xcrunPath := writeFakeExecutable(t, "xcrun", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$XCRUN_LOG"
exit 0
`)
	xcrunLog := filepath.Join(t.TempDir(), "xcrun.log")
	t.Setenv("XCRUN_LOG", xcrunLog)

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: APP_VARIANT=%s :: %s\n' "$PWD" "$APP_VARIANT" "$*" >> "$NPX_LOG"
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	maestroLog := filepath.Join(t.TempDir(), "maestro.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$MAESTRO_LOG"
debug_dir=""
for arg in "$@"; do
  case "$arg" in
    --debug-output=*) debug_dir="${arg#--debug-output=}" ;;
  esac
done
if [ -n "$debug_dir" ]; then
  mkdir -p "$debug_dir"
  printf 'debug log\n' > "$debug_dir/maestro.log"
  printf '{"commands":[]}\n' > "$debug_dir/commands-1.json"
fi
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("MAESTRO_LOG", maestroLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var mu sync.Mutex
	var calls []string
	var artifactUploads []map[string]any
	claimCount := 0
	workflowStatus := "queued"
	workflowPhase := "waiting_for_runner"
	createdWorkflow := make(chan struct{})
	var createdWorkflowOnce sync.Once

	setProjection := func(status string, phase string) {
		mu.Lock()
		defer mu.Unlock()
		workflowStatus = status
		workflowPhase = phase
	}
	readProjection := func() (string, string) {
		mu.Lock()
		defer mu.Unlock()
		return workflowStatus, workflowPhase
	}
	recordCall := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordCall(r)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin; no cert is
		// configured for this fake, which is the 404 it treats as "nothing to
		// install".
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode prove-app body: %v", err)
			}
			sourceBinding := body["sourceBinding"].(map[string]any)
			if sourceBinding["packageName"] != "@forgegraph/mobile" {
				t.Fatalf("unexpected packageName %#v", sourceBinding)
			}
			if sourceBinding["workspaceRoot"] != workspaceRoot || sourceBinding["packagePath"] != "apps/mobile" {
				t.Fatalf("unexpected source binding root/path %#v", sourceBinding)
			}
			createdWorkflowOnce.Do(func() { close(createdWorkflow) })
			setProjection("running", "waiting_for_runner")
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_accept","status":"queued","appId":"pfapp_forgegraph_mobile","platform":"ios","lane":"simulator"},"runnerJob":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_create"}}`))
		case "GET /api/preflight/v1/workflows/pfw_accept/events":
			http.NotFound(w, r)
		case "GET /api/preflight/v1/workflows/pfw_accept":
			status, phase := readProjection()
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_accept","status":%q,"appId":"pfapp_forgegraph_mobile","platform":"ios","lane":"simulator"},"workflowProjection":{"workflowId":"pfw_accept","status":%q,"phase":%q},"runnerJobs":[],"events":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_watch"}}`, status, status, phase)
		case "POST /api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_accept","workspaceId":"ws_accept","name":"Acceptance Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["expo","maestro","xcrun"],"adapters":["expo.dev_server","expo.local_build","ios.simulator.discovery","ios.simulator.boot","ios.simulator.install"],"runnerArtifactUpload":true}},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on heartbeat: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_accept","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/claim":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode claim body: %v", err)
			}
			if body["workspaceRoot"] != workspaceRoot {
				t.Fatalf("unexpected claim workspaceRoot %v", body["workspaceRoot"])
			}
			claimCount += 1
			switch claimCount {
			case 1:
				_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"running","runnerId":"pfrun_accept","workflowId":"pfw_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_probe"}}`))
			case 2:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_discover","kind":"device.discover","status":"running","runnerId":"pfrun_accept","workflowId":"pfw_accept","payload":{"platform":"ios","lane":"simulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_discover"}}`, workspaceRoot)
			case 3:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_accept","workflowId":"pfw_accept","targetId":"pftgt_accept","payload":{"platform":"ios","lane":"simulator","targetId":"pftgt_accept","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
			case 4:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"running","runnerId":"pfrun_accept","workflowId":"pfw_accept","targetId":"pftgt_accept","payload":{"platform":"ios","lane":"simulator","targetId":"pftgt_accept","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf","iosBundleId":"com.gmacko.forgegraph.dev"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
			case 5:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_accept","workflowId":"pfw_accept","targetId":"pftgt_accept","payload":{"platform":"ios","lane":"simulator","targetId":"pftgt_accept","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","flowPath":"apps/mobile/.maestro/01-app-launches.yaml","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_maestro"}}`, workspaceRoot)
			default:
				_, _ = w.Write([]byte(`{"data":{"job":null},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_no_job"}}`))
			}
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_probe/complete":
			setProjection("waiting", "runner_ready")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"succeeded","runnerId":"pfrun_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_probe"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/targets/ios-simulators":
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_accept","platform":"ios","kind":"ios_simulator","displayName":"iPhone 17","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_targets"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_discover/targets/pftgt_accept/lock":
			setProjection("waiting", "dev_session_queued")
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_accept","displayName":"iPhone 17","availability":"busy","lockedByJobId":"pfjob_discover"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_devsession/complete":
			setProjection("waiting", "simulator_open_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_devsession/artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev-session artifact body: %v", err)
			}
			artifactUploads = append(artifactUploads, body)
			artifactID := "pfart_devsession_log"
			if body["kind"] == "qr_code" {
				artifactID = "pfart_devsession_qr"
			}
			_, _ = fmt.Fprintf(w, `{"data":{"artifact":{"id":%q,"runnerJobId":"pfjob_devsession","kind":%q,"uri":%q}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_artifact"}}`, artifactID, body["kind"], body["uri"])
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_open/complete":
			setProjection("waiting", "maestro_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"succeeded","runnerId":"pfrun_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		case "GET /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_maestro":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_maestro"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_maestro/artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact body: %v", err)
			}
			artifactUploads = append(artifactUploads, body)
			_, _ = w.Write([]byte(`{"data":{"artifact":{"id":"pfart_accept","runnerJobId":"pfjob_maestro"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_artifact"}}`))
		case "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_maestro/complete":
			setProjection("passed", "maestro_smoke_passed")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"succeeded","runnerId":"pfrun_accept"},"workflowProjection":{"workflowId":"pfw_accept","status":"passed","phase":"maestro_smoke_passed"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_maestro"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var proveStdout bytes.Buffer
	var proveStderr bytes.Buffer
	proveDone := make(chan int, 1)
	go func() {
		proveDone <- run(
			[]string{
				"prove-app",
				"--api-url",
				server.URL,
				"--app-dir",
				appDir,
				"--watch",
				"--poll-interval",
				"1ms",
				"--watch-timeout",
				"3s",
			},
			&proveStdout,
			&proveStderr,
			server.Client(),
		)
	}()

	select {
	case <-createdWorkflow:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for prove-app to create workflow\nstdout: %s\nstderr: %s", proveStdout.String(), proveStderr.String())
	}

	var runnerStdout bytes.Buffer
	var runnerStderr bytes.Buffer
	runnerCode := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_accept",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"Acceptance Runner",
			"--simctl-json",
			simctlJSON,
			"--xcrun-path",
			xcrunPath,
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&runnerStdout,
		&runnerStderr,
		server.Client(),
	)
	if runnerCode != 0 {
		t.Fatalf("expected runner exit 0, got %d\nstdout: %s\nstderr: %s", runnerCode, runnerStdout.String(), runnerStderr.String())
	}

	var proveCode int
	select {
	case proveCode = <-proveDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for prove-app watch to finish\nstdout: %s\nstderr: %s", proveStdout.String(), proveStderr.String())
	}
	if proveCode != 0 {
		t.Fatalf("expected prove-app exit 0, got %d\nstdout: %s\nstderr: %s", proveCode, proveStdout.String(), proveStderr.String())
	}

	for _, expected := range []string{
		"created workflow pfw_accept queued",
		"workflow pfw_accept running waiting_for_runner",
		"workflow pfw_accept passed maestro_smoke_passed",
	} {
		if !strings.Contains(proveStdout.String(), expected) {
			t.Fatalf("expected prove-app stdout to contain %q, got %q", expected, proveStdout.String())
		}
	}
	for _, expected := range []string{
		"registered runner pfrun_accept",
		"completed capability probe pfjob_probe",
		"reported 1 iOS simulator target(s)",
		"locked target pftgt_accept iPhone 17",
		"started dev session pfjob_devsession http://127.0.0.1:19000",
		"opened simulator app pfjob_open",
		"completed Maestro smoke pfjob_maestro",
	} {
		if !strings.Contains(runnerStdout.String(), expected) {
			t.Fatalf("expected runner stdout to contain %q, got %q", expected, runnerStdout.String())
		}
	}
	if len(artifactUploads) != 5 {
		t.Fatalf("expected dev-session plus Maestro artifact uploads, got %#v", artifactUploads)
	}
	artifactKinds := []string{}
	for _, upload := range artifactUploads {
		artifactKinds = append(artifactKinds, fmt.Sprint(upload["kind"]))
	}
	if strings.Join(artifactKinds, " ") != "qr_code maestro_report log log tool_output" {
		t.Fatalf("unexpected artifact upload kinds %v", artifactKinds)
	}
	if strings.Contains(fmt.Sprint(artifactUploads), "runner_token") {
		t.Fatalf("artifact uploads leaked runner token: %#v", artifactUploads)
	}

	xcrunOutput, err := os.ReadFile(xcrunLog)
	if err != nil {
		t.Fatalf("read xcrun log: %v", err)
	}
	if bootCount := strings.Count(string(xcrunOutput), "simctl boot 6BA8F38E-BF97-4830-98A6-E459E4312F29"); bootCount < 2 {
		t.Fatalf("expected simulator boot command before install and before dev-client open, got %d in %q", bootCount, string(xcrunOutput))
	}
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	if !strings.Contains(string(npxOutput), "expo run:ios --device 6BA8F38E-BF97-4830-98A6-E459E4312F29 --no-bundler") {
		t.Fatalf("expected expo run:ios command, got %q", string(npxOutput))
	}
	if !strings.Contains(string(xcrunOutput), "simctl openurl 6BA8F38E-BF97-4830-98A6-E459E4312F29") {
		t.Fatalf("expected simulator openurl command, got %q", string(xcrunOutput))
	}
	if !strings.Contains(string(xcrunOutput), "simctl terminate 6BA8F38E-BF97-4830-98A6-E459E4312F29 com.gmacko.forgegraph.dev") {
		t.Fatalf("expected simulator app termination before Preflight URL open, got %q", string(xcrunOutput))
	}
	// developmentDeepLinkURL/appSchemeForDevelopmentClient always prefer the
	// source binding's explicit appScheme ("forgegraph", set on the
	// simulator.open job claim above) over the exp+<slug> fallback; the fake
	// xcrun here is a no-op stub, so installedAppDevClientScheme's
	// get_app_container/plutil lookup finds nothing and the source binding
	// scheme is used as-is.
	if !strings.Contains(string(xcrunOutput), "forgegraph://expo-development-client/?url=http%3A%2F%2F127.0.0.1%3A19000") {
		t.Fatalf("expected simulator openurl to target Preflight dev client URL, got %q", string(xcrunOutput))
	}
	maestroOutput, err := os.ReadFile(maestroLog)
	if err != nil {
		t.Fatalf("read maestro log: %v", err)
	}
	expectedFlowPath := filepath.Join(workspaceRoot, "apps/mobile/.maestro/01-app-launches.yaml")
	expectedMaestroArgs := "--platform ios --device 6BA8F38E-BF97-4830-98A6-E459E4312F29 test --test-output-dir=.preflight/maestro/pfjob_maestro/runtime-artifacts --debug-output=.preflight/maestro/pfjob_maestro/runtime-artifacts --format junit --output .preflight/maestro/pfjob_maestro/junit.xml -e FG_DEV_CLIENT_URL=http://127.0.0.1:19000 " + expectedFlowPath
	if !strings.Contains(string(maestroOutput), expectedMaestroArgs) {
		t.Fatalf("expected Maestro command, got %q", string(maestroOutput))
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_accept/jobs/pfjob_maestro/artifacts") != 4 {
		t.Fatalf("expected four artifact upload calls, got %v", calls)
	}
}

func TestProveAppIOSDevelopmentProofLoopCoordinatesEASBuildQRAndOpenAttempt(t *testing.T) {
	workspaceRoot := t.TempDir()
	// macOS puts TempDir under /var, a symlink to /private/var. The runner
	// reports the resolved path, so the fixture has to hold the same one or
	// every workspace-root comparison below fails on a Mac and passes on CI.
	if resolved, err := filepath.EvalSymlinks(workspaceRoot); err == nil {
		workspaceRoot = resolved
	}
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	for name, content := range map[string]string{
		"package.json":             `{"name":"forgegraph-root","private":true,"workspaces":["apps/*"]}`,
		"pnpm-workspace.yaml":      "packages:\n  - apps/*\n",
		"apps/mobile/package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"apps/mobile/app.config.ts": `export default {
			slug: "forgegraf",
			scheme: "forgegraph",
			ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" },
			android: { package: "com.gmacko.forgegraph.dev" },
			extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } }
		}`,
		"apps/mobile/eas.json": `{
			"build": {
				"development": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {"APP_VARIANT": "development"},
					"ios": {"simulator": true}
				},
				"development-device": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {"APP_VARIANT": "development"},
					"ios": {"simulator": false}
				}
			}
		}`,
		"apps/mobile/.maestro/01-app-launches.yaml": "appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n",
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$EAS_LOG"
if [ "$1" = "whoami" ]; then
  printf 'forgegraph-bot\n'
  exit 0
fi
if [ "$1" = "build:list" ]; then
  printf '[]\n'
  exit 0
fi
if [ "$1" = "build" ]; then
  printf '{"id":"build_ios_dev_accept","platform":"ios","profile":"development-device","status":"finished","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/ios-dev-accept.ipa"},"url":"https://expo.dev/accounts/acme/projects/mobile/builds/build_ios_dev_accept"}\n'
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_LAN_HOST", "192.168.4.10")

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	const (
		workflowID = "pfw_dev_accept"
		runnerID   = "pfrun_dev_accept"
		runnerName = "Development Runner"
	)
	devInstallURL := "https://expo.dev/runtime-artifacts/ios-dev-accept.ipa"
	// developmentDeepLinkURL/appSchemeForDevelopmentClient always prefer the
	// source binding's explicit appScheme ("forgegraph", set below in
	// sourceBindingPayload) over the exp+<slug> fallback.
	deepLinkURL := "forgegraph://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000"
	qrURL := "https://qr.expo.dev/development-client?appScheme=forgegraph&url=http%3A%2F%2F192.168.4.10%3A19000"

	var mu sync.Mutex
	var calls []string
	claimCount := 0
	workflowStatus := "queued"
	workflowPhase := "waiting_for_runner"
	createdWorkflow := make(chan struct{})
	var createdWorkflowOnce sync.Once

	setProjection := func(status string, phase string) {
		mu.Lock()
		defer mu.Unlock()
		workflowStatus = status
		workflowPhase = phase
	}
	readProjection := func() (string, string) {
		mu.Lock()
		defer mu.Unlock()
		return workflowStatus, workflowPhase
	}
	recordCall := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
	}
	nextClaimNumber := func() int {
		mu.Lock()
		defer mu.Unlock()
		claimCount += 1
		return claimCount
	}
	callsSnapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, calls...)
	}

	writeDevelopmentJob := func(w http.ResponseWriter, jobID string, kind string, payload string) {
		_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":%q,"kind":%q,"status":"running","runnerId":%q,"workflowId":%q,"payload":%s}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_%s"}}`, jobID, kind, runnerID, workflowID, payload, jobID)
	}
	sourceBindingPayload := func(extra string) string {
		if strings.TrimSpace(extra) != "" {
			extra = "," + strings.TrimSpace(extra)
		}
		return fmt.Sprintf(`"sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","easProfileName":"development-device","appScheme":"forgegraph","expoSlug":"forgegraf","iosBundleId":"com.gmacko.forgegraph.dev","androidPackage":"com.gmacko.forgegraph.dev","easProjectId":"05e5245e-6da8-4f7a-a557-324d36b02979"}%s`, workspaceRoot, extra)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordCall(r)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin; no cert is
		// configured for this fake, which is the 404 it treats as "nothing to
		// install".
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode prove-app body: %v", err)
			}
			sourceBinding := body["sourceBinding"].(map[string]any)
			for key, expected := range map[string]string{
				"packageName":    "@forgegraph/mobile",
				"workspaceRoot":  workspaceRoot,
				"packagePath":    "apps/mobile",
				"platform":       "ios",
				"lane":           "development",
				"easProfileName": "development-device",
				"appScheme":      "forgegraph",
				"expoSlug":       "forgegraf",
				"iosBundleId":    "com.gmacko.forgegraph.dev",
				"androidPackage": "com.gmacko.forgegraph.dev",
				"easProjectId":   "05e5245e-6da8-4f7a-a557-324d36b02979",
				"workflowIntent": "prove-app",
				"packageManager": "pnpm",
			} {
				if sourceBinding[key] != expected {
					t.Fatalf("unexpected source binding %s: got %#v in %#v", key, sourceBinding[key], sourceBinding)
				}
			}
			if !strings.HasPrefix(fmt.Sprint(sourceBinding["easProfileEnvDigest"]), "sha256:") {
				t.Fatalf("expected EAS profile env digest in source binding, got %#v", sourceBinding)
			}
			createdWorkflowOnce.Do(func() { close(createdWorkflow) })
			setProjection("running", "waiting_for_runner")
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_dev_accept","status":"queued","appId":"pfapp_forgegraph_mobile","platform":"ios","lane":"development"},"runnerJob":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_create"}}`))
		case "GET /api/preflight/v1/workflows/pfw_dev_accept/events":
			http.NotFound(w, r)
		case "GET /api/preflight/v1/workflows/pfw_dev_accept":
			status, phase := readProjection()
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_dev_accept","status":%q,"appId":"pfapp_forgegraph_mobile","platform":"ios","lane":"development"},"workflowProjection":{"workflowId":"pfw_dev_accept","status":%q,"phase":%q},"runnerJobs":[],"events":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_watch"}}`, status, status, phase)
		case "POST /api/preflight/v1/runners/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode register body: %v", err)
			}
			allowedRoots, _ := body["allowedWorkspaceRoots"].([]any)
			if body["workspaceId"] != "ws_dev_accept" || body["name"] != runnerName || len(allowedRoots) != 1 || allowedRoots[0] != workspaceRoot {
				t.Fatalf("unexpected register body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_dev_accept","workspaceId":"ws_dev_accept","name":"Development Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["eas","expo"],"adapters":["eas.development","expo.dev_client","expo.dev_server"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on heartbeat: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_dev_accept","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/claim":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode claim body: %v", err)
			}
			if body["workspaceRoot"] != workspaceRoot {
				t.Fatalf("unexpected claim workspaceRoot %v", body["workspaceRoot"])
			}
			switch nextClaimNumber() {
			case 1:
				writeDevelopmentJob(w, "pfjob_probe", "runner.capabilities.probe", `{}`)
			case 2:
				writeDevelopmentJob(w, "pfjob_readiness", "eas.readiness.probe", fmt.Sprintf(`{"platform":"ios","lane":"development","easProfileName":"development-device","targetClass":"device",%s}`, sourceBindingPayload("")))
			case 3:
				writeDevelopmentJob(w, "pfjob_build", "eas.build.dev", fmt.Sprintf(`{"platform":"ios","lane":"development","easProfileName":"development-device","targetClass":"device",%s,"readiness":{"ready":true,"targetClass":"device"}}`, sourceBindingPayload("")))
			case 4:
				writeDevelopmentJob(w, "pfjob_devsession", "dev_session.start", fmt.Sprintf(`{"platform":"ios","lane":"development",%s,"devBuild":{"buildId":"build_ios_dev_accept","platform":"ios","installUrl":%q}}`, sourceBindingPayload(""), devInstallURL))
			case 5:
				writeDevelopmentJob(w, "pfjob_open", "dev_session.open", fmt.Sprintf(`{"platform":"ios","lane":"development",%s,"devBuild":{"buildId":"build_ios_dev_accept","platform":"ios","installUrl":%q},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":%q,"qrUrl":%q,"installUrl":%q}}`, sourceBindingPayload(""), devInstallURL, deepLinkURL, qrURL, devInstallURL))
			default:
				_, _ = w.Write([]byte(`{"data":{"job":null},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_no_job"}}`))
			}
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_probe/complete":
			setProjection("waiting", "runner_ready")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"succeeded","runnerId":"pfrun_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_probe"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_readiness/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected readiness result %#v", result)
			}
			readiness := result["readiness"].(map[string]any)
			if readiness["easProfileName"] != "development-device" || readiness["targetClass"] != "device" || readiness["iosSimulator"] != false {
				t.Fatalf("unexpected readiness payload %#v", readiness)
			}
			setProjection("waiting", "eas_dev_build_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","runnerId":"pfrun_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_readiness"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected build result %#v", result)
			}
			devBuild := result["devBuild"].(map[string]any)
			if devBuild["buildId"] != "build_ios_dev_accept" || devBuild["installUrl"] != devInstallURL || devBuild["buildPageUrl"] == "" {
				t.Fatalf("unexpected dev build payload %#v", devBuild)
			}
			setProjection("waiting", "dev_session_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "GET /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_devsession":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_devsession"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_devsession/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected dev session result %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["advertisedUrl"] != "http://192.168.4.10:19000" || devSession["deepLinkUrl"] != deepLinkURL || devSession["qrUrl"] != qrURL || devSession["installUrl"] != devInstallURL {
				t.Fatalf("unexpected dev session payload %#v", devSession)
			}
			setProjection("waiting", "dev_session_open_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected open result %#v", result)
			}
			openAttempt := result["openAttempt"].(map[string]any)
			if openAttempt["strategy"] != "qr_install" || openAttempt["outcome"] != "manual_required" || openAttempt["installUrl"] != devInstallURL || openAttempt["deepLinkUrl"] != deepLinkURL || openAttempt["qrUrl"] != qrURL {
				t.Fatalf("unexpected open attempt payload %#v", openAttempt)
			}
			setProjection("passed_with_warnings", "development_open_attempted")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_dev_accept"},"workflowProjection":{"workflowId":"pfw_dev_accept","status":"passed_with_warnings","phase":"development_open_attempted"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var proveStdout bytes.Buffer
	var proveStderr bytes.Buffer
	proveDone := make(chan int, 1)
	go func() {
		proveDone <- run(
			[]string{
				"prove-app",
				"--api-url",
				server.URL,
				"--app-dir",
				appDir,
				"--platform",
				"ios",
				"--lane",
				"development",
				"--watch",
				"--poll-interval",
				"1ms",
				"--watch-timeout",
				"3s",
			},
			&proveStdout,
			&proveStderr,
			server.Client(),
		)
	}()

	select {
	case <-createdWorkflow:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for prove-app to create workflow\nstdout: %s\nstderr: %s", proveStdout.String(), proveStderr.String())
	}

	var runnerStdout bytes.Buffer
	var runnerStderr bytes.Buffer
	runnerCode := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_dev_accept",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			runnerName,
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&runnerStdout,
		&runnerStderr,
		server.Client(),
	)
	if runnerCode != 0 {
		t.Fatalf("expected runner exit 0, got %d\nstdout: %s\nstderr: %s", runnerCode, runnerStdout.String(), runnerStderr.String())
	}

	var proveCode int
	select {
	case proveCode = <-proveDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for prove-app watch to finish\nstdout: %s\nstderr: %s", proveStdout.String(), proveStderr.String())
	}
	if proveCode != 0 {
		t.Fatalf("expected prove-app exit 0, got %d\nstdout: %s\nstderr: %s", proveCode, proveStdout.String(), proveStderr.String())
	}

	for _, expected := range []string{
		"created workflow pfw_dev_accept queued",
		"workflow pfw_dev_accept running waiting_for_runner",
		"workflow pfw_dev_accept passed_with_warnings development_open_attempted",
	} {
		if !strings.Contains(proveStdout.String(), expected) {
			t.Fatalf("expected prove-app stdout to contain %q, got %q", expected, proveStdout.String())
		}
	}
	for _, expected := range []string{
		"registered runner pfrun_dev_accept",
		"completed capability probe pfjob_probe",
		"verified EAS readiness pfjob_readiness development-device",
		"completed EAS development build pfjob_build build_ios_dev_accept",
		"started dev session pfjob_devsession http://192.168.4.10:19000",
		"recorded development install/open attempt pfjob_open manual_required",
	} {
		if !strings.Contains(runnerStdout.String(), expected) {
			t.Fatalf("expected runner stdout to contain %q, got %q", expected, runnerStdout.String())
		}
	}

	waitForFileContains(t, easLog, "apps/mobile :: build --platform ios --profile development-device --json --non-interactive --wait")
	easOutput, err := os.ReadFile(easLog)
	if err != nil {
		t.Fatalf("read EAS log: %v", err)
	}
	for _, expected := range []string{
		"apps/mobile :: whoami",
		"apps/mobile :: build:list --platform ios --build-profile development-device --status finished --distribution internal --limit 1 --json --non-interactive",
		"apps/mobile :: build --platform ios --profile development-device --json --non-interactive --wait",
	} {
		if !strings.Contains(string(easOutput), expected) {
			t.Fatalf("expected EAS log to contain %q, got %q", expected, string(easOutput))
		}
	}
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	if !strings.Contains(string(npxOutput), "apps/mobile :: expo start --dev-client --host lan --port 19000") {
		t.Fatalf("expected Expo dev server command, got %q", string(npxOutput))
	}
	if strings.Contains(string(easOutput), "runner_token") || strings.Contains(string(npxOutput), "runner_token") {
		t.Fatalf("runner token leaked to local tool logs\neas: %s\nnpx: %s", string(easOutput), string(npxOutput))
	}
	if countCalls(callsSnapshot(), "POST /api/preflight/v1/runners/pfrun_dev_accept/jobs/claim") != 5 {
		t.Fatalf("expected five job claim calls, got %v", callsSnapshot())
	}
}

func TestProveAppAndroidDevelopmentProofLoopCoordinatesEASBuildADBInstallAndOpenAttempt(t *testing.T) {
	workspaceRoot := t.TempDir()
	// macOS puts TempDir under /var, a symlink to /private/var. The runner
	// reports the resolved path, so the fixture has to hold the same one or
	// every workspace-root comparison below fails on a Mac and passes on CI.
	if resolved, err := filepath.EvalSymlinks(workspaceRoot); err == nil {
		workspaceRoot = resolved
	}
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	for name, content := range map[string]string{
		"package.json":             `{"name":"forgegraph-root","private":true,"workspaces":["apps/*"]}`,
		"pnpm-workspace.yaml":      "packages:\n  - apps/*\n",
		"apps/mobile/package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"apps/mobile/app.config.ts": `export default {
			slug: "forgegraf",
			scheme: "forgegraph",
			ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" },
			android: { package: "com.gmacko.forgegraph.dev" },
			extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } }
		}`,
		"apps/mobile/eas.json": `{
			"build": {
				"development": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {"APP_VARIANT": "development"},
					"android": {"buildType": "apk"}
				}
			}
		}`,
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}

	apkPath := filepath.Join(t.TempDir(), "downloaded-android-dev-accept.apk")
	if err := os.WriteFile(apkPath, []byte("fake downloaded apk"), 0o644); err != nil {
		t.Fatalf("write fake downloaded APK: %v", err)
	}

	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$EAS_LOG"
if [ "$1" = "whoami" ]; then
  printf 'forgegraph-bot\n'
  exit 0
fi
if [ "$1" = "build:list" ] && [ "$3" = "android" ]; then
  printf '[]\n'
  exit 0
fi
if [ "$1" = "build" ] && [ "$3" = "android" ]; then
  printf '{"id":"build_android_dev_accept","platform":"android","profile":"development","status":"finished","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/android-dev-accept.apk"},"url":"https://expo.dev/accounts/acme/projects/mobile/builds/build_android_dev_accept"}\n'
  exit 0
fi
if [ "$1" = "build:download" ] && [ "$2" = "--build-id" ] && [ "$3" = "build_android_dev_accept" ]; then
  printf '{"path":"%s"}\n' "$DOWNLOADED_APK"
  exit 0
fi
printf 'unexpected eas args: %s\n' "$*" >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  exit 0
fi
printf 'unexpected npx args: %s\n' "$*" >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	adbLog := filepath.Join(t.TempDir(), "adb.log")
	adbPath := writeFakeExecutable(t, "adb", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$ADB_LOG"
if [ "$1" = "devices" ] && [ "$2" = "-l" ]; then
  printf 'List of devices attached\nemulator-5554 device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n'
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "install" ] && [ "$4" = "-r" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "shell" ] && [ "$4" = "am" ] && [ "$5" = "start" ]; then
  exit 0
fi
printf 'unexpected adb args: %s\n' "$*" >&2
exit 42
`)
	maestroLog := filepath.Join(t.TempDir(), "maestro.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$MAESTRO_LOG"
debug_dir=""
for arg in "$@"; do
  case "$arg" in
    --debug-output=*) debug_dir="${arg#--debug-output=}" ;;
  esac
done
if [ -n "$debug_dir" ]; then
  mkdir -p "$debug_dir"
  printf 'debug log\n' > "$debug_dir/maestro.log"
  printf '{"commands":[]}\n' > "$debug_dir/commands-1.json"
fi
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("ADB_LOG", adbLog)
	t.Setenv("MAESTRO_LOG", maestroLog)
	t.Setenv("DOWNLOADED_APK", apkPath)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_LAN_HOST", "192.168.4.10")

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	const (
		workflowID = "pfw_android_dev_accept"
		runnerID   = "pfrun_android_dev_accept"
		runnerName = "Android Development Runner"
	)
	devInstallURL := "https://expo.dev/runtime-artifacts/android-dev-accept.apk"
	// developmentDeepLinkURL/appSchemeForDevelopmentClient always prefer the
	// source binding's explicit appScheme ("forgegraph", set below in
	// sourceBindingPayload) over the exp+<slug> fallback.
	deepLinkURL := "forgegraph://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000"
	qrURL := "https://qr.expo.dev/development-client?appScheme=forgegraph&url=http%3A%2F%2F192.168.4.10%3A19000"

	var mu sync.Mutex
	var calls []string
	claimCount := 0
	workflowStatus := "queued"
	workflowPhase := "waiting_for_runner"
	createdWorkflow := make(chan struct{})
	var createdWorkflowOnce sync.Once

	setProjection := func(status string, phase string) {
		mu.Lock()
		defer mu.Unlock()
		workflowStatus = status
		workflowPhase = phase
	}
	readProjection := func() (string, string) {
		mu.Lock()
		defer mu.Unlock()
		return workflowStatus, workflowPhase
	}
	recordCall := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
	}
	nextClaimNumber := func() int {
		mu.Lock()
		defer mu.Unlock()
		claimCount += 1
		return claimCount
	}
	callsSnapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, calls...)
	}

	writeDevelopmentJob := func(w http.ResponseWriter, jobID string, kind string, payload string) {
		_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":%q,"kind":%q,"status":"running","runnerId":%q,"workflowId":%q,"payload":%s}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_%s"}}`, jobID, kind, runnerID, workflowID, payload, jobID)
	}
	sourceBindingPayload := func(extra string) string {
		if strings.TrimSpace(extra) != "" {
			extra = "," + strings.TrimSpace(extra)
		}
		return fmt.Sprintf(`"sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","easProfileName":"development","appScheme":"forgegraph","expoSlug":"forgegraf","iosBundleId":"com.gmacko.forgegraph.dev","androidPackage":"com.gmacko.forgegraph.dev","easProjectId":"05e5245e-6da8-4f7a-a557-324d36b02979"}%s`, workspaceRoot, extra)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordCall(r)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin; no cert is
		// configured for this fake, which is the 404 it treats as "nothing to
		// install".
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/capabilities":
			_, _ = w.Write(authenticatedCapabilitiesFixture(t))
		case "GET /api/preflight/v1/runners/capacity":
			_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
		case "POST /api/preflight/v1/workflows/prove-app":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode prove-app body: %v", err)
			}
			sourceBinding := body["sourceBinding"].(map[string]any)
			for key, expected := range map[string]string{
				"packageName":    "@forgegraph/mobile",
				"workspaceRoot":  workspaceRoot,
				"packagePath":    "apps/mobile",
				"platform":       "android",
				"lane":           "development",
				"easProfileName": "development",
				"appScheme":      "forgegraph",
				"expoSlug":       "forgegraf",
				"iosBundleId":    "com.gmacko.forgegraph.dev",
				"androidPackage": "com.gmacko.forgegraph.dev",
				"easProjectId":   "05e5245e-6da8-4f7a-a557-324d36b02979",
				"workflowIntent": "prove-app",
				"packageManager": "pnpm",
			} {
				if sourceBinding[key] != expected {
					t.Fatalf("unexpected source binding %s: got %#v in %#v", key, sourceBinding[key], sourceBinding)
				}
			}
			if !strings.HasPrefix(fmt.Sprint(sourceBinding["easProfileEnvDigest"]), "sha256:") {
				t.Fatalf("expected EAS profile env digest in source binding, got %#v", sourceBinding)
			}
			createdWorkflowOnce.Do(func() { close(createdWorkflow) })
			setProjection("running", "waiting_for_runner")
			_, _ = w.Write([]byte(`{"data":{"workflow":{"id":"pfw_android_dev_accept","status":"queued","appId":"pfapp_forgegraph_mobile","platform":"android","lane":"development"},"runnerJob":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_create"}}`))
		case "GET /api/preflight/v1/workflows/pfw_android_dev_accept/events":
			http.NotFound(w, r)
		case "GET /api/preflight/v1/workflows/pfw_android_dev_accept":
			status, phase := readProjection()
			_, _ = fmt.Fprintf(w, `{"data":{"workflow":{"id":"pfw_android_dev_accept","status":%q,"appId":"pfapp_forgegraph_mobile","platform":"android","lane":"development"},"workflowProjection":{"workflowId":"pfw_android_dev_accept","status":%q,"phase":%q},"runnerJobs":[],"events":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_watch"}}`, status, status, phase)
		case "POST /api/preflight/v1/runners/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode register body: %v", err)
			}
			allowedRoots, _ := body["allowedWorkspaceRoots"].([]any)
			if body["workspaceId"] != "ws_android_dev_accept" || body["name"] != runnerName || len(allowedRoots) != 1 || allowedRoots[0] != workspaceRoot {
				t.Fatalf("unexpected register body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_android_dev_accept","workspaceId":"ws_android_dev_accept","name":"Android Development Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["android"],"localTools":["adb","eas","expo"],"adapters":["android.emulator","eas.development","expo.dev_client","expo.dev_server"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on heartbeat: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_android_dev_accept","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/claim":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode claim body: %v", err)
			}
			if body["workspaceRoot"] != workspaceRoot {
				t.Fatalf("unexpected claim workspaceRoot %v", body["workspaceRoot"])
			}
			switch nextClaimNumber() {
			case 1:
				writeDevelopmentJob(w, "pfjob_probe", "runner.capabilities.probe", `{}`)
			case 2:
				writeDevelopmentJob(w, "pfjob_readiness", "eas.readiness.probe", fmt.Sprintf(`{"platform":"android","lane":"development","easProfileName":"development","targetClass":"emulator",%s}`, sourceBindingPayload("")))
			case 3:
				writeDevelopmentJob(w, "pfjob_build", "eas.build.dev", fmt.Sprintf(`{"platform":"android","lane":"development","easProfileName":"development","targetClass":"emulator",%s,"readiness":{"ready":true,"targetClass":"emulator"}}`, sourceBindingPayload("")))
			case 4:
				writeDevelopmentJob(w, "pfjob_discover", "device.discover", fmt.Sprintf(`{"platform":"android","lane":"development","targetClass":"emulator",%s,"devBuild":{"buildId":"build_android_dev_accept","platform":"android","installUrl":%q}}`, sourceBindingPayload(""), devInstallURL))
			case 5:
				writeDevelopmentJob(w, "pfjob_devsession", "dev_session.start", fmt.Sprintf(`{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetClass":"emulator",%s,"devBuild":{"buildId":"build_android_dev_accept","platform":"android","installUrl":%q}}`, sourceBindingPayload(""), devInstallURL))
			case 6:
				writeDevelopmentJob(w, "pfjob_open", "dev_session.open", fmt.Sprintf(`{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetClass":"emulator",%s,"devBuild":{"buildId":"build_android_dev_accept","platform":"android","installUrl":%q},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":%q,"qrUrl":%q,"installUrl":%q}}`, sourceBindingPayload(""), devInstallURL, deepLinkURL, qrURL, devInstallURL))
			case 7:
				writeDevelopmentJob(w, "pfjob_maestro", "maestro.run", fmt.Sprintf(`{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetDisplayName":"sdk_gphone64_arm64","flowPath":"apps/mobile/.maestro/01-app-launches.yaml",%s,"devSession":{"url":"http://192.168.4.10:19000","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":%q,"qrUrl":%q,"port":19000}}`, sourceBindingPayload(""), deepLinkURL, qrURL))
			default:
				_, _ = w.Write([]byte(`{"data":{"job":null},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_no_job"}}`))
			}
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_probe/complete":
			setProjection("waiting", "runner_ready")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"succeeded","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_probe"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_readiness/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected readiness result %#v", result)
			}
			readiness := result["readiness"].(map[string]any)
			if readiness["platform"] != "android" || readiness["easProfileName"] != "development" || readiness["targetClass"] != "emulator" {
				t.Fatalf("unexpected Android readiness payload %#v", readiness)
			}
			if readiness["androidArtifact"] != "apk" || readiness["nonInteractive"] != true {
				t.Fatalf("unexpected Android readiness proof %#v", readiness)
			}
			setProjection("waiting", "eas_dev_build_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_readiness"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected build result %#v", result)
			}
			devBuild := result["devBuild"].(map[string]any)
			if devBuild["buildId"] != "build_android_dev_accept" || devBuild["platform"] != "android" || devBuild["installUrl"] != devInstallURL || devBuild["buildPageUrl"] == "" {
				t.Fatalf("unexpected Android dev build payload %#v", devBuild)
			}
			setProjection("waiting", "android_emulator_discovery_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/targets/android-emulators":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode Android targets body: %v", err)
			}
			if !strings.Contains(body["adbDevicesOutput"].(string), "emulator-5554") {
				t.Fatalf("unexpected adb devices output %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_android","displayName":"sdk_gphone64_arm64","providerIdentity":"emulator-5554","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_report_android_targets"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_discover/targets/pftgt_android/lock":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode Android lock body: %v", err)
			}
			if body["lockOwner"] != "preflight-cli:macbook.local" {
				t.Fatalf("unexpected lock body %#v", body)
			}
			setProjection("waiting", "dev_session_queued")
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_android","displayName":"sdk_gphone64_arm64","providerIdentity":"emulator-5554","availability":"busy"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock_android_target"}}`))
		case "GET /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_devsession":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_devsession"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_devsession/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected dev session result %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["advertisedUrl"] != "http://192.168.4.10:19000" || devSession["deepLinkUrl"] != deepLinkURL || devSession["qrUrl"] != qrURL || devSession["installUrl"] != devInstallURL {
				t.Fatalf("unexpected dev session payload %#v", devSession)
			}
			setProjection("waiting", "dev_session_open_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected open result %#v", result)
			}
			openAttempt := result["openAttempt"].(map[string]any)
			if openAttempt["strategy"] != "adb_install_deeplink" || openAttempt["outcome"] != "opened" || openAttempt["targetClass"] != "android_emulator" {
				t.Fatalf("unexpected Android open attempt %#v", openAttempt)
			}
			if openAttempt["providerIdentity"] != "emulator-5554" || openAttempt["installUrl"] != devInstallURL || openAttempt["apkPath"] != apkPath {
				t.Fatalf("unexpected Android install evidence %#v", openAttempt)
			}
			if openAttempt["deepLinkUrl"] != deepLinkURL || openAttempt["qrUrl"] != qrURL {
				t.Fatalf("unexpected Android URL evidence %#v", openAttempt)
			}
			setProjection("waiting", "maestro_queued")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_android_dev_accept"},"workflowProjection":{"workflowId":"pfw_android_dev_accept","status":"waiting","phase":"maestro_queued"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		case "GET /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_maestro":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_android_dev_accept"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_maestro"}}`))
		case "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/pfjob_maestro/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode maestro complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected maestro result %#v", result)
			}
			maestro := result["maestro"].(map[string]any)
			if maestro["platform"] != "android" || maestro["providerIdentity"] != "emulator-5554" || maestro["flowPath"] != "apps/mobile/.maestro/01-app-launches.yaml" {
				t.Fatalf("unexpected maestro payload %#v", maestro)
			}
			setProjection("passed", "maestro_smoke_passed")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"succeeded","runnerId":"pfrun_android_dev_accept"},"workflowProjection":{"workflowId":"pfw_android_dev_accept","status":"passed","phase":"maestro_smoke_passed"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_maestro"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var proveStdout bytes.Buffer
	var proveStderr bytes.Buffer
	proveDone := make(chan int, 1)
	go func() {
		proveDone <- run(
			[]string{
				"prove-app",
				"--api-url",
				server.URL,
				"--app-dir",
				appDir,
				"--platform",
				"android",
				"--lane",
				"development",
				"--watch",
				"--poll-interval",
				"1ms",
				"--watch-timeout",
				"3s",
			},
			&proveStdout,
			&proveStderr,
			server.Client(),
		)
	}()

	select {
	case <-createdWorkflow:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for prove-app to create workflow\nstdout: %s\nstderr: %s", proveStdout.String(), proveStderr.String())
	}

	var runnerStdout bytes.Buffer
	var runnerStderr bytes.Buffer
	runnerCode := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_android_dev_accept",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			runnerName,
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
			"--adb-path",
			adbPath,
		},
		&runnerStdout,
		&runnerStderr,
		server.Client(),
	)
	if runnerCode != 0 {
		t.Fatalf("expected runner exit 0, got %d\nstdout: %s\nstderr: %s", runnerCode, runnerStdout.String(), runnerStderr.String())
	}

	var proveCode int
	select {
	case proveCode = <-proveDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for prove-app watch to finish\nstdout: %s\nstderr: %s", proveStdout.String(), proveStderr.String())
	}
	if proveCode != 0 {
		t.Fatalf("expected prove-app exit 0, got %d\nstdout: %s\nstderr: %s", proveCode, proveStdout.String(), proveStderr.String())
	}

	for _, expected := range []string{
		"created workflow pfw_android_dev_accept queued",
		"workflow pfw_android_dev_accept running waiting_for_runner",
		"workflow pfw_android_dev_accept passed maestro_smoke_passed",
	} {
		if !strings.Contains(proveStdout.String(), expected) {
			t.Fatalf("expected prove-app stdout to contain %q, got %q", expected, proveStdout.String())
		}
	}
	for _, expected := range []string{
		"registered runner pfrun_android_dev_accept",
		"completed capability probe pfjob_probe",
		"verified EAS readiness pfjob_readiness development",
		"completed EAS development build pfjob_build build_android_dev_accept",
		"reported 1 Android emulator target(s)",
		"locked target pftgt_android sdk_gphone64_arm64",
		"started dev session pfjob_devsession http://192.168.4.10:19000",
		"opened Android development build pfjob_open emulator-5554",
		"completed Maestro smoke pfjob_maestro",
	} {
		if !strings.Contains(runnerStdout.String(), expected) {
			t.Fatalf("expected runner stdout to contain %q, got %q", expected, runnerStdout.String())
		}
	}

	waitForFileContains(t, easLog, "apps/mobile :: build:download --build-id build_android_dev_accept --json --non-interactive")
	easOutput, err := os.ReadFile(easLog)
	if err != nil {
		t.Fatalf("read EAS log: %v", err)
	}
	for _, expected := range []string{
		"apps/mobile :: whoami",
		"apps/mobile :: build:list --platform android --build-profile development --status finished --distribution internal --limit 1 --json --non-interactive",
		"apps/mobile :: build --platform android --profile development --json --non-interactive --wait",
		"apps/mobile :: build:download --build-id build_android_dev_accept --json --non-interactive",
	} {
		if !strings.Contains(string(easOutput), expected) {
			t.Fatalf("expected EAS log to contain %q, got %q", expected, string(easOutput))
		}
	}
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	if !strings.Contains(string(npxOutput), "apps/mobile :: expo start --dev-client --host lan --port 19000") {
		t.Fatalf("expected Expo dev server command, got %q", string(npxOutput))
	}
	adbOutput, err := os.ReadFile(adbLog)
	if err != nil {
		t.Fatalf("read ADB log: %v", err)
	}
	for _, expected := range []string{
		"devices -l",
		"emulator-5554 install -r " + apkPath,
		"emulator-5554 shell am start -a android.intent.action.VIEW -d " + deepLinkURL + " -p com.gmacko.forgegraph.dev",
	} {
		if !strings.Contains(string(adbOutput), expected) {
			t.Fatalf("expected ADB log to contain %q, got %q", expected, string(adbOutput))
		}
	}
	if strings.Contains(string(easOutput), "runner_token") || strings.Contains(string(npxOutput), "runner_token") || strings.Contains(string(adbOutput), "runner_token") {
		t.Fatalf("runner token leaked to local tool logs\neas: %s\nnpx: %s\nadb: %s", string(easOutput), string(npxOutput), string(adbOutput))
	}
	maestroOutput, err := os.ReadFile(maestroLog)
	if err != nil {
		t.Fatalf("read Maestro log: %v", err)
	}
	expectedFlowPath := filepath.Join(workspaceRoot, "apps/mobile/.maestro/01-app-launches.yaml")
	expectedMaestroArgs := "--platform android --device emulator-5554 test --test-output-dir=.preflight/maestro/pfjob_maestro/runtime-artifacts --debug-output=.preflight/maestro/pfjob_maestro/runtime-artifacts --format junit --output .preflight/maestro/pfjob_maestro/junit.xml -e FG_DEV_CLIENT_URL=http://192.168.4.10:19000 -e FG_DEV_CLIENT_DEEP_LINK=" + deepLinkURL + " -e FG_DEV_CLIENT_QR_URL=" + qrURL + " " + expectedFlowPath
	if !strings.Contains(string(maestroOutput), expectedMaestroArgs) {
		t.Fatalf("expected Android Maestro command, got %q", string(maestroOutput))
	}
	if countCalls(callsSnapshot(), "POST /api/preflight/v1/runners/pfrun_android_dev_accept/jobs/claim") != 7 {
		t.Fatalf("expected seven job claim calls, got %v", callsSnapshot())
	}
}

func TestProveAppRejectsNonExpoPackageBeforeCallingAPI(t *testing.T) {
	appDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(`{"name":"plain-node"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	code := run(
		[]string{"prove-app", "--api-url", server.URL, "--app-dir", appDir, "--json"},
		&bytes.Buffer{},
		&bytes.Buffer{},
		server.Client(),
	)

	if code == 0 {
		t.Fatal("expected non-zero exit for non-Expo package")
	}
	if called {
		t.Fatal("API should not be called for a non-Expo package")
	}
}

func TestClaimRunnerJobPrefersStreamBeforeClaimingLease(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/runners/pfrun_cli/jobs/stream":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on stream: %q", r.Header.Get("Authorization"))
			}
			if r.URL.Query().Get("workspaceRoot") != "/repo/apps/mobile" {
				t.Fatalf("unexpected stream workspace root %q", r.URL.Query().Get("workspaceRoot"))
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(
				"id: 1\n" +
					"event: runner.job.available\n" +
					`data: {"eventType":"runner.job.available","job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"queued"}}` + "\n\n",
			))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	claim, err := claimRunnerJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: "/repo/apps/mobile",
		},
		runnerRegistrationData{
			Runner: apiRunner{
				ID: "pfrun_cli",
				Capabilities: map[string]any{
					"runnerJobStream": true,
				},
			},
			Token: "runner_token",
		},
	)

	if err != nil {
		t.Fatalf("claim runner job: %v", err)
	}
	if claim == nil || claim.Job.ID != "pfjob_probe" {
		t.Fatalf("expected streamed job to be claimed, got %#v", claim)
	}
	if strings.Join(calls, "\n") != strings.Join([]string{
		"GET /api/preflight/v1/runners/pfrun_cli/jobs/stream",
		"POST /api/preflight/v1/runners/pfrun_cli/jobs/claim",
	}, "\n") {
		t.Fatalf("expected stream before claim, got %v", calls)
	}
}

func TestClaimRunnerJobFallsBackToClaimWhenStreamUnavailable(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "GET /api/preflight/v1/runners/pfrun_cli/jobs/stream":
			http.NotFound(w, r)
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	claim, err := claimRunnerJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: "/repo/apps/mobile",
		},
		runnerRegistrationData{
			Runner: apiRunner{
				ID: "pfrun_cli",
				Capabilities: map[string]any{
					"runnerJobStream": true,
				},
			},
			Token: "runner_token",
		},
	)

	if err != nil {
		t.Fatalf("claim runner job: %v", err)
	}
	if claim == nil || claim.Job.ID != "pfjob_probe" {
		t.Fatalf("expected fallback claim, got %#v", claim)
	}
	if strings.Join(calls, "\n") != strings.Join([]string{
		"GET /api/preflight/v1/runners/pfrun_cli/jobs/stream",
		"POST /api/preflight/v1/runners/pfrun_cli/jobs/claim",
	}, "\n") {
		t.Fatalf("expected stream fallback before claim, got %v", calls)
	}
}

func TestRunnerJobCancellationCheckHeartbeatsRunningJobLease(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_long/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_long","kind":"maestro.run","status":"running","runnerId":"pfrun_cli","leaseExpiresAt":"2026-05-20T12:01:45.000Z"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_job_heartbeat"}}`))
		case "GET /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_long":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_long","kind":"maestro.run","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_job_read"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	cancelled, err := runnerJobCancellationCheck(
		server.Client(),
		runnerOnceOptions{apiURL: server.URL},
		runnerRegistrationData{
			Runner: apiRunner{
				ID: "pfrun_cli",
				Capabilities: map[string]any{
					"runnerJobHeartbeat": true,
				},
			},
			Token: "runner_token",
		},
		apiRunnerJob{ID: "pfjob_long", Kind: "maestro.run", Status: "running"},
	)()

	if err != nil {
		t.Fatalf("cancellation check: %v", err)
	}
	if cancelled {
		t.Fatal("expected running heartbeat response to keep job active")
	}
	if strings.Join(calls, "\n") != "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_long/heartbeat" {
		t.Fatalf("expected heartbeat without fallback read, got %v", calls)
	}
}

func TestDeviceDiscoveryHeartbeatsJobWhileDiscoveryIsInProgress(t *testing.T) {
	t.Setenv("PREFLIGHT_RUNNER_JOB_HEARTBEAT_INTERVAL", "10ms")

	simctlPath := filepath.Join(t.TempDir(), "simctl.json")
	if err := os.WriteFile(simctlPath, []byte(`{"devices":{}}`), 0o644); err != nil {
		t.Fatalf("write simctl fixture: %v", err)
	}
	xcrunPath := writeFakeExecutable(t, "xcrun", "#!/usr/bin/env sh\nexit 1\n")

	heartbeatSeen := make(chan struct{})
	var heartbeatOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_discover/heartbeat":
			heartbeatOnce.Do(func() { close(heartbeatSeen) })
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_discover","kind":"device.discover","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_job_heartbeat"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/targets/ios-simulators":
			select {
			case <-heartbeatSeen:
				_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_iphone","displayName":"iPhone 17","providerIdentity":"SIM-UDID","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_targets"}}`))
			case <-time.After(250 * time.Millisecond):
				// The configured 10ms heartbeat has 25 opportunities to arrive;
				// this timeout proves the lifecycle is absent rather than racing one tick.
				_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_iphone","displayName":"iPhone 17","providerIdentity":"SIM-UDID","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_targets_without_heartbeat"}}`))
			}
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_discover/targets/pftgt_iphone/lock":
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_iphone","displayName":"iPhone 17","providerIdentity":"SIM-UDID","availability":"available"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleDeviceDiscoveryJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: t.TempDir(),
			simctlJSON:    simctlPath,
			xcrunPath:     xcrunPath,
		},
		runnerRegistrationData{
			Runner: apiRunner{
				ID: "pfrun_cli",
				Capabilities: map[string]any{
					"runnerJobHeartbeat": true,
				},
			},
			Token: "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_discover",
			Kind:   "device.discover",
			Status: "running",
			Payload: runnerJobPayload{
				Platform: "ios",
				Lane:     "simulator",
			},
		},
		&stdout,
	)

	if err != nil {
		t.Fatalf("device discovery should keep its job lease alive: %v", err)
	}
	select {
	case <-heartbeatSeen:
	default:
		t.Fatal("expected device discovery to heartbeat its running job")
	}
}

func TestUploadMaestroArtifactsPostsArtifactMetadata(t *testing.T) {
	workspaceRoot := t.TempDir()
	reportPath := filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "junit.xml")
	logPath := filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "maestro-run.log")
	screenshotPath := filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "runtime-artifacts", "screen.png")
	for path, content := range map[string]string{
		reportPath:     "<testsuite />",
		logPath:        "maestro log",
		screenshotPath: "png",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write artifact %s: %v", path, err)
		}
	}

	var uploads []map[string]any
	var blobPuts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The upload is two steps: POST the metadata, then PUT the bytes to the
		// blob URL the first response names.
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/blob") {
			blobPuts++
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method+" "+r.URL.Path != "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/artifacts" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer runner_token" {
			t.Fatalf("missing runner token on artifact upload: %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode artifact upload: %v", err)
		}
		uploads = append(uploads, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"artifact":{"id":"pfart_test","kind":"maestro_report"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_artifact"}}`))
	}))
	t.Cleanup(server.Close)

	err := uploadMaestroRunArtifacts(
		server.Client(),
		runnerOnceOptions{apiURL: server.URL, workspaceRoot: workspaceRoot},
		runnerRegistrationData{
			Runner: apiRunner{
				ID: "pfrun_cli",
				Capabilities: map[string]any{
					"runnerArtifactUpload": true,
				},
			},
			Token: "runner_token",
		},
		apiRunnerJob{
			ID:       "pfjob_maestro",
			Kind:     "maestro.run",
			TargetID: "pftgt_1",
			Payload: runnerJobPayload{
				FlowPath: "apps/mobile/.maestro/01-app-launches.yaml",
			},
		},
		"6BA8F38E-BF97-4830-98A6-E459E4312F29",
		filepath.Join(workspaceRoot, "apps/mobile/.maestro/01-app-launches.yaml"),
		maestroRunArtifacts{
			OutputDir:       filepath.Dir(reportPath),
			DebugOutputDir:  filepath.Dir(screenshotPath),
			ReportPath:      reportPath,
			LogPath:         logPath,
			ScreenshotPaths: []string{screenshotPath},
			CommandPaths:    nil,
			VideoPaths:      nil,
		},
		io.Discard,
	)

	if err != nil {
		t.Fatalf("upload maestro artifacts: %v", err)
	}
	if len(uploads) != 3 {
		t.Fatalf("expected report, log, and screenshot uploads, got %#v", uploads)
	}
	if uploads[0]["kind"] != "maestro_report" || uploads[0]["uri"] != reportPath {
		t.Fatalf("unexpected report upload %#v", uploads[0])
	}
	if uploads[0]["sizeBytes"] != float64(len("<testsuite />")) {
		t.Fatalf("expected report size, got %#v", uploads[0])
	}
	if uploads[1]["kind"] != "log" || uploads[2]["kind"] != "screenshot" {
		t.Fatalf("unexpected artifact kinds %#v", uploads)
	}
	metadata := uploads[0]["metadata"].(map[string]any)
	if metadata["flowPath"] != "apps/mobile/.maestro/01-app-launches.yaml" {
		t.Fatalf("expected flow path metadata, got %#v", metadata)
	}
	if metadata["providerIdentity"] != "6BA8F38E-BF97-4830-98A6-E459E4312F29" {
		t.Fatalf("expected provider identity metadata, got %#v", metadata)
	}
}

func TestEASBuildFailsSourceBindingMismatchBeforeRunningLocalTools(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"package.json":  `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"app.config.ts": `export default { slug: "forgegraf", scheme: "forgegraph" }`,
		"eas.json":      `{"build":{"development-device":{"developmentClient":true,"distribution":"internal","ios":{"simulator":false}}}}`,
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$EAS_LOG"
printf '{"id":"unexpected","artifacts":{"buildUrl":"https://expo.dev/unexpected.ipa"}}\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on complete: %q", r.Header.Get("Authorization"))
			}
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleEASBuildDevJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: workspaceRoot,
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_build",
			Kind:   "eas.build.dev",
			Status: "running",
			Payload: runnerJobPayload{
				Platform:       "ios",
				Lane:           "development",
				EASProfileName: "development-device",
				TargetClass:    "device",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot:    workspaceRoot,
					PackagePath:      "apps/mobile",
					ExpoConfigDigest: "sha256:stale",
					EASJSONDigest:    digestIfExists(filepath.Join(appDir, "eas.json")),
					AppScheme:        "forgegraph",
					ExpoSlug:         "forgegraf",
				},
			},
		},
		&stdout,
	)

	if err != nil {
		t.Fatalf("expected source mismatch to be reported as job completion, got %v", err)
	}
	result := completed["result"].(map[string]any)
	if result["status"] != "failed" {
		t.Fatalf("expected failed result, got %#v", result)
	}
	failure := result["failure"].(map[string]any)
	if failure["code"] != "source_binding_mismatch" {
		t.Fatalf("expected source_binding_mismatch failure, got %#v", failure)
	}
	if _, err := os.Stat(easLog); err == nil {
		t.Fatalf("source mismatch must stop before running eas; log exists at %s", easLog)
	}
	if !strings.Contains(stdout.String(), "source binding mismatch pfjob_build") {
		t.Fatalf("expected source mismatch output, got %q", stdout.String())
	}
}

func TestRunnerJobFailsWhenSetupFilesChangeAfterSourceBinding(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"pnpm-workspace.yaml":      "packages:\n  - apps/*\n",
		"package.json":             `{"name":"forgegraph-root","private":true}`,
		"apps/mobile/package.json": `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"apps/mobile/app.config.ts": `export default {
			slug: "forgegraf",
			scheme: "forgegraph",
			ios: { bundleIdentifier: "com.gmacko.forgegraph" },
			android: { package: "com.gmacko.forgegraph" },
			extra: { eas: { projectId: "05e5245e-6da8-4f7a-a557-324d36b02979" } }
		}`,
		"apps/mobile/eas.json": `{"build":{"development-device":{"developmentClient":true,"distribution":"internal","ios":{"simulator":false}}}}`,
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	runGit(t, workspaceRoot, "init")
	runGit(t, workspaceRoot, "checkout", "-b", "preflight-test")
	runGit(t, workspaceRoot, "remote", "add", "origin", "https://example.com/forgegraph.git")
	runGit(t, workspaceRoot, "add", ".")
	runGit(t, workspaceRoot, "-c", "user.email=preflight@example.com", "-c", "user.name=Preflight Test", "commit", "-m", "baseline")
	commitSHA := runGitOutput(t, workspaceRoot, "rev-parse", "HEAD")

	if err := os.WriteFile(
		filepath.Join(appDir, "package.json"),
		[]byte(`{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27","expo-router":"~6.0.14"}}`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$EAS_LOG"
printf '{"id":"unexpected","artifacts":{"buildUrl":"https://expo.dev/unexpected.ipa"}}\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	jobJSON := fmt.Sprintf(`{
		"id":"pfjob_build",
		"kind":"eas.build.dev",
		"status":"running",
		"payload":{
			"platform":"ios",
			"lane":"development",
			"easProfileName":"development-device",
			"targetClass":"device",
			"sourceBinding":{
				"workspaceRoot":%q,
				"packagePath":"apps/mobile",
				"easProfileName":"development-device",
				"expoConfigDigest":%q,
				"easJsonDigest":%q,
				"appScheme":"forgegraph",
				"expoSlug":"forgegraf",
				"iosBundleId":"com.gmacko.forgegraph",
				"androidPackage":"com.gmacko.forgegraph",
				"easProjectId":"05e5245e-6da8-4f7a-a557-324d36b02979",
				"gitRemoteUrl":"https://example.com/forgegraph.git",
				"gitBranch":"preflight-test",
				"gitCommitSha":%q,
				"dirtyWorkspace":false,
				"changedSetupFiles":[]
			},
			"readiness":{"ready":true}
		}
	}`, workspaceRoot, digestIfExists(filepath.Join(appDir, "app.config.ts")), digestIfExists(filepath.Join(appDir, "eas.json")), commitSHA)
	var job apiRunnerJob
	if err := json.Unmarshal([]byte(jobJSON), &job); err != nil {
		t.Fatalf("decode job fixture: %v", err)
	}
	if job.Payload.SourceBinding.DirtyWorkspace == nil || job.Payload.SourceBinding.ChangedSetupFiles == nil {
		t.Fatalf("job fixture did not decode source binding drift fields: %#v", job.Payload.SourceBinding)
	}
	dirtyWorkspace, changedSetupFiles := sourceBindingGitState(workspaceRoot, appDir)
	if !dirtyWorkspace || fmt.Sprint(changedSetupFiles) != "[apps/mobile/package.json]" {
		t.Fatalf("expected local setup-file drift, got dirty=%v changed=%v", dirtyWorkspace, changedSetupFiles)
	}

	var stdout bytes.Buffer
	err := handleEASBuildDevJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: workspaceRoot,
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		job,
		&stdout,
	)

	if err != nil {
		t.Fatalf("expected setup-file drift to be reported as job completion, got %v", err)
	}
	result := completed["result"].(map[string]any)
	failure, ok := result["failure"].(map[string]any)
	if !ok {
		t.Fatalf("expected source binding failure, got result %#v", result)
	}
	if failure["code"] != "source_binding_mismatch" {
		t.Fatalf("expected source_binding_mismatch failure, got %#v", failure)
	}
	if !strings.Contains(failure["message"].(string), "changedSetupFiles") {
		t.Fatalf("expected changed setup files mismatch, got %#v", failure)
	}
	if _, err := os.Stat(easLog); err == nil {
		t.Fatalf("source mismatch must stop before running eas; log exists at %s", easLog)
	}
	if !strings.Contains(stdout.String(), "source binding mismatch pfjob_build") {
		t.Fatalf("expected source mismatch output, got %q", stdout.String())
	}
}

func TestFilterRunnerManagedPathsDropsRootAndAppPreflightArtifacts(t *testing.T) {
	workspaceRoot := filepath.Join(string(os.PathSeparator), "repo")
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	got := filterRunnerManagedPaths(workspaceRoot, appDir, []string{
		".preflight/eas/pfjob_build/eas-build-output.json",
		"apps/mobile/.preflight/expo-dev-session.pid",
		"apps/mobile/src/App.tsx",
	})
	if fmt.Sprint(got) != "[apps/mobile/src/App.tsx]" {
		t.Fatalf("expected only source changes to remain, got %v", got)
	}
}

func TestSourceBindingValidationAllowsDiscoveryJobToUseBindingEASProfile(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	for name, content := range map[string]string{
		"package.json": `{"name":"forgegraph-root","private":true}`,
		"apps/mobile/package.json": `{
			"name":"@forgegraph/mobile",
			"private":true,
			"main":"expo-router/entry",
			"dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}
		}`,
		"apps/mobile/app.config.ts": `export default {
			slug: "forgegraf",
			scheme: "forgegraph",
			ios: { bundleIdentifier: "com.gmacko.forgegraph" },
			android: { package: "com.gmacko.forgegraph" }
		}`,
		"apps/mobile/eas.json": `{"build":{"development":{"developmentClient":true,"distribution":"internal","ios":{"simulator":true}}}}`,
	} {
		path := filepath.Join(workspaceRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	job := apiRunnerJob{
		ID:     "pfjob_discover",
		Kind:   "device.discover",
		Status: "running",
		Payload: runnerJobPayload{
			Platform: "ios",
			Lane:     "simulator",
			SourceBinding: runnerJobSourceBinding{
				WorkspaceRoot:    workspaceRoot,
				PackagePath:      "apps/mobile",
				EASProfileName:   "development",
				ExpoConfigDigest: digestIfExists(filepath.Join(appDir, "app.config.ts")),
				EASJSONDigest:    digestIfExists(filepath.Join(appDir, "eas.json")),
				AppScheme:        "forgegraph",
				ExpoSlug:         "forgegraf",
				IOSBundleID:      "com.gmacko.forgegraph",
				AndroidPackage:   "com.gmacko.forgegraph",
			},
		},
	}

	err := validateRunnerJobSourceBinding(
		runnerOnceOptions{workspaceRoot: workspaceRoot},
		job,
	)

	if err != nil {
		t.Fatalf("expected discovery job to validate source binding EAS profile, got %v", err)
	}
}

func TestRunnerOnceHandlesEASReadinessAndDevelopmentBuild(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"package.json":  `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"app.config.ts": `export default { slug: "forgegraf", scheme: "forgegraph" }`,
		"eas.json": `{
			"build": {
				"development": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {"APP_VARIANT": "development"},
					"ios": {"simulator": true}
				},
				"development-device": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {"APP_VARIANT": "development"},
					"ios": {"simulator": false}
				}
			}
		}`,
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "whoami" ]; then
  printf 'forgegraph-bot\n'
  exit 0
fi
if [ "$1" = "build:list" ]; then
  printf '[]\n'
  exit 0
fi
if [ "$1" = "build" ]; then
  printf '{"id":"build_ios_dev_1","platform":"ios","profile":"development-device","status":"finished","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/ios-dev.ipa"},"url":"https://expo.dev/accounts/acme/projects/mobile/builds/build_ios_dev_1"}\n'
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_LAN_HOST", "192.168.4.10")

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["eas"],"adapters":["eas.development"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode reconcile body: %v", err)
			}
			if body["reason"] != "runner_startup" {
				t.Fatalf("unexpected reconcile body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 1 {
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"running","runnerId":"pfrun_cli","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_readiness"}}`, workspaceRoot)
				return
			}
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 2 {
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"running","runnerId":"pfrun_cli","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"readiness":{"ready":true}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_build"}}`, workspaceRoot)
				return
			}
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 3 {
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","payload":{"sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_ios_dev_1","installUrl":"https://expo.dev/runtime-artifacts/ios-dev.ipa"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"running","runnerId":"pfrun_cli","payload":{"sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":"exp+forgegraf://expo-development-client/?url=http%%3A%%2F%%2F192.168.4.10%%3A19000","qrUrl":"https://qr.expo.dev/development-client?appScheme=exp%%2Bforgegraf&url=http%%3A%%2F%%2F192.168.4.10%%3A19000","installUrl":"https://expo.dev/runtime-artifacts/ios-dev.ipa"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_readiness/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected readiness result %#v", result)
			}
			readiness := result["readiness"].(map[string]any)
			if readiness["easProfileName"] != "development-device" || readiness["iosSimulator"] != false {
				t.Fatalf("unexpected readiness payload %#v", readiness)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_readiness"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected build result %#v", result)
			}
			devBuild := result["devBuild"].(map[string]any)
			if devBuild["buildId"] != "build_ios_dev_1" || devBuild["installUrl"] != "https://expo.dev/runtime-artifacts/ios-dev.ipa" {
				t.Fatalf("unexpected dev build payload %#v", devBuild)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/heartbeat":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method for job heartbeat: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for job read: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected dev session result %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["advertisedUrl"] != "http://192.168.4.10:19000" {
				t.Fatalf("unexpected advertised URL %#v", devSession)
			}
			// The source binding sets an explicit appScheme ("forgegraph"), which
			// appSchemeForDevelopmentClient always prefers over the exp+<slug>
			// fallback, so the deep link/QR URL use that scheme literally.
			if devSession["deepLinkUrl"] != "forgegraph://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000" {
				t.Fatalf("unexpected deep link %#v", devSession)
			}
			if devSession["qrUrl"] != "https://qr.expo.dev/development-client?appScheme=forgegraph&url=http%3A%2F%2F192.168.4.10%3A19000" {
				t.Fatalf("unexpected QR URL %#v", devSession)
			}
			if devSession["installUrl"] != "https://expo.dev/runtime-artifacts/ios-dev.ipa" {
				t.Fatalf("unexpected install URL %#v", devSession)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected open result %#v", result)
			}
			openAttempt := result["openAttempt"].(map[string]any)
			if openAttempt["strategy"] != "qr_install" || openAttempt["outcome"] != "manual_required" {
				t.Fatalf("unexpected open attempt payload %#v", openAttempt)
			}
			if openAttempt["installUrl"] != "https://expo.dev/runtime-artifacts/ios-dev.ipa" {
				t.Fatalf("unexpected install URL %#v", openAttempt)
			}
			if openAttempt["deepLinkUrl"] != "exp+forgegraf://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000" {
				t.Fatalf("unexpected deep link %#v", openAttempt)
			}
			if openAttempt["qrUrl"] != "https://qr.expo.dev/development-client?appScheme=exp%2Bforgegraf&url=http%3A%2F%2F192.168.4.10%3A19000" {
				t.Fatalf("unexpected QR URL %#v", openAttempt)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") != 4 {
		t.Fatalf("expected four claim calls, got %v", calls)
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/reconcile") != 1 {
		t.Fatalf("expected one startup reconcile call, got %v", calls)
	}
	for _, expected := range []string{
		"verified EAS readiness pfjob_readiness development-device",
		"completed EAS development build pfjob_build build_ios_dev_1",
		"started dev session pfjob_devsession http://192.168.4.10:19000",
		"recorded development install/open attempt pfjob_open manual_required",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected stdout to contain %q, got %q", expected, stdout.String())
		}
	}
	waitForFileContains(t, npxLog, "apps/mobile :: expo start --dev-client --host lan --port 19000")
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	for _, expected := range []string{
		"apps/mobile :: whoami",
		"apps/mobile :: build:list --platform ios --build-profile development-device --status finished --distribution internal --limit 1 --json --non-interactive",
		"apps/mobile :: build --platform ios --profile development-device --json --non-interactive --wait",
		"apps/mobile :: expo start --dev-client --host lan --port 19000",
	} {
		if !strings.Contains(string(npxOutput), expected) {
			t.Fatalf("expected npx log to contain %q, got %q", expected, string(npxOutput))
		}
	}
}

func TestRunnerOnceReusesEASDevelopmentBuildFromReadiness(t *testing.T) {
	appDir := writeExpoFixture(t)

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "whoami" ]; then
  printf 'forgegraph-bot\n'
  exit 0
fi
if [ "$1" = "build:list" ]; then
  printf '[{"id":"build_ios_dev_reused","platform":"ios","profile":"development-device","status":"finished","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/ios-dev-reused.ipa"},"url":"https://expo.dev/accounts/acme/projects/mobile/builds/build_ios_dev_reused"}]\n'
  exit 0
fi
if [ "$1" = "build" ]; then
  printf 'unexpected fresh EAS build\n' >&2
  exit 12
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_LAN_HOST", "192.168.4.10")

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["eas"],"adapters":["eas.development"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			switch countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") {
			case 1:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"running","runnerId":"pfrun_cli","payload":{"platform":"ios","lane":"development","easProfileName":"development-device","targetClass":"device","sourceBinding":{"workspaceRoot":%q,"packagePath":".","appScheme":"forgegraph","expoSlug":"forgegraf"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_readiness"}}`, appDir)
			case 2:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","payload":{"platform":"ios","lane":"development","sourceBinding":{"workspaceRoot":%q,"packagePath":".","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_ios_dev_reused","installUrl":"https://expo.dev/runtime-artifacts/ios-dev-reused.ipa"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, appDir)
			default:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"running","runnerId":"pfrun_cli","payload":{"platform":"ios","lane":"development","sourceBinding":{"workspaceRoot":%q,"packagePath":".","appScheme":"forgegraph","expoSlug":"forgegraf"},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":"exp+forgegraf://expo-development-client/?url=http%%3A%%2F%%2F192.168.4.10%%3A19000","qrUrl":"https://qr.expo.dev/development-client?appScheme=exp%%2Bforgegraf&url=http%%3A%%2F%%2F192.168.4.10%%3A19000","installUrl":"https://expo.dev/runtime-artifacts/ios-dev-reused.ipa"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, appDir)
			}
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_readiness/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			devBuild, ok := result["devBuild"].(map[string]any)
			if !ok {
				t.Fatalf("expected readiness result to include reusable devBuild, got %#v", result)
			}
			if devBuild["buildId"] != "build_ios_dev_reused" || devBuild["installUrl"] != "https://expo.dev/runtime-artifacts/ios-dev-reused.ipa" {
				t.Fatalf("unexpected reusable dev build %#v", devBuild)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_readiness"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/heartbeat":
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			appDir,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") != 3 {
		t.Fatalf("expected three claim calls without eas.build.dev, got %v", calls)
	}
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	if strings.Contains(string(npxOutput), "build --platform") {
		t.Fatalf("expected reusable build to avoid fresh eas build, got npx log:\n%s", string(npxOutput))
	}
	if !strings.Contains(string(npxOutput), "build:list --platform ios --build-profile development-device --status finished --distribution internal --limit 1 --json --non-interactive") {
		t.Fatalf("expected filtered build:list lookup, got npx log:\n%s", string(npxOutput))
	}
}

func TestDevSessionStartUsesExpoOwnedTunnelURLForDevelopmentBuilds(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  printf 'exp+forgegraf://expo-development-client/?url=https%%3A%%2F%%2Fpreflight-tunnel.ngrok-free.app\n'
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	// developmentDeepLinkURL/appSchemeForDevelopmentClient always prefer the
	// source binding's explicit appScheme ("forgegraph") over the exp+<slug>
	// fallback; only the advertised URL itself is scraped from the Expo CLI's
	// tunnel output (via expoTunnelDevServerURLFromLogContent).
	expectedAdvertisedURL := "https://preflight-tunnel.ngrok-free.app"
	expectedDeepLinkURL := "forgegraph://expo-development-client/?url=https%3A%2F%2Fpreflight-tunnel.ngrok-free.app"
	expectedQRURL := "https://qr.expo.dev/development-client?appScheme=forgegraph&url=https%3A%2F%2Fpreflight-tunnel.ngrok-free.app"
	completed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method+" "+r.URL.Path == "GET /api/preflight/v1/runners/pfrun_tunnel/jobs/pfjob_tunnel" {
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_tunnel","kind":"dev_session.start","status":"running","runnerId":"pfrun_tunnel"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_tunnel"}}`))
			return
		}
		if r.Method+" "+r.URL.Path == "POST /api/preflight/v1/runners/pfrun_tunnel/jobs/pfjob_tunnel/heartbeat" {
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_tunnel","kind":"dev_session.start","status":"running","runnerId":"pfrun_tunnel"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_tunnel_heartbeat"}}`))
			return
		}
		if r.Method+" "+r.URL.Path != "POST /api/preflight/v1/runners/pfrun_tunnel/jobs/pfjob_tunnel/complete" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode dev session completion: %v", err)
		}
		result := body["result"].(map[string]any)
		devSession, ok := result["devSession"].(map[string]any)
		if !ok {
			t.Fatalf("expected dev session result, got %#v", result)
		}
		if devSession["advertisedUrl"] != expectedAdvertisedURL ||
			devSession["deepLinkUrl"] != expectedDeepLinkURL ||
			devSession["qrUrl"] != expectedQRURL {
			t.Fatalf("expected tunnel dev-session URLs, got %#v", devSession)
		}
		completed = true
		_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_tunnel","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_tunnel"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_tunnel"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	continueWorkflow, err := handleDevSessionStartJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:         server.URL,
			workspaceRoot:  appDir,
			hostMode:       "tunnel",
			metroPort:      19000,
			metroStatusURL: metroServer.URL + "/status",
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_tunnel"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:   "pfjob_tunnel",
			Kind: "dev_session.start",
			Payload: runnerJobPayload{
				Platform: "ios",
				Lane:     "development",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: appDir,
					PackagePath:   ".",
					AppScheme:     "forgegraph",
					ExpoSlug:      "forgegraf",
				},
				DevBuild: map[string]any{
					"buildId":    "build_ios_tunnel",
					"installUrl": "https://expo.dev/runtime-artifacts/ios-dev.ipa",
				},
			},
		},
		&stdout,
	)
	if err != nil {
		t.Fatalf("expected dev session start to complete: %v\nstdout: %s", err, stdout.String())
	}
	if !continueWorkflow || !completed {
		t.Fatalf("expected dev session workflow to continue with completed API call; continue=%v completed=%v", continueWorkflow, completed)
	}
	if !strings.Contains(stdout.String(), "started dev session pfjob_tunnel "+expectedAdvertisedURL) {
		t.Fatalf("expected stdout to include tunnel URL, got %q", stdout.String())
	}
}

func TestDevSessionStartUploadsQRPayloadAndExpoLogArtifacts(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  printf 'Metro waiting on http://192.168.4.10:19000\n'
  printf 'Scan the QR code above with a development build\n'
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_LAN_HOST", "192.168.4.10")

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var artifactUploads []map[string]any
	var completedDevSession map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/runners/pfrun_qr/jobs/pfjob_devsession":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_qr"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_devsession"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/runners/pfrun_qr/jobs/pfjob_devsession/heartbeat":
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_qr"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/runners/pfrun_qr/jobs/pfjob_devsession/artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact upload body: %v", err)
			}
			artifactUploads = append(artifactUploads, body)
			artifactID := "pfart_log"
			if body["kind"] == "qr_code" {
				artifactID = "pfart_qr"
			}
			_, _ = fmt.Fprintf(w, `{"data":{"artifact":{"id":%q,"runnerJobId":"pfjob_devsession","kind":%q,"uri":%q}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_artifact"}}`, artifactID, body["kind"], body["uri"])
		case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/runners/pfrun_qr/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session completion: %v", err)
			}
			result := body["result"].(map[string]any)
			completedDevSession = result["devSession"].(map[string]any)
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_qr"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	continueWorkflow, err := handleDevSessionStartJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:         server.URL,
			workspaceRoot:  appDir,
			hostMode:       "lan",
			metroPort:      19000,
			metroStatusURL: metroServer.URL + "/status",
		},
		runnerRegistrationData{
			Runner: apiRunner{
				ID: "pfrun_qr",
				Capabilities: map[string]any{
					"runnerArtifactUpload": true,
				},
			},
			Token: "runner_token",
		},
		apiRunnerJob{
			ID:   "pfjob_devsession",
			Kind: "dev_session.start",
			Payload: runnerJobPayload{
				Platform: "ios",
				Lane:     "development",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: appDir,
					PackagePath:   ".",
					AppScheme:     "forgegraph",
					ExpoSlug:      "forgegraf",
				},
				DevBuild: map[string]any{
					"buildId":    "build_ios_dev_1",
					"installUrl": "https://expo.dev/runtime-artifacts/ios-dev.ipa",
				},
			},
		},
		&stdout,
	)
	if err != nil {
		t.Fatalf("expected dev session start to complete: %v\nstdout: %s", err, stdout.String())
	}
	if !continueWorkflow {
		t.Fatal("expected workflow to continue after dev-session start")
	}
	if completedDevSession["qrArtifactId"] != "pfart_qr" {
		t.Fatalf("expected uploaded QR artifact id in completion, got %#v", completedDevSession)
	}
	if completedDevSession["qrPayloadPath"] == "" || completedDevSession["logPath"] == "" {
		t.Fatalf("expected QR payload and log paths in completion, got %#v", completedDevSession)
	}
	if len(artifactUploads) != 2 {
		t.Fatalf("expected QR payload and Expo log artifact uploads, got %#v", artifactUploads)
	}
	if artifactUploads[0]["kind"] != "qr_code" || artifactUploads[1]["kind"] != "log" {
		t.Fatalf("unexpected artifact upload kinds %#v", artifactUploads)
	}
	qrArtifact := artifactUploads[0]
	qrURI := fmt.Sprint(qrArtifact["uri"])
	if !strings.HasSuffix(qrURI, filepath.Join(".preflight", "dev-sessions", "pfjob_devsession", "qr-payload.json")) {
		t.Fatalf("expected QR payload artifact path, got %#v", qrArtifact)
	}
	qrMetadata := qrArtifact["metadata"].(map[string]any)
	if qrMetadata["qrUrl"] != completedDevSession["qrUrl"] ||
		qrMetadata["deepLinkUrl"] != completedDevSession["deepLinkUrl"] ||
		qrMetadata["advertisedUrl"] != "http://192.168.4.10:19000" ||
		qrMetadata["installUrl"] != "https://expo.dev/runtime-artifacts/ios-dev.ipa" {
		t.Fatalf("unexpected QR artifact metadata %#v", qrMetadata)
	}
	qrPayload, readErr := os.ReadFile(qrURI)
	if readErr != nil {
		t.Fatalf("read QR payload artifact: %v", readErr)
	}
	// developmentDeepLinkURL/appSchemeForDevelopmentClient always prefer the
	// source binding's explicit appScheme ("forgegraph") over the exp+<slug>
	// fallback, so the QR payload's deep link uses that scheme literally.
	if !strings.Contains(string(qrPayload), "https://qr.expo.dev/development-client") ||
		!strings.Contains(string(qrPayload), "forgegraph://expo-development-client/") {
		t.Fatalf("expected QR payload to preserve Expo QR/deep-link evidence, got %q", string(qrPayload))
	}
}

func TestReusableDevBuildFromEASBuildListRejectsExpiredArtifacts(t *testing.T) {
	output := []byte(`[
		{
			"id": "build_ios_dev_expired",
			"platform": "IOS",
			"profile": "development-device",
			"status": "FINISHED",
			"artifacts": {
				"buildUrl": "https://expo.dev/runtime-artifacts/expired.ipa"
			},
			"expirationDate": "2000-01-01T00:00:00.000Z"
		}
	]`)

	if devBuild, ok := reusableDevBuildFromEASBuildList(output, "development-device", "device"); ok {
		t.Fatalf("expected expired build to be rejected, got %#v", devBuild)
	}
}

func TestParseEASBuildOutputReadsEASArtifactsBuildURL(t *testing.T) {
	output := []byte(`{
		"id": "build_ios_dev_artifact",
		"platform": "ios",
		"profile": "development-device",
		"status": "finished",
		"artifacts": {
			"buildUrl": "https://expo.dev/artifacts/build_ios_dev_artifact.ipa"
		},
		"url": "https://expo.dev/accounts/acme/projects/mobile/builds/build_ios_dev_artifact"
	}`)

	devBuild, err := parseEASBuildOutput(output, "development-device")
	if err != nil {
		t.Fatalf("parse EAS build output: %v", err)
	}
	if devBuild["installUrl"] != "https://expo.dev/artifacts/build_ios_dev_artifact.ipa" {
		t.Fatalf("expected install URL from EAS artifacts, got %#v", devBuild)
	}
}

func TestReusableDevBuildFromEASBuildListReadsEASArtifactsBuildURL(t *testing.T) {
	output := []byte(`[
		{
			"id": "build_ios_dev_reusable",
			"platform": "IOS",
			"profile": "development-device",
			"status": "FINISHED",
			"artifacts": {
				"buildUrl": "https://expo.dev/artifacts/reusable.ipa"
			},
			"expirationDate": "2999-01-01T00:00:00.000Z"
		}
	]`)

	devBuild, ok := reusableDevBuildFromEASBuildList(output, "development-device", "device")
	if !ok {
		t.Fatalf("expected reusable EAS build from artifacts buildUrl")
	}
	if devBuild["installUrl"] != "https://expo.dev/artifacts/reusable.ipa" {
		t.Fatalf("expected install URL from EAS artifacts, got %#v", devBuild)
	}
}

func TestParseEASBuildDownloadOutputReadsEASArtifactsArchivePath(t *testing.T) {
	output := []byte(`{
		"id": "build_android_dev",
		"artifacts": {
			"applicationArchivePath": "/tmp/preflight/builds/android-dev.apk"
		}
	}`)

	path, err := parseEASBuildDownloadOutput(output)
	if err != nil {
		t.Fatalf("parse EAS build download output: %v", err)
	}
	if path != "/tmp/preflight/builds/android-dev.apk" {
		t.Fatalf("expected archive path from EAS artifacts, got %q", path)
	}
}

func TestRunEASCommandPrefersInstalledEASBinary(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'eas %s\n' "$*" >> "$EAS_LOG"
printf 'forgegraph-bot\n'
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf 'npx %s\n' "$*" >> "$EAS_LOG"
exit 12
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	output, err := runEASCommand(appDir, "whoami")
	if err != nil {
		t.Fatalf("expected eas command to succeed, got %v", err)
	}
	if strings.TrimSpace(string(output)) != "forgegraph-bot" {
		t.Fatalf("unexpected eas output %q", output)
	}
	logOutput, err := os.ReadFile(easLog)
	if err != nil {
		t.Fatalf("read eas log: %v", err)
	}
	if strings.Contains(string(logOutput), "npx ") {
		t.Fatalf("expected installed eas binary, got log:\n%s", string(logOutput))
	}
	if !strings.Contains(string(logOutput), "eas whoami") {
		t.Fatalf("expected eas whoami, got log:\n%s", string(logOutput))
	}
}

func TestEASBuildRevealsPreflightExpoTokenWithoutLoggingValue(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	envLog := filepath.Join(t.TempDir(), "eas-env.log")
	secretValue := "expo_secret_cli_token_123"
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'token=%s\n' "$EXPO_TOKEN" >> "$EAS_ENV_LOG"
printf 'ci=%s no_interactive=%s\n' "$CI" "$EXPO_NO_INTERACTIVE" >> "$EAS_ENV_LOG"
if [ "$EXPO_TOKEN" != "$EXPECTED_EXPO_TOKEN" ]; then
  printf 'missing EXPO_TOKEN\n' >&2
  exit 44
fi
if [ "$CI" != "1" ] || [ "$EXPO_NO_INTERACTIVE" != "1" ]; then
  printf 'missing non-interactive CI env\n' >&2
  exit 45
fi
printf '{"id":"build_ios_dev_1","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/ios-dev.ipa"},"platform":"ios","profile":"development-device"}\n'
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("EAS_ENV_LOG", envLog)
	t.Setenv("EXPECTED_EXPO_TOKEN", secretValue)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	revealCalled := false
	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/secrets/pfsec_expo/reveal":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on secret reveal: %q", r.Header.Get("Authorization"))
			}
			revealCalled = true
			_, _ = fmt.Fprintf(w, `{"data":{"secretReference":{"id":"pfsec_expo","provider":"expo","purpose":"api_token","key":"EXPO_TOKEN"},"value":%q,"expiresAt":"2026-05-20T12:00:00.000Z"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_secret_reveal"}}`, secretValue)
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on complete: %q", r.Header.Get("Authorization"))
			}
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			if strings.Contains(fmt.Sprint(completed), secretValue) {
				t.Fatalf("completion body leaked secret value: %#v", completed)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleEASBuildDevJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: appDir,
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_build",
			Kind:   "eas.build.dev",
			Status: "running",
			Payload: runnerJobPayload{
				Platform:       "ios",
				Lane:           "development",
				EASProfileName: "development-device",
				TargetClass:    "device",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot:    appDir,
					PackagePath:      ".",
					ExpoConfigDigest: digestIfExists(filepath.Join(appDir, "app.config.ts")),
					EASJSONDigest:    digestIfExists(filepath.Join(appDir, "eas.json")),
					AppScheme:        "forgegraph",
					ExpoSlug:         "forgegraf",
				},
				Readiness: map[string]any{"ready": true},
				SecretReferences: []runnerJobSecretReference{
					{
						ID:       "pfsec_expo",
						Provider: "expo",
						Purpose:  "api_token",
						Key:      "EXPO_TOKEN",
					},
				},
			},
		},
		&stdout,
	)

	if err != nil {
		t.Fatalf("expected EAS build to use revealed Preflight token, got %v", err)
	}
	if !revealCalled {
		t.Fatalf("expected runner to reveal the Preflight-owned Expo token")
	}
	result := completed["result"].(map[string]any)
	if result["status"] != "ok" {
		t.Fatalf("expected successful EAS build completion, got %#v", result)
	}
	logOutput, err := os.ReadFile(envLog)
	if err != nil {
		t.Fatalf("read EAS env log: %v", err)
	}
	if !strings.Contains(string(logOutput), "token="+secretValue) {
		t.Fatalf("expected fake EAS to receive EXPO_TOKEN, got log:\n%s", string(logOutput))
	}
	if !strings.Contains(string(logOutput), "ci=1 no_interactive=1") {
		t.Fatalf("expected EAS command to run in CI/non-interactive mode, got log:\n%s", string(logOutput))
	}
	if strings.Contains(stdout.String(), secretValue) {
		t.Fatalf("stdout leaked secret value: %q", stdout.String())
	}
}

func TestEASBuildRefusesProductionProfileOutsideCI(t *testing.T) {
	// Production builds run only through CI. When the runner is not in a CI
	// context it must refuse to invoke the production EAS profile, completing the
	// job as setup_required with a clear code instead of building.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("EAS_BUILD", "")

	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "eas-invoked")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte("#!/usr/bin/env sh\ntouch "+sentinel+"\n"), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleEASBuildDevJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: appDir,
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_build",
			Kind:   "eas.build.dev",
			Status: "running",
			Payload: runnerJobPayload{
				Platform:       "ios",
				Lane:           "store",
				EASProfileName: "production",
				TargetClass:    "device",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot:    appDir,
					PackagePath:      ".",
					ExpoConfigDigest: digestIfExists(filepath.Join(appDir, "app.config.ts")),
					EASJSONDigest:    digestIfExists(filepath.Join(appDir, "eas.json")),
					AppScheme:        "forgegraph",
					ExpoSlug:         "forgegraf",
				},
				Readiness: map[string]any{"ready": true},
			},
		},
		&stdout,
	)
	if err != nil {
		t.Fatalf("expected production guard to complete cleanly, got %v", err)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatalf("expected eas NOT to be invoked for a CI-only production build")
	}
	result, ok := completed["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected completion result, got %#v", completed)
	}
	if result["status"] != "setup_required" {
		t.Fatalf("expected setup_required, got %#v", result)
	}
	setupRequired, ok := result["setupRequired"].(map[string]any)
	if !ok || setupRequired["code"] != "production_build_ci_only" {
		t.Fatalf("expected production_build_ci_only, got %#v", result["setupRequired"])
	}
}

func TestEASBuildAllowsProductionProfileInCI(t *testing.T) {
	// In a CI context the runner builds the production profile normally.
	t.Setenv("CI", "1")

	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '{"id":"build_ios_prod","artifacts":{"buildUrl":"https://expo.dev/artifacts/ios-prod.ipa"},"platform":"ios","profile":"production"}\n'
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/artifacts":
			_, _ = w.Write([]byte(`{"data":{"artifact":{"id":"pfart_eas","kind":"tool_output","uri":"/repo/.preflight/eas/pfjob_build/eas-build.json","retentionClass":"diagnostic"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_artifact"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleEASBuildDevJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: appDir,
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_build",
			Kind:   "eas.build.dev",
			Status: "running",
			Payload: runnerJobPayload{
				Platform:       "ios",
				Lane:           "store",
				EASProfileName: "production",
				TargetClass:    "device",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot:    appDir,
					PackagePath:      ".",
					ExpoConfigDigest: digestIfExists(filepath.Join(appDir, "app.config.ts")),
					EASJSONDigest:    digestIfExists(filepath.Join(appDir, "eas.json")),
					AppScheme:        "forgegraph",
					ExpoSlug:         "forgegraf",
				},
				Readiness: map[string]any{"ready": true},
			},
		},
		&stdout,
	)
	if err != nil {
		t.Fatalf("expected production build in CI to succeed, got %v", err)
	}
	result, ok := completed["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected completion result, got %#v", completed)
	}
	if result["status"] != "ok" {
		t.Fatalf("expected ok production build in CI, got %#v", result)
	}
}

func TestEASBuildUploadsRedactedToolOutputArtifacts(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	secretValue := "expo_secret_cli_token_artifact"
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'EXPO_TOKEN=%s\n' "$EXPO_TOKEN" >&2
printf '{"id":"build_ios_dev_artifacts","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/ios-dev-artifacts.ipa"},"platform":"ios","profile":"development-device"}\n'
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var artifactBodies []map[string]any
	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/secrets/pfsec_expo/reveal":
			_, _ = fmt.Fprintf(w, `{"data":{"secretReference":{"id":"pfsec_expo","provider":"expo","purpose":"api_token","key":"EXPO_TOKEN"},"value":%q,"expiresAt":"2026-05-20T12:00:00.000Z"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_secret_reveal"}}`, secretValue)
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode artifact body: %v", err)
			}
			artifactBodies = append(artifactBodies, body)
			_, _ = w.Write([]byte(`{"data":{"artifact":{"id":"pfart_eas","kind":"tool_output","uri":"/repo/.preflight/eas/pfjob_build/eas-build.json","retentionClass":"diagnostic"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_artifact"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleEASBuildDevJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceRoot: appDir,
		},
		runnerRegistrationData{
			Runner: apiRunner{
				ID:           "pfrun_cli",
				Capabilities: map[string]any{"runnerArtifactUpload": true},
			},
			Token: "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_build",
			Kind:   "eas.build.dev",
			Status: "running",
			Payload: runnerJobPayload{
				Platform:       "ios",
				Lane:           "development",
				EASProfileName: "development-device",
				TargetClass:    "device",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot:    appDir,
					PackagePath:      ".",
					ExpoConfigDigest: digestIfExists(filepath.Join(appDir, "app.config.ts")),
					EASJSONDigest:    digestIfExists(filepath.Join(appDir, "eas.json")),
					AppScheme:        "forgegraph",
					ExpoSlug:         "forgegraf",
				},
				Readiness: map[string]any{"ready": true},
				SecretReferences: []runnerJobSecretReference{
					{
						ID:       "pfsec_expo",
						Provider: "expo",
						Purpose:  "api_token",
						Key:      "EXPO_TOKEN",
					},
				},
			},
		},
		&stdout,
	)

	if err != nil {
		t.Fatalf("expected EAS build to upload artifacts: %v", err)
	}
	if len(artifactBodies) != 2 {
		t.Fatalf("expected EAS build JSON and log artifacts, got %#v", artifactBodies)
	}
	kinds := []string{artifactBodies[0]["kind"].(string), artifactBodies[1]["kind"].(string)}
	if !slices.Contains(kinds, "tool_output") || !slices.Contains(kinds, "log") {
		t.Fatalf("expected tool_output and log artifacts, got %#v", artifactBodies)
	}
	for _, body := range artifactBodies {
		uri := body["uri"].(string)
		content, err := os.ReadFile(uri)
		if err != nil {
			t.Fatalf("read EAS artifact %s: %v", uri, err)
		}
		if strings.Contains(string(content), secretValue) {
			t.Fatalf("EAS artifact leaked secret in %s: %s", uri, string(content))
		}
		if body["sizeBytes"].(float64) <= 0 {
			t.Fatalf("expected artifact size for %#v", body)
		}
	}
	if completed["result"].(map[string]any)["status"] != "ok" {
		t.Fatalf("expected successful completion after artifact upload, got %#v", completed)
	}
}

func TestEASReadinessRequiresPreflightExpoTokenBeforeCallingEAS(t *testing.T) {
	appDir := writeExpoFixture(t)
	fakeBin := t.TempDir()
	easLog := filepath.Join(t.TempDir(), "eas.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'unexpected eas call %s\n' "$*" >> "$EAS_LOG"
exit 55
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("EAS_LOG", easLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_readiness/complete":
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_readiness"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	err := handleEASReadinessProbeJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:        server.URL,
			workspaceID:   "ws_cli",
			workspaceRoot: appDir,
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:          "pfjob_readiness",
			WorkspaceID: "ws_cli",
			AppID:       "pfapp_mobile",
			Kind:        "eas.readiness.probe",
			Status:      "running",
			Payload: runnerJobPayload{
				Platform:       "ios",
				Lane:           "development",
				EASProfileName: "development-device",
				TargetClass:    "device",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: appDir,
					PackagePath:   ".",
				},
				RequiredSecretReferences: []runnerJobRequiredSecretReference{
					{
						Provider:  "expo",
						Purpose:   "api_token",
						Key:       "EXPO_TOKEN",
						LaneScope: "development",
						Required:  true,
					},
				},
			},
		},
		&stdout,
	)

	if err != nil {
		t.Fatalf("expected setup-required completion, got %v", err)
	}
	result := completed["result"].(map[string]any)
	if result["status"] != "setup_required" {
		t.Fatalf("expected setup_required result, got %#v", result)
	}
	setupRequired := result["setupRequired"].(map[string]any)
	if setupRequired["code"] != "expo_token_secret_required" {
		t.Fatalf("expected Expo token setup blocker, got %#v", setupRequired)
	}
	commands := setupRequired["commands"].([]any)
	expectedCommand := "preflight credentials create --api-url " + server.URL + " --workspace-id ws_cli --app-id pfapp_mobile --provider expo --purpose api_token --key EXPO_TOKEN --lane development --value-env EXPO_TOKEN"
	if len(commands) != 1 || commands[0] != expectedCommand {
		t.Fatalf("unexpected setup commands %#v", commands)
	}
	if _, err := os.Stat(easLog); !os.IsNotExist(err) {
		content, _ := os.ReadFile(easLog)
		t.Fatalf("EAS should not be called without a Preflight EXPO_TOKEN secret, log err=%v content=%s", err, content)
	}
}

func TestRunnerClaimDecodesRequiredSecretReferencesWithoutValues(t *testing.T) {
	var claim runnerClaimData
	err := decodeEnvelopeData([]byte(`{
		"job": {
			"id": "pfjob_readiness",
			"kind": "eas.readiness.probe",
			"status": "running",
			"payload": {
				"requiredSecretReferences": [
					{
						"provider": "expo",
						"purpose": "api_token",
						"key": "EXPO_TOKEN",
						"laneScope": "development",
						"required": true
					}
				]
			}
		}
	}`), &claim)
	if err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	if len(claim.Job.Payload.RequiredSecretReferences) != 1 {
		t.Fatalf("expected one required secret reference, got %#v", claim.Job.Payload.RequiredSecretReferences)
	}
	required := claim.Job.Payload.RequiredSecretReferences[0]
	if required.Provider != "expo" || required.Purpose != "api_token" || required.Key != "EXPO_TOKEN" || !required.Required {
		t.Fatalf("unexpected required secret reference %#v", required)
	}
	if required.ID != "" {
		t.Fatalf("required secret metadata must not include a concrete secret ref ID: %#v", required)
	}
}

func TestDevSessionStartFailsWhenMetroPortBelongsToAnotherProject(t *testing.T) {
	appDir := writeExpoFixture(t)
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(statusServer.Close)

	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '› Port 8081 is running @other/mobile in another window\n'
printf '› Skipping dev server\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var completed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read"}}`))
			return
		}
		if r.URL.Path == "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/heartbeat" {
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
			return
		}
		if r.URL.Path != "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer runner_token" {
			t.Fatalf("missing runner token on complete: %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
			t.Fatalf("decode completion body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete"}}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	continueWorkflow, err := handleDevSessionStartJob(
		server.Client(),
		runnerOnceOptions{
			apiURL:         server.URL,
			workspaceRoot:  appDir,
			metroPort:      8081,
			metroStatusURL: statusServer.URL,
			hostMode:       "lan",
		},
		runnerRegistrationData{
			Runner: apiRunner{ID: "pfrun_cli"},
			Token:  "runner_token",
		},
		apiRunnerJob{
			ID:     "pfjob_devsession",
			Kind:   "dev_session.start",
			Status: "running",
			Payload: runnerJobPayload{
				Platform: "ios",
				Lane:     "development",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: appDir,
					PackagePath:   ".",
				},
			},
		},
		&stdout,
	)

	if err != nil {
		t.Fatalf("expected handled failure, got error %v", err)
	}
	if continueWorkflow {
		t.Fatal("expected workflow to stop after foreign Metro detection")
	}
	result := completed["result"].(map[string]any)
	if result["status"] != "failed" {
		t.Fatalf("expected failed result, got %#v", result)
	}
	failure := result["failure"].(map[string]any)
	if failure["code"] != "metro_port_owned_by_other_project" {
		t.Fatalf("expected metro ownership failure, got %#v", failure)
	}
	if !strings.Contains(stdout.String(), "failed dev session pfjob_devsession") {
		t.Fatalf("expected failed dev session output, got %q", stdout.String())
	}
}

func TestRunnerOnceHandlesAndroidEASReadinessAndDevelopmentBuild(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	apkPath := filepath.Join(t.TempDir(), "downloaded-android-dev.apk")
	if err := os.WriteFile(apkPath, []byte("fake downloaded apk"), 0o644); err != nil {
		t.Fatalf("write fake downloaded apk: %v", err)
	}
	for name, content := range map[string]string{
		"package.json":  `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"app.config.ts": `export default { slug: "forgegraf", scheme: "forgegraph" }`,
		"eas.json": `{
			"build": {
				"development": {
					"developmentClient": true,
					"distribution": "internal",
					"env": {"APP_VARIANT": "development"},
					"android": {"buildType": "apk"}
				}
			}
		}`,
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "whoami" ]; then
  printf 'forgegraph-bot\n'
  exit 0
fi
if [ "$1" = "build:list" ] && [ "$3" = "android" ]; then
  printf '[]\n'
  exit 0
fi
if [ "$1" = "build" ] && [ "$3" = "android" ]; then
  printf '{"id":"build_android_dev_1","platform":"android","profile":"development","status":"finished","artifacts":{"buildUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"},"url":"https://expo.dev/accounts/acme/projects/mobile/builds/build_android_dev_1"}\n'
  exit 0
fi
if [ "$1" = "build:download" ] && [ "$2" = "--build-id" ] && [ "$3" = "build_android_dev_1" ]; then
  printf '{"path":"%s"}\n' "$DOWNLOADED_APK"
  exit 0
fi
printf 'unexpected eas args: %s\n' "$*" >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "expo" ] && [ "$2" = "start" ]; then
  exit 0
fi
printf 'unexpected npx args: %s\n' "$*" >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("DOWNLOADED_APK", apkPath)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_LAN_HOST", "192.168.4.10")
	adbLog := filepath.Join(t.TempDir(), "adb.log")
	adbPath := writeFakeExecutable(t, "adb", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$ADB_LOG"
if [ "$1" = "devices" ] && [ "$2" = "-l" ]; then
  printf 'List of devices attached\nemulator-5554 device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n'
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "install" ] && [ "$4" = "-r" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "shell" ] && [ "$4" = "am" ] && [ "$5" = "start" ]; then
  exit 0
fi
printf 'unexpected adb args: %s\n' "$*" >&2
exit 42
`)
	t.Setenv("ADB_LOG", adbLog)

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["android"],"localTools":["eas"],"adapters":["eas.development"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			switch countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") {
			case 1:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"development","easProfileName":"development","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_readiness"}}`, workspaceRoot)
			case 2:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"development","easProfileName":"development","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"readiness":{"ready":true,"targetClass":"emulator"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_build"}}`, workspaceRoot)
			case 3:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_discover","kind":"device.discover","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"development","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_android_dev_1","platform":"android","installUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_discover"}}`, workspaceRoot)
			case 4:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_android_dev_1","platform":"android","installUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
			default:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_android_dev_1","platform":"android","installUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":"exp+forgegraf://expo-development-client/?url=http%%3A%%2F%%2F192.168.4.10%%3A19000","qrUrl":"https://qr.expo.dev/development-client?appScheme=exp%%2Bforgegraf&url=http%%3A%%2F%%2F192.168.4.10%%3A19000","installUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
			}
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_readiness/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode readiness complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected readiness result %#v", result)
			}
			readiness := result["readiness"].(map[string]any)
			if readiness["platform"] != "android" || readiness["easProfileName"] != "development" {
				t.Fatalf("unexpected Android readiness payload %#v", readiness)
			}
			if readiness["androidArtifact"] != "apk" || readiness["targetClass"] != "emulator" {
				t.Fatalf("unexpected Android artifact readiness %#v", readiness)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_readiness","kind":"eas.readiness.probe","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_readiness"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected build result %#v", result)
			}
			devBuild := result["devBuild"].(map[string]any)
			if devBuild["buildId"] != "build_android_dev_1" || devBuild["platform"] != "android" || devBuild["installUrl"] != "https://expo.dev/runtime-artifacts/android-dev.apk" {
				t.Fatalf("unexpected Android dev build payload %#v", devBuild)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/targets/android-emulators":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode Android targets body: %v", err)
			}
			if !strings.Contains(body["adbDevicesOutput"].(string), "emulator-5554") {
				t.Fatalf("unexpected adb devices output %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_android","displayName":"sdk_gphone64_arm64","providerIdentity":"emulator-5554","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_report_android_targets"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_discover/targets/pftgt_android/lock":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode Android lock body: %v", err)
			}
			if body["lockOwner"] != "preflight-cli:macbook.local" {
				t.Fatalf("unexpected lock body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_android","displayName":"sdk_gphone64_arm64","providerIdentity":"emulator-5554","availability":"busy"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock_android_target"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/heartbeat":
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected dev session result %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["installUrl"] != "https://expo.dev/runtime-artifacts/android-dev.apk" {
				t.Fatalf("unexpected install URL %#v", devSession)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected open result %#v", result)
			}
			openAttempt := result["openAttempt"].(map[string]any)
			if openAttempt["targetClass"] != "android_emulator" {
				t.Fatalf("unexpected Android open target class %#v", openAttempt)
			}
			if openAttempt["strategy"] != "adb_install_deeplink" || openAttempt["outcome"] != "opened" {
				t.Fatalf("unexpected Android open attempt %#v", openAttempt)
			}
			if openAttempt["installUrl"] != "https://expo.dev/runtime-artifacts/android-dev.apk" || openAttempt["apkPath"] != apkPath {
				t.Fatalf("unexpected Android install evidence %#v", openAttempt)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
			"--adb-path",
			adbPath,
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") != 5 {
		t.Fatalf("expected five claim calls, got %v", calls)
	}
	waitForFileContains(t, npxLog, "apps/mobile :: expo start --dev-client --host lan --port 19000")
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	for _, expected := range []string{
		"apps/mobile :: whoami",
		"apps/mobile :: build:list --platform android --build-profile development --status finished --distribution internal --limit 1 --json --non-interactive",
		"apps/mobile :: build --platform android --profile development --json --non-interactive --wait",
		"apps/mobile :: build:download --build-id build_android_dev_1 --json --non-interactive",
		"apps/mobile :: expo start --dev-client --host lan --port 19000",
	} {
		if !strings.Contains(string(npxOutput), expected) {
			t.Fatalf("expected npx log to contain %q, got %q", expected, string(npxOutput))
		}
	}
}

func TestRunnerOnceInstallsAndroidDevelopmentBuildOnLockedEmulator(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	apkPath := filepath.Join(t.TempDir(), "android-dev.apk")
	if err := os.WriteFile(apkPath, []byte("fake apk"), 0o644); err != nil {
		t.Fatalf("write fake apk: %v", err)
	}

	adbLog := filepath.Join(t.TempDir(), "adb.log")
	adbPath := writeFakeExecutable(t, "adb", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$ADB_LOG"
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "install" ] && [ "$4" = "-r" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "shell" ] && [ "$4" = "am" ] && [ "$5" = "start" ]; then
  exit 0
fi
printf 'unexpected adb args: %s\n' "$*" >&2
exit 42
`)
	t.Setenv("ADB_LOG", adbLog)

	var calls []string
	var openAttempt map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["android"],"localTools":["adb"],"adapters":["eas.development"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_android","payload":{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf","androidPackage":"com.gmacko.forgegraph.dev"},"devBuild":{"buildId":"build_android_dev_1","platform":"android","installUrl":%q},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":"exp+forgegraf://expo-development-client/?url=http%%3A%%2F%%2F192.168.4.10%%3A19000","qrUrl":"https://qr.expo.dev/development-client?appScheme=exp%%2Bforgegraf&url=http%%3A%%2F%%2F192.168.4.10%%3A19000","installUrl":%q}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot, apkPath, apkPath)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected open result %#v", result)
			}
			openAttempt = result["openAttempt"].(map[string]any)
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--adb-path",
			adbPath,
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if openAttempt["strategy"] != "adb_install_deeplink" || openAttempt["outcome"] != "opened" {
		t.Fatalf("unexpected Android open attempt %#v", openAttempt)
	}
	if openAttempt["providerIdentity"] != "emulator-5554" || openAttempt["apkPath"] != apkPath {
		t.Fatalf("unexpected Android open evidence %#v", openAttempt)
	}
	adbOutput, err := os.ReadFile(adbLog)
	if err != nil {
		t.Fatalf("read adb log: %v", err)
	}
	if !strings.Contains(string(adbOutput), "emulator-5554 install -r "+apkPath) {
		t.Fatalf("expected adb install command, got %q", string(adbOutput))
	}
	if !strings.Contains(string(adbOutput), "emulator-5554 shell am start -a android.intent.action.VIEW -d exp+forgegraf://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000 -p com.gmacko.forgegraph.dev") {
		t.Fatalf("expected adb deep link command, got %q", string(adbOutput))
	}
}

func TestRunnerOnceDownloadsRemoteAndroidDevelopmentBuildBeforeOpening(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	apkPath := filepath.Join(t.TempDir(), "downloaded-android-dev.apk")
	if err := os.WriteFile(apkPath, []byte("fake downloaded apk"), 0o644); err != nil {
		t.Fatalf("write fake downloaded apk: %v", err)
	}

	npxLog := filepath.Join(t.TempDir(), "npx.log")
	easPath := writeFakeExecutable(t, "eas", `#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
if [ "$1" = "build:download" ] && [ "$2" = "--build-id" ] && [ "$3" = "build_android_dev_1" ]; then
  printf '{"path":"%s"}\n' "$DOWNLOADED_APK"
  exit 0
fi
printf 'unexpected eas args: %s\n' "$*" >&2
exit 42
`)
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("DOWNLOADED_APK", apkPath)
	t.Setenv("PATH", filepath.Dir(easPath)+string(os.PathListSeparator)+os.Getenv("PATH"))

	adbLog := filepath.Join(t.TempDir(), "adb.log")
	adbPath := writeFakeExecutable(t, "adb", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$ADB_LOG"
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "install" ] && [ "$4" = "-r" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "shell" ] && [ "$4" = "am" ] && [ "$5" = "start" ]; then
  exit 0
fi
printf 'unexpected adb args: %s\n' "$*" >&2
exit 42
`)
	t.Setenv("ADB_LOG", adbLog)

	var openAttempt map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["android"],"localTools":["adb","eas"],"adapters":["eas.development"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_android","payload":{"platform":"android","lane":"development","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetClass":"emulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_android_dev_1","platform":"android","installUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"},"devSession":{"status":"started","hostMode":"lan","advertisedUrl":"http://192.168.4.10:19000","deepLinkUrl":"exp+forgegraf://expo-development-client/?url=http%%3A%%2F%%2F192.168.4.10%%3A19000","qrUrl":"https://qr.expo.dev/development-client?appScheme=exp%%2Bforgegraf&url=http%%3A%%2F%%2F192.168.4.10%%3A19000","installUrl":"https://expo.dev/runtime-artifacts/android-dev.apk"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected open result %#v", result)
			}
			openAttempt = result["openAttempt"].(map[string]any)
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"dev_session.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--adb-path",
			adbPath,
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if openAttempt["strategy"] != "adb_install_deeplink" || openAttempt["outcome"] != "opened" {
		t.Fatalf("unexpected Android open attempt %#v", openAttempt)
	}
	if openAttempt["apkPath"] != apkPath {
		t.Fatalf("expected downloaded APK path, got %#v", openAttempt)
	}
	waitForFileContains(t, npxLog, "apps/mobile :: build:download --build-id build_android_dev_1 --json --non-interactive")
	adbOutput, err := os.ReadFile(adbLog)
	if err != nil {
		t.Fatalf("read adb log: %v", err)
	}
	if !strings.Contains(string(adbOutput), "emulator-5554 install -r "+apkPath) {
		t.Fatalf("expected adb install command, got %q", string(adbOutput))
	}
}

func TestRunnerOnceCancelsInFlightEASDevelopmentBuild(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
sleep 1
printf '{"id":"build_ios_dev_1","platform":"ios","profile":"development-device","status":"finished"}\n'
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")

	var calls []string
	completedCancelled := false
	var startedAt time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["eas"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			if startedAt.IsZero() {
				startedAt = time.Now()
			}
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"running","runnerId":"pfrun_cli","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"readiness":{"ready":true}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_build"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/heartbeat":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method for job heartbeat: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would: with the job's
			// current (cancelled) status, not just the plain job-read route.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_job_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for job read: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_job"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode EAS build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "cancelled" {
				t.Fatalf("expected cancelled EAS build result, got %#v", result)
			}
			completedCancelled = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	// startedAt is stamped by the claim handler below.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/heartbeat") == 0 {
		t.Fatalf("expected runner to poll EAS build job status via heartbeat (default-enabled), got %v", calls)
	}
	if !completedCancelled {
		t.Fatalf("expected runner to complete cancelled EAS build job, got calls %v", calls)
	}
	if elapsed := time.Since(startedAt); elapsed > 700*time.Millisecond {
		t.Fatalf("expected cancellation to stop EAS build promptly, elapsed %s", elapsed)
	}
}

func TestRunnerOnceReportsEASCredentialSetupAsSetupRequired(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'Failed to set up credentials.\n' >&2
printf 'You'"'"'re in non-interactive mode. EAS CLI couldn'"'"'t find any credentials suitable for internal distribution. Run this command again in interactive mode.\n' >&2
exit 1
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var calls []string
	completedSetupRequired := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["eas"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"running","runnerId":"pfrun_cli","payload":{"platform":"ios","lane":"development","easProfileName":"development-device","targetClass":"device","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"readiness":{"ready":true,"targetClass":"device"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_build"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode EAS build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "setup_required" {
				t.Fatalf("expected setup_required EAS build result, got %#v", result)
			}
			setupRequired := result["setupRequired"].(map[string]any)
			if setupRequired["code"] != "eas_credentials_setup_required" {
				t.Fatalf("expected credentials setup blocker, got %#v", setupRequired)
			}
			commands := setupRequired["commands"].([]any)
			if commands[0] != "eas build --platform ios --profile development-device" {
				t.Fatalf("unexpected setup command %#v", commands)
			}
			completedSetupRequired = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedSetupRequired {
		t.Fatalf("expected runner to complete setup-required EAS build job, got calls %v", calls)
	}
}

func TestEASBuildSetupRequiredClassifiesExpoTokenAuthFailures(t *testing.T) {
	setupRequired := easBuildSetupRequired(
		fmt.Errorf("run EAS development build: eas build failed: Not logged in, set EXPO_TOKEN in the environment"),
		apiRunnerJob{
			WorkspaceID: "ws_cli",
			AppID:       "pfapp_mobile",
			Payload: runnerJobPayload{
				Platform: "ios",
				Lane:     "development",
			},
		},
		"development-device",
	)
	if setupRequired == nil {
		t.Fatal("expected Expo token auth failure to be setup-required")
	}
	if setupRequired["code"] != "expo_token_auth_failed" {
		t.Fatalf("unexpected setup blocker %#v", setupRequired)
	}
	commands := setupRequired["commands"].([]string)
	if len(commands) != 1 || !strings.Contains(commands[0], "preflight credentials create") || !strings.Contains(commands[0], "--key EXPO_TOKEN") {
		t.Fatalf("unexpected setup command %#v", commands)
	}
}

func TestRunnerOnceReportsFailingEASDevelopmentBuildAsFailedJob(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "eas"), []byte(`#!/usr/bin/env sh
printf 'EAS build failed\n' >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake eas: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var calls []string
	completedFailed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["eas"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"running","runnerId":"pfrun_cli","payload":{"easProfileName":"development-device","targetClass":"device","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"readiness":{"ready":true,"targetClass":"device"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_build"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_build/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode EAS build complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "failed" {
				t.Fatalf("expected failed EAS build result, got %#v", result)
			}
			failure := result["failure"].(map[string]any)
			if failure["code"] != "eas_build_failed" {
				t.Fatalf("expected eas_build_failed failure, got %#v", failure)
			}
			easBuild := result["easBuild"].(map[string]any)
			if easBuild["profile"] != "development-device" || easBuild["platform"] != "ios" || easBuild["targetClass"] != "device" {
				t.Fatalf("unexpected EAS build payload %#v", easBuild)
			}
			completedFailed = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_build","kind":"eas.build.dev","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_build"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedFailed {
		t.Fatalf("expected runner to complete failed EAS build job, got calls %v", calls)
	}
}

func TestRunnerOnceCancelsDevSessionStartWhileWaitingForMetro(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
sleep 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")

	metroStartedAt := time.Now()
	var startedAt time.Time
	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		if time.Since(metroStartedAt) < 250*time.Millisecond {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("packager-status:starting"))
			return
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	completedCancelled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["expo"],"runnerJobHeartbeat":false},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			if startedAt.IsZero() {
				startedAt = time.Now()
			}
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","payload":{"lane":"development","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devBuild":{"buildId":"build_ios_dev_1","installUrl":"https://expo.dev/runtime-artifacts/ios-dev.ipa"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for job read: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_job"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "cancelled" {
				t.Fatalf("expected cancelled dev session result, got %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["status"] != "cancelled" {
				t.Fatalf("expected cancelled dev session payload, got %#v", devSession)
			}
			completedCancelled = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	// startedAt is stamped by the claim handler below.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--host-mode",
			"localhost",
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "GET /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession") == 0 {
		t.Fatalf("expected runner to poll dev session job status, got %v", calls)
	}
	if !completedCancelled {
		t.Fatalf("expected runner to complete cancelled dev session job, got calls %v", calls)
	}
	if elapsed := time.Since(startedAt); elapsed > 700*time.Millisecond {
		t.Fatalf("expected cancellation to stop dev session promptly, elapsed %s", elapsed)
	}
}

func TestRunnerOnceStopsPreflightOwnedDevSession(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	preflightDir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(preflightDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)

	command := exec.Command("sh", "-c", "sleep 60")
	if err := command.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	pidPath := filepath.Join(preflightDir, "expo-dev-session.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprint(command.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}

	completedStop := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["expo"],"runnerJobHeartbeat":false},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_stop","kind":"dev_session.stop","status":"running","runnerId":"pfrun_cli","payload":{"platform":"ios","lane":"development","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devSession":{"id":"pfds_cli","status":"running","url":"http://127.0.0.1:19000","advertisedUrl":"http://127.0.0.1:19000","statusUrl":"http://127.0.0.1:19000/status","hostMode":"localhost","port":19000,"pid":%d}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_stop"}}`, workspaceRoot, command.Process.Pid)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_stop/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode stop completion: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("expected ok stop result, got %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["id"] != "pfds_cli" || devSession["status"] != "stopped" {
				t.Fatalf("unexpected stopped dev session payload %#v", devSession)
			}
			shutdown := devSession["shutdown"].(map[string]any)
			if shutdown["outcome"] != "terminated" {
				t.Fatalf("expected terminated shutdown, got %#v", shutdown)
			}
			completedStop = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_stop","kind":"dev_session.stop","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_stop"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedStop {
		t.Fatal("expected runner to complete dev_session.stop")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("expected pid file to be removed, stat err = %v", err)
	}
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- command.Wait()
	}()
	select {
	case <-waitResult:
		waited = true
	case <-time.After(2 * time.Second):
		t.Fatal("expected dev-session stop to terminate child process")
	}
	if !strings.Contains(stdout.String(), "stopped dev session pfjob_stop terminated") {
		t.Fatalf("expected stopped session output, got %q", stdout.String())
	}
}

func TestRunnerOnceReportsDevSessionStartTimeoutAsFailedJob(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
sleep 1
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_EXPO_START_TIMEOUT", "80ms")
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")

	var startedAt time.Time
	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("packager-status:starting"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	completedFailed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["expo"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			if startedAt.IsZero() {
				startedAt = time.Now()
			}
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","payload":{"sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29"}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/heartbeat":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method for job heartbeat: %s", r.Method)
			}
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_devsession_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for job read: %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_job"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "failed" {
				t.Fatalf("expected failed dev session result, got %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["status"] != "failed" {
				t.Fatalf("expected failed dev session payload, got %#v", devSession)
			}
			failure := result["failure"].(map[string]any)
			if failure["code"] != "metro_start_timeout" {
				t.Fatalf("expected metro_start_timeout failure, got %#v", failure)
			}
			completedFailed = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	// startedAt is stamped by the claim handler below.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--xcrun-path",
			writeFakeExecutable(t, "xcrun", `#!/usr/bin/env sh
exit 0
`),
			"--host-mode",
			"localhost",
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedFailed {
		t.Fatalf("expected runner to complete failed dev session job, got calls %v", calls)
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") > 1 {
		t.Fatalf("expected timeout to stop before follow-on claims, got %v", calls)
	}
	// Generous relative to the 20ms dev-session timeout under test: this runs
	// alongside the rest of the suite, and the assertion is "the timeout fired"
	// rather than "the machine was fast". The follow-on-claim check above is
	// what catches a timeout that did not stop the lane.
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("expected timeout to stop dev session promptly, elapsed %s", elapsed)
	}
}

func TestRunnerOnceReportsSimulatorBootFailureAsFailedDevSessionJob(t *testing.T) {
	workspaceRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspaceRoot, "apps", "mobile"), 0o755); err != nil {
		t.Fatal(err)
	}
	xcrunPath := writeFakeExecutable(t, "xcrun", `#!/usr/bin/env sh
if [ "$2" = "bootstatus" ]; then
  printf 'boot failed\n' >&2
  exit 42
fi
exit 0
`)

	var calls []string
	completedFailed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["xcrun"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "failed" {
				t.Fatalf("expected failed dev session result, got %#v", result)
			}
			failure := result["failure"].(map[string]any)
			if failure["code"] != "simulator_boot_failed" {
				t.Fatalf("expected simulator_boot_failed failure, got %#v", failure)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["status"] != "failed" || devSession["providerIdentity"] != "6BA8F38E-BF97-4830-98A6-E459E4312F29" {
				t.Fatalf("unexpected failed dev session payload %#v", devSession)
			}
			completedFailed = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--xcrun-path",
			xcrunPath,
			"--host-mode",
			"localhost",
			"--metro-port",
			"19000",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedFailed {
		t.Fatalf("expected runner to complete failed dev session job, got calls %v", calls)
	}
}

func TestRunnerOnceReportsAndLocksAndroidEmulator(t *testing.T) {
	workspaceRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspaceRoot, "apps", "mobile"), 0o755); err != nil {
		t.Fatal(err)
	}
	adbPath := writeFakeExecutable(t, "adb", `#!/usr/bin/env sh
if [ "$1" = "devices" ] && [ "$2" = "-l" ]; then
  printf 'List of devices attached\n'
  printf 'emulator-5554 device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n'
  exit 0
fi
printf 'unexpected adb args: %s\n' "$*" >&2
exit 42
`)

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios","android"],"localTools":["adb"],"adapters":["android.emulator.discovery"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 1 {
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_discover","kind":"device.discover","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"simulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_discover"}}`, workspaceRoot)
				return
			}
			_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/targets/android-emulators":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode android targets body: %v", err)
			}
			if !strings.Contains(body["adbDevicesOutput"].(string), "emulator-5554 device") {
				t.Fatalf("adb devices output was not forwarded: %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_android","platform":"android","kind":"android_emulator","displayName":"sdk gphone64 arm64","providerIdentity":"emulator-5554","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_targets"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_discover/targets/pftgt_android/lock":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode android lock body: %v", err)
			}
			if body["lockOwner"] != "preflight-cli:macbook.local" {
				t.Fatalf("unexpected lockOwner %v", body["lockOwner"])
			}
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_android","displayName":"sdk gphone64 arm64","availability":"busy","lockedByJobId":"pfjob_discover"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--adb-path",
			adbPath,
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{
		"reported 1 Android emulator target(s)",
		"locked target pftgt_android sdk gphone64 arm64",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected stdout to contain %q, got %q", expected, stdout.String())
		}
	}
}

func TestRunnerOnceRunsAndroidEmulatorDevSessionOpenAndMaestro(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(filepath.Join(appDir, ".preflight"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	gradleLog := filepath.Join(t.TempDir(), "gradle.log")
	if err := os.MkdirAll(filepath.Join(appDir, "android"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "android", "gradlew"), []byte(`#!/usr/bin/env sh
printf '%s :: APP_VARIANT=%s :: %s\n' "$PWD" "$APP_VARIANT" "$*" >> "$GRADLE_LOG"
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake gradle wrapper: %v", err)
	}
	staleAutolinkingFile := filepath.Join(appDir, "android", "build", "generated", "autolinking", "autolinking.json")
	if err := os.MkdirAll(filepath.Dir(staleAutolinkingFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleAutolinkingFile, []byte(`{"project":{"android":{"packageName":"com.gmacko.forgegraph"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRADLE_LOG", gradleLog)
	if err := os.WriteFile(filepath.Join(appDir, ".preflight", "expo-dev-session.pid"), []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}

	adbLog := filepath.Join(t.TempDir(), "adb.log")
	adbPath := writeFakeExecutable(t, "adb", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$ADB_LOG"
if [ "$1" = "devices" ] && [ "$2" = "-l" ]; then
  printf 'List of devices attached\n'
  printf 'emulator-5554 device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n'
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "wait-for-device" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "emu" ] && [ "$4" = "avd" ] && [ "$5" = "name" ]; then
  printf 'Maestro_Pixel_6_API_33_1\nOK\n'
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "emulator-5554" ] && [ "$3" = "shell" ] && [ "$4" = "am" ] && [ "$5" = "start" ]; then
  exit 0
fi
printf 'unexpected adb args: %s\n' "$*" >&2
exit 42
`)
	t.Setenv("ADB_LOG", adbLog)

	xcrunLog := filepath.Join(t.TempDir(), "xcrun.log")
	xcrunPath := writeFakeExecutable(t, "xcrun", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$XCRUN_LOG"
exit 42
`)
	t.Setenv("XCRUN_LOG", xcrunLog)

	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: APP_VARIANT=%s :: %s\n' "$PWD" "$APP_VARIANT" "$*" >> "$NPX_LOG"
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	maestroLog := filepath.Join(t.TempDir(), "maestro.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$MAESTRO_LOG"
debug_dir=""
for arg in "$@"; do
  case "$arg" in
    --debug-output=*) debug_dir="${arg#--debug-output=}" ;;
  esac
done
if [ -n "$debug_dir" ]; then
  mkdir -p "$debug_dir"
  printf 'debug log\n' > "$debug_dir/maestro.log"
  printf '{"commands":[]}\n' > "$debug_dir/commands-1.json"
fi
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("MAESTRO_LOG", maestroLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	var devSessionResult map[string]any
	var simulatorOpenResult map[string]any
	var maestroResult map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios","android"],"localTools":["adb","expo","maestro"],"adapters":["android.emulator.discovery"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			switch countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") {
			case 1:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_discover","kind":"device.discover","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"simulator","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_discover"}}`, workspaceRoot)
			case 2:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_android","payload":{"platform":"android","lane":"simulator","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetDisplayName":"sdk gphone64 arm64","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
			case 3:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_android","payload":{"platform":"android","lane":"simulator","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetDisplayName":"sdk gphone64 arm64","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","androidPackage":"com.gmacko.forgegraph.dev"},"devSession":{"url":"http://127.0.0.1:19000","advertisedUrl":"http://127.0.0.1:19000","deepLinkUrl":"forgegraph://expo-development-client/?url=http%%3A%%2F%%2F127.0.0.1%%3A19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
			case 4:
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_android","payload":{"platform":"android","lane":"simulator","targetId":"pftgt_android","providerIdentity":"emulator-5554","targetDisplayName":"sdk gphone64 arm64","flowPath":"apps/mobile/.maestro/01-app-launches.yaml","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_maestro"}}`, workspaceRoot)
			default:
				_, _ = w.Write([]byte(`{"data":null,"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_none"}}`))
			}
		case "/api/preflight/v1/runners/pfrun_cli/targets/android-emulators":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode android targets body: %v", err)
			}
			if !strings.Contains(body["adbDevicesOutput"].(string), "emulator-5554 device") {
				t.Fatalf("adb devices output was not forwarded: %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_android","platform":"android","kind":"android_emulator","displayName":"sdk gphone64 arm64","providerIdentity":"emulator-5554","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_targets"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_discover/targets/pftgt_android/lock":
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_android","displayName":"sdk gphone64 arm64","availability":"busy","lockedByJobId":"pfjob_discover"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			devSessionResult = body["result"].(map[string]any)
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode simulator open complete body: %v", err)
			}
			simulatorOpenResult = body["result"].(map[string]any)
			if simulatorOpenResult["status"] != "ok" {
				t.Fatalf("expected simulator open completion status ok, got %#v", simulatorOpenResult)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro":
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_maestro"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode maestro complete body: %v", err)
			}
			maestroResult = body["result"].(map[string]any)
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_maestro"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--adb-path",
			adbPath,
			"--xcrun-path",
			xcrunPath,
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") != 4 {
		t.Fatalf("expected four claim calls, got %v", calls)
	}
	if devSessionResult["status"] != "ok" {
		t.Fatalf("expected Android dev session status ok, got %#v", devSessionResult)
	}
	devSession := devSessionResult["devSession"].(map[string]any)
	if devSession["providerIdentity"] != "emulator-5554" {
		t.Fatalf("unexpected Android dev session payload %#v", devSession)
	}
	if simulatorOpenResult["status"] != "ok" {
		t.Fatalf("expected Android simulator open status ok, got %#v", simulatorOpenResult)
	}
	simulatorOpen := simulatorOpenResult["simulatorOpen"].(map[string]any)
	if simulatorOpen["platform"] != "android" || simulatorOpen["providerIdentity"] != "emulator-5554" {
		t.Fatalf("unexpected Android simulator open payload %#v", simulatorOpen)
	}
	if maestroResult["status"] != "ok" {
		t.Fatalf("expected Android Maestro status ok, got %#v", maestroResult)
	}
	maestro := maestroResult["maestro"].(map[string]any)
	if maestro["platform"] != "android" || maestro["providerIdentity"] != "emulator-5554" {
		t.Fatalf("unexpected Android Maestro payload %#v", maestro)
	}
	xcrunOutput, err := os.ReadFile(xcrunLog)
	if err == nil && strings.TrimSpace(string(xcrunOutput)) != "" {
		t.Fatalf("Android emulator path must not call xcrun, got %q", string(xcrunOutput))
	}
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	if !strings.Contains(string(npxOutput), "APP_VARIANT=development :: expo prebuild --platform android") {
		t.Fatalf("expected Android prebuild with development variant, got %q", string(npxOutput))
	}
	if !strings.Contains(string(npxOutput), "APP_VARIANT=development :: expo run:android --device Maestro_Pixel_6_API_33_1 --no-build-cache --no-bundler") {
		t.Fatalf("expected expo run:android command, got %q", string(npxOutput))
	}
	gradleOutput, err := os.ReadFile(gradleLog)
	if err != nil {
		t.Fatalf("read gradle log: %v", err)
	}
	if !strings.Contains(string(gradleOutput), "APP_VARIANT=development :: --stop") ||
		!strings.Contains(string(gradleOutput), "APP_VARIANT=development :: :app:generateReactNativeEntryPoint :app:generateAutolinkingPackageList :app:generateAutolinkingNewArchitectureFiles --rerun-tasks") {
		t.Fatalf("expected Android Gradle daemon stop and autolinking regeneration with development variant, got %q", string(gradleOutput))
	}
	if strings.Contains(string(gradleOutput), " :: clean") {
		t.Fatalf("Android preparation must not run Gradle clean because native CMake clean can fail before codegen exists, got %q", string(gradleOutput))
	}
	if _, err := os.Stat(staleAutolinkingFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale root autolinking cache to be removed, got err %v", err)
	}
	adbOutput, err := os.ReadFile(adbLog)
	if err != nil {
		t.Fatalf("read adb log: %v", err)
	}
	if !strings.Contains(string(adbOutput), "emulator-5554 shell am start -a android.intent.action.VIEW -d forgegraph://expo-development-client/?url=http%3A%2F%2F127.0.0.1%3A19000 -p com.gmacko.forgegraph.dev") {
		t.Fatalf("expected adb deep link open command, got %q", string(adbOutput))
	}
	maestroOutput, err := os.ReadFile(maestroLog)
	if err != nil {
		t.Fatalf("read maestro log: %v", err)
	}
	expectedFlowPath := filepath.Join(workspaceRoot, "apps/mobile/.maestro/01-app-launches.yaml")
	expectedMaestroArgs := "--platform android --device emulator-5554 test --test-output-dir=.preflight/maestro/pfjob_maestro/runtime-artifacts --debug-output=.preflight/maestro/pfjob_maestro/runtime-artifacts --format junit --output .preflight/maestro/pfjob_maestro/junit.xml -e FG_DEV_CLIENT_URL=http://127.0.0.1:19000 " + expectedFlowPath
	if !strings.Contains(string(maestroOutput), expectedMaestroArgs) {
		t.Fatalf("expected Android maestro command, got %q", string(maestroOutput))
	}
}

func TestAllocateBuildMetroPortGivesDistinctPorts(t *testing.T) {
	// Simulate several concurrent builds allocating a Metro port from the same
	// base — each must get a distinct free port (no collision), which is what
	// lets concurrent iOS builds run on one host without per-agent config.
	seen := map[int]bool{}
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for i := 0; i < 6; i++ {
		p := allocateBuildMetroPort(8081)
		if p < 8081 {
			t.Fatalf("allocated port %d below base", p)
		}
		if seen[p] {
			t.Fatalf("port %d allocated twice — concurrent builds would collide", p)
		}
		seen[p] = true
		// Hold the port (as expo would) so the next allocation must pick another.
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Fatalf("allocated port %d was not actually free: %v", p, err)
		}
		listeners = append(listeners, l)
	}
	if len(seen) != 6 {
		t.Fatalf("expected 6 distinct ports, got %d", len(seen))
	}
}

func TestUnityArtifactKindForTargetIncludesLinuxServer(t *testing.T) {
	cases := map[string]string{
		"Android":           "android_apk",
		"iOS":               "ios_xcode_archive",
		"WebGL":             "webgl_bundle",
		"StandaloneLinux64": "linux_server_build",
		"LinuxServer":       "linux_server_build",
		"DedicatedServer":   "linux_server_build",
		"server":            "linux_server_build",
		"somethingElse":     "tool_output",
	}
	for target, want := range cases {
		if got := unityArtifactKindForTarget(target); got != want {
			t.Errorf("unityArtifactKindForTarget(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestValidateUnityBuildCommandPlanDecoupledFromLevelForge(t *testing.T) {
	// A generic (non-LevelForge) Unity plan: no -lf* args, target/output carried
	// in the structured output block, and a custom execute method.
	genericPlan := func(method string) runnerJobCommandPlan {
		return runnerJobCommandPlan{
			Tool:    "unity",
			Command: "batchmode",
			Args: []string{
				"-batchmode", "-nographics", "-quit",
				"-projectPath", "/tmp/game",
				"-executeMethod", method,
				"-logFile", "/tmp/game/build.log",
			},
			Output: runnerJobCommandPlanOutput{
				BuildTarget:  "WebGL",
				OutputPath:   "/tmp/game/Build/webgl",
				LogPath:      "/tmp/game/build.log",
				ArtifactKind: "tool_output",
			},
		}
	}

	// LevelForge's method stays allowlisted by default.
	if err := validateUnityBuildCommandPlan(genericPlan(levelForgeUnityExecuteMethod)); err != nil {
		t.Fatalf("LevelForge method should remain allowlisted: %v", err)
	}

	// A non-allowlisted method is rejected (arbitrary C# guard).
	if err := validateUnityBuildCommandPlan(genericPlan("MyGame.Build.CI")); err == nil {
		t.Fatal("expected non-allowlisted execute method to be rejected")
	}

	// Operator opt-in permits any project's method.
	t.Setenv("PREFLIGHT_UNITY_EXECUTE_METHODS", "MyGame.Build.CI")
	if err := validateUnityBuildCommandPlan(genericPlan("MyGame.Build.CI")); err != nil {
		t.Fatalf("allowlisted custom method should validate: %v", err)
	}

	// A plan with no resolvable build output is rejected.
	noOutput := genericPlan("MyGame.Build.CI")
	noOutput.Output = runnerJobCommandPlanOutput{LogPath: "/tmp/game/build.log"}
	if err := validateUnityBuildCommandPlan(noOutput); err == nil {
		t.Fatal("expected plan with no build output path to be rejected")
	}
}

func TestRunnerOnceRunsUnityAndroidBuildPlayer(t *testing.T) {
	workspaceRoot := t.TempDir()
	if err := os.MkdirAll(workspaceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(workspaceRoot, ".preflight", "unity-builds", "pfjob_unity")
	outputDir := filepath.Join(artifactRoot, "android")
	logPath := filepath.Join(artifactRoot, "unity-build.log")
	unityCommandLog := filepath.Join(t.TempDir(), "unity-command.log")
	unityPath := writeFakeExecutable(t, "Unity", `#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$UNITY_COMMAND_LOG"
output_dir=""
log_path=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -lfBuildOutput)
      output_dir="$2"
      shift 2
      ;;
    -logFile)
      log_path="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$output_dir"
printf 'apk bytes\n' > "$output_dir/Game.apk"
if [ -n "$log_path" ]; then
  mkdir -p "$(dirname "$log_path")"
  printf 'unity build log\n' >> "$log_path"
fi
exit 0
`)
	t.Setenv("PREFLIGHT_UNITY_COMMAND", unityPath)
	t.Setenv("UNITY_COMMAND_LOG", unityCommandLog)

	var calls []string
	var artifactBodies []map[string]any
	var completeResult map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode register body: %v", err)
			}
			capabilities := body["capabilities"].(map[string]any)
			if !containsAny(capabilities["localTools"].([]any), "unity") {
				t.Fatalf("expected Unity local tool capability, got %#v", capabilities)
			}
			if !containsAny(capabilities["adapters"].([]any), "unity.android.build_support") {
				t.Fatalf("expected Unity Android adapter capability, got %#v", capabilities)
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"vanuc","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["android"],"localTools":["unity"],"adapters":["unity.editor","unity.android.build_support"],"runnerArtifactUpload":true,"runnerJobHeartbeat":false},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_unity","workspaceId":"ws_cli","appId":"pfapp_levelforge","workflowId":"pfw_unity","kind":"unity.build.player","status":"running","runnerId":"pfrun_cli","payload":{"platform":"android","lane":"development","buildProvider":"local_runner","sourceBinding":{"workspaceRoot":%q,"packagePath":"."},"unityProject":{"projectPath":%q,"buildTarget":"Android"},"commandPlan":{"tool":"unity","command":"batchmode","workingDirectory":%q,"executable":{"env":"UNITY_EDITOR","candidates":["/opt/unity/Editor/Unity"]},"args":["-batchmode","-nographics","-quit","-projectPath",%q,"-executeMethod","LevelForge.Editor.LevelForgeBuild.RunHeadlessBuild","-lfBuildTarget","Android","-lfBuildOutput",%q,"-logFile",%q,"-lfDevelopmentBuild","-lfUploadOnSuccess","-lfRunnerUrl","http://127.0.0.1:7600"],"output":{"buildTarget":"Android","artifactKind":"android_apk","buildOutputDirectory":%q,"logPath":%q},"levelForge":{"registerArtifactProcedure":"unityPod.registerBuildArtifact","projectId":"lfproject_1","unityProjectId":"lfunity_1","unityPodId":"lfpod_vanuc"}}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_unity"}}`,
				workspaceRoot,
				workspaceRoot,
				workspaceRoot,
				workspaceRoot,
				outputDir,
				logPath,
				outputDir,
				logPath,
			)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_unity/artifacts":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode Unity artifact body: %v", err)
			}
			artifactBodies = append(artifactBodies, body)
			_, _ = fmt.Fprintf(w, `{"data":{"artifact":{"id":"pfartifact_%d","kind":%q,"uri":%q}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_artifact"}}`, len(artifactBodies), body["kind"], body["uri"])
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_unity/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode Unity complete body: %v", err)
			}
			completeResult = body["result"].(map[string]any)
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_unity","kind":"unity.build.player","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_unity"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"vanuc",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "completed Unity build pfjob_unity Android") {
		t.Fatalf("expected Unity completion output, got %q", stdout.String())
	}
	commandOutput, err := os.ReadFile(unityCommandLog)
	if err != nil {
		t.Fatalf("read Unity command log: %v", err)
	}
	if !strings.Contains(string(commandOutput), "-executeMethod LevelForge.Editor.LevelForgeBuild.RunHeadlessBuild") ||
		!strings.Contains(string(commandOutput), "-lfBuildOutput "+outputDir) {
		t.Fatalf("expected Unity batchmode args, got %q", string(commandOutput))
	}
	if len(artifactBodies) != 2 {
		t.Fatalf("expected APK and Unity log artifact uploads, got %#v", artifactBodies)
	}
	if artifactBodies[0]["kind"] != "android_apk" ||
		artifactBodies[0]["uri"] != filepath.Join(outputDir, "Game.apk") ||
		artifactBodies[0]["retentionClass"] != "release" {
		t.Fatalf("unexpected Unity APK artifact upload %#v", artifactBodies[0])
	}
	if artifactBodies[1]["kind"] != "unity_build_log" ||
		artifactBodies[1]["uri"] != logPath ||
		artifactBodies[1]["retentionClass"] != "debug" {
		t.Fatalf("unexpected Unity log artifact upload %#v", artifactBodies[1])
	}
	if completeResult["status"] != "ok" {
		t.Fatalf("expected Unity completion status ok, got %#v", completeResult)
	}
	unityBuild := completeResult["unityBuild"].(map[string]any)
	if unityBuild["target"] != "Android" ||
		unityBuild["artifactKind"] != "android_apk" ||
		unityBuild["outputPath"] != outputDir ||
		unityBuild["logPath"] != logPath ||
		unityBuild["primaryArtifactPath"] != filepath.Join(outputDir, "Game.apk") {
		t.Fatalf("unexpected Unity build result %#v", unityBuild)
	}
	resultArtifacts := completeResult["artifacts"].([]any)
	if len(resultArtifacts) != 1 || resultArtifacts[0].(map[string]any)["kind"] != "android_apk" {
		t.Fatalf("unexpected Unity result artifacts %#v", resultArtifacts)
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") != 1 {
		t.Fatalf("expected one Unity claim, got %v", calls)
	}
}

func TestResetAndroidAutolinkingOutputsRemovesOnlyGeneratedAutolinkingCaches(t *testing.T) {
	appDir := t.TempDir()
	androidDir := filepath.Join(appDir, "android")
	for _, path := range []string{
		filepath.Join(androidDir, "build", "generated", "autolinking", "autolinking.json"),
		filepath.Join(androidDir, "app", "build", "generated", "autolinking", "src", "main", "java", "com", "facebook", "react", "ReactNativeApplicationEntryPoint.java"),
		filepath.Join(androidDir, "build", "generated", "res", "keep.txt"),
		filepath.Join(androidDir, "app", "build", "generated", "res", "keep.txt"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("generated\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := resetAndroidAutolinkingOutputs(appDir); err != nil {
		t.Fatalf("reset Android autolinking outputs: %v", err)
	}

	for _, path := range []string{
		filepath.Join(androidDir, "build", "generated", "autolinking"),
		filepath.Join(androidDir, "app", "build", "generated", "autolinking"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be removed, got err %v", path, err)
		}
	}
	for _, path := range []string{
		filepath.Join(androidDir, "build", "generated", "res", "keep.txt"),
		filepath.Join(androidDir, "app", "build", "generated", "res", "keep.txt"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected sibling generated file %s to remain: %v", path, err)
		}
	}
}

func TestAdvertisedDevServerURLUsesLocalhostForLocalhostHostMode(t *testing.T) {
	url, err := advertisedDevServerURL(
		runnerOnceOptions{
			hostMode:  "localhost",
			metroPort: 19000,
		},
		apiRunnerJob{},
	)
	if err != nil {
		t.Fatalf("advertised dev server URL failed: %v", err)
	}
	if url != "http://localhost:19000" {
		t.Fatalf("expected localhost dev server URL, got %q", url)
	}
}

func TestAdvertisedDevServerURLUsesAndroidEmulatorHostForAndroidSimulator(t *testing.T) {
	url, err := advertisedDevServerURL(
		runnerOnceOptions{
			hostMode:  "lan",
			metroPort: 19000,
		},
		apiRunnerJob{
			Payload: runnerJobPayload{
				Platform: "android",
				Lane:     "simulator",
			},
		},
	)
	if err != nil {
		t.Fatalf("advertised dev server URL failed: %v", err)
	}
	if url != "http://10.0.2.2:19000" {
		t.Fatalf("expected Android emulator dev server URL, got %q", url)
	}
}

func TestSimulatorDeepLinkURLUsesAndroidEmulatorHostFallback(t *testing.T) {
	deepLinkURL := simulatorDeepLinkURL(
		apiRunnerJob{
			Payload: runnerJobPayload{
				Platform: "android",
				Lane:     "simulator",
				SourceBinding: runnerJobSourceBinding{
					AppScheme: "forgegraph",
				},
			},
		},
		19000,
	)
	expected := "forgegraph://expo-development-client/?url=http%3A%2F%2F10.0.2.2%3A19000"
	if deepLinkURL != expected {
		t.Fatalf("expected Android emulator deep link %q, got %q", expected, deepLinkURL)
	}
}

func TestRunnerOnceRegistersClaimsDiscoversAndLocksIOSSimulator(t *testing.T) {
	workspaceRoot := t.TempDir()
	// macOS puts TempDir under /var, a symlink to /private/var. The runner
	// reports the resolved path, so the fixture has to hold the same one or
	// every workspace-root comparison below fails on a Mac and passes on CI.
	if resolved, err := filepath.EvalSymlinks(workspaceRoot); err == nil {
		workspaceRoot = resolved
	}
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	preflightDir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(preflightDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(preflightDir, "expo-dev-session.pid"), []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	simctlJSON := filepath.Join(t.TempDir(), "simctl.json")
	if err := os.WriteFile(simctlJSON, []byte(`{
		"devices": {
			"com.apple.CoreSimulator.SimRuntime.iOS-26-4": [
				{
					"udid": "6BA8F38E-BF97-4830-98A6-E459E4312F29",
					"isAvailable": true,
					"deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17",
					"state": "Shutdown",
					"name": "iPhone 17"
				}
			]
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// installedAppDevClientScheme reads the installed dev build's real URL
	// scheme from its Info.plist (see 69c3d577) via
	// `simctl get_app_container <udid> <bundleId> app` (ground truth app
	// bundle path) followed by `plutil -convert json -o - <app>/Info.plist`.
	// To exercise the actual scheme-rewrite (not just fall back to the
	// source-binding scheme), the fake xcrun below serves a real app bundle
	// directory containing an Info.plist that (fake) plutil can convert to
	// JSON, with CFBundleURLSchemes advertising the canonical exp+ scheme —
	// which chooseDevClientScheme prefers over the source binding's
	// "forgegraph" scheme.
	appContainerDir := filepath.Join(t.TempDir(), "Bundle", "Application", "com.gmacko.forgegraph.dev.app")
	if err := os.MkdirAll(appContainerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	infoPlistPath := filepath.Join(appContainerDir, "Info.plist")
	infoPlistJSON := `{"CFBundleURLTypes":[{"CFBundleURLSchemes":["exp+forgegraf"]}]}`
	if err := os.WriteFile(infoPlistPath, []byte(infoPlistJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	xcrunPath := writeFakeExecutable(t, "xcrun", fmt.Sprintf(`#!/usr/bin/env sh
printf '%%s\n' "$*" >> "$XCRUN_LOG"
if [ "$1" = "simctl" ] && [ "$2" = "get_app_container" ]; then
  printf '%%s\n' %q
  exit 0
fi
exit 0
`, appContainerDir))
	xcrunLog := filepath.Join(t.TempDir(), "xcrun.log")
	t.Setenv("XCRUN_LOG", xcrunLog)
	fakeBin := t.TempDir()
	npxLog := filepath.Join(t.TempDir(), "npx.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$NPX_LOG"
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	// installedAppDevClientScheme shells out to "plutil" directly (not via
	// options.xcrunPath), so the fake must be resolvable on PATH like npx and
	// maestro below. It only ever needs to convert an Info.plist that is
	// already valid JSON (the fixture above), so a passthrough cat suffices.
	if err := os.WriteFile(filepath.Join(fakeBin, "plutil"), []byte(`#!/usr/bin/env sh
# Usage in this codebase: plutil -convert json -o - <path>
path="$5"
cat "$path"
`), 0o755); err != nil {
		t.Fatalf("write fake plutil: %v", err)
	}
	maestroLog := filepath.Join(t.TempDir(), "maestro.log")
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf '%s :: %s\n' "$PWD" "$*" >> "$MAESTRO_LOG"
debug_dir=""
for arg in "$@"; do
  case "$arg" in
    --debug-output=*) debug_dir="${arg#--debug-output=}" ;;
  esac
done
if [ -n "$debug_dir" ]; then
  mkdir -p "$debug_dir"
  printf 'debug log\n' > "$debug_dir/maestro.log"
  printf '{"commands":[]}\n' > "$debug_dir/commands-1.json"
fi
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("NPX_LOG", npxLog)
	t.Setenv("MAESTRO_LOG", maestroLog)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	metroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("unexpected Metro status path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(metroServer.Close)

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode register body: %v", err)
			}
			if body["workspaceId"] != "ws_cli" {
				t.Fatalf("unexpected workspaceId %v", body["workspaceId"])
			}
			if body["hostIdentity"] != "macbook.local" {
				t.Fatalf("unexpected hostIdentity %v", body["hostIdentity"])
			}
			roots := body["allowedWorkspaceRoots"].([]any)
			if len(roots) != 1 || roots[0] != workspaceRoot {
				t.Fatalf("unexpected allowedWorkspaceRoots %#v", roots)
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["xcrun","simctl"],"adapters":["ios.simulator.discovery"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on heartbeat: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on reconcile: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode reconcile body: %v", err)
			}
			if body["reason"] != "runner_startup" {
				t.Fatalf("unexpected reconcile body %#v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on claim: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode claim body: %v", err)
			}
			if body["workspaceRoot"] != workspaceRoot {
				t.Fatalf("unexpected claim workspaceRoot %v", body["workspaceRoot"])
			}
			if strings.HasPrefix(body["leaseOwner"].(string), "preflight-cli:") == false {
				t.Fatalf("unexpected leaseOwner %v", body["leaseOwner"])
			}
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 1 {
				_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_probe"}}`))
				return
			}
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 2 {
				_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_discover","kind":"device.discover","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_discover"}}`))
				return
			}
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 3 {
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_devsession"}}`, workspaceRoot)
				return
			}
			if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") == 4 {
				_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf","iosBundleId":"com.gmacko.forgegraph.dev"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","flowPath":"apps/mobile/.maestro/01-app-launches.yaml","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_maestro"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_probe/complete":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on complete: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected capability result %#v", result)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_probe","kind":"runner.capabilities.probe","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_probe"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/targets/ios-simulators":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on target report: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode targets body: %v", err)
			}
			inventory := body["simctlInventory"].(map[string]any)
			devices := inventory["devices"].(map[string]any)
			if _, ok := devices["com.apple.CoreSimulator.SimRuntime.iOS-26-4"]; !ok {
				t.Fatalf("simctl inventory was not forwarded: %#v", inventory)
			}
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_cli","platform":"ios","kind":"ios_simulator","displayName":"iPhone 17","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","availability":"available"}]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_targets"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_discover/targets/pftgt_cli/lock":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on target lock: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode lock body: %v", err)
			}
			if body["lockOwner"] != "preflight-cli:macbook.local" {
				t.Fatalf("unexpected lockOwner %v", body["lockOwner"])
			}
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"pftgt_cli","displayName":"iPhone 17","availability":"busy","lockedByJobId":"pfjob_discover"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_lock"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_devsession/complete":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on dev session complete: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dev session complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected dev session result %#v", result)
			}
			devSession := result["devSession"].(map[string]any)
			if devSession["status"] != "reused" || devSession["url"] != "http://127.0.0.1:19000" {
				t.Fatalf("unexpected dev session payload %#v", devSession)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_devsession","kind":"dev_session.start","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_devsession"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on simulator open complete: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode simulator open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected simulator open result %#v", result)
			}
			simulatorOpen := result["simulatorOpen"].(map[string]any)
			if simulatorOpen["providerIdentity"] != "6BA8F38E-BF97-4830-98A6-E459E4312F29" {
				t.Fatalf("unexpected simulator open payload %#v", simulatorOpen)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/complete":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on maestro complete: %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode maestro complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "ok" {
				t.Fatalf("unexpected maestro result %#v", result)
			}
			maestro := result["maestro"].(map[string]any)
			if maestro["flowPath"] != "apps/mobile/.maestro/01-app-launches.yaml" {
				t.Fatalf("unexpected maestro payload %#v", maestro)
			}
			if maestro["outputDir"] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "runtime-artifacts") {
				t.Fatalf("unexpected maestro output dir %#v", maestro)
			}
			if maestro["debugOutputDir"] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "runtime-artifacts") {
				t.Fatalf("unexpected maestro debug output dir %#v", maestro)
			}
			if maestro["reportPath"] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "junit.xml") {
				t.Fatalf("unexpected maestro report path %#v", maestro)
			}
			if maestro["logPath"] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "maestro-run.log") {
				t.Fatalf("unexpected maestro log path %#v", maestro)
			}
			if maestro["debugLogPath"] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "runtime-artifacts", "maestro.log") {
				t.Fatalf("unexpected maestro debug log path %#v", maestro)
			}
			commandPaths := maestro["commandPaths"].([]any)
			if len(commandPaths) != 1 || commandPaths[0] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "runtime-artifacts", "commands-1.json") {
				t.Fatalf("unexpected maestro command paths %#v", maestro)
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"succeeded","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_maestro"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--simctl-json",
			simctlJSON,
			"--xcrun-path",
			xcrunPath,
			"--metro-port",
			"19000",
			"--metro-status-url",
			metroServer.URL + "/status",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/claim") != 5 {
		t.Fatalf("expected five claim calls, got %v", calls)
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/reconcile") != 1 {
		t.Fatalf("expected one startup reconcile call, got %v", calls)
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/heartbeat") < 2 {
		t.Fatalf("expected runner to heartbeat before claiming Maestro after local build, got %v", calls)
	}
	for _, expected := range []string{
		"registered runner pfrun_cli",
		"completed capability probe pfjob_probe",
		"reported 1 iOS simulator target(s)",
		"locked target pftgt_cli iPhone 17",
		"started dev session pfjob_devsession http://127.0.0.1:19000",
		"opened simulator app pfjob_open",
		"completed Maestro smoke pfjob_maestro",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("expected stdout to contain %q, got %q", expected, stdout.String())
		}
	}
	xcrunOutput, err := os.ReadFile(xcrunLog)
	if err != nil {
		t.Fatalf("read xcrun log: %v", err)
	}
	if !strings.Contains(string(xcrunOutput), "simctl boot 6BA8F38E-BF97-4830-98A6-E459E4312F29") {
		t.Fatalf("expected simulator boot command, got %q", string(xcrunOutput))
	}
	npxOutput, err := os.ReadFile(npxLog)
	if err != nil {
		t.Fatalf("read npx log: %v", err)
	}
	if !strings.Contains(string(npxOutput), "expo run:ios --device 6BA8F38E-BF97-4830-98A6-E459E4312F29 --no-bundler") {
		t.Fatalf("expected expo run:ios command, got %q", string(npxOutput))
	}
	if !strings.Contains(string(xcrunOutput), "simctl openurl 6BA8F38E-BF97-4830-98A6-E459E4312F29") {
		t.Fatalf("expected simulator openurl command, got %q", string(xcrunOutput))
	}
	if !strings.Contains(string(xcrunOutput), "simctl terminate 6BA8F38E-BF97-4830-98A6-E459E4312F29 com.gmacko.forgegraph.dev") {
		t.Fatalf("expected simulator app termination before Preflight URL open, got %q", string(xcrunOutput))
	}
	if !strings.Contains(string(xcrunOutput), "exp+forgegraf://expo-development-client/?url=http%3A%2F%2F127.0.0.1%3A19000") {
		t.Fatalf("expected simulator openurl to target Preflight dev client URL, got %q", string(xcrunOutput))
	}
	maestroOutput, err := os.ReadFile(maestroLog)
	if err != nil {
		t.Fatalf("read maestro log: %v", err)
	}
	expectedFlowPath := filepath.Join(workspaceRoot, "apps/mobile/.maestro/01-app-launches.yaml")
	expectedMaestroArgs := "--platform ios --device 6BA8F38E-BF97-4830-98A6-E459E4312F29 test --test-output-dir=.preflight/maestro/pfjob_maestro/runtime-artifacts --debug-output=.preflight/maestro/pfjob_maestro/runtime-artifacts --format junit --output .preflight/maestro/pfjob_maestro/junit.xml -e FG_DEV_CLIENT_URL=http://127.0.0.1:19000 " + expectedFlowPath
	if !strings.Contains(string(maestroOutput), expectedMaestroArgs) {
		t.Fatalf("expected maestro command, got %q", string(maestroOutput))
	}
}

func TestRunnerOnceReportsFailingSimulatorOpenAsFailedJob(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
printf 'expo run ios failed\n' >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var calls []string
	completedFailed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["expo"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode simulator open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "failed" {
				t.Fatalf("expected failed simulator open result, got %#v", result)
			}
			failure := result["failure"].(map[string]any)
			if failure["code"] != "simulator_open_failed" {
				t.Fatalf("expected simulator_open_failed failure, got %#v", failure)
			}
			simulatorOpen := result["simulatorOpen"].(map[string]any)
			if simulatorOpen["logPath"] != filepath.Join(appDir, ".preflight", "expo-run-ios.log") {
				t.Fatalf("unexpected simulator open payload %#v", simulatorOpen)
			}
			completedFailed = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedFailed {
		t.Fatalf("expected runner to complete failed simulator open job, got calls %v", calls)
	}
}

func TestOpenExpoDevelopmentClientRebootsIOSSimulatorBeforeOpenURL(t *testing.T) {
	xcrunPath := writeFakeExecutable(t, "xcrun", `#!/usr/bin/env sh
printf '%s\n' "$*" >> "$XCRUN_LOG"
exit 0
`)
	xcrunLog := filepath.Join(t.TempDir(), "xcrun.log")
	t.Setenv("XCRUN_LOG", xcrunLog)

	logPath := filepath.Join(t.TempDir(), "expo-run-ios.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	job := apiRunnerJob{
		TargetID: "pftgt_cli",
		Payload: runnerJobPayload{
			ProviderIdentity: "6BA8F38E-BF97-4830-98A6-E459E4312F29",
			SourceBinding: runnerJobSourceBinding{
				AppScheme:   "forgegraph",
				ExpoSlug:    "forgegraf",
				IOSBundleID: "com.gmacko.forgegraph.dev",
			},
			DevSession: runnerJobDevSession{
				URL:  "http://127.0.0.1:19000",
				Port: 19000,
			},
		},
	}

	err = openExpoDevelopmentClient(
		logFile,
		runnerOnceOptions{xcrunPath: xcrunPath},
		"ios",
		"6BA8F38E-BF97-4830-98A6-E459E4312F29",
		19000,
		job,
		nil,
	)
	if err != nil {
		t.Fatalf("open development client: %v", err)
	}

	xcrunOutput, err := os.ReadFile(xcrunLog)
	if err != nil {
		t.Fatalf("read xcrun log: %v", err)
	}
	expected := strings.Join([]string{
		"simctl boot 6BA8F38E-BF97-4830-98A6-E459E4312F29",
		"simctl bootstatus 6BA8F38E-BF97-4830-98A6-E459E4312F29 -b",
		"simctl get_app_container 6BA8F38E-BF97-4830-98A6-E459E4312F29 com.gmacko.forgegraph.dev app",
		"simctl terminate 6BA8F38E-BF97-4830-98A6-E459E4312F29 com.gmacko.forgegraph.dev",
		"simctl openurl 6BA8F38E-BF97-4830-98A6-E459E4312F29 forgegraph://expo-development-client/?url=http%3A%2F%2F127.0.0.1%3A19000",
	}, "\n") + "\n"
	if string(xcrunOutput) != expected {
		t.Fatalf("expected simulator to be booted immediately before openurl\nwant:\n%s\ngot:\n%s", expected, string(xcrunOutput))
	}
}

func TestRunnerJobHeartbeatDefaultsToEnabledForPersistedRunnerCapabilities(t *testing.T) {
	registration := runnerRegistrationData{
		Runner: apiRunner{
			ID: "pfrun_persisted",
			Capabilities: map[string]any{
				"runnerJobStream": true,
			},
		},
		Token: "runner_token",
	}

	if !runnerJobHeartbeatEnabled(registration) {
		t.Fatal("expected job heartbeat to default on when persisted runner capabilities omit the feature flag")
	}
}

func TestRunnerOnceCancelsInFlightSimulatorOpenWhenJobStatusTurnsCancelled(t *testing.T) {
	workspaceRoot := t.TempDir()
	appDir := filepath.Join(workspaceRoot, "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExpoConfigIdentity(t, appDir)
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
case "$*" in
	"expo prebuild --platform ios") mkdir -p ios/ForgeGraph.xcworkspace; exit 0 ;;
	"expo run:ios"*) sleep 1; exit 0 ;;
	*) printf 'unexpected npx args: %s\n' "$*" >&2; exit 44 ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "xcodebuild"), []byte("#!/usr/bin/env sh\nsleep 1\n"), 0o755); err != nil {
		t.Fatalf("write fake xcodebuild: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")
	t.Setenv("PREFLIGHT_SIMULATOR_OPEN_TIMEOUT", "2s")

	// A fake xcrun: without it the lane shells out to the real simulator
	// subsystem to shut down, boot and query a UDID that does not exist on this
	// machine, which costs seconds and makes the promptness assertion below
	// measure the host rather than the runner.
	xcrunPath := filepath.Join(fakeBin, "xcrun")
	if err := os.WriteFile(xcrunPath, []byte(`#!/usr/bin/env sh
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake xcrun: %v", err)
	}

	var calls []string
	completedCancelled := false
	var startedAt time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["expo"],"runnerJobHeartbeat":false},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile","appScheme":"forgegraph","expoSlug":"forgegraf"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_open"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open":
			// The runner learns the job is cancelled here; promptness is measured
			// from this point, not from process start (registration probes the
			// host for installed tooling, which is not what this asserts).
			if startedAt.IsZero() {
				startedAt = time.Now()
			}
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for job read: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_job"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/heartbeat":
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"running","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_job_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode simulator open complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "cancelled" {
				t.Fatalf("expected cancelled simulator open result, got %#v", result)
			}
			simulatorOpen := result["simulatorOpen"].(map[string]any)
			if simulatorOpen["logPath"] != filepath.Join(appDir, ".preflight", "expo-run-ios.log") {
				t.Fatalf("unexpected simulator open payload %#v", simulatorOpen)
			}
			completedCancelled = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_open","kind":"simulator.open","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_open"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/signing-cert":
			// No fleet signing identity configured for this runner. The runner
			// treats 404 as the normal "nothing to install" case; the lane under
			// test never signs anything.
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	// startedAt is stamped by the claim handler below.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
			"--xcrun-path",
			xcrunPath,
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "GET /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_open") == 0 {
		t.Fatalf("expected runner to poll simulator open job status, got %v", calls)
	}
	if !completedCancelled {
		t.Fatalf("expected runner to complete cancelled simulator open job, got calls %v", calls)
	}
	if elapsed := time.Since(startedAt); elapsed > 700*time.Millisecond {
		t.Fatalf("expected cancellation to stop simulator open promptly, elapsed %s", elapsed)
	}
}

func TestRunnerOnceCancelsInFlightMaestroWhenJobStatusTurnsCancelled(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf 'maestro started\n'
sleep 1
printf 'maestro finished\n'
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")

	var calls []string
	completedCancelled := false
	var startedAt time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["maestro"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","flowPath":"apps/mobile/.maestro/01-app-launches.yaml","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_maestro"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/heartbeat":
			// This fake reports the cancellation on the job heartbeat, which is
			// where the runner learns of it — promptness is measured from here,
			// not from process start (registration probes the host for tooling).
			if startedAt.IsZero() {
				startedAt = time.Now()
			}
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method for job heartbeat: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job heartbeat: %q", r.Header.Get("Authorization"))
			}
			// The runner defaults to heartbeat-based cancellation polling (job
			// heartbeat capability defaults on unless explicitly disabled, see
			// runnerJobHeartbeatEnabled), so the fake control plane must answer
			// this route the same way a live server would: with the job's
			// current (cancelled) status, not just the plain job-read route.
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_job_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method for job read: %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer runner_token" {
				t.Fatalf("missing runner token on job read: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_read_job"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode maestro complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "cancelled" {
				t.Fatalf("expected cancelled Maestro result, got %#v", result)
			}
			completedCancelled = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"cancelled","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_maestro"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/signing-cert":
			// No fleet signing identity configured for this runner. The runner
			// treats 404 as the normal "nothing to install" case; the lane under
			// test never signs anything.
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	// startedAt is stamped by the claim handler below.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if countCalls(calls, "POST /api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/heartbeat") == 0 {
		t.Fatalf("expected runner to poll job status via heartbeat (default-enabled), got %v", calls)
	}
	if !completedCancelled {
		t.Fatalf("expected runner to complete cancelled Maestro job, got calls %v", calls)
	}
	if elapsed := time.Since(startedAt); elapsed > 700*time.Millisecond {
		t.Fatalf("expected cancellation to stop Maestro promptly, elapsed %s", elapsed)
	}
}

func TestRunnerOnceReportsFailingMaestroAsFailedJob(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf 'maestro failed\n' >&2
exit 42
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	var calls []string
	completedFailed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		// `runner once` probes for a fleet signing identity on darwin. No cert is
		// configured for these fakes, which is the 404 the runner treats as the
		// normal "nothing to install" case.
		if strings.HasSuffix(r.URL.Path, "/signing-cert") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/api/preflight/v1/runners/register":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","workspaceId":"ws_cli","name":"CLI Runner","hostIdentity":"macbook.local","allowedWorkspaceRoots":["/repo"],"capabilities":{"platforms":["ios"],"localTools":["maestro"]},"status":"online"},"token":"runner_token"},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_register"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/heartbeat":
			_, _ = w.Write([]byte(`{"data":{"runner":{"id":"pfrun_cli","status":"online"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_heartbeat"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/reconcile":
			_, _ = w.Write([]byte(`{"data":{"reason":"runner_startup","expiredJobs":[],"releasedTargets":[]},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_reconcile"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/jobs/claim":
			_, _ = fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"running","runnerId":"pfrun_cli","targetId":"pftgt_cli","payload":{"targetId":"pftgt_cli","providerIdentity":"6BA8F38E-BF97-4830-98A6-E459E4312F29","flowPath":"apps/mobile/.maestro/01-app-launches.yaml","sourceBinding":{"workspaceRoot":%q,"packagePath":"apps/mobile"},"devSession":{"url":"http://127.0.0.1:19000","port":19000}}}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_claim_maestro"}}`, workspaceRoot)
		case "/api/preflight/v1/runners/pfrun_cli/jobs/pfjob_maestro/complete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode maestro complete body: %v", err)
			}
			result := body["result"].(map[string]any)
			if result["status"] != "failed" {
				t.Fatalf("expected failed Maestro result, got %#v", result)
			}
			failure := result["failure"].(map[string]any)
			if failure["code"] != "maestro_run_failed" {
				t.Fatalf("expected maestro_run_failed failure, got %#v", failure)
			}
			maestro := result["maestro"].(map[string]any)
			if maestro["logPath"] != filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_maestro", "maestro-run.log") {
				t.Fatalf("unexpected maestro payload %#v", maestro)
			}
			completedFailed = true
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_maestro","kind":"maestro.run","status":"failed","runnerId":"pfrun_cli"}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_complete_maestro"}}`))
		case "/api/preflight/v1/runners/pfrun_cli/signing-cert":
			// No fleet signing identity configured for this runner. The runner
			// treats 404 as the normal "nothing to install" case; the lane under
			// test never signs anything.
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"runner",
			"once",
			"--api-url",
			server.URL,
			"--workspace-id",
			"ws_cli",
			"--workspace-root",
			workspaceRoot,
			"--host-identity",
			"macbook.local",
			"--name",
			"CLI Runner",
		},
		&stdout,
		&stderr,
		server.Client(),
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !completedFailed {
		t.Fatalf("expected runner to complete failed Maestro job, got calls %v", calls)
	}
}

func TestFirstAvailableTargetPrefersIPhoneSimulator(t *testing.T) {
	target := firstAvailableTarget([]apiTarget{
		{ID: "pftgt_ipad", DisplayName: "iPad mini (A17 Pro)", Availability: "available"},
		{ID: "pftgt_iphone", DisplayName: "iPhone 17", Availability: "available"},
	})

	if target == nil || target.ID != "pftgt_iphone" {
		t.Fatalf("expected iPhone target, got %#v", target)
	}
}

func TestExpoRunArgsReusePreflightOwnedBundler(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "ios default port", args: expoRunIOSArgs("SIM-UDID", 8081)},
		{name: "ios custom port", args: expoRunIOSArgs("SIM-UDID", 19000)},
		{name: "android default port", args: expoRunAndroidArgs("Maestro_Pixel_6_API_33_1", 8081)},
		{name: "android custom port", args: expoRunAndroidArgs("Maestro_Pixel_6_API_33_1", 19000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !containsArg(tc.args, "--no-bundler") {
				t.Fatalf("expo run args should reuse Preflight-owned Metro: %v", tc.args)
			}
		})
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "ios custom port", args: expoRunIOSArgs("SIM-UDID", 19000)},
		{name: "android custom port", args: expoRunAndroidArgs("Maestro_Pixel_6_API_33_1", 19000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if containsArg(tc.args, "--port") {
				t.Fatalf("expo run --no-bundler rejects --port; Preflight must open the dev client separately: %v", tc.args)
			}
		})
	}
}

func TestDevelopmentClientURLsUseExplicitAppScheme(t *testing.T) {
	sourceBinding := runnerJobSourceBinding{
		AppScheme: "forgegraph",
		ExpoSlug:  "forgegraf",
	}

	deepLinkURL := developmentDeepLinkURL(sourceBinding, "http://localhost:19000")
	if deepLinkURL != "forgegraph://expo-development-client/?url=http%3A%2F%2Flocalhost%3A19000" {
		t.Fatalf("expected explicit app dev-client scheme, got %q", deepLinkURL)
	}

	qrURL := developmentQRURL(sourceBinding, "http://localhost:19000")
	if qrURL != "https://qr.expo.dev/development-client?appScheme=forgegraph&url=http%3A%2F%2Flocalhost%3A19000" {
		t.Fatalf("expected QR URL to target explicit app dev-client scheme, got %q", qrURL)
	}
}

func TestDevSessionResultPayloadIncludesSimulatorNetworkingEvidence(t *testing.T) {
	sourceBinding := runnerJobSourceBinding{
		AppScheme: "forgegraph",
		ExpoSlug:  "forgegraf",
	}

	payload := devSessionResultPayload(devSessionResultInput{
		status:        "started",
		localURL:      "http://127.0.0.1:19000",
		advertisedURL: "http://127.0.0.1:19000",
		statusURL:     "http://127.0.0.1:19000/status",
		hostMode:      "localhost",
		port:          19000,
		sourceBinding: sourceBinding,
		development:   false,
	})

	if payload["deepLinkUrl"] != "forgegraph://expo-development-client/?url=http%3A%2F%2F127.0.0.1%3A19000" {
		t.Fatalf("expected simulator dev-session deep link, got %#v", payload)
	}
	if payload["qrUrl"] != "https://qr.expo.dev/development-client?appScheme=forgegraph&url=http%3A%2F%2F127.0.0.1%3A19000" {
		t.Fatalf("expected simulator dev-session QR URL, got %#v", payload)
	}
	if payload["hostIp"] != "127.0.0.1" {
		t.Fatalf("expected simulator dev-session host IP, got %#v", payload)
	}
	if warnings, ok := payload["warnings"].([]string); !ok || len(warnings) != 0 {
		t.Fatalf("expected no localhost dev-session warnings, got %#v", payload)
	}
	health, ok := payload["health"].(map[string]any)
	if !ok {
		t.Fatalf("expected dev-session health metadata, got %#v", payload)
	}
	if health["metroStatus"] != "running" || health["localStatusUrl"] != "http://127.0.0.1:19000/status" {
		t.Fatalf("unexpected dev-session health metadata %#v", health)
	}
}

func TestDevSessionResultPayloadDoesNotEmitLaunchArtifactsBeforeReadiness(t *testing.T) {
	payload := devSessionResultPayload(devSessionResultInput{
		status:        "failed",
		localURL:      "http://127.0.0.1:19000",
		advertisedURL: "http://127.0.0.1:19000",
		statusURL:     "http://127.0.0.1:19000/status",
		hostMode:      "localhost",
		port:          19000,
		sourceBinding: runnerJobSourceBinding{
			AppScheme: "forgegraph",
			ExpoSlug:  "forgegraf",
		},
		development: true,
	})

	if _, ok := payload["deepLinkUrl"]; ok {
		t.Fatalf("failed dev-session start must not emit a deep link before readiness: %#v", payload)
	}
	if _, ok := payload["qrUrl"]; ok {
		t.Fatalf("failed dev-session start must not emit a QR URL before readiness: %#v", payload)
	}
	health, ok := payload["health"].(map[string]any)
	if !ok || health["metroStatus"] != "unknown" {
		t.Fatalf("expected unknown health before readiness, got %#v", payload)
	}
}

func TestRunMaestroSmokeInjectsDevSessionParametersAndDeterministicEnv(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "maestro.args")
	envPath := filepath.Join(t.TempDir(), "maestro.env")
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf '%s\n' "$*" > "$MAESTRO_ARGS_PATH"
env | sort > "$MAESTRO_ENV_PATH"
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MAESTRO_ARGS_PATH", argsPath)
	t.Setenv("MAESTRO_ENV_PATH", envPath)

	_, err := runMaestroSmoke(
		runnerOnceOptions{workspaceRoot: workspaceRoot},
		apiRunnerJob{
			ID: "pfjob_maestro_env",
			Payload: runnerJobPayload{
				Platform: "ios",
				FlowPath: "apps/mobile/.maestro/01-app-launches.yaml",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: workspaceRoot,
					PackagePath:   "apps/mobile",
				},
				DevSession: runnerJobDevSession{
					URL:           "http://127.0.0.1:19000",
					AdvertisedURL: "http://192.168.4.10:19000",
					DeepLinkURL:   "exp+forgegraf://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000",
					QRURL:         "https://qr.expo.dev/development-client?appScheme=exp%2Bforgegraf&url=http%3A%2F%2F192.168.4.10%3A19000",
				},
			},
		},
		"SIM-UDID",
		flowPath,
	)
	if err != nil {
		t.Fatalf("expected Maestro smoke to pass: %v", err)
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read Maestro args: %v", err)
	}
	argsString := string(args)
	for _, expected := range []string{
		"-e FG_DEV_CLIENT_URL=http://192.168.4.10:19000",
		"-e FG_DEV_CLIENT_DEEP_LINK=exp+forgegraf://expo-development-client/?url=http%3A%2F%2F192.168.4.10%3A19000",
		"-e FG_DEV_CLIENT_QR_URL=https://qr.expo.dev/development-client?appScheme=exp%2Bforgegraf&url=http%3A%2F%2F192.168.4.10%3A19000",
	} {
		if !strings.Contains(argsString, expected) {
			t.Fatalf("expected Maestro args to contain %q, got %q", expected, argsString)
		}
	}

	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read Maestro env: %v", err)
	}
	envString := string(env)
	for _, expected := range []string{
		"MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true",
		"MAESTRO_CLI_NO_ANALYTICS=true",
		"MAESTRO_DISABLE_UPDATE_CHECK=true",
	} {
		if !strings.Contains(envString, expected) {
			t.Fatalf("expected Maestro env to contain %q, got %q", expected, envString)
		}
	}
}

func TestRunMaestroSmokeTimesOutLongRunningCommand(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
sleep 1
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_MAESTRO_TIMEOUT", "20ms")

	startedAt := time.Now()
	_, err := runMaestroSmoke(
		runnerOnceOptions{workspaceRoot: workspaceRoot},
		apiRunnerJob{
			ID: "pfjob_timeout",
			Payload: runnerJobPayload{
				FlowPath: "apps/mobile/.maestro/01-app-launches.yaml",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: workspaceRoot,
					PackagePath:   "apps/mobile",
				},
			},
		},
		"SIM-UDID",
		flowPath,
	)

	if err == nil || !strings.Contains(err.Error(), "timed out after 20ms") {
		t.Fatalf("expected Maestro timeout error, got %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("timeout should stop Maestro promptly, elapsed %s", elapsed)
	}
}

func TestRunMaestroSmokeReportsMissingMaestroBinary(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())

	_, err := runMaestroSmoke(
		runnerOnceOptions{workspaceRoot: workspaceRoot},
		apiRunnerJob{
			ID: "pfjob_missing_maestro",
			Payload: runnerJobPayload{
				FlowPath: "apps/mobile/.maestro/01-app-launches.yaml",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: workspaceRoot,
					PackagePath:   "apps/mobile",
				},
			},
		},
		"SIM-UDID",
		flowPath,
	)

	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("expected missing Maestro binary error, got %v", err)
	}
}

func TestRunMaestroSmokeReturnsFailingCommandError(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf 'maestro failed\n' >&2
exit 7
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := runMaestroSmoke(
		runnerOnceOptions{workspaceRoot: workspaceRoot},
		apiRunnerJob{
			ID: "pfjob_failed_maestro",
			Payload: runnerJobPayload{
				FlowPath: "apps/mobile/.maestro/01-app-launches.yaml",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: workspaceRoot,
					PackagePath:   "apps/mobile",
				},
			},
		},
		"SIM-UDID",
		flowPath,
	)

	if err == nil || !strings.Contains(err.Error(), "run Maestro smoke flow") {
		t.Fatalf("expected failing Maestro command error, got %v", err)
	}
	logPath := filepath.Join(workspaceRoot, ".preflight", "maestro", "pfjob_failed_maestro", "maestro-run.log")
	logContent, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read Maestro failure log: %v", readErr)
	}
	if !strings.Contains(string(logContent), "maestro failed") {
		t.Fatalf("expected failure output in Maestro log, got %q", string(logContent))
	}
}

func TestRunMaestroSmokeRedactsSensitiveOutputBeforeWritingLocalLog(t *testing.T) {
	workspaceRoot := t.TempDir()
	flowPath := filepath.Join(workspaceRoot, "apps", "mobile", ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "maestro"), []byte(`#!/usr/bin/env sh
printf 'EXPO_TOKEN=expo_secret_123\n'
printf 'Authorization: Bearer eas_secret_456\n' >&2
printf 'https://example.test/callback?token=maestro_secret_789&safe=1\n'
exit 0
`), 0o755); err != nil {
		t.Fatalf("write fake maestro: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	artifacts, err := runMaestroSmoke(
		runnerOnceOptions{workspaceRoot: workspaceRoot},
		apiRunnerJob{
			ID: "pfjob_redacted_maestro",
			Payload: runnerJobPayload{
				FlowPath: "apps/mobile/.maestro/01-app-launches.yaml",
				SourceBinding: runnerJobSourceBinding{
					WorkspaceRoot: workspaceRoot,
					PackagePath:   "apps/mobile",
				},
			},
		},
		"SIM-UDID",
		flowPath,
	)

	if err != nil {
		t.Fatalf("expected Maestro smoke to pass: %v", err)
	}
	logContent, readErr := os.ReadFile(artifacts.LogPath)
	if readErr != nil {
		t.Fatalf("read Maestro log: %v", readErr)
	}
	logString := string(logContent)
	for _, secret := range []string{
		"expo_secret_123",
		"eas_secret_456",
		"maestro_secret_789",
	} {
		if strings.Contains(logString, secret) {
			t.Fatalf("Maestro log leaked %q in %q", secret, logString)
		}
	}
	for _, redacted := range []string{
		"EXPO_TOKEN=[REDACTED]",
		"Authorization: Bearer [REDACTED]",
		"token=[REDACTED]",
	} {
		if !strings.Contains(logString, redacted) {
			t.Fatalf("expected Maestro log to contain %q, got %q", redacted, logString)
		}
	}
}

func TestRedactSetupTranscriptTextRedactsJSONAndColonSecrets(t *testing.T) {
	raw := `{"accessToken":"json_access_secret","refresh_token":"json_refresh_secret","privateKey":"json_private_secret"} apiKey: colon_api_secret signingSecret: colon_signing_secret`
	redacted := redactSetupTranscriptText(raw)

	for _, secret := range []string{
		"json_access_secret",
		"json_refresh_secret",
		"json_private_secret",
		"colon_api_secret",
		"colon_signing_secret",
	} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redaction leaked %q in %q", secret, redacted)
		}
	}
	if strings.Count(redacted, "[REDACTED]") < 5 {
		t.Fatalf("expected every secret value to be redacted, got %q", redacted)
	}
}

func TestRunEASCommandTimesOutLongRunningReadinessCommand(t *testing.T) {
	appDir := t.TempDir()
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(`#!/usr/bin/env sh
sleep 1
printf 'forgegraph-bot\n'
`), 0o755); err != nil {
		t.Fatalf("write fake npx: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_EAS_READINESS_TIMEOUT", "20ms")

	startedAt := time.Now()
	_, err := runEASCommand(appDir, "whoami")

	if err == nil || !strings.Contains(err.Error(), "timed out after 20ms") {
		t.Fatalf("expected EAS readiness timeout error, got %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("timeout should stop EAS promptly, elapsed %s", elapsed)
	}
}

func TestPreflightOwnedMetroRequiresLivePid(t *testing.T) {
	appDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(server.Close)

	if preflightOwnedMetroReady(server.Client(), appDir, server.URL) {
		t.Fatal("status-only Metro must not be treated as Preflight-owned")
	}

	preflightDir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(preflightDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(preflightDir, "expo-dev-session.pid"), []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	if !preflightOwnedMetroReady(server.Client(), appDir, server.URL) {
		t.Fatal("live Preflight pid and healthy status should be reusable")
	}
}

func TestPreflightOwnedMetroRemovesStalePidHandle(t *testing.T) {
	appDir := t.TempDir()
	preflightDir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(preflightDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(preflightDir, "expo-dev-session.pid")
	if err := os.WriteFile(pidPath, []byte("not-a-pid"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	t.Cleanup(server.Close)

	if preflightOwnedMetroReady(server.Client(), appDir, server.URL) {
		t.Fatal("stale Preflight pid must not be reusable")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("expected stale pid file to be removed, stat err = %v", err)
	}
}

func readCapabilitiesFixture(t *testing.T) []byte {
	t.Helper()

	// This fixture is preflight-runner's own copy of the shared Preflight
	// capabilities contract (see docs/contracts/preflight/capabilities.v1.json
	// at the repo root): the response shape /api/preflight/v1/capabilities
	// returns, matching preflightCapabilitiesData in main.go (apiVersion,
	// supportedContractVersions, auth.authenticated). It is checked into this
	// repo so a fresh clone can run the test suite without any other repo
	// checked out alongside it. PREFLIGHT_CAPABILITIES_FIXTURE can override
	// the path (e.g. to point at a different contract during development).
	candidates := []string{
		os.Getenv("PREFLIGHT_CAPABILITIES_FIXTURE"),
		"../../docs/contracts/preflight/capabilities.v1.json",
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		content, err := os.ReadFile(candidate)
		if err == nil {
			return content
		}
	}

	t.Fatal("could not read Preflight capabilities fixture")
	return nil
}

func authenticatedCapabilitiesFixture(t *testing.T) []byte {
	t.Helper()

	return bytes.Replace(
		readCapabilitiesFixture(t),
		[]byte(`"authenticated": false`),
		[]byte(`"authenticated": true`),
		1,
	)
}

func serveCapabilitiesFixture(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()

	if r.Method != http.MethodGet || r.URL.Path != "/api/preflight/v1/capabilities" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(authenticatedCapabilitiesFixture(t))
	return true
}

func serveReadyRunnerCapacityFixture(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()

	if r.Method != http.MethodGet || r.URL.Path != "/api/preflight/v1/runners/capacity" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":{"capacity":{"status":"ready","workspaceId":"local","matchingRunnerCount":1,"runnerIds":["pfrun_ready"]}},"meta":{"apiVersion":"v1","contractVersion":"2026-05-20","requestId":"req_capacity_ready"}}`))
	return true
}

func writeExpoFixture(t *testing.T) string {
	t.Helper()

	appDir := t.TempDir()
	files := map[string]string{
		"package.json":  `{"name":"@forgegraph/mobile","private":true,"main":"expo-router/entry","dependencies":{"expo":"~55.0.15","expo-dev-client":"~55.0.27"}}`,
		"app.config.ts": `export default { slug: "forgegraf", scheme: "forgegraph" }`,
		"eas.json":      `{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":true}},"development-device":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development"},"ios":{"simulator":false}}}}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	return appDir
}

func writeExpoConfigIdentity(t *testing.T, appDir string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(appDir, "app.config.ts"), []byte(`export default { name: "ForgeGraph Mobile", slug: "forgegraf", scheme: "forgegraph", ios: { bundleIdentifier: "com.gmacko.forgegraph.dev" }, android: { package: "com.gmacko.forgegraph.dev" } }`), 0o644); err != nil {
		t.Fatalf("write app.config.ts: %v", err)
	}
}

func countCalls(calls []string, expected string) int {
	count := 0
	for _, call := range calls {
		if call == expected {
			count += 1
		}
	}
	return count
}

func containsArg(args []string, expected string) bool {
	for _, arg := range args {
		if arg == expected {
			return true
		}
	}
	return false
}

func containsAny(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func waitForFileContains(t *testing.T, path string, expected string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(content), expected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	content, _ := os.ReadFile(path)
	t.Fatalf("timed out waiting for %q in %s; got %q", expected, path, string(content))
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *lockedBuffer) Write(chunk []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(chunk)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func waitForBufferContains(t *testing.T, buffer *lockedBuffer, expected string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buffer.String(), expected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %q in setup output; got %q", expected, buffer.String())
}

func generateTestAppStoreConnectKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test ASC key: %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test ASC key: %v", err)
	}
	return privateKey, string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	}))
}

func generateTestGooglePlayServiceAccount(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test Play key: %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test Play key: %v", err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	}))
	serviceAccount := map[string]string{
		"type":           "service_account",
		"project_id":     "fg-mobile-prod",
		"private_key_id": "play-key-123",
		"private_key":    privateKeyPEM,
		"client_email":   "play-publisher@fg-mobile-prod.iam.gserviceaccount.com",
		"client_id":      "123456789012345678901",
		"token_uri":      "__TOKEN_URI__",
	}
	content, err := json.Marshal(serviceAccount)
	if err != nil {
		t.Fatalf("marshal test Play service account: %v", err)
	}
	return privateKey, string(content)
}

func assertValidAppStoreConnectJWT(t *testing.T, authorization string, privateKey *ecdsa.PrivateKey) {
	t.Helper()

	if !strings.HasPrefix(authorization, "Bearer ") {
		t.Fatalf("missing bearer token in %q", authorization)
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("expected three JWT segments, got %q", token)
	}

	header := decodeJWTJSON(t, segments[0])
	if header["alg"] != "ES256" || header["kid"] != "ASC1234567" {
		t.Fatalf("unexpected JWT header %#v", header)
	}
	payload := decodeJWTJSON(t, segments[1])
	if payload["iss"] != "00000000-1111-2222-3333-444444444444" || payload["aud"] != "appstoreconnect-v1" {
		t.Fatalf("unexpected JWT payload %#v", payload)
	}
	exp, ok := payload["exp"].(float64)
	if !ok || exp <= float64(time.Now().Unix()) || exp > float64(time.Now().Add(20*time.Minute+time.Minute).Unix()) {
		t.Fatalf("unexpected JWT expiration %#v", payload["exp"])
	}

	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("expected raw ES256 signature to be 64 bytes, got %d", len(signature))
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&privateKey.PublicKey, digest[:], r, s) {
		t.Fatal("JWT signature did not verify")
	}
}

func assertValidGoogleServiceAccountJWT(t *testing.T, token string, privateKey *rsa.PrivateKey, clientEmail string, keyID string, tokenURI string, scope string) {
	t.Helper()

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("expected three JWT segments, got %q", token)
	}
	header := decodeJWTJSON(t, segments[0])
	if header["alg"] != "RS256" || header["kid"] != keyID || header["typ"] != "JWT" {
		t.Fatalf("unexpected Google JWT header %#v", header)
	}
	payload := decodeJWTJSON(t, segments[1])
	if payload["iss"] != clientEmail || payload["scope"] != scope || payload["aud"] != tokenURI {
		t.Fatalf("unexpected Google JWT payload %#v", payload)
	}
	iat, iatOK := payload["iat"].(float64)
	exp, expOK := payload["exp"].(float64)
	if !iatOK || !expOK || exp <= iat || exp > float64(time.Now().Add(time.Hour+time.Minute).Unix()) {
		t.Fatalf("unexpected Google JWT timestamps %#v", payload)
	}

	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		t.Fatalf("decode Google JWT signature: %v", err)
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("Google JWT signature did not verify: %v", err)
	}
}

func decodeJWTJSON(t *testing.T, segment string) map[string]any {
	t.Helper()

	content, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode JWT segment: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("decode JWT JSON: %v", err)
	}
	return decoded
}

func writeFakeExecutable(t *testing.T, name string, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return path
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	_ = runGitOutput(t, dir, args...)
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()

	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func TestParseEASSubmitSubmissionID(t *testing.T) {
	fromURL := parseEASSubmitSubmissionID(
		"See logs: https://expo.dev/accounts/gmackie/projects/crucible/submissions/567d0211-ab12-4cd3-9ef4-0123456789ab",
	)
	if fromURL != "567d0211-ab12-4cd3-9ef4-0123456789ab" {
		t.Fatalf("expected submission id from URL, got %q", fromURL)
	}
	fromLine := parseEASSubmitSubmissionID("Submission ID: 567d0211-ab12-4cd3-9ef4-0123456789ab")
	if fromLine != "567d0211-ab12-4cd3-9ef4-0123456789ab" {
		t.Fatalf("expected submission id from line, got %q", fromLine)
	}
	if got := parseEASSubmitSubmissionID("no ids here"); got != "" {
		t.Fatalf("expected empty for no match, got %q", got)
	}
}

func TestEASSubmitFailureCode(t *testing.T) {
	cases := map[string]string{
		"exec: \"eas\": executable file not found in $PATH": "eas_cli_missing",
		"command timed out after 30m":                       "eas_submit_timeout",
		"request failed 401":                                "asc_auth_failed",
		"Something went wrong":                              "eas_submit_failed",
	}
	for message, expected := range cases {
		if got := easSubmitFailureCode(errors.New(message)); got != expected {
			t.Fatalf("easSubmitFailureCode(%q) = %q, expected %q", message, got, expected)
		}
	}
}

func TestDefaultRunnerCapabilitiesAdvertiseTunnelDevServer(t *testing.T) {
	lan := defaultRunnerCapabilities("lan")
	if adapters, _ := lan["adapters"].([]string); slices.Contains(adapters, "expo.dev_server.tunnel") {
		t.Fatalf("lan runner must not advertise expo.dev_server.tunnel")
	}
	tunnel := defaultRunnerCapabilities("tunnel")
	adapters, _ := tunnel["adapters"].([]string)
	if !slices.Contains(adapters, "expo.dev_server.tunnel") {
		t.Fatalf("tunnel runner must advertise expo.dev_server.tunnel, got %v", adapters)
	}
	// Tailscale mode satisfies the same phone-reachability contract, so it
	// must advertise the same adapter for claim routing to stay unchanged.
	tailscale := defaultRunnerCapabilities("tailscale")
	adapters, _ = tailscale["adapters"].([]string)
	if !slices.Contains(adapters, "expo.dev_server.tunnel") {
		t.Fatalf("tailscale runner must advertise expo.dev_server.tunnel, got %v", adapters)
	}
}

func TestExpoHostArgMapsTailscaleToLan(t *testing.T) {
	if got := expoHostArg("tailscale"); got != "lan" {
		t.Fatalf("expected tailscale host mode to start expo with lan, got %q", got)
	}
	for _, mode := range []string{"lan", "localhost", "tunnel"} {
		if got := expoHostArg(mode); got != mode {
			t.Fatalf("expected %q to pass through, got %q", mode, got)
		}
	}
}

func TestAdvertisedDevServerURLUsesTailscaleHostForDevelopment(t *testing.T) {
	t.Setenv("PREFLIGHT_TAILSCALE_HOST", "100.101.102.103")
	url, err := advertisedDevServerURL(
		runnerOnceOptions{
			hostMode:  "tailscale",
			metroPort: 8400,
		},
		apiRunnerJob{
			Payload: runnerJobPayload{
				Platform: "ios",
				Lane:     "development",
			},
		},
	)
	if err != nil {
		t.Fatalf("advertised dev server URL failed: %v", err)
	}
	if url != "http://100.101.102.103:8400" {
		t.Fatalf("expected tailscale dev server URL, got %q", url)
	}
}

func TestTailscaleHostFromAddrsMatchesCGNATRangeOnly(t *testing.T) {
	mustParse := func(cidr string) net.Addr {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}
	host, ok := tailscaleHostFromAddrs([]net.Addr{
		mustParse("127.0.0.1/8"),
		mustParse("192.168.4.10/24"),
		mustParse("100.76.132.28/32"),
	})
	if !ok || host != "100.76.132.28" {
		t.Fatalf("expected the 100.64.0.0/10 address, got %q ok=%v", host, ok)
	}
	// 100.63.x and 100.128.x sit just outside the CGNAT range.
	if host, ok := tailscaleHostFromAddrs([]net.Addr{
		mustParse("100.63.255.254/32"),
		mustParse("100.128.0.1/32"),
		mustParse("10.1.2.3/8"),
	}); ok {
		t.Fatalf("expected no tailscale address, got %q", host)
	}
}

func TestExpoTunnelDevServerURLFromLogContentRejectsNgrokStatusPage(t *testing.T) {
	content := "CommandError: failed to start tunnel\n\nremote gone away\n\nCheck the Ngrok status page for outages: https://status.ngrok.com/\n"
	if url, ok := expoTunnelDevServerURLFromLogContent(content); ok {
		t.Fatalf("ngrok status page must not be treated as a dev server URL, got %q", url)
	}
	content = "Tunnel ready.\nMetro waiting on exp://abc-anonymous-8400.exp.direct\n"
	url, ok := expoTunnelDevServerURLFromLogContent(content)
	if !ok || url != "exp://abc-anonymous-8400.exp.direct" {
		t.Fatalf("expected exp.direct URL, got %q ok=%v", url, ok)
	}
}

func TestExpoTunnelDevServerURLFromManifestReadsHostURI(t *testing.T) {
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("expo-platform") != "ios" {
			t.Errorf("expected expo-platform header, got %q", r.Header.Get("expo-platform"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hostUri":"abc-anonymous-8400.exp.direct","launchAsset":{"url":"http://abc-anonymous-8400.exp.direct/node_modules/expo/AppEntry.bundle"}}`))
	}))
	defer manifestServer.Close()
	parsed, err := url.Parse(manifestServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := expoTunnelDevServerURLFromManifest(port)
	if !ok || got != "exp://abc-anonymous-8400.exp.direct" {
		t.Fatalf("expected exp.direct URL from manifest hostUri, got %q ok=%v", got, ok)
	}
}

func TestExpoTunnelDevServerURLFromManifestIgnoresLocalHostURI(t *testing.T) {
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hostUri":"127.0.0.1:8400"}`))
	}))
	defer manifestServer.Close()
	parsed, err := url.Parse(manifestServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := expoTunnelDevServerURLFromManifest(port); ok {
		t.Fatalf("loopback hostUri must be rejected, got %q", got)
	}
}

// The runner used to report only the exec error ("exit status 1") for a failed
// build command, leaving the operative error in a log file on whichever Mac ran
// the job. 348 workflows across 12 apps collapsed into four indistinguishable
// blocker messages as a result. commandLogExcerpt lifts the real error into the
// message; these cases pin that behaviour.
func TestCommandLogExcerptSurfacesOperativeError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expo-run-ios.log")
	// Shaped after a real failure: ANSI colour, noisy progress lines, and the
	// operative error well above the end of the file.
	contents := "$ npx expo prebuild --platform ios\n" +
		"- Creating native directory (./ios)\n" +
		"\x1b[33m› \x1b[1m[@sentry/react-native/expo]\x1b[22m sentry-xcode.sh already exists.\x1b[0m\n" +
		"✖ Prebuild failed\n" +
		"Error: [ios.podfile]: withIosPodfileBaseMod: Failed to find Podfile anchor for forgegraph-fmt-consteval-helper\n" +
		"    at insertGeneratedBlock (/x/plugins/with-ios-fmt-consteval.js:23:11)\n" +
		"    at async compileModsAsync (/x/node_modules/@expo/config-plugins/build/plugins/mod-compiler.js:120:10)\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	handle, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer func() { _ = handle.Close() }()

	excerpt := commandLogExcerpt(handle)
	if !strings.Contains(excerpt, "Failed to find Podfile anchor for forgegraph-fmt-consteval-helper") {
		t.Fatalf("excerpt must carry the operative error, got %q", excerpt)
	}
	if strings.Contains(excerpt, "\x1b[") {
		t.Fatalf("excerpt must strip ANSI escapes, got %q", excerpt)
	}
	if len(excerpt) > commandLogExcerptMax+len(" — ")+len("…") {
		t.Fatalf("excerpt must stay bounded, got %d chars", len(excerpt))
	}

	// A wrapped failure has to read as one sentence naming the real cause.
	wrapped := fmt.Errorf("run Expo %s prebuild: %w%s", "ios", errors.New("exit status 1"), excerpt)
	if !strings.Contains(wrapped.Error(), "exit status 1") ||
		!strings.Contains(wrapped.Error(), "Podfile anchor") {
		t.Fatalf("wrapped error lost information: %q", wrapped.Error())
	}
}

func TestCommandLogExcerptFallsBackAndDegradesSafely(t *testing.T) {
	dir := t.TempDir()

	// No recognised marker: still say something rather than nothing.
	plain := filepath.Join(dir, "plain.log")
	if err := os.WriteFile(plain, []byte("building\nsomething went sideways\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	handle, err := os.Open(plain)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer func() { _ = handle.Close() }()
	if got := commandLogExcerpt(handle); !strings.Contains(got, "something went sideways") {
		t.Fatalf("expected tail fallback, got %q", got)
	}

	// Empty log and nil handle must contribute nothing, never panic — a failure
	// path must not become a second failure.
	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty log: %v", err)
	}
	emptyHandle, err := os.Open(empty)
	if err != nil {
		t.Fatalf("open empty log: %v", err)
	}
	defer func() { _ = emptyHandle.Close() }()
	if got := commandLogExcerpt(emptyHandle); got != "" {
		t.Fatalf("empty log must yield no excerpt, got %q", got)
	}
	if got := commandLogExcerpt(nil); got != "" {
		t.Fatalf("nil log must yield no excerpt, got %q", got)
	}
}

// launchd starts the runner with no locale, so Ruby (and therefore CocoaPods)
// defaults to US-ASCII and every `pod install` raises
// Encoding::CompatibilityError. `expo prebuild` runs pod install, so the whole
// class of failures surfaced only as "run Expo ios prebuild: exit status 1".
func TestExpoCommandEnvForcesUTF8LocaleWhenUnset(t *testing.T) {
	for _, key := range []string{"LANG", "LC_ALL", "LC_CTYPE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
	var lang string
	for _, entry := range expoCommandEnv(apiRunnerJob{}) {
		if strings.HasPrefix(entry, "LANG=") {
			lang = strings.TrimPrefix(entry, "LANG=")
		}
	}
	if !strings.Contains(strings.ToUpper(lang), "UTF-8") {
		t.Fatalf("expected a UTF-8 LANG so CocoaPods can normalise paths, got %q", lang)
	}
}

func TestExpoCommandEnvKeepsOperatorLocale(t *testing.T) {
	for _, key := range []string{"LC_ALL", "LC_CTYPE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
	t.Setenv("LANG", "en_GB.UTF-8")
	found := false
	for _, entry := range expoCommandEnv(apiRunnerJob{}) {
		if entry == "LANG=en_GB.UTF-8" {
			found = true
		}
		if entry == "LANG=en_US.UTF-8" {
			t.Fatalf("must not override an operator-configured locale")
		}
	}
	if !found {
		t.Fatalf("operator locale missing from env")
	}
}

// The labtop runner's CI checkout area is a symlink onto another volume
// (/Volumes/dev/.preflight-ci -> /Volumes/dev-ssd/preflight-ci, from the SSD
// node_modules offload). Source bindings therefore recorded the resolved
// /Volumes/dev-ssd/... path while the runner advertises --workspace-root
// /Volumes/dev, so containment failed, every claim was released as a
// source-binding mismatch, and the workflow thrashed between target_discovered
// and runner_job_expired indefinitely.
func TestSymlinkedChildCoversResolvedCheckoutPath(t *testing.T) {
	base := t.TempDir()
	// Stand in for the two volumes.
	devRoot := filepath.Join(base, "dev")
	ssdRoot := filepath.Join(base, "dev-ssd")
	realCheckout := filepath.Join(ssdRoot, "preflight-ci")
	appDir := filepath.Join(realCheckout, "ForgeGraph", "apps", "mobile")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	if err := os.MkdirAll(devRoot, 0o755); err != nil {
		t.Fatalf("mkdir dev: %v", err)
	}
	if err := os.Symlink(realCheckout, filepath.Join(devRoot, ".preflight-ci")); err != nil {
		t.Fatalf("symlink checkout: %v", err)
	}

	// The exact shape that wedged the farm: runner root on one volume, binding
	// path resolved onto the other.
	if pathWithin(devRoot, appDir) {
		t.Fatalf("precondition: the resolved app dir must NOT be lexically inside the runner root")
	}
	if !symlinkedChildCovers(devRoot, appDir) {
		t.Fatalf("runner root %q must cover %q through its symlinked child", devRoot, appDir)
	}

	// An unrelated tree on the same volume must still be rejected, or the check
	// would accept any job and defeat the point of workspace-root matching.
	outside := filepath.Join(ssdRoot, "somewhere-else", "apps", "mobile")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	if symlinkedChildCovers(devRoot, outside) {
		t.Fatalf("must not cover %q, which no symlinked child reaches", outside)
	}
	// A root with no symlinked children covers nothing.
	if symlinkedChildCovers(ssdRoot, appDir) {
		t.Fatalf("a root with no symlinked child must not match")
	}
}

// Two runner agents on the same Mac used to prebuild the same CI checkout at
// once and race Expo's atomic writes, producing
// "[ios.podfileProperties]: ENOENT ... rename '<tmp>' -> 'Podfile.properties.json'".
// The pre-existing ps-scraping guard cannot prevent that: it only matches
// `expo run:ios`/`xcodebuild`, and a bool check lets two callers both proceed.
func TestAcquireCheckoutLockSerialisesOneCheckout(t *testing.T) {
	lockDir := filepath.Join(t.TempDir(), ".preflight")
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	release, err := acquireCheckoutLock(lockDir, time.Second)
	if err != nil {
		t.Fatalf("first acquire must succeed: %v", err)
	}

	// A second holder, standing in for another agent on the same host, must be
	// refused rather than allowed to race.
	blocked := make(chan error, 1)
	go func() {
		second, secondErr := acquireCheckoutLock(lockDir, 300*time.Millisecond)
		if secondErr == nil {
			second()
		}
		blocked <- secondErr
	}()
	select {
	case secondErr := <-blocked:
		if secondErr == nil {
			t.Fatalf("a second agent must not enter a checkout already held")
		}
		if !strings.Contains(secondErr.Error(), "another runner on this host") {
			t.Fatalf("error must name the real cause, got %q", secondErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("second acquire neither succeeded nor timed out")
	}

	// After release the checkout is usable again, or one stuck build would wedge
	// that app permanently.
	release()
	again, err := acquireCheckoutLock(lockDir, 2*time.Second)
	if err != nil {
		t.Fatalf("must be acquirable after release: %v", err)
	}
	again()
}

func TestAcquireCheckoutLockKeyedPerAppDirectory(t *testing.T) {
	base := t.TempDir()
	first := filepath.Join(base, "appA", ".preflight")
	second := filepath.Join(base, "appB", ".preflight")
	for _, d := range []string{first, second} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	releaseA, err := acquireCheckoutLock(first, time.Second)
	if err != nil {
		t.Fatalf("appA: %v", err)
	}
	defer releaseA()
	// Unrelated apps must still build in parallel; a host-wide lock would halve
	// farm throughput for no reason.
	releaseB, err := acquireCheckoutLock(second, time.Second)
	if err != nil {
		t.Fatalf("a different app must not be blocked by appA's lock: %v", err)
	}
	releaseB()
}

func TestAcquireCheckoutLockProceedsWhenUnlockable(t *testing.T) {
	// A lock file that cannot be created must not take the runner offline.
	release, err := acquireCheckoutLock(filepath.Join(t.TempDir(), "does", "not", "exist"), time.Second)
	if err != nil {
		t.Fatalf("must degrade to unlocked, got %v", err)
	}
	release()
}

// Several runner agents share each Mac and poll independently, so losing a race
// for a job is routine. It used to end the invocation as "runner once failed",
// which made a lost race indistinguishable from a broken runner (28 such lines
// in 400 on gmacko-mini).
func TestJobLeaseLostRecognisesLeaseErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"denied", &preflightAPIError{status: 403, code: "runner_job_lease_denied", message: "Runner does not own this job lease."}, true},
		{"expired", &preflightAPIError{status: 409, code: "runner_job_lease_expired", message: "Runner job lease expired before the runner write."}, true},
		{"wrapped", fmt.Errorf("complete job: %w", &preflightAPIError{status: 403, code: "runner_job_lease_denied"}), true},
		{"other api error", &preflightAPIError{status: 500, code: "internal_error", message: "boom"}, false},
		{"unauthorised is still fatal", &preflightAPIError{status: 401, code: "unauthorized", message: "bad token"}, false},
		{"plain error", errors.New("runner_job_lease_denied"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := jobLeaseLost(c.err); got != c.want {
			t.Fatalf("%s: jobLeaseLost = %v, want %v", c.name, got, c.want)
		}
	}
}

// The typed error must print exactly as before, or every log line and every
// blocker_message built from an API failure changes shape.
func TestPreflightAPIErrorMessageUnchanged(t *testing.T) {
	withCode := &preflightAPIError{status: 403, code: "runner_job_lease_denied", message: "Runner does not own this job lease."}
	wantWithCode := "Preflight API returned HTTP 403 (runner_job_lease_denied): Runner does not own this job lease."
	if withCode.Error() != wantWithCode {
		t.Fatalf("with code:\n got %q\nwant %q", withCode.Error(), wantWithCode)
	}
	bare := &preflightAPIError{status: 502}
	if bare.Error() != "Preflight API returned HTTP 502" {
		t.Fatalf("bare: got %q", bare.Error())
	}
}
