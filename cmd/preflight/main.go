package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"
)

const contractVersion = "2026-05-20"
const defaultMaestroSmokeTimeout = 10 * time.Minute
const defaultEASReadinessTimeout = 2 * time.Minute
const defaultEASBuildTimeout = 45 * time.Minute
const defaultExpoConfigTimeout = 30 * time.Second
const defaultExpoDevSessionStartTimeout = 2 * time.Minute
const defaultSimulatorOpenTimeout = 10 * time.Minute
const defaultUnityBuildTimeout = 60 * time.Minute
const defaultAndroidDevelopmentOpenTimeout = 5 * time.Minute
const defaultAndroidDeviceNameTimeout = 2 * time.Second
const defaultRunnerPollInterval = time.Second

// defaultRunnerLivenessHeartbeatInterval keeps the runner-level heartbeat well
// under the server's stale-runner threshold (90s) during long jobs.
const defaultRunnerLivenessHeartbeatInterval = 30 * time.Second

// defaultRunnerJobHeartbeatInterval keeps the per-JOB lease fresh during a long
// handler (build, dev-session, sim boot, maestro). Without this, a multi-minute
// step outlives the job lease and the next write is rejected with HTTP 409
// (runner_job_not_running). Kept well under the lease window like the runner one.
const defaultRunnerJobHeartbeatInterval = 20 * time.Second
const defaultProveAppWatchTimeout = 10 * time.Minute
const defaultLocalArtifactTTL = 24 * time.Hour
const defaultAppStoreConnectAPIURL = "https://api.appstoreconnect.apple.com"
const defaultGooglePlayAPIURL = "https://androidpublisher.googleapis.com"
const defaultSentryAPIURL = "https://sentry.io"
const googlePlayAndroidPublisherScope = "https://www.googleapis.com/auth/androidpublisher"

var errCommandCancelled = errors.New("preflight runner job cancelled")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, http.DefaultClient))
}

func run(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 {
		printRootHelp(stdout)
		return 0
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "preflight dev (contract %s)\n", contractVersion)
		return 0
	case "login":
		return runLogin(args[1:], stdout, stderr, client)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "setup":
		return runSetup(args[1:], stdout, stderr, client)
	case "prove-app":
		return runProveApp(args[1:], stdout, stderr, client)
	case "runner":
		return runRunner(args[1:], stdout, stderr, client)
	case "apps":
		return runApps(args[1:], stdout, stderr, client)
	case "cleanup":
		return runCleanup(args[1:], stdout, stderr)
	case "fleet":
		return runFleet(args[1:], stdout, stderr, client)
	case "status":
		return runStatusAlias(args[1:], stdout, stderr, client)
	case "testflight":
		return runTestFlight(args[1:], stdout, stderr, client)
	case "capabilities":
		return runCapabilities(args[1:], stdout, stderr, client)
	case "targets":
		return runTargets(args[1:], stdout, stderr, client)
	case "credentials":
		return runCredentials(args[1:], stdout, stderr, client)
	case "providers":
		return runProviders(args[1:], stdout, stderr, client)
	case "provider-readiness":
		return runProviderReadiness(args[1:], stdout, stderr, client)
	case "credential-flows":
		return runCredentialFlows(args[1:], stdout, stderr, client)
	case "oauth-clients":
		return runOAuthClients(args[1:], stdout, stderr, client)
	case "--help", "-h", "help":
		printRootHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printRootHelp(stderr)
		return 2
	}
}

func printRootHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  version       Print CLI and contract version")
	fmt.Fprintln(w, "  login         Authenticate with the Preflight API")
	fmt.Fprintln(w, "  apps          Release-program status (list/status/checklist/doctor/screenshots/submit-for-review)")
	fmt.Fprintln(w, "  fleet         Fleet cockpit: `fleet next` = per-app next action + owner")
	fmt.Fprintln(w, "  status        Alias: apps status <app> / apps list")
	fmt.Fprintln(w, "  testflight    Manage TestFlight tester enrollment")
	fmt.Fprintln(w, "  config        Inspect local Preflight CLI config")
	fmt.Fprintln(w, "  capabilities  Probe /api/preflight/v1/capabilities")
	fmt.Fprintln(w, "  targets       Register and list local simulator/device inventory")
	fmt.Fprintln(w, "  credentials   Manage Preflight-owned credential references")
	fmt.Fprintln(w, "  providers     Manage mobile provider accounts")
	fmt.Fprintln(w, "  provider-readiness  Inspect or record app provider readiness")
	fmt.Fprintln(w, "  credential-flows    Inspect provider credential/setup flows")
	fmt.Fprintln(w, "  oauth-clients Manage Google and Apple OAuth client records")
	fmt.Fprintln(w, "  setup         Run guided setup for a blocked workflow")
	fmt.Fprintln(w, "  prove-app     Create a mobile proof workflow")
	fmt.Fprintln(w, "  runner        Run local mobile tooling jobs")
}

func printHelpOrPlaceholder(args []string, stdout io.Writer, name string, summary string) int {
	if len(args) > 1 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Fprintf(stdout, "Usage: preflight %s\n\n%s\n", name, summary)
		return 0
	}

	fmt.Fprintf(stdout, "preflight %s is not implemented in Milestone 0 beyond --help.\n", name)
	return 2
}

func runLogin(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight login")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Authenticate with the Preflight API. By default this opens your browser to")
		fmt.Fprintln(stdout, "forgegraf.com and authorizes the CLI (if you're already signed in, it just works).")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Options:")
		fmt.Fprintln(stdout, "  --api-url <url>     Preflight API URL (default: https://preflight.forgegraf.com)")
		fmt.Fprintln(stdout, "  --device            Print a code + URL to authorize from another device (headless/SSH)")
		fmt.Fprintln(stdout, "  --no-browser        Don't auto-open the browser; print the URL instead")
		fmt.Fprintln(stdout, "  --token-env <name>  Use a token from this env var instead of the browser flow")
		fmt.Fprintln(stdout, "  --workspace-id <id> Override the default workspace ID")
		return 0
	}

	config, err := loadPreflightCLIConfig()
	if err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	apiURL := firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL)
	tokenEnv := ""
	workspaceID := config.WorkspaceID
	deviceMode := false
	noBrowser := false

	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return 2
			}
			apiURL = value
		case "--token-env":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--token-env requires a value")
				return 2
			}
			tokenEnv = value
		case "--workspace-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--workspace-id requires a value")
				return 2
			}
			workspaceID = value
		case "--device":
			deviceMode = true
		case "--no-browser":
			noBrowser = true
		default:
			fmt.Fprintf(stderr, "unknown login flag %q\n", args[index])
			return 2
		}
	}

	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if apiURL == "" {
		fmt.Fprintln(stderr, "missing Preflight API URL; pass --api-url or set PREFLIGHT_API_URL")
		return 2
	}

	// Token resolution: an explicit token env var (CI / scripted), an already
	// populated PREFLIGHT_TOKEN, or the interactive browser/device flow.
	resolvedWorkspace := firstNonEmpty(workspaceID, "local")
	var token string
	if tokenEnv != "" {
		token = strings.TrimSpace(os.Getenv(tokenEnv))
		if token == "" {
			fmt.Fprintf(stderr, "--token-env %s is empty\n", tokenEnv)
			return 2
		}
	} else if envToken := strings.TrimSpace(os.Getenv("PREFLIGHT_TOKEN")); envToken != "" {
		token = envToken
	} else {
		flowToken, flowWorkspace, loginErr := deviceLogin(client, apiURL, !deviceMode && !noBrowser, stdout, stderr)
		if loginErr != nil {
			fmt.Fprintf(stderr, "login failed: %v\n", loginErr)
			return 1
		}
		token = flowToken
		resolvedWorkspace = firstNonEmpty(workspaceID, flowWorkspace, "local")
	}

	if err := verifyPreflightAPICompatibility(client, apiURL, token); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	config.APIURL = apiURL
	config.Token = token
	config.WorkspaceID = resolvedWorkspace
	if config.WorkspaceBindings == nil {
		config.WorkspaceBindings = map[string]string{}
	}
	if err := savePreflightCLIConfig(config); err != nil {
		fmt.Fprintf(stderr, "save Preflight CLI config failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Signed in to %s (workspace %s)\n", config.APIURL, config.WorkspaceID)
	return 0
}

const defaultPreflightAPIURL = "https://preflight.forgegraf.com"

// deviceLogin runs the OAuth 2.0 device-authorization grant against the
// Preflight API: start a request, send the user to the browser to approve it
// (authenticated by their forgegraf.com session), and poll for the token.
func deviceLogin(client *http.Client, apiURL string, openBrowserFlag bool, stdout io.Writer, stderr io.Writer) (string, string, error) {
	base := strings.TrimRight(apiURL, "/") + "/api/preflight/v1/cli/auth/device"

	start, _, err := postDeviceEndpoint(client, base+"/start", nil)
	if err != nil {
		return "", "", err
	}
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	verifyURI, _ := start["verification_uri"].(string)
	verifyComplete, _ := start["verification_uri_complete"].(string)
	if deviceCode == "" || userCode == "" {
		return "", "", fmt.Errorf("unexpected response from device/start")
	}
	intervalSec := 5
	if v, ok := start["interval"].(float64); ok && v > 0 {
		intervalSec = int(v)
	}
	expiresSec := 600
	if v, ok := start["expires_in"].(float64); ok && v > 0 {
		expiresSec = int(v)
	}

	if openBrowserFlag {
		fmt.Fprintf(stdout, "Opening your browser to authorize the Preflight CLI...\n")
		fmt.Fprintf(stdout, "  Confirm this code: %s\n", userCode)
		fmt.Fprintf(stdout, "  If the browser doesn't open, visit: %s\n\n", firstNonEmpty(verifyComplete, verifyURI))
		if browserErr := openBrowser(firstNonEmpty(verifyComplete, verifyURI)); browserErr != nil {
			fmt.Fprintf(stderr, "  (couldn't open a browser automatically: %v)\n", browserErr)
		}
	} else {
		fmt.Fprintf(stdout, "To authorize this CLI, open:\n  %s\nand enter the code:\n  %s\n\n", verifyURI, userCode)
	}
	fmt.Fprintln(stdout, "Waiting for approval...")

	interval := time.Duration(intervalSec) * time.Second
	deadline := time.Now().Add(time.Duration(expiresSec) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		body, status, pollErr := postDeviceEndpoint(client, base+"/token", map[string]string{"device_code": deviceCode})
		if pollErr != nil {
			continue // transient; keep polling until the deadline
		}
		if status == http.StatusOK {
			token, _ := body["access_token"].(string)
			workspaceID, _ := body["workspace_id"].(string)
			if token == "" {
				return "", "", fmt.Errorf("authorization succeeded but no token was returned")
			}
			return token, workspaceID, nil
		}
		switch errCode, _ := body["error"].(string); errCode {
		case "authorization_pending", "slow_down":
			continue
		case "expired_token":
			return "", "", fmt.Errorf("the authorization request expired; run `preflight login` again")
		default:
			return "", "", fmt.Errorf("authorization failed: %s", firstNonEmpty(errCode, "unknown error"))
		}
	}
	return "", "", fmt.Errorf("timed out waiting for browser approval")
}

func postDeviceEndpoint(client *http.Client, endpoint string, payload any) (map[string]any, int, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	if decoded == nil {
		decoded = map[string]any{}
	}
	return decoded, response.StatusCode, nil
}

// openBrowser opens a URL in the user's default browser, cross-platform.
func openBrowser(target string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", target).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}

func runConfig(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: preflight config <command>")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Commands:")
		fmt.Fprintln(stdout, "  show            Inspect local Preflight CLI config with secrets redacted")
		fmt.Fprintln(stdout, "  bind-workspace  Persist a workspace ID for an app path")
		return 0
	}
	switch args[0] {
	case "show":
		return runConfigShow(stdout, stderr)
	case "bind-workspace":
		return runConfigBindWorkspace(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown config command %q\n", args[0])
		return 2
	}
}

func runConfigShow(stdout io.Writer, stderr io.Writer) int {
	config, err := loadPreflightCLIConfig()
	if err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if config.Token != "" {
		config.Token = "[REDACTED]"
	}
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode Preflight CLI config failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(content))
	return 0
}

func runConfigBindWorkspace(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight config bind-workspace --app-dir <path> --workspace-id <id>")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Persist a workspace ID for the current mobile app path.")
		return 0
	}
	appDir := "."
	workspaceID := ""
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--app-dir":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--app-dir requires a value")
				return 2
			}
			appDir = value
		case "--workspace-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--workspace-id requires a value")
				return 2
			}
			workspaceID = value
		default:
			fmt.Fprintf(stderr, "unknown config bind-workspace flag %q\n", args[index])
			return 2
		}
	}
	if strings.TrimSpace(workspaceID) == "" {
		fmt.Fprintln(stderr, "--workspace-id requires a value")
		return 2
	}
	bindingKey, err := preflightAppConfigBindingKey(appDir)
	if err != nil {
		fmt.Fprintf(stderr, "resolve app dir failed: %v\n", err)
		return 2
	}
	config, err := loadPreflightCLIConfig()
	if err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if config.WorkspaceBindings == nil {
		config.WorkspaceBindings = map[string]string{}
	}
	config.WorkspaceBindings[bindingKey] = workspaceID
	if err := savePreflightCLIConfig(config); err != nil {
		fmt.Fprintf(stderr, "save Preflight CLI config failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "bound %s to workspace %s\n", bindingKey, workspaceID)
	return 0
}

func runCapabilities(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	apiURL := os.Getenv("PREFLIGHT_API_URL")
	for index := 0; index < len(args); index += 1 {
		if args[index] == "--api-url" && index+1 < len(args) {
			apiURL = args[index+1]
			index += 1
		}
	}

	if apiURL == "" {
		fmt.Fprintln(stderr, "missing Preflight API URL; pass --api-url or set PREFLIGHT_API_URL")
		return 2
	}

	endpoint := strings.TrimRight(apiURL, "/") + "/api/preflight/v1/capabilities"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		fmt.Fprintf(stderr, "invalid Preflight API URL: %v\n", err)
		return 2
	}

	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(stderr, "capability probe failed: %v\n", err)
		return 1
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Fprintf(stderr, "capability probe returned HTTP %d\n", response.StatusCode)
		return 1
	}

	if _, err := io.Copy(stdout, response.Body); err != nil {
		fmt.Fprintf(stderr, "failed to read capability response: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout); err != nil {
		fmt.Fprintf(stderr, "failed to write capability response: %v\n", err)
		return 1
	}

	return 0
}

type providerAccountSummary struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"`
}

type providerAccountsEnvelopeData struct {
	ProviderAccount  providerAccountSummary   `json:"providerAccount"`
	ProviderAccounts []providerAccountSummary `json:"providerAccounts"`
}

type credentialSummary struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Key       string `json:"key"`
	LaneScope string `json:"laneScope"`
	Status    string `json:"status"`
}

type credentialsEnvelopeData struct {
	SecretReference  credentialSummary   `json:"secretReference"`
	SecretReferences []credentialSummary `json:"secretReferences"`
}

type providerReadinessSummary struct {
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	Capability        string `json:"capability"`
	Status            string `json:"status"`
	BlockerCode       string `json:"blockerCode"`
	NextAction        string `json:"nextAction"`
	RequiredHumanRole string `json:"requiredHumanRole"`
}

type providerReadinessRecordEnvelopeData struct {
	ProviderReadiness providerReadinessSummary `json:"providerReadiness"`
}

type providerReadinessListEnvelopeData struct {
	ProviderReadiness []providerReadinessSummary `json:"providerReadiness"`
}

type providerSetupPlanEnvelopeData struct {
	ProviderSetupPlan providerSetupPlanSummary `json:"providerSetupPlan"`
}

type providerSetupPlanSummary struct {
	AppID        string                            `json:"appId"`
	Platform     string                            `json:"platform"`
	Lane         string                            `json:"lane"`
	Ready        bool                              `json:"ready"`
	Requirements []providerSetupRequirementSummary `json:"requirements"`
	NextActions  []string                          `json:"nextActions"`
}

type providerSetupRequirementSummary struct {
	Provider          string `json:"provider"`
	Capability        string `json:"capability"`
	Status            string `json:"status"`
	BlockerCode       string `json:"blockerCode"`
	NextAction        string `json:"nextAction"`
	RequiredHumanRole string `json:"requiredHumanRole"`
	Source            string `json:"source"`
}

type oauthClientSummary struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	ClientKind  string `json:"clientKind"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"`
}

type oauthClientsEnvelopeData struct {
	OAuthClient  oauthClientSummary   `json:"oauthClient"`
	OAuthClients []oauthClientSummary `json:"oauthClients"`
}

type targetSummary struct {
	ID           string `json:"id"`
	RunnerID     string `json:"runnerId"`
	Platform     string `json:"platform"`
	Kind         string `json:"kind"`
	TargetKey    string `json:"targetKey"`
	DisplayName  string `json:"displayName"`
	Availability string `json:"availability"`
}

type credentialFlowSummary struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	Capability string `json:"capability"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	NextAction string `json:"nextAction"`
}

type oauthClientConfigureEnvelopeData struct {
	ProviderAccount   providerAccountSummary     `json:"providerAccount"`
	CredentialFlow    credentialFlowSummary      `json:"credentialFlow"`
	OAuthClient       oauthClientSummary         `json:"oauthClient"`
	ProviderReadiness []providerReadinessSummary `json:"providerReadiness"`
}

type credentialFlowEnvelopeData struct {
	CredentialFlow credentialFlowSummary `json:"credentialFlow"`
}

type credentialFlowsEnvelopeData struct {
	CredentialFlows []credentialFlowSummary `json:"credentialFlows"`
}

func runTargets(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printTargetsHelp(stdout)
		return 0
	}
	switch args[0] {
	case "upsert":
		return runTargetsUpsert(args[1:], stdout, stderr, client)
	case "list":
		return runTargetsList(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown targets command %q\n", args[0])
		printTargetsHelp(stderr)
		return 2
	}
}

func printTargetsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight targets <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  upsert  Register or update a simulator/emulator/device target")
	fmt.Fprintln(w, "  list    List registered workspace targets")
}

func runTargetsUpsert(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":       os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId":  "local",
		"availability": "unknown",
	}
	capabilities := map[string]string{}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--runner-id":
			if !readFlagValue(args, &index, options, "runnerId", stderr) {
				return 2
			}
		case "--platform":
			if !readFlagValue(args, &index, options, "platform", stderr) {
				return 2
			}
		case "--kind":
			if !readFlagValue(args, &index, options, "kind", stderr) {
				return 2
			}
		case "--target-key":
			if !readFlagValue(args, &index, options, "targetKey", stderr) {
				return 2
			}
		case "--display-name":
			if !readFlagValue(args, &index, options, "displayName", stderr) {
				return 2
			}
		case "--provider-identity":
			if !readFlagValue(args, &index, options, "providerIdentity", stderr) {
				return 2
			}
		case "--availability":
			if !readFlagValue(args, &index, options, "availability", stderr) {
				return 2
			}
		case "--capability":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--capability requires a value")
				return 2
			}
			key, parsedValue, err := parseKeyValue(value)
			if err != nil {
				fmt.Fprintf(stderr, "invalid --capability: %v\n", err)
				return 2
			}
			capabilities[key] = parsedValue
		default:
			fmt.Fprintf(stderr, "unknown targets upsert flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "platform", "kind", "targetKey", "displayName", "providerIdentity"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	payload := map[string]any{
		"workspaceId":      options["workspaceId"],
		"runnerId":         options["runnerId"],
		"platform":         options["platform"],
		"kind":             options["kind"],
		"targetKey":        options["targetKey"],
		"displayName":      options["displayName"],
		"providerIdentity": options["providerIdentity"],
		"availability":     options["availability"],
		"capabilities":     capabilities,
	}
	data, err := postPreflightWorkspaceJSON(client, runnerEndpoint(options["apiURL"], "/api/v1/targets"), options["token"], options["workspaceId"], payload)
	if err != nil {
		fmt.Fprintf(stderr, "target upsert failed: %v\n", err)
		return 1
	}
	var target targetSummary
	if err := decodeEnvelopeData(data, &target); err != nil {
		fmt.Fprintf(stderr, "decode target response failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "target %s %s %s %s %s\n", target.ID, target.Platform, target.Kind, target.Availability, target.DisplayName)
	return 0
}

func runTargetsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--platform":
			if !readFlagValue(args, &index, options, "platform", stderr) {
				return 2
			}
		case "--kind":
			if !readFlagValue(args, &index, options, "kind", stderr) {
				return 2
			}
		case "--runner-id":
			if !readFlagValue(args, &index, options, "runnerId", stderr) {
				return 2
			}
		case "--availability":
			if !readFlagValue(args, &index, options, "availability", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown targets list flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/v1/targets") + queryString(options, "platform", "kind", "runnerId", "availability")
	data, err := getPreflightWorkspaceJSON(client, endpoint, options["token"], options["workspaceId"])
	if err != nil {
		fmt.Fprintf(stderr, "target list failed: %v\n", err)
		return 1
	}
	var targets []targetSummary
	if err := decodeEnvelopeData(data, &targets); err != nil {
		fmt.Fprintf(stderr, "decode target list failed: %v\n", err)
		return 1
	}
	for _, target := range targets {
		fmt.Fprintf(stdout, "%s %s %s %s %s\n", target.ID, target.Platform, target.Kind, target.Availability, target.DisplayName)
	}
	return 0
}

func runCredentials(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printCredentialsHelp(stdout)
		return 0
	}
	switch args[0] {
	case "create":
		return runCredentialsCreate(args[1:], stdout, stderr, client)
	case "list":
		return runCredentialsList(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown credentials command %q\n", args[0])
		printCredentialsHelp(stderr)
		return 2
	}
}

func printCredentialsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight credentials <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  create  Create a Preflight-owned credential reference")
	fmt.Fprintln(w, "  list    List credential references")
}

func runCredentialsCreate(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
		"laneScope":   "all",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--purpose":
			if !readFlagValue(args, &index, options, "purpose", stderr) {
				return 2
			}
		case "--key":
			if !readFlagValue(args, &index, options, "key", stderr) {
				return 2
			}
		case "--lane":
			if !readFlagValue(args, &index, options, "laneScope", stderr) {
				return 2
			}
		case "--value-env":
			if !readFlagValue(args, &index, options, "valueEnv", stderr) {
				return 2
			}
		case "--value-stdin":
			options["valueStdin"] = "true"
		default:
			fmt.Fprintf(stderr, "unknown credentials create flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "provider", "purpose", "key"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	value, err := credentialValue(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	payload := map[string]any{
		"workspaceId": options["workspaceId"],
		"provider":    options["provider"],
		"purpose":     options["purpose"],
		"key":         options["key"],
		"value":       value,
		"laneScope":   options["laneScope"],
	}
	if options["appId"] != "" {
		payload["appId"] = options["appId"]
	}
	data, err := postPreflightJSON(client, runnerEndpoint(options["apiURL"], "/api/preflight/v1/secret-refs"), options["token"], payload)
	if err != nil {
		fmt.Fprintf(stderr, "credential create failed: %v\n", err)
		return 1
	}
	var created credentialsEnvelopeData
	if err := decodeEnvelopeData(data, &created); err != nil {
		fmt.Fprintf(stderr, "decode credential response failed: %v\n", err)
		return 1
	}
	credential := created.SecretReference
	fmt.Fprintf(stdout, "created credential %s %s %s %s\n", credential.ID, credential.Provider, credential.Key, credential.LaneScope)
	return 0
}

func runCredentialsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown credentials list flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/secret-refs") + queryString(options, "workspaceId", "appId", "provider")
	data, err := getPreflightJSON(client, endpoint, options["token"])
	if err != nil {
		fmt.Fprintf(stderr, "credential list failed: %v\n", err)
		return 1
	}
	var listed credentialsEnvelopeData
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode credential list failed: %v\n", err)
		return 1
	}
	for _, credential := range listed.SecretReferences {
		fmt.Fprintf(stdout, "%s %s %s %s %s\n", credential.ID, credential.Provider, credential.Key, credential.LaneScope, credential.Status)
	}
	return 0
}

func runProviders(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printProvidersHelp(stdout)
		return 0
	}
	switch args[0] {
	case "upsert":
		return runProvidersUpsert(args[1:], stdout, stderr, client)
	case "list":
		return runProvidersList(args[1:], stdout, stderr, client)
	case "verify":
		return runProvidersVerify(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown providers command %q\n", args[0])
		printProvidersHelp(stderr)
		return 2
	}
}

func printProvidersHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight providers <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  upsert  Create or update a provider account")
	fmt.Fprintln(w, "  list    List provider accounts")
	fmt.Fprintln(w, "  verify  Verify a provider account through Preflight-owned credentials")
}

func runProvidersUpsert(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
		"status":      "needs_setup",
	}
	externalIDs := map[string]string{}
	var capabilities []string
	var credentialRefs []string
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--display-name":
			if !readFlagValue(args, &index, options, "displayName", stderr) {
				return 2
			}
		case "--status":
			if !readFlagValue(args, &index, options, "status", stderr) {
				return 2
			}
		case "--external-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--external-id requires a value")
				return 2
			}
			key, parsedValue, err := parseKeyValue(value)
			if err != nil {
				fmt.Fprintf(stderr, "invalid --external-id: %v\n", err)
				return 2
			}
			externalIDs[key] = parsedValue
		case "--capability":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--capability requires a value")
				return 2
			}
			capabilities = append(capabilities, value)
		case "--credential-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--credential-ref requires a value")
				return 2
			}
			credentialRefs = append(credentialRefs, value)
		default:
			fmt.Fprintf(stderr, "unknown providers upsert flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "provider", "displayName"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	payload := map[string]any{
		"workspaceId":            options["workspaceId"],
		"provider":               options["provider"],
		"displayName":            options["displayName"],
		"externalIds":            externalIDs,
		"capabilities":           capabilities,
		"credentialReferenceIds": credentialRefs,
		"status":                 options["status"],
	}
	if options["appId"] != "" {
		payload["appId"] = options["appId"]
	}
	data, err := postPreflightJSON(client, runnerEndpoint(options["apiURL"], "/api/preflight/v1/provider-accounts"), options["token"], payload)
	if err != nil {
		fmt.Fprintf(stderr, "provider upsert failed: %v\n", err)
		return 1
	}
	var upserted providerAccountsEnvelopeData
	if err := decodeEnvelopeData(data, &upserted); err != nil {
		fmt.Fprintf(stderr, "decode provider response failed: %v\n", err)
		return 1
	}
	account := upserted.ProviderAccount
	fmt.Fprintf(stdout, "provider account %s %s %s\n", account.ID, account.Provider, account.Status)
	return 0
}

func runProvidersList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown providers list flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/provider-accounts") + queryString(options, "workspaceId", "appId", "provider")
	data, err := getPreflightJSON(client, endpoint, options["token"])
	if err != nil {
		fmt.Fprintf(stderr, "provider list failed: %v\n", err)
		return 1
	}
	var listed providerAccountsEnvelopeData
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode provider list failed: %v\n", err)
		return 1
	}
	for _, account := range listed.ProviderAccounts {
		fmt.Fprintf(stdout, "%s %s %s %s\n", account.ID, account.Provider, account.Status, account.DisplayName)
	}
	return 0
}

func runProvidersVerify(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":       os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId":  "local",
		"ascAPIURL":    defaultAppStoreConnectAPIURL,
		"playAPIURL":   defaultGooglePlayAPIURL,
		"sentryAPIURL": defaultSentryAPIURL,
	}
	var credentialRefs []string
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--display-name":
			if !readFlagValue(args, &index, options, "displayName", stderr) {
				return 2
			}
		case "--issuer-id":
			if !readFlagValue(args, &index, options, "issuerId", stderr) {
				return 2
			}
		case "--key-id":
			if !readFlagValue(args, &index, options, "keyId", stderr) {
				return 2
			}
		case "--private-key-env":
			if !readFlagValue(args, &index, options, "privateKeyEnv", stderr) {
				return 2
			}
		case "--private-key-path":
			if !readFlagValue(args, &index, options, "privateKeyPath", stderr) {
				return 2
			}
		case "--asc-api-url":
			if !readFlagValue(args, &index, options, "ascAPIURL", stderr) {
				return 2
			}
		case "--play-api-url":
			if !readFlagValue(args, &index, options, "playAPIURL", stderr) {
				return 2
			}
		case "--sentry-api-url":
			if !readFlagValue(args, &index, options, "sentryAPIURL", stderr) {
				return 2
			}
		case "--org-slug":
			if !readFlagValue(args, &index, options, "orgSlug", stderr) {
				return 2
			}
		case "--project-slug":
			if !readFlagValue(args, &index, options, "projectSlug", stderr) {
				return 2
			}
		case "--auth-token-env":
			if !readFlagValue(args, &index, options, "authTokenEnv", stderr) {
				return 2
			}
		case "--token-env":
			if !readFlagValue(args, &index, options, "tokenEnv", stderr) {
				return 2
			}
		case "--app-dir":
			if !readFlagValue(args, &index, options, "appDir", stderr) {
				return 2
			}
		case "--package-name":
			if !readFlagValue(args, &index, options, "packageName", stderr) {
				return 2
			}
		case "--service-account-json-env":
			if !readFlagValue(args, &index, options, "serviceAccountJSONEnv", stderr) {
				return 2
			}
		case "--service-account-json-path":
			if !readFlagValue(args, &index, options, "serviceAccountJSONPath", stderr) {
				return 2
			}
		case "--credential-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--credential-ref requires a value")
				return 2
			}
			credentialRefs = append(credentialRefs, value)
		default:
			fmt.Fprintf(stderr, "unknown providers verify flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "appId", "provider", "displayName"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	if options["provider"] == "google_cloud" {
		return runProvidersVerifyGoogleCloud(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "android_local" {
		return runProvidersVerifyAndroidLocal(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "expo" {
		return runProvidersVerifyExpo(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "eas" {
		return runProvidersVerifyEAS(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "google_play" {
		return runProvidersVerifyGooglePlay(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "google_oauth" {
		return runProvidersVerifyGoogleOAuth(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "apple_oauth" {
		return runProvidersVerifyAppleOAuth(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] == "sentry" {
		return runProvidersVerifySentry(options, credentialRefs, stdout, stderr, client)
	}
	if options["provider"] != "app_store_connect" {
		fmt.Fprintf(stderr, "providers verify does not support %q yet\n", options["provider"])
		return 2
	}
	if missing := requireOptions(options, "issuerId", "keyId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	privateKey, err := providerPrivateKey(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	probe, err := probeAppStoreConnectAPI(client, options["ascAPIURL"], options["issuerId"], options["keyId"], privateKey)
	if err != nil {
		fmt.Fprintf(stderr, "app store connect probe failed: %v\n", err)
		return 1
	}
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}

	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "app_store_connect",
			ProviderStatus: providerStatus,
			ExternalIDs: map[string]string{
				"issuerId": options["issuerId"],
				"keyId":    options["keyId"],
			},
			Capabilities:   []string{"asc.api.auth", "asc.apps.read"},
			Readiness:      probe,
			Platform:       "ios",
			Capability:     "asc.api.auth",
			AdapterVersion: "preflight-cli@app-store-connect.v1",
			Facts: map[string]any{
				"apiURL": strings.TrimRight(options["ascAPIURL"], "/"),
				"keyId":  options["keyId"],
			},
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyExpo(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	_, env, err := providerExpoToken(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	output, commandErr := runEASCommandWithEnv(providerAppDir(options), env, "whoami")
	accountName := strings.TrimSpace(string(output))
	probe := providerProbeResult{
		Status: "ready",
		Facts: map[string]any{
			"accountName":      accountName,
			"credentialSource": "preflight_secret_ref",
			"tokenEnv":         providerExpoTokenEnv(options),
			"cliCommand":       "eas whoami",
			"nonInteractive":   true,
		},
	}
	if commandErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "expo_token_auth_failed",
			BlockerMessage: commandErr.Error(),
			Facts: map[string]any{
				"credentialSource": "preflight_secret_ref",
				"tokenEnv":         providerExpoTokenEnv(options),
				"cliCommand":       "eas whoami",
				"nonInteractive":   true,
			},
		}
	}
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}
	externalIDs := map[string]string{}
	if accountName != "" {
		externalIDs["accountName"] = accountName
	}

	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "expo",
			ProviderStatus: providerStatus,
			ExternalIDs:    externalIDs,
			Capabilities:   []string{"expo.api.auth", "expo.account.read"},
			Readiness:      probe,
			Capability:     "expo.api.auth",
			AdapterVersion: "preflight-cli@expo.v1",
			Facts:          probe.Facts,
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyEAS(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	_, env, err := providerExpoToken(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	appDir := providerAppDir(options)
	output, commandErr := runEASCommandWithEnv(appDir, env, "config", "--json", "--non-interactive")
	externalIDs := map[string]string{}
	facts := map[string]any{
		"appDir":           appDir,
		"credentialSource": "preflight_secret_ref",
		"tokenEnv":         providerExpoTokenEnv(options),
		"cliCommand":       "eas config --json --non-interactive",
		"nonInteractive":   true,
	}
	probe := providerProbeResult{Status: "ready"}
	if commandErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "eas_non_interactive_probe_failed",
			BlockerMessage: commandErr.Error(),
			Facts:          facts,
		}
	} else {
		parsedExternalIDs, parsedFacts, parseErr := parseEASProviderConfigOutput(output)
		for key, value := range parsedExternalIDs {
			externalIDs[key] = value
		}
		for key, value := range parsedFacts {
			facts[key] = value
		}
		if parseErr != nil {
			probe = providerProbeResult{
				Status:         "blocked",
				BlockerCode:    "eas_config_parse_failed",
				BlockerMessage: parseErr.Error(),
				Facts:          facts,
			}
		} else if strings.TrimSpace(externalIDs["projectId"]) == "" {
			probe = providerProbeResult{
				Status:         "blocked",
				BlockerCode:    "eas_project_id_missing",
				BlockerMessage: "EAS config did not include extra.eas.projectId.",
				Facts:          facts,
			}
		} else {
			probe.Facts = facts
		}
	}
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}

	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "eas",
			ProviderStatus: providerStatus,
			ExternalIDs:    externalIDs,
			Capabilities:   []string{"eas.cli.auth", "eas.project.config"},
			Readiness:      probe,
			Capability:     "eas.project.config",
			AdapterVersion: "preflight-cli@eas.v1",
			Facts:          probe.Facts,
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyGoogleCloud(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	account, accountErr := runProviderLocalCommand("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)")
	projectID, projectErr := runProviderLocalCommand("gcloud", "config", "get-value", "project")
	probe := providerProbeResult{Status: "ready"}
	if accountErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "gcloud_auth_unavailable",
			BlockerMessage: accountErr.Error(),
		}
	} else if strings.TrimSpace(account) == "" {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "gcloud_auth_missing",
			BlockerMessage: "gcloud did not report an active account",
		}
	} else if projectErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "gcloud_project_unavailable",
			BlockerMessage: projectErr.Error(),
		}
	} else if strings.TrimSpace(projectID) == "" {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "gcloud_project_missing",
			BlockerMessage: "gcloud did not report an active project",
		}
	}
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}
	externalIDs := map[string]string{}
	if strings.TrimSpace(account) != "" {
		externalIDs["account"] = strings.TrimSpace(account)
	}
	if strings.TrimSpace(projectID) != "" {
		externalIDs["projectId"] = strings.TrimSpace(projectID)
	}
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "google_cloud",
			ProviderStatus: providerStatus,
			ExternalIDs:    externalIDs,
			Capabilities:   []string{"gcloud.cli.auth", "google.cloud.project"},
			Readiness:      probe,
			Capability:     "gcloud.cli.auth",
			AdapterVersion: "preflight-cli@google-cloud.v1",
			Facts: map[string]any{
				"account":   strings.TrimSpace(account),
				"projectId": strings.TrimSpace(projectID),
			},
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyGoogleOAuth(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	projectID, projectErr := runProviderLocalCommand("gcloud", "config", "get-value", "project")
	probe := providerProbeResult{
		Status:         "blocked",
		BlockerCode:    "google_auth_platform_clients_require_import",
		BlockerMessage: "Google Sign-In OAuth clients must be created or imported through Preflight OAuth client records; IAM OAuth clients are not treated as Google Auth Platform app clients.",
	}
	if projectErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "gcloud_project_unavailable",
			BlockerMessage: projectErr.Error(),
		}
	} else if strings.TrimSpace(projectID) == "" {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "gcloud_project_missing",
			BlockerMessage: "gcloud did not report an active project",
		}
	}

	providerStatus := "needs_setup"
	if projectErr != nil {
		providerStatus = "degraded"
	}
	trimmedProjectID := strings.TrimSpace(projectID)
	externalIDs := map[string]string{}
	if trimmedProjectID != "" {
		externalIDs["projectId"] = trimmedProjectID
	}
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "google_oauth",
			ProviderStatus: providerStatus,
			ExternalIDs:    externalIDs,
			Capabilities:   []string{"google_oauth.management", "oauth.google.ios", "oauth.google.android", "oauth.google.web"},
			Readiness:      probe,
			Capability:     "google_oauth.management",
			AdapterVersion: "preflight-cli@google-oauth.v1",
			Facts: map[string]any{
				"projectId":     trimmedProjectID,
				"clientSource":  "preflight_oauth_client_records",
				"setupCommand":  "preflight oauth-clients configure",
				"providerSetup": "Google Auth Platform Clients console",
			},
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyAppleOAuth(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if missing := requireOptions(options, "issuerId", "keyId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	privateKey, err := providerPrivateKey(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	probe, err := probeAppleOAuthAPI(client, options["ascAPIURL"], options["issuerId"], options["keyId"], privateKey)
	if err != nil {
		fmt.Fprintf(stderr, "apple oauth probe failed: %v\n", err)
		return 1
	}
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "apple_oauth",
			ProviderStatus: providerStatus,
			ExternalIDs: map[string]string{
				"issuerId": options["issuerId"],
				"keyId":    options["keyId"],
			},
			Capabilities:   []string{"apple_oauth.management", "oauth.apple.app_id", "oauth.apple.services_id"},
			Readiness:      probe,
			Capability:     "apple_oauth.management",
			AdapterVersion: "preflight-cli@apple-oauth.v1",
			Facts:          probe.Facts,
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifySentry(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if missing := requireOptions(options, "orgSlug", "projectSlug", "authTokenEnv"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	authToken := strings.TrimSpace(os.Getenv(options["authTokenEnv"]))
	if authToken == "" {
		fmt.Fprintf(stderr, "environment variable %s is empty\n", options["authTokenEnv"])
		return 2
	}
	project, probe := probeSentryProjectAPI(client, options["sentryAPIURL"], options["orgSlug"], options["projectSlug"], authToken)
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}
	externalIDs := map[string]string{
		"orgSlug":     options["orgSlug"],
		"projectSlug": options["projectSlug"],
	}
	if project.ID != "" {
		externalIDs["projectId"] = project.ID
	}
	if project.Platform != "" {
		externalIDs["platform"] = project.Platform
	}
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "sentry",
			ProviderStatus: providerStatus,
			ExternalIDs:    externalIDs,
			Capabilities: []string{
				"sentry.project.api",
				"sentry.source_maps.upload",
				"sentry.release.health",
			},
			Readiness:      probe,
			Capability:     "sentry.source_maps.upload",
			AdapterVersion: "preflight-cli@sentry.v1",
			Facts:          probe.Facts,
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyAndroidLocal(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	devices, devicesErr := runProviderLocalCommand("adb", "devices")
	avds, avdsErr := runProviderLocalCommand("emulator", "-list-avds")
	probe := providerProbeResult{Status: "ready"}
	if devicesErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "android_adb_unavailable",
			BlockerMessage: devicesErr.Error(),
		}
	} else if avdsErr != nil {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "android_emulator_unavailable",
			BlockerMessage: avdsErr.Error(),
		}
	} else if strings.TrimSpace(avds) == "" {
		probe = providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "android_avd_missing",
			BlockerMessage: "emulator did not report any Android virtual devices",
		}
	}
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "android_local",
			ProviderStatus: providerStatus,
			ExternalIDs: map[string]string{
				"host": localHostname(),
			},
			Capabilities:   []string{"android.adb", "android.emulator"},
			Readiness:      probe,
			Platform:       "android",
			Capability:     "android.local.management",
			AdapterVersion: "preflight-cli@android-local.v1",
			Facts: map[string]any{
				"adbDevicesOutput": strings.TrimSpace(devices),
				"avds":             nonEmptyLines(avds),
			},
		},
		stdout,
		stderr,
	)
}

func runProvidersVerifyGooglePlay(options map[string]string, credentialRefs []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if missing := requireOptions(options, "packageName"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	serviceAccountContent, err := providerServiceAccountJSON(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	serviceAccount, err := parseGoogleServiceAccount(serviceAccountContent)
	if err != nil {
		fmt.Fprintf(stderr, "parse Google Play service account: %v\n", err)
		return 2
	}
	token, err := googleServiceAccountAccessToken(client, serviceAccount, googlePlayAndroidPublisherScope, time.Now())
	if err != nil {
		return recordGooglePlayBlocked(options, credentialRefs, serviceAccount, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "play_service_account_auth_failed",
			BlockerMessage: err.Error(),
		}, stdout, stderr, client)
	}
	probe := probeGooglePlayAPI(client, options["playAPIURL"], token, options["packageName"])
	providerStatus := "connected"
	if probe.Status != "ready" {
		providerStatus = "degraded"
	}
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "google_play",
			ProviderStatus: providerStatus,
			ExternalIDs: map[string]string{
				"clientEmail": serviceAccount.ClientEmail,
				"packageName": options["packageName"],
				"projectId":   serviceAccount.ProjectID,
			},
			Capabilities:   []string{"play.publisher.api", "play.edits.tracks.read", "play.internal.submit"},
			Readiness:      probe,
			Platform:       "android",
			Capability:     "play.publisher.api",
			AdapterVersion: "preflight-cli@google-play.v1",
			Facts: map[string]any{
				"apiURL":             strings.TrimRight(options["playAPIURL"], "/"),
				"clientEmail":        serviceAccount.ClientEmail,
				"packageName":        options["packageName"],
				"projectId":          serviceAccount.ProjectID,
				"trackCount":         probe.Facts["trackCount"],
				"tracks":             probe.Facts["tracks"],
				"editCreatedAndGone": probe.Facts["editCreatedAndGone"],
			},
		},
		stdout,
		stderr,
	)
}

func recordGooglePlayBlocked(options map[string]string, credentialRefs []string, serviceAccount googleServiceAccount, probe providerProbeResult, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	return recordProviderVerification(
		client,
		options,
		credentialRefs,
		providerVerificationRecord{
			Provider:       "google_play",
			ProviderStatus: "degraded",
			ExternalIDs: map[string]string{
				"clientEmail": serviceAccount.ClientEmail,
				"packageName": options["packageName"],
				"projectId":   serviceAccount.ProjectID,
			},
			Capabilities:   []string{"play.publisher.api", "play.edits.tracks.read", "play.internal.submit"},
			Readiness:      probe,
			Platform:       "android",
			Capability:     "play.publisher.api",
			AdapterVersion: "preflight-cli@google-play.v1",
			Facts: map[string]any{
				"apiURL":      strings.TrimRight(options["playAPIURL"], "/"),
				"clientEmail": serviceAccount.ClientEmail,
				"packageName": options["packageName"],
				"projectId":   serviceAccount.ProjectID,
			},
		},
		stdout,
		stderr,
	)
}

type providerVerificationRecord struct {
	Provider       string
	ProviderStatus string
	ExternalIDs    map[string]string
	Capabilities   []string
	Readiness      providerProbeResult
	Platform       string
	Capability     string
	AdapterVersion string
	Facts          map[string]any
}

func recordProviderVerification(client *http.Client, options map[string]string, credentialRefs []string, record providerVerificationRecord, stdout io.Writer, stderr io.Writer) int {
	providerData, err := postPreflightJSON(
		client,
		runnerEndpoint(options["apiURL"], "/api/preflight/v1/provider-accounts"),
		options["token"],
		map[string]any{
			"workspaceId":            options["workspaceId"],
			"appId":                  options["appId"],
			"provider":               record.Provider,
			"displayName":            options["displayName"],
			"externalIds":            record.ExternalIDs,
			"capabilities":           record.Capabilities,
			"credentialReferenceIds": credentialRefs,
			"status":                 record.ProviderStatus,
		},
	)
	if err != nil {
		fmt.Fprintf(stderr, "provider verify failed: %v\n", err)
		return 1
	}
	var upserted providerAccountsEnvelopeData
	if err := decodeEnvelopeData(providerData, &upserted); err != nil {
		fmt.Fprintf(stderr, "decode provider verify response failed: %v\n", err)
		return 1
	}
	account := upserted.ProviderAccount
	if err := createProviderVerificationCredentialFlow(client, options, credentialRefs, account, record); err != nil {
		fmt.Fprintf(stderr, "provider credential flow verify failed: %v\n", err)
		return 1
	}
	readinessPayload := map[string]any{
		"workspaceId":            options["workspaceId"],
		"providerAccountId":      account.ID,
		"provider":               record.Provider,
		"capability":             record.Capability,
		"status":                 record.Readiness.Status,
		"adapterVersion":         record.AdapterVersion,
		"facts":                  record.Facts,
		"credentialReferenceIds": credentialRefs,
	}
	if record.Platform != "" {
		readinessPayload["platform"] = record.Platform
	}
	if record.Readiness.BlockerCode != "" {
		readinessPayload["blockerCode"] = record.Readiness.BlockerCode
	}
	if record.Readiness.BlockerMessage != "" {
		readinessPayload["blockerMessage"] = record.Readiness.BlockerMessage
	}
	readinessData, err := postPreflightJSON(
		client,
		runnerEndpoint(options["apiURL"], "/api/preflight/v1/apps/"+url.PathEscape(options["appId"])+"/provider-readiness"),
		options["token"],
		readinessPayload,
	)
	if err != nil {
		fmt.Fprintf(stderr, "provider readiness verify failed: %v\n", err)
		return 1
	}
	var recorded providerReadinessRecordEnvelopeData
	if err := decodeEnvelopeData(readinessData, &recorded); err != nil {
		fmt.Fprintf(stderr, "decode provider readiness verify response failed: %v\n", err)
		return 1
	}
	readiness := recorded.ProviderReadiness
	fmt.Fprintf(stdout, "verified provider %s %s %s\n", account.ID, account.Provider, readiness.Status)
	if readiness.Status != "ready" {
		return 1
	}
	return 0
}

func createProviderVerificationCredentialFlow(client *http.Client, options map[string]string, credentialRefs []string, account providerAccountSummary, record providerVerificationRecord) error {
	payload := map[string]any{
		"workspaceId":        options["workspaceId"],
		"appId":              options["appId"],
		"provider":           record.Provider,
		"capability":         record.Capability,
		"action":             "inspect",
		"status":             providerVerificationCredentialFlowStatus(record.Readiness.Status),
		"secretReferenceIds": credentialRefs,
		"prompt":             providerVerificationCredentialFlowPrompt(record),
		"nextAction":         providerVerificationCredentialFlowNextAction(record),
		"metadata":           providerVerificationCredentialFlowMetadata(record),
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options["apiURL"], "/api/preflight/v1/provider-accounts/"+url.PathEscape(account.ID)+"/credential-flows"),
		options["token"],
		payload,
	)
	if err != nil {
		return err
	}
	var created credentialFlowEnvelopeData
	if err := decodeEnvelopeData(data, &created); err != nil {
		return fmt.Errorf("decode provider credential flow response failed: %w", err)
	}
	return nil
}

func providerVerificationCredentialFlowStatus(readinessStatus string) string {
	switch readinessStatus {
	case "ready":
		return "completed"
	case "blocked":
		return "waiting_for_human"
	case "unknown":
		return "pending"
	default:
		return "failed"
	}
}

func providerVerificationCredentialFlowPrompt(record providerVerificationRecord) string {
	if strings.TrimSpace(record.Readiness.BlockerMessage) != "" {
		return strings.TrimSpace(record.Readiness.BlockerMessage)
	}
	if record.Readiness.Status == "ready" {
		return "Preflight verified " + record.Provider + " " + record.Capability + " readiness."
	}
	return "Preflight needs provider setup for " + record.Provider + " " + record.Capability + "."
}

func providerVerificationCredentialFlowNextAction(record providerVerificationRecord) string {
	if record.Readiness.Status == "ready" {
		return "ready"
	}
	switch record.Provider {
	case "expo":
		return "preflight credentials create --provider expo --purpose api_token --key EXPO_TOKEN --lane development --value-env EXPO_TOKEN"
	case "eas":
		return "preflight providers verify --provider eas --credential-ref <EXPO_TOKEN_SECRET_REF> --app-dir <APP_DIR>"
	case "google_oauth", "apple_oauth":
		return "preflight oauth-clients configure --app-dir <APP_DIR> --all-required"
	case "app_store_connect":
		return "preflight providers verify --provider app_store_connect --credential-ref <ASC_API_KEY_SECRET_REF>"
	case "google_play":
		return "preflight providers verify --provider google_play --credential-ref <GOOGLE_PLAY_SERVICE_ACCOUNT_SECRET_REF>"
	case "google_cloud":
		return "preflight providers verify --provider google_cloud --app-dir <APP_DIR>"
	case "android_local":
		return "install Android SDK platform tools and create an Android Virtual Device"
	case "sentry":
		return "preflight providers verify --provider sentry --credential-ref <SENTRY_AUTH_TOKEN_SECRET_REF>"
	default:
		return "resolve_provider_readiness"
	}
}

func providerVerificationCredentialFlowMetadata(record providerVerificationRecord) map[string]any {
	metadata := map[string]any{
		"adapterVersion": record.AdapterVersion,
		"providerStatus": record.ProviderStatus,
	}
	if record.Platform != "" {
		metadata["platform"] = record.Platform
	}
	if record.Readiness.BlockerCode != "" {
		metadata["blockerCode"] = record.Readiness.BlockerCode
	}
	if record.Readiness.Facts != nil {
		metadata["facts"] = record.Readiness.Facts
	}
	return metadata
}

func providerExpoTokenEnv(options map[string]string) string {
	if value := strings.TrimSpace(options["tokenEnv"]); value != "" {
		return value
	}
	return "EXPO_TOKEN"
}

func providerExpoToken(options map[string]string) (string, map[string]string, error) {
	envName := providerExpoTokenEnv(options)
	token := strings.TrimSpace(os.Getenv(envName))
	if token == "" {
		return "", nil, fmt.Errorf("environment variable %s is empty", envName)
	}
	return token, map[string]string{"EXPO_TOKEN": token}, nil
}

func providerAppDir(options map[string]string) string {
	if value := strings.TrimSpace(options["appDir"]); value != "" {
		return value
	}
	return "."
}

func parseEASProviderConfigOutput(output []byte) (map[string]string, map[string]any, error) {
	var decoded map[string]any
	if err := decodeEASJSONOutput(output, &decoded); err != nil {
		return nil, nil, fmt.Errorf("decode EAS config JSON output: %w", err)
	}
	expoConfig, _ := decoded["expo"].(map[string]any)
	if expoConfig == nil {
		expoConfig = decoded
	}

	projectID := readNestedMapString(expoConfig, "extra", "eas", "projectId")
	if projectID == "" {
		projectID = readNestedMapString(decoded, "extra", "eas", "projectId")
	}
	owner := readMapString(expoConfig, "owner")
	slug := readMapString(expoConfig, "slug")
	name := readMapString(expoConfig, "name")
	profiles := easProviderBuildProfiles(decoded)

	externalIDs := map[string]string{}
	if projectID != "" {
		externalIDs["projectId"] = projectID
	}
	if owner != "" {
		externalIDs["owner"] = owner
	}
	if slug != "" {
		externalIDs["slug"] = slug
	}

	return externalIDs, map[string]any{
		"projectId":         projectID,
		"owner":             owner,
		"slug":              slug,
		"name":              name,
		"buildProfileCount": len(profiles),
		"buildProfiles":     profiles,
	}, nil
}

func easProviderBuildProfiles(config map[string]any) []string {
	var build map[string]any
	if easConfig, ok := config["eas"].(map[string]any); ok {
		build, _ = easConfig["build"].(map[string]any)
	}
	if build == nil {
		build, _ = config["build"].(map[string]any)
	}
	profiles := make([]string, 0, len(build))
	for profile := range build {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	return profiles
}

func runProviderLocalCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		details := strings.TrimSpace(stderr.String())
		if details == "" {
			details = strings.TrimSpace(stdout.String())
		}
		if details != "" {
			return "", fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, details)
		}
		return "", fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func localHostname() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "unknown"
	}
	return hostname
}

func nonEmptyLines(value string) []string {
	lines := strings.Split(value, "\n")
	items := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

type providerProbeResult struct {
	Status         string
	BlockerCode    string
	BlockerMessage string
	Facts          map[string]any
}

func parseGoogleOAuthClients(content string) ([]map[string]string, error) {
	if strings.TrimSpace(content) == "" {
		return []map[string]string{}, nil
	}
	var rawClients []struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		ClientID    string `json:"clientId"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal([]byte(content), &rawClients); err != nil {
		return nil, fmt.Errorf("decode Google OAuth clients: %w", err)
	}
	clients := make([]map[string]string, 0, len(rawClients))
	for _, rawClient := range rawClients {
		client := map[string]string{}
		if strings.TrimSpace(rawClient.Name) != "" {
			client["name"] = strings.TrimSpace(rawClient.Name)
		}
		if strings.TrimSpace(rawClient.DisplayName) != "" {
			client["displayName"] = strings.TrimSpace(rawClient.DisplayName)
		}
		if strings.TrimSpace(rawClient.ClientID) != "" {
			client["clientId"] = strings.TrimSpace(rawClient.ClientID)
		}
		if strings.TrimSpace(rawClient.State) != "" {
			client["state"] = strings.TrimSpace(rawClient.State)
		}
		if len(client) > 0 {
			clients = append(clients, client)
		}
	}
	return clients, nil
}

func providerPrivateKey(options map[string]string) (string, error) {
	if options["privateKeyEnv"] != "" {
		value := os.Getenv(options["privateKeyEnv"])
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("environment variable %s is empty", options["privateKeyEnv"])
		}
		return value, nil
	}
	if options["privateKeyPath"] != "" {
		content, err := os.ReadFile(options["privateKeyPath"])
		if err != nil {
			return "", fmt.Errorf("read App Store Connect private key: %w", err)
		}
		if strings.TrimSpace(string(content)) == "" {
			return "", fmt.Errorf("App Store Connect private key file is empty")
		}
		return string(content), nil
	}
	return "", fmt.Errorf("missing --private-key-env or --private-key-path")
}

type googleServiceAccount struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	TokenURI     string `json:"token_uri"`
}

func providerServiceAccountJSON(options map[string]string) (string, error) {
	if options["serviceAccountJSONEnv"] != "" {
		value := os.Getenv(options["serviceAccountJSONEnv"])
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("environment variable %s is empty", options["serviceAccountJSONEnv"])
		}
		return value, nil
	}
	if options["serviceAccountJSONPath"] != "" {
		content, err := os.ReadFile(options["serviceAccountJSONPath"])
		if err != nil {
			return "", fmt.Errorf("read Google Play service account JSON: %w", err)
		}
		if strings.TrimSpace(string(content)) == "" {
			return "", fmt.Errorf("Google Play service account JSON file is empty")
		}
		return string(content), nil
	}
	return "", fmt.Errorf("missing --service-account-json-env or --service-account-json-path")
}

func parseGoogleServiceAccount(content string) (googleServiceAccount, error) {
	var serviceAccount googleServiceAccount
	if err := json.Unmarshal([]byte(content), &serviceAccount); err != nil {
		return googleServiceAccount{}, err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "project_id", value: serviceAccount.ProjectID},
		{name: "private_key_id", value: serviceAccount.PrivateKeyID},
		{name: "private_key", value: serviceAccount.PrivateKey},
		{name: "client_email", value: serviceAccount.ClientEmail},
		{name: "token_uri", value: serviceAccount.TokenURI},
	} {
		if strings.TrimSpace(field.value) == "" {
			return googleServiceAccount{}, fmt.Errorf("missing %s", field.name)
		}
	}
	return serviceAccount, nil
}

func googleServiceAccountAccessToken(client *http.Client, serviceAccount googleServiceAccount, scope string, issuedAt time.Time) (string, error) {
	assertion, err := googleServiceAccountJWT(serviceAccount, scope, issuedAt)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	request, err := http.NewRequest(http.MethodPost, serviceAccount.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build Google OAuth token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read Google OAuth token response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = fmt.Sprintf("Google OAuth token endpoint returned HTTP %d", response.StatusCode)
		}
		return "", errors.New(message)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode Google OAuth token response: %w", err)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return "", fmt.Errorf("Google OAuth token response did not include an access token")
	}
	if parsed.TokenType != "" && !strings.EqualFold(parsed.TokenType, "Bearer") {
		return "", fmt.Errorf("Google OAuth token response used unsupported token type %q", parsed.TokenType)
	}
	return parsed.AccessToken, nil
}

func googleServiceAccountJWT(serviceAccount googleServiceAccount, scope string, issuedAt time.Time) (string, error) {
	privateKey, err := parseRSAPrivateKey(serviceAccount.PrivateKey)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": serviceAccount.PrivateKeyID,
		"typ": "JWT",
	})
	if err != nil {
		return "", fmt.Errorf("encode Google service account JWT header: %w", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss":   serviceAccount.ClientEmail,
		"scope": scope,
		"aud":   serviceAccount.TokenURI,
		"iat":   issuedAt.Unix(),
		"exp":   issuedAt.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encode Google service account JWT payload: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign Google service account JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseRSAPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("decode Google service account private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Google service account private key must be an RSA key")
		}
		return privateKey, nil
	}
	pkcs1Key, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if pkcs1Err != nil {
		return nil, fmt.Errorf("parse Google service account private key: %w", err)
	}
	return pkcs1Key, nil
}

func probeGooglePlayAPI(client *http.Client, baseURL string, accessToken string, packageName string) providerProbeResult {
	editID, err := googlePlayInsertEdit(client, baseURL, accessToken, packageName)
	if err != nil {
		return googlePlayBlockedProbe(err)
	}
	cleanupDone := false
	defer func() {
		if !cleanupDone {
			_ = googlePlayDeleteEdit(client, baseURL, accessToken, packageName, editID)
		}
	}()
	tracks, err := googlePlayListTracks(client, baseURL, accessToken, packageName, editID)
	if err != nil {
		return googlePlayBlockedProbe(err)
	}
	if err := googlePlayDeleteEdit(client, baseURL, accessToken, packageName, editID); err != nil {
		return providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "play_edit_cleanup_failed",
			BlockerMessage: err.Error(),
			Facts: map[string]any{
				"editId": editID,
			},
		}
	}
	cleanupDone = true
	return providerProbeResult{
		Status: "ready",
		Facts: map[string]any{
			"editCreatedAndGone": true,
			"editId":             editID,
			"trackCount":         len(tracks),
			"tracks":             tracks,
		},
	}
}

func googlePlayBlockedProbe(err error) providerProbeResult {
	message := err.Error()
	blockerCode := "play_api_unavailable"
	if strings.Contains(message, "HTTP 401") || strings.Contains(message, "HTTP 403") {
		blockerCode = "play_auth_failed"
	} else if strings.Contains(message, "HTTP 404") {
		blockerCode = "play_package_not_found"
	}
	return providerProbeResult{
		Status:         "blocked",
		BlockerCode:    blockerCode,
		BlockerMessage: message,
	}
}

func googlePlayInsertEdit(client *http.Client, baseURL string, accessToken string, packageName string) (string, error) {
	body, err := googlePlayRequestJSON(
		client,
		http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/androidpublisher/v3/applications/"+url.PathEscape(packageName)+"/edits",
		accessToken,
		strings.NewReader("{}"),
	)
	if err != nil {
		return "", err
	}
	var edit struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &edit); err != nil {
		return "", fmt.Errorf("decode Google Play edit response: %w", err)
	}
	if strings.TrimSpace(edit.ID) == "" {
		return "", fmt.Errorf("Google Play edit response did not include an edit ID")
	}
	return edit.ID, nil
}

func googlePlayListTracks(client *http.Client, baseURL string, accessToken string, packageName string, editID string) ([]string, error) {
	body, err := googlePlayRequestJSON(
		client,
		http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/androidpublisher/v3/applications/"+url.PathEscape(packageName)+"/edits/"+url.PathEscape(editID)+"/tracks",
		accessToken,
		nil,
	)
	if err != nil {
		return nil, err
	}
	var response struct {
		Tracks []struct {
			Track string `json:"track"`
		} `json:"tracks"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode Google Play tracks response: %w", err)
	}
	tracks := make([]string, 0, len(response.Tracks))
	for _, track := range response.Tracks {
		if strings.TrimSpace(track.Track) != "" {
			tracks = append(tracks, track.Track)
		}
	}
	sort.Strings(tracks)
	return tracks, nil
}

func googlePlayDeleteEdit(client *http.Client, baseURL string, accessToken string, packageName string, editID string) error {
	_, err := googlePlayRequestJSON(
		client,
		http.MethodDelete,
		strings.TrimRight(baseURL, "/")+"/androidpublisher/v3/applications/"+url.PathEscape(packageName)+"/edits/"+url.PathEscape(editID),
		accessToken,
		nil,
	)
	return err
}

func googlePlayRequestJSON(client *http.Client, method string, endpoint string, accessToken string, body io.Reader) ([]byte, error) {
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("build Google Play request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read Google Play response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(content))
		if message == "" {
			message = fmt.Sprintf("Google Play returned HTTP %d", response.StatusCode)
		}
		return nil, fmt.Errorf("Google Play returned HTTP %d: %s", response.StatusCode, message)
	}
	return content, nil
}

func probeAppStoreConnectAPI(client *http.Client, baseURL string, issuerID string, keyID string, privateKeyPEM string) (providerProbeResult, error) {
	token, err := appStoreConnectJWT(issuerID, keyID, privateKeyPEM, time.Now())
	if err != nil {
		return providerProbeResult{}, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/apps?limit=1"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return providerProbeResult{}, fmt.Errorf("build App Store Connect request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "asc_api_unreachable",
			BlockerMessage: err.Error(),
		}, nil
	}
	defer response.Body.Close()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return providerProbeResult{Status: "ready"}, nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	blockerCode := "asc_api_unavailable"
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		blockerCode = "asc_auth_failed"
	}
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = fmt.Sprintf("App Store Connect returned HTTP %d", response.StatusCode)
	}
	return providerProbeResult{
		Status:         "blocked",
		BlockerCode:    blockerCode,
		BlockerMessage: message,
	}, nil
}

func probeAppleOAuthAPI(client *http.Client, baseURL string, issuerID string, keyID string, privateKeyPEM string) (providerProbeResult, error) {
	token, err := appStoreConnectJWT(issuerID, keyID, privateKeyPEM, time.Now())
	if err != nil {
		return providerProbeResult{}, err
	}
	query := url.Values{}
	query.Set("limit", "1")
	query.Set("include", "bundleIdCapabilities")
	query.Set("fields[bundleIds]", "identifier,name,platform,bundleIdCapabilities")
	query.Set("fields[bundleIdCapabilities]", "capabilityType")
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/bundleIds?" + query.Encode()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return providerProbeResult{}, fmt.Errorf("build Apple OAuth request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "apple_oauth_api_unreachable",
			BlockerMessage: err.Error(),
			Facts: map[string]any{
				"apiURL": strings.TrimRight(baseURL, "/"),
				"keyId":  keyID,
			},
		}, nil
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, 65536))
	if readErr != nil {
		return providerProbeResult{}, fmt.Errorf("read Apple OAuth response: %w", readErr)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		blockerCode := "apple_oauth_api_unavailable"
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			blockerCode = "apple_oauth_auth_failed"
		}
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = fmt.Sprintf("App Store Connect returned HTTP %d", response.StatusCode)
		}
		return providerProbeResult{
			Status:         "blocked",
			BlockerCode:    blockerCode,
			BlockerMessage: message,
			Facts: map[string]any{
				"apiURL": strings.TrimRight(baseURL, "/"),
				"keyId":  keyID,
			},
		}, nil
	}

	var parsed struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
				Platform   string `json:"platform"`
			} `json:"attributes"`
		} `json:"data"`
		Included []struct {
			Type       string `json:"type"`
			Attributes struct {
				CapabilityType string `json:"capabilityType"`
			} `json:"attributes"`
		} `json:"included"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return providerProbeResult{}, fmt.Errorf("decode Apple OAuth bundle IDs response: %w", err)
	}

	bundleIDs := make([]map[string]string, 0, len(parsed.Data))
	for _, bundle := range parsed.Data {
		item := map[string]string{}
		if strings.TrimSpace(bundle.ID) != "" {
			item["id"] = strings.TrimSpace(bundle.ID)
		}
		if strings.TrimSpace(bundle.Attributes.Identifier) != "" {
			item["identifier"] = strings.TrimSpace(bundle.Attributes.Identifier)
		}
		if strings.TrimSpace(bundle.Attributes.Name) != "" {
			item["name"] = strings.TrimSpace(bundle.Attributes.Name)
		}
		if strings.TrimSpace(bundle.Attributes.Platform) != "" {
			item["platform"] = strings.TrimSpace(bundle.Attributes.Platform)
		}
		if len(item) > 0 {
			bundleIDs = append(bundleIDs, item)
		}
	}

	signInWithAppleCapabilityCount := 0
	for _, included := range parsed.Included {
		if included.Type == "bundleIdCapabilities" && included.Attributes.CapabilityType == "SIGN_IN_WITH_APPLE" {
			signInWithAppleCapabilityCount += 1
		}
	}
	return providerProbeResult{
		Status: "ready",
		Facts: map[string]any{
			"apiURL":                         strings.TrimRight(baseURL, "/"),
			"keyId":                          keyID,
			"bundleIdCount":                  len(parsed.Data),
			"bundleIds":                      bundleIDs,
			"signInWithAppleCapabilityCount": signInWithAppleCapabilityCount,
		},
	}, nil
}

type sentryProjectProbe struct {
	ID       string
	Slug     string
	Name     string
	Platform string
	Access   []string
}

func probeSentryProjectAPI(client *http.Client, baseURL string, orgSlug string, projectSlug string, authToken string) (sentryProjectProbe, providerProbeResult) {
	trimmedBaseURL := strings.TrimRight(baseURL, "/")
	facts := map[string]any{
		"apiURL":                  trimmedBaseURL,
		"orgSlug":                 orgSlug,
		"projectSlug":             projectSlug,
		"sourceMapUploadTooling":  "sentry-cli-or-expo",
		"debugIdArtifactStrategy": true,
		"requiredScopes":          []string{"project:read", "project:releases"},
	}
	endpoint := trimmedBaseURL + "/api/0/projects/" + url.PathEscape(orgSlug) + "/" + url.PathEscape(projectSlug) + "/"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return sentryProjectProbe{}, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "sentry_request_invalid",
			BlockerMessage: err.Error(),
			Facts:          facts,
		}
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return sentryProjectProbe{}, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "sentry_api_unreachable",
			BlockerMessage: err.Error(),
			Facts:          facts,
		}
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, 65536))
	if readErr != nil {
		return sentryProjectProbe{}, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "sentry_response_unreadable",
			BlockerMessage: readErr.Error(),
			Facts:          facts,
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		blockerCode := "sentry_api_unavailable"
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			blockerCode = "sentry_auth_failed"
		case http.StatusNotFound:
			blockerCode = "sentry_project_not_found"
		}
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = fmt.Sprintf("Sentry returned HTTP %d", response.StatusCode)
		}
		return sentryProjectProbe{}, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    blockerCode,
			BlockerMessage: message,
			Facts:          facts,
		}
	}

	var parsed struct {
		ID       string   `json:"id"`
		Slug     string   `json:"slug"`
		Name     string   `json:"name"`
		Platform string   `json:"platform"`
		Access   []string `json:"access"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return sentryProjectProbe{}, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "sentry_response_invalid",
			BlockerMessage: err.Error(),
			Facts:          facts,
		}
	}
	project := sentryProjectProbe{
		ID:       strings.TrimSpace(parsed.ID),
		Slug:     strings.TrimSpace(parsed.Slug),
		Name:     strings.TrimSpace(parsed.Name),
		Platform: strings.TrimSpace(parsed.Platform),
		Access:   dedupeNonEmptyStrings(parsed.Access),
	}
	facts["projectId"] = project.ID
	facts["projectName"] = project.Name
	facts["projectPlatform"] = project.Platform
	facts["availableScopes"] = project.Access
	missingScopes := missingStrings(project.Access, []string{"project:read", "project:releases"})
	if len(missingScopes) > 0 {
		facts["missingScopes"] = missingScopes
		return project, providerProbeResult{
			Status:         "blocked",
			BlockerCode:    "sentry_source_map_scope_missing",
			BlockerMessage: "Sentry auth token must include project:read and project:releases for source-map readiness.",
			Facts:          facts,
		}
	}

	return project, providerProbeResult{
		Status: "ready",
		Facts:  facts,
	}
}

func dedupeNonEmptyStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func missingStrings(actual []string, required []string) []string {
	actualSet := map[string]bool{}
	for _, value := range actual {
		actualSet[value] = true
	}
	missing := make([]string, 0)
	for _, value := range required {
		if !actualSet[value] {
			missing = append(missing, value)
		}
	}
	return missing
}

func appStoreConnectJWT(issuerID string, keyID string, privateKeyPEM string, issuedAt time.Time) (string, error) {
	privateKey, err := parseAppStoreConnectPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{
		"alg": "ES256",
		"kid": keyID,
		"typ": "JWT",
	})
	if err != nil {
		return "", fmt.Errorf("encode App Store Connect JWT header: %w", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": issuerID,
		"iat": issuedAt.Unix(),
		"exp": issuedAt.Add(20 * time.Minute).Unix(),
		"aud": "appstoreconnect-v1",
	})
	if err != nil {
		return "", fmt.Errorf("encode App Store Connect JWT payload: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign App Store Connect JWT: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseAppStoreConnectPrivateKey(privateKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("decode App Store Connect private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse App Store Connect private key: %w", err)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("App Store Connect private key must be an ECDSA key")
	}
	if privateKey.Curve == nil || privateKey.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("App Store Connect private key must use the P-256 curve")
	}
	return privateKey, nil
}

func runProviderReadiness(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printProviderReadinessHelp(stdout)
		return 0
	}
	switch args[0] {
	case "record":
		return runProviderReadinessRecord(args[1:], stdout, stderr, client)
	case "list":
		return runProviderReadinessList(args[1:], stdout, stderr, client)
	case "plan":
		return runProviderReadinessPlan(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown provider-readiness command %q\n", args[0])
		printProviderReadinessHelp(stderr)
		return 2
	}
}

func printProviderReadinessHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight provider-readiness <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  record  Record app provider readiness")
	fmt.Fprintln(w, "  list    List app provider readiness")
	fmt.Fprintln(w, "  plan    Show the app provider setup plan for a platform/lane")
}

func runProviderReadinessRecord(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	var credentialRefs []string
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider-account-id":
			if !readFlagValue(args, &index, options, "providerAccountId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--platform":
			if !readFlagValue(args, &index, options, "platform", stderr) {
				return 2
			}
		case "--lane":
			if !readFlagValue(args, &index, options, "lane", stderr) {
				return 2
			}
		case "--capability":
			if !readFlagValue(args, &index, options, "capability", stderr) {
				return 2
			}
		case "--status":
			if !readFlagValue(args, &index, options, "status", stderr) {
				return 2
			}
		case "--blocker-code":
			if !readFlagValue(args, &index, options, "blockerCode", stderr) {
				return 2
			}
		case "--blocker-message":
			if !readFlagValue(args, &index, options, "blockerMessage", stderr) {
				return 2
			}
		case "--next-action":
			if !readFlagValue(args, &index, options, "nextAction", stderr) {
				return 2
			}
		case "--required-human-role":
			if !readFlagValue(args, &index, options, "requiredHumanRole", stderr) {
				return 2
			}
		case "--adapter-version":
			if !readFlagValue(args, &index, options, "adapterVersion", stderr) {
				return 2
			}
		case "--credential-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--credential-ref requires a value")
				return 2
			}
			credentialRefs = append(credentialRefs, value)
		default:
			fmt.Fprintf(stderr, "unknown provider-readiness record flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "appId", "provider", "capability", "status"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	payload := map[string]any{
		"workspaceId":            options["workspaceId"],
		"provider":               options["provider"],
		"capability":             options["capability"],
		"status":                 options["status"],
		"credentialReferenceIds": credentialRefs,
	}
	for _, key := range []string{"providerAccountId", "platform", "lane", "blockerCode", "blockerMessage", "nextAction", "requiredHumanRole", "adapterVersion"} {
		if options[key] != "" {
			payload[key] = options[key]
		}
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/apps/"+url.PathEscape(options["appId"])+"/provider-readiness")
	data, err := postPreflightJSON(client, endpoint, options["token"], payload)
	if err != nil {
		fmt.Fprintf(stderr, "provider readiness record failed: %v\n", err)
		return 1
	}
	var recorded providerReadinessRecordEnvelopeData
	if err := decodeEnvelopeData(data, &recorded); err != nil {
		fmt.Fprintf(stderr, "decode provider readiness response failed: %v\n", err)
		return 1
	}
	readiness := recorded.ProviderReadiness
	fmt.Fprintf(stdout, "provider readiness %s %s %s %s\n", readiness.ID, readiness.Provider, readiness.Capability, readiness.Status)
	return 0
}

func runProviderReadinessList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--capability":
			if !readFlagValue(args, &index, options, "capability", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown provider-readiness list flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "appId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/apps/"+url.PathEscape(options["appId"])+"/provider-readiness") + queryString(options, "workspaceId", "provider", "capability")
	data, err := getPreflightJSON(client, endpoint, options["token"])
	if err != nil {
		fmt.Fprintf(stderr, "provider readiness list failed: %v\n", err)
		return 1
	}
	var listed providerReadinessListEnvelopeData
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode provider readiness list failed: %v\n", err)
		return 1
	}
	for _, readiness := range listed.ProviderReadiness {
		fmt.Fprintf(stdout, "%s %s %s %s %s", readiness.ID, readiness.Provider, readiness.Capability, readiness.Status, readiness.BlockerCode)
		if readiness.NextAction != "" {
			fmt.Fprintf(stdout, " next_action=%q", readiness.NextAction)
		}
		if readiness.RequiredHumanRole != "" {
			fmt.Fprintf(stdout, " required_human_role=%q", readiness.RequiredHumanRole)
		}
		fmt.Fprintln(stdout)
	}
	return 0
}

func runProviderReadinessPlan(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--platform":
			if !readFlagValue(args, &index, options, "platform", stderr) {
				return 2
			}
		case "--lane":
			if !readFlagValue(args, &index, options, "lane", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown provider-readiness plan flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "appId", "platform", "lane"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/apps/"+url.PathEscape(options["appId"])+"/provider-setup-plan") + queryString(options, "workspaceId", "platform", "lane")
	data, err := getPreflightJSON(client, endpoint, options["token"])
	if err != nil {
		fmt.Fprintf(stderr, "provider setup plan failed: %v\n", err)
		return 1
	}
	var envelope providerSetupPlanEnvelopeData
	if err := decodeEnvelopeData(data, &envelope); err != nil {
		fmt.Fprintf(stderr, "decode provider setup plan failed: %v\n", err)
		return 1
	}
	plan := envelope.ProviderSetupPlan
	state := "ready"
	if !plan.Ready {
		state = "blocked"
	}
	fmt.Fprintf(stdout, "provider setup plan %s %s %s %s\n", plan.AppID, plan.Platform, plan.Lane, state)
	for _, requirement := range plan.Requirements {
		fmt.Fprintf(stdout, "%s %s %s %s", requirement.Provider, requirement.Capability, requirement.Status, requirement.BlockerCode)
		if requirement.NextAction != "" {
			fmt.Fprintf(stdout, " next_action=%q", requirement.NextAction)
		}
		if requirement.RequiredHumanRole != "" {
			fmt.Fprintf(stdout, " required_human_role=%q", requirement.RequiredHumanRole)
		}
		if requirement.Source != "" {
			fmt.Fprintf(stdout, " source=%q", requirement.Source)
		}
		fmt.Fprintln(stdout)
	}
	if !plan.Ready {
		return 1
	}
	return 0
}

func runCredentialFlows(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printCredentialFlowsHelp(stdout)
		return 0
	}
	switch args[0] {
	case "create":
		return runCredentialFlowsCreate(args[1:], stdout, stderr, client)
	case "list":
		return runCredentialFlowsList(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown credential-flows command %q\n", args[0])
		printCredentialFlowsHelp(stderr)
		return 2
	}
}

func printCredentialFlowsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight credential-flows <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  create Create a provider credential/setup flow")
	fmt.Fprintln(w, "  list   List provider credential/setup flows")
}

func runCredentialFlowsCreate(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	var credentialRefs []string
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider-account-id":
			if !readFlagValue(args, &index, options, "providerAccountId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--capability":
			if !readFlagValue(args, &index, options, "capability", stderr) {
				return 2
			}
		case "--action":
			if !readFlagValue(args, &index, options, "action", stderr) {
				return 2
			}
		case "--status":
			if !readFlagValue(args, &index, options, "status", stderr) {
				return 2
			}
		case "--prompt":
			if !readFlagValue(args, &index, options, "prompt", stderr) {
				return 2
			}
		case "--next-action":
			if !readFlagValue(args, &index, options, "nextAction", stderr) {
				return 2
			}
		case "--credential-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--credential-ref requires a value")
				return 2
			}
			credentialRefs = append(credentialRefs, value)
		default:
			fmt.Fprintf(stderr, "unknown credential-flows create flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "providerAccountId", "provider", "capability", "action"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	payload := map[string]any{
		"workspaceId":        options["workspaceId"],
		"provider":           options["provider"],
		"capability":         options["capability"],
		"action":             options["action"],
		"secretReferenceIds": credentialRefs,
	}
	for _, key := range []string{"appId", "status", "prompt", "nextAction"} {
		if options[key] != "" {
			payload[key] = options[key]
		}
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options["apiURL"], "/api/preflight/v1/provider-accounts/"+url.PathEscape(options["providerAccountId"])+"/credential-flows"),
		options["token"],
		payload,
	)
	if err != nil {
		fmt.Fprintf(stderr, "credential flow create failed: %v\n", err)
		return 1
	}
	var created credentialFlowEnvelopeData
	if err := decodeEnvelopeData(data, &created); err != nil {
		fmt.Fprintf(stderr, "decode credential flow create failed: %v\n", err)
		return 1
	}
	printCredentialFlowSummary(stdout, created.CredentialFlow)
	return 0
}

func runCredentialFlowsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider-account-id":
			if !readFlagValue(args, &index, options, "providerAccountId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--status":
			if !readFlagValue(args, &index, options, "status", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown credential-flows list flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "providerAccountId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/provider-accounts/"+url.PathEscape(options["providerAccountId"])+"/credential-flows") + queryString(options, "workspaceId", "appId", "provider", "status")
	data, err := getPreflightJSON(client, endpoint, options["token"])
	if err != nil {
		fmt.Fprintf(stderr, "credential flows list failed: %v\n", err)
		return 1
	}
	var listed credentialFlowsEnvelopeData
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode credential flows list failed: %v\n", err)
		return 1
	}
	for _, flow := range listed.CredentialFlows {
		printCredentialFlowSummary(stdout, flow)
	}
	return 0
}

func printCredentialFlowSummary(stdout io.Writer, flow credentialFlowSummary) {
	fmt.Fprintf(stdout, "credential flow %s %s %s %s %s", flow.ID, flow.Provider, flow.Capability, flow.Action, flow.Status)
	if flow.NextAction != "" {
		fmt.Fprintf(stdout, " next_action=%q", flow.NextAction)
	}
	fmt.Fprintln(stdout)
}

func runOAuthClients(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printOAuthClientsHelp(stdout)
		return 0
	}
	switch args[0] {
	case "upsert":
		return runOAuthClientsUpsert(args[1:], stdout, stderr, client)
	case "configure":
		return runOAuthClientsConfigure(args[1:], stdout, stderr, client)
	case "list":
		return runOAuthClientsList(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown oauth-clients command %q\n", args[0])
		printOAuthClientsHelp(stderr)
		return 2
	}
}

func printOAuthClientsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight oauth-clients <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  upsert  Create or update a Google/Apple OAuth client record")
	fmt.Fprintln(w, "  configure  Configure OAuth provider account, setup flow, and client record")
	fmt.Fprintln(w, "  list    List Google/Apple OAuth client records")
}

func runOAuthClientsConfigure(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		printOAuthClientsConfigureHelp(stdout)
		return 0
	}

	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	var redirectURIs []string
	var javascriptOrigins []string
	var scopes []string
	var secretRefs []string
	allRequired := false
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--all-required":
			allRequired = true
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-dir":
			if !readFlagValue(args, &index, options, "appDir", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--platform":
			if !readFlagValue(args, &index, options, "platform", stderr) {
				return 2
			}
		case "--provider-account-id":
			if !readFlagValue(args, &index, options, "providerAccountId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--provider-display-name":
			if !readFlagValue(args, &index, options, "providerDisplayName", stderr) {
				return 2
			}
		case "--client-kind":
			if !readFlagValue(args, &index, options, "clientKind", stderr) {
				return 2
			}
		case "--display-name":
			if !readFlagValue(args, &index, options, "displayName", stderr) {
				return 2
			}
		case "--google-cloud-project-id":
			if !readFlagValue(args, &index, options, "googleCloudProjectId", stderr) {
				return 2
			}
		case "--external-client-id":
			if !readFlagValue(args, &index, options, "externalClientId", stderr) {
				return 2
			}
		case "--bundle-id":
			if !readFlagValue(args, &index, options, "bundleId", stderr) {
				return 2
			}
		case "--android-package":
			if !readFlagValue(args, &index, options, "androidPackage", stderr) {
				return 2
			}
		case "--android-sha1":
			if !readFlagValue(args, &index, options, "androidSha1Fingerprint", stderr) {
				return 2
			}
		case "--apple-team-id":
			if !readFlagValue(args, &index, options, "appleTeamId", stderr) {
				return 2
			}
		case "--apple-services-id":
			if !readFlagValue(args, &index, options, "appleServicesId", stderr) {
				return 2
			}
		case "--redirect-uri":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--redirect-uri requires a value")
				return 2
			}
			redirectURIs = append(redirectURIs, value)
		case "--javascript-origin":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--javascript-origin requires a value")
				return 2
			}
			javascriptOrigins = append(javascriptOrigins, value)
		case "--scope":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--scope requires a value")
				return 2
			}
			scopes = append(scopes, value)
		case "--credential-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--credential-ref requires a value")
				return 2
			}
			secretRefs = append(secretRefs, value)
		default:
			fmt.Fprintf(stderr, "unknown oauth-clients configure flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if allRequired {
		if missing := requireOptions(options, "apiURL", "workspaceId", "appDir"); missing != "" {
			fmt.Fprintf(stderr, "missing %s\n", missing)
			return 2
		}
		payloads, err := buildAllRequiredOAuthClientConfigurePayloads(options, redirectURIs, javascriptOrigins, scopes, secretRefs)
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		for _, payload := range payloads {
			data, err := postPreflightJSON(client, runnerEndpoint(options["apiURL"], "/api/preflight/v1/oauth-clients/configure"), options["token"], payload)
			if err != nil {
				fmt.Fprintf(stderr, "oauth client configure failed: %v\n", err)
				return 1
			}
			var configured oauthClientConfigureEnvelopeData
			if err := decodeEnvelopeData(data, &configured); err != nil {
				fmt.Fprintf(stderr, "decode oauth client configure response failed: %v\n", err)
				return 1
			}
			oauthClient := configured.OAuthClient
			fmt.Fprintf(stdout, "oauth client %s %s %s %s\n", oauthClient.ID, oauthClient.Provider, oauthClient.ClientKind, oauthClient.Status)
			if configured.CredentialFlow.ID != "" {
				fmt.Fprintf(stdout, "credential flow %s %s %s\n", configured.CredentialFlow.ID, configured.CredentialFlow.Status, configured.CredentialFlow.NextAction)
			}
		}
		return 0
	}
	if strings.TrimSpace(options["appDir"]) != "" {
		if err := applyOAuthClientConfigureAppDefaults(options); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "appId", "provider", "clientKind", "displayName"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	payload := map[string]any{
		"workspaceId":        options["workspaceId"],
		"appId":              options["appId"],
		"provider":           options["provider"],
		"clientKind":         options["clientKind"],
		"displayName":        options["displayName"],
		"redirectUris":       redirectURIs,
		"javascriptOrigins":  javascriptOrigins,
		"scopes":             scopes,
		"secretReferenceIds": secretRefs,
	}
	for _, key := range []string{
		"providerAccountId",
		"providerDisplayName",
		"googleCloudProjectId",
		"externalClientId",
		"bundleId",
		"androidPackage",
		"androidSha1Fingerprint",
		"appleTeamId",
		"appleServicesId",
	} {
		if options[key] != "" {
			payload[key] = options[key]
		}
	}
	data, err := postPreflightJSON(client, runnerEndpoint(options["apiURL"], "/api/preflight/v1/oauth-clients/configure"), options["token"], payload)
	if err != nil {
		fmt.Fprintf(stderr, "oauth client configure failed: %v\n", err)
		return 1
	}
	var configured oauthClientConfigureEnvelopeData
	if err := decodeEnvelopeData(data, &configured); err != nil {
		fmt.Fprintf(stderr, "decode oauth client configure response failed: %v\n", err)
		return 1
	}
	oauthClient := configured.OAuthClient
	fmt.Fprintf(stdout, "oauth client %s %s %s %s\n", oauthClient.ID, oauthClient.Provider, oauthClient.ClientKind, oauthClient.Status)
	if configured.CredentialFlow.ID != "" {
		fmt.Fprintf(stdout, "credential flow %s %s %s\n", configured.CredentialFlow.ID, configured.CredentialFlow.Status, configured.CredentialFlow.NextAction)
	}
	return 0
}

func printOAuthClientsConfigureHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight oauth-clients configure")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Configure an app-scoped Google or Apple OAuth client through Preflight.")
	fmt.Fprintln(w, "Derives app ID and native identifiers from an Expo app when --app-dir is provided.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --api-url <url>                 Preflight API URL or PREFLIGHT_API_URL")
	fmt.Fprintln(w, "  --workspace-id <id>             Workspace ID (default: local)")
	fmt.Fprintln(w, "  --app-dir <path>                Expo app directory for default derivation")
	fmt.Fprintln(w, "  --all-required                  Configure all required Google/Apple OAuth client records for the Expo app")
	fmt.Fprintln(w, "  --app-id <id>                   Preflight app ID; derived from package.json with --app-dir")
	fmt.Fprintln(w, "  --provider google_oauth|apple_oauth")
	fmt.Fprintln(w, "  --platform ios|android          Platform used to derive client kind and native IDs")
	fmt.Fprintln(w, "  --client-kind <kind>            google_ios, google_android, google_web, apple_app_id, or apple_services_id")
	fmt.Fprintln(w, "  --display-name <name>           OAuth client display name; derived from Expo name with --app-dir")
	fmt.Fprintln(w, "  --external-client-id <id>       Provider OAuth client ID when already created")
	fmt.Fprintln(w, "  --google-cloud-project-id <id>  Google Cloud project associated with Google Auth Platform")
	fmt.Fprintln(w, "  --bundle-id <id>                iOS bundle ID; derived from Expo config with --app-dir")
	fmt.Fprintln(w, "  --android-package <name>        Android package; derived from Expo config with --app-dir")
	fmt.Fprintln(w, "  --android-sha1 <fingerprint>    Android signing certificate SHA-1")
	fmt.Fprintln(w, "  --apple-team-id <id>            Apple Developer Team ID")
	fmt.Fprintln(w, "  --apple-services-id <id>        Apple Services ID for web/callback flows")
	fmt.Fprintln(w, "  --redirect-uri <uri>            Repeatable redirect URI")
	fmt.Fprintln(w, "  --javascript-origin <origin>    Repeatable Google web JavaScript origin")
	fmt.Fprintln(w, "  --scope <scope>                 Repeatable OAuth scope")
	fmt.Fprintln(w, "  --credential-ref <id>           Repeatable Preflight-owned secret reference")
}

func runOAuthClientsUpsert(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
		"status":      "missing",
	}
	var redirectURIs []string
	var javascriptOrigins []string
	var scopes []string
	var secretRefs []string
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider-account-id":
			if !readFlagValue(args, &index, options, "providerAccountId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--client-kind":
			if !readFlagValue(args, &index, options, "clientKind", stderr) {
				return 2
			}
		case "--display-name":
			if !readFlagValue(args, &index, options, "displayName", stderr) {
				return 2
			}
		case "--external-client-id":
			if !readFlagValue(args, &index, options, "externalClientId", stderr) {
				return 2
			}
		case "--bundle-id":
			if !readFlagValue(args, &index, options, "bundleId", stderr) {
				return 2
			}
		case "--android-package":
			if !readFlagValue(args, &index, options, "androidPackage", stderr) {
				return 2
			}
		case "--android-sha1":
			if !readFlagValue(args, &index, options, "androidSha1Fingerprint", stderr) {
				return 2
			}
		case "--apple-team-id":
			if !readFlagValue(args, &index, options, "appleTeamId", stderr) {
				return 2
			}
		case "--apple-services-id":
			if !readFlagValue(args, &index, options, "appleServicesId", stderr) {
				return 2
			}
		case "--redirect-uri":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--redirect-uri requires a value")
				return 2
			}
			redirectURIs = append(redirectURIs, value)
		case "--javascript-origin":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--javascript-origin requires a value")
				return 2
			}
			javascriptOrigins = append(javascriptOrigins, value)
		case "--scope":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--scope requires a value")
				return 2
			}
			scopes = append(scopes, value)
		case "--credential-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--credential-ref requires a value")
				return 2
			}
			secretRefs = append(secretRefs, value)
		case "--status":
			if !readFlagValue(args, &index, options, "status", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown oauth-clients upsert flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId", "appId", "provider", "clientKind", "displayName"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	payload := map[string]any{
		"workspaceId":        options["workspaceId"],
		"appId":              options["appId"],
		"provider":           options["provider"],
		"clientKind":         options["clientKind"],
		"displayName":        options["displayName"],
		"redirectUris":       redirectURIs,
		"javascriptOrigins":  javascriptOrigins,
		"scopes":             scopes,
		"secretReferenceIds": secretRefs,
		"status":             options["status"],
	}
	for _, key := range []string{
		"providerAccountId",
		"externalClientId",
		"bundleId",
		"androidPackage",
		"androidSha1Fingerprint",
		"appleTeamId",
		"appleServicesId",
	} {
		if options[key] != "" {
			payload[key] = options[key]
		}
	}
	data, err := postPreflightJSON(client, runnerEndpoint(options["apiURL"], "/api/preflight/v1/oauth-clients"), options["token"], payload)
	if err != nil {
		fmt.Fprintf(stderr, "oauth client upsert failed: %v\n", err)
		return 1
	}
	var upserted oauthClientsEnvelopeData
	if err := decodeEnvelopeData(data, &upserted); err != nil {
		fmt.Fprintf(stderr, "decode oauth client response failed: %v\n", err)
		return 1
	}
	oauthClient := upserted.OAuthClient
	fmt.Fprintf(stdout, "oauth client %s %s %s %s\n", oauthClient.ID, oauthClient.Provider, oauthClient.ClientKind, oauthClient.Status)
	return 0
}

func runOAuthClientsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options := map[string]string{
		"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
		"workspaceId": "local",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if !readFlagValue(args, &index, options, "apiURL", stderr) {
				return 2
			}
		case "--workspace-id":
			if !readFlagValue(args, &index, options, "workspaceId", stderr) {
				return 2
			}
		case "--app-id":
			if !readFlagValue(args, &index, options, "appId", stderr) {
				return 2
			}
		case "--provider":
			if !readFlagValue(args, &index, options, "provider", stderr) {
				return 2
			}
		case "--client-kind":
			if !readFlagValue(args, &index, options, "clientKind", stderr) {
				return 2
			}
		case "--status":
			if !readFlagValue(args, &index, options, "status", stderr) {
				return 2
			}
		default:
			fmt.Fprintf(stderr, "unknown oauth-clients list flag %q\n", args[index])
			return 2
		}
	}
	if err := resolvePreflightAPIOptions(options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	if missing := requireOptions(options, "apiURL", "workspaceId"); missing != "" {
		fmt.Fprintf(stderr, "missing %s\n", missing)
		return 2
	}
	endpoint := runnerEndpoint(options["apiURL"], "/api/preflight/v1/oauth-clients") + queryString(options, "workspaceId", "appId", "provider", "clientKind", "status")
	data, err := getPreflightJSON(client, endpoint, options["token"])
	if err != nil {
		fmt.Fprintf(stderr, "oauth client list failed: %v\n", err)
		return 1
	}
	var listed oauthClientsEnvelopeData
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode oauth client list failed: %v\n", err)
		return 1
	}
	for _, oauthClient := range listed.OAuthClients {
		fmt.Fprintf(stdout, "%s %s %s %s %s\n", oauthClient.ID, oauthClient.Provider, oauthClient.ClientKind, oauthClient.Status, oauthClient.DisplayName)
	}
	return 0
}

func readFlagValue(args []string, index *int, options map[string]string, key string, stderr io.Writer) bool {
	value, ok := nextFlagValue(args, index)
	if !ok {
		fmt.Fprintf(stderr, "%s requires a value\n", args[*index])
		return false
	}
	options[key] = value
	return true
}

func resolvePreflightAPIOptions(options map[string]string) error {
	apiURLBeforeConfig := strings.TrimRight(strings.TrimSpace(options["apiURL"]), "/")
	if envToken := strings.TrimSpace(os.Getenv("PREFLIGHT_TOKEN")); envToken != "" {
		options["token"] = envToken
	}

	needsConfig := apiURLBeforeConfig == "" ||
		strings.TrimSpace(options["token"]) == "" ||
		options["workspaceId"] == "local"
	if !needsConfig {
		return nil
	}

	config, err := loadPreflightCLIConfig()
	if err != nil {
		return err
	}
	loadedAPIURLFromConfig := false
	if strings.TrimSpace(options["apiURL"]) == "" && strings.TrimSpace(config.APIURL) != "" {
		options["apiURL"] = strings.TrimRight(config.APIURL, "/")
		apiURLBeforeConfig = strings.TrimRight(options["apiURL"], "/")
		loadedAPIURLFromConfig = true
	}
	if strings.TrimSpace(options["token"]) == "" {
		options["token"] = strings.TrimSpace(config.Token)
	}
	if options["workspaceId"] == "local" &&
		strings.TrimSpace(config.WorkspaceID) != "" &&
		preflightConfigAppliesToAPIURL(config, apiURLBeforeConfig, loadedAPIURLFromConfig) {
		options["workspaceId"] = config.WorkspaceID
	}
	return nil
}

func preflightConfigAppliesToAPIURL(config preflightCLIConfig, apiURL string, loadedAPIURLFromConfig bool) bool {
	if loadedAPIURLFromConfig {
		return true
	}
	configAPIURL := strings.TrimRight(strings.TrimSpace(config.APIURL), "/")
	return configAPIURL != "" && strings.TrimRight(strings.TrimSpace(apiURL), "/") == configAPIURL
}

func requireOptions(options map[string]string, keys ...string) string {
	for _, key := range keys {
		if strings.TrimSpace(options[key]) == "" {
			return "--" + flagName(key)
		}
	}
	return ""
}

func credentialValue(options map[string]string) (string, error) {
	if options["valueEnv"] != "" {
		value := os.Getenv(options["valueEnv"])
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty", options["valueEnv"])
		}
		return value, nil
	}
	if options["valueStdin"] == "true" {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read credential from stdin: %w", err)
		}
		value := strings.TrimRight(string(content), "\r\n")
		if value == "" {
			return "", fmt.Errorf("stdin credential value is empty")
		}
		return value, nil
	}
	return "", fmt.Errorf("missing --value-env or --value-stdin")
}

func parseKeyValue(value string) (string, string, error) {
	index := strings.Index(value, "=")
	if index <= 0 {
		return "", "", fmt.Errorf("expected key=value")
	}
	key := strings.TrimSpace(value[:index])
	parsedValue := strings.TrimSpace(value[index+1:])
	if key == "" || parsedValue == "" {
		return "", "", fmt.Errorf("expected non-empty key=value")
	}
	return key, parsedValue, nil
}

func queryString(options map[string]string, keys ...string) string {
	values := url.Values{}
	for _, key := range keys {
		if options[key] != "" {
			values.Set(queryParamName(key), options[key])
		}
	}
	encoded := values.Encode()
	if encoded == "" {
		return ""
	}
	return "?" + encoded
}

func queryParamName(value string) string {
	switch value {
	case "workspaceId":
		return "workspaceId"
	case "appId":
		return "appId"
	default:
		return value
	}
}

func flagName(value string) string {
	switch value {
	case "apiURL":
		return "api-url"
	case "workspaceId":
		return "workspace-id"
	case "appId":
		return "app-id"
	case "displayName":
		return "display-name"
	case "providerAccountId":
		return "provider-account-id"
	case "blockerCode":
		return "blocker-code"
	case "blockerMessage":
		return "blocker-message"
	case "adapterVersion":
		return "adapter-version"
	}
	var builder strings.Builder
	for index, r := range value {
		if r >= 'A' && r <= 'Z' {
			if index > 0 {
				builder.WriteByte('-')
			}
			builder.WriteRune(r + ('a' - 'A'))
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

type setupOptions struct {
	apiURL      string
	token       string
	workflowID  string
	appDir      string
	workspaceID string
	actorID     string
	run         bool
}

type setupWorkflowRead struct {
	Workflow           setupWorkflowSummary       `json:"workflow"`
	WorkflowProjection proveAppWorkflowProjection `json:"workflowProjection"`
	RunnerJobs         []apiRunnerJob             `json:"runnerJobs"`
}

type setupWorkflowSummary struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspaceId"`
	AppID       string `json:"appId"`
	Status      string `json:"status"`
	Platform    string `json:"platform"`
	Lane        string `json:"lane"`
}

type setupTranscriptRecordData struct {
	SetupTranscript setupTranscriptSummary `json:"setupTranscript"`
}

type setupTranscriptSummary struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func runSetup(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		printSetupHelp(stdout)
		return 0
	}

	options := setupOptions{
		apiURL:  os.Getenv("PREFLIGHT_API_URL"),
		token:   os.Getenv("PREFLIGHT_TOKEN"),
		actorID: os.Getenv("PREFLIGHT_ACTOR_ID"),
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return 2
			}
			options.apiURL = value
		case "--workflow-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--workflow-id requires a value")
				return 2
			}
			options.workflowID = value
		case "--app-dir":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--app-dir requires a value")
				return 2
			}
			options.appDir = value
		case "--workspace-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--workspace-id requires a value")
				return 2
			}
			options.workspaceID = value
		case "--actor-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--actor-id requires a value")
				return 2
			}
			options.actorID = value
		case "--run":
			options.run = true
		default:
			fmt.Fprintf(stderr, "unknown setup flag %q\n", args[index])
			return 2
		}
	}

	apiOptions := map[string]string{
		"apiURL":      options.apiURL,
		"token":       options.token,
		"workspaceId": firstNonEmpty(options.workspaceID, "local"),
	}
	if err := resolvePreflightAPIOptions(apiOptions); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	options.apiURL = apiOptions["apiURL"]
	options.token = apiOptions["token"]
	if options.workspaceID == "" && apiOptions["workspaceId"] != "local" {
		options.workspaceID = apiOptions["workspaceId"]
	}

	if options.apiURL == "" {
		fmt.Fprintln(stderr, "missing Preflight API URL; pass --api-url or set PREFLIGHT_API_URL")
		return 2
	}
	if options.workflowID == "" {
		fmt.Fprintln(stderr, "missing workflow ID; pass --workflow-id")
		return 2
	}

	read, err := readSetupWorkflow(client, options)
	if err != nil {
		fmt.Fprintf(stderr, "read setup workflow failed: %v\n", err)
		return 1
	}
	job, setupRequired, err := setupRequiredJob(read)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	code := stringFromMap(setupRequired, "code")
	if code == "" {
		code = "setup_required"
	}
	commands := stringSliceFromMap(setupRequired, "commands")
	if len(commands) == 0 {
		fmt.Fprintln(stderr, "setup blocker did not include any guided commands")
		return 1
	}
	fmt.Fprintf(stdout, "setup required %s %s\n", options.workflowID, code)
	for _, command := range commands {
		fmt.Fprintf(stdout, "setup command: %s\n", command)
	}
	if !options.run {
		fmt.Fprintln(stdout, "rerun with --run to execute the guided setup commands")
		return 0
	}

	appDir, err := setupAppDir(options, job)
	if err != nil {
		fmt.Fprintf(stderr, "resolve setup app directory: %v\n", err)
		return 1
	}
	setupFileSnapshot := snapshotSourceBoundSetupFiles(appDir, job.Payload.SourceBinding)
	var transcript bytes.Buffer
	status := "completed"
	for _, commandLine := range commands {
		fmt.Fprintf(stdout, "running setup command: %s\n", commandLine)
		output, err := runGuidedSetupCommand(commandLine, appDir, stdout)
		transcript.WriteString("$ ")
		transcript.WriteString(commandLine)
		transcript.WriteString("\n")
		transcript.WriteString(output)
		if err != nil {
			status = "failed"
			transcript.WriteString("\n")
			transcript.WriteString(err.Error())
			transcript.WriteString("\n")
			break
		}
	}
	changedFiles := changedSourceBoundSetupFiles(appDir, job.Payload.SourceBinding, setupFileSnapshot)

	recorded, err := recordSetupTranscript(client, options, read, job, setupRequired, status, redactSetupTranscriptText(transcript.String()), changedFiles)
	if err != nil {
		fmt.Fprintf(stderr, "record setup transcript failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "recorded setup transcript %s %s\n", recorded.SetupTranscript.ID, recorded.SetupTranscript.Status)
	if status != "completed" {
		return 1
	}

	successorSourceBinding, err := setupSuccessorSourceBinding(options, read, job, appDir, changedFiles)
	if err != nil {
		fmt.Fprintf(stderr, "recompute setup source binding failed: %v\n", err)
		return 1
	}

	resumed, err := resumeSetupWorkflow(client, options, read, recorded.SetupTranscript.ID, successorSourceBinding)
	if err != nil {
		fmt.Fprintf(stderr, "resume setup workflow failed: %v\n", err)
		return 1
	}
	phase := resumed.WorkflowProjection.Phase
	if phase == "" {
		phase = resumed.Workflow.Status
	}
	fmt.Fprintf(stdout, "resumed workflow %s %s\n", options.workflowID, phase)
	return 0
}

func printSetupHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight setup --workflow-id <id> [--run]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Runs guided setup commands for a Preflight workflow blocked on setup.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --api-url <url>       Preflight API URL or PREFLIGHT_API_URL")
	fmt.Fprintln(w, "  --workflow-id <id>    Blocked Preflight workflow ID")
	fmt.Fprintln(w, "  --app-dir <path>      Override app directory for setup commands")
	fmt.Fprintln(w, "  --workspace-id <id>   Override workspace ID used for resume")
	fmt.Fprintln(w, "  --actor-id <id>       Actor recorded on the setup transcript")
	fmt.Fprintln(w, "  --run                 Execute the guided commands and resume on success")
}

func readSetupWorkflow(client *http.Client, options setupOptions) (setupWorkflowRead, error) {
	data, err := getPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, "/api/preflight/v1/workflows/"+options.workflowID),
		options.token,
	)
	if err != nil {
		return setupWorkflowRead{}, err
	}
	var read setupWorkflowRead
	if err := decodeEnvelopeData(data, &read); err != nil {
		return setupWorkflowRead{}, err
	}
	return read, nil
}

func setupRequiredJob(read setupWorkflowRead) (apiRunnerJob, map[string]any, error) {
	for index := len(read.RunnerJobs) - 1; index >= 0; index -= 1 {
		job := read.RunnerJobs[index]
		if job.Kind != "eas.readiness.probe" && job.Kind != "eas.build.dev" {
			continue
		}
		if job.Result == nil || job.Result["status"] != "setup_required" {
			continue
		}
		setupRequired, ok := job.Result["setupRequired"].(map[string]any)
		if !ok {
			return apiRunnerJob{}, nil, fmt.Errorf("setup-required job did not include setupRequired details")
		}
		return job, setupRequired, nil
	}
	return apiRunnerJob{}, nil, fmt.Errorf("workflow is not blocked on EAS setup")
}

func setupAppDir(options setupOptions, job apiRunnerJob) (string, error) {
	if options.appDir != "" {
		return filepath.Abs(options.appDir)
	}
	if job.Payload.SourceBinding.WorkspaceRoot == "" {
		return "", fmt.Errorf("setup job did not include source binding workspace root")
	}
	packagePath := job.Payload.SourceBinding.PackagePath
	if packagePath == "" {
		packagePath = "."
	}
	return filepath.Join(job.Payload.SourceBinding.WorkspaceRoot, packagePath), nil
}

type sourceBoundSetupFile struct {
	path        string
	displayPath string
}

func snapshotSourceBoundSetupFiles(appDir string, binding runnerJobSourceBinding) map[string]string {
	snapshot := map[string]string{}
	for _, file := range sourceBoundSetupFiles(appDir, binding) {
		snapshot[file.displayPath] = setupFileDigest(file.path)
	}
	return snapshot
}

func changedSourceBoundSetupFiles(appDir string, binding runnerJobSourceBinding, before map[string]string) []string {
	changedFiles := []string{}
	for _, file := range sourceBoundSetupFiles(appDir, binding) {
		if setupFileDigest(file.path) != before[file.displayPath] {
			changedFiles = append(changedFiles, file.displayPath)
		}
	}
	return changedFiles
}

func sourceBoundSetupFiles(appDir string, binding runnerJobSourceBinding) []sourceBoundSetupFile {
	names := []string{
		"eas.json",
		"app.config.ts",
		"app.config.js",
		"app.json",
		"preflight.json",
		".preflight.json",
	}
	files := make([]sourceBoundSetupFile, 0, len(names))
	for _, name := range names {
		files = append(files, sourceBoundSetupFile{
			path:        filepath.Join(appDir, name),
			displayPath: sourceBoundSetupFileDisplayPath(appDir, name, binding),
		})
	}
	return files
}

func sourceBoundSetupFileDisplayPath(appDir string, name string, binding runnerJobSourceBinding) string {
	if strings.TrimSpace(binding.WorkspaceRoot) != "" {
		workspaceRoot, rootErr := filepath.Abs(binding.WorkspaceRoot)
		filePath, fileErr := filepath.Abs(filepath.Join(appDir, name))
		if rootErr == nil && fileErr == nil {
			if relativePath, err := filepath.Rel(workspaceRoot, filePath); err == nil && relativePath != "." {
				return filepath.ToSlash(relativePath)
			}
		}
	}
	if strings.TrimSpace(binding.PackagePath) != "" && binding.PackagePath != "." {
		return filepath.ToSlash(filepath.Join(binding.PackagePath, name))
	}
	return filepath.ToSlash(name)
}

func setupFileDigest(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "error:" + err.Error()
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func setupSuccessorSourceBinding(
	options setupOptions,
	read setupWorkflowRead,
	job apiRunnerJob,
	appDir string,
	changedFiles []string,
) (*sourceBinding, error) {
	if len(changedFiles) == 0 {
		return nil, nil
	}
	binding, err := discoverSourceBinding(proveAppOptions{
		appDir:   appDir,
		platform: firstNonEmpty(read.Workflow.Platform, job.Payload.Platform),
		lane:     firstNonEmpty(read.Workflow.Lane, job.Payload.Lane, "development"),
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(job.Payload.SourceBinding.WorkspaceRoot) != "" {
		workspaceRoot, rootErr := filepath.Abs(job.Payload.SourceBinding.WorkspaceRoot)
		absoluteAppDir, appErr := filepath.Abs(appDir)
		if rootErr == nil && appErr == nil {
			if packagePath, relErr := filepath.Rel(workspaceRoot, absoluteAppDir); relErr == nil && packagePath != ".." && !strings.HasPrefix(packagePath, ".."+string(os.PathSeparator)) {
				if packagePath == "" {
					packagePath = "."
				}
				binding.WorkspaceRoot = workspaceRoot
				binding.PackagePath = filepath.ToSlash(packagePath)
			}
		}
	}
	binding.AppID = firstNonEmpty(read.Workflow.AppID, binding.AppID)
	binding.ChangedSetupFiles = append([]string{}, changedFiles...)
	return &binding, nil
}

func runGuidedSetupCommand(commandLine string, appDir string, stdout io.Writer) (string, error) {
	parts := strings.Fields(commandLine)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty setup command")
	}
	if err := validateGuidedSetupCommand(parts); err != nil {
		return "", err
	}
	command := exec.Command(parts[0], parts[1:]...)
	command.Dir = appDir
	command.Stdin = os.Stdin
	var output bytes.Buffer
	stream := &redactingTranscriptWriter{
		transcript: &output,
		stream:     stdout,
	}
	command.Stdout = stream
	command.Stderr = stream
	err := command.Run()
	stream.Flush()
	return output.String(), err
}

func validateGuidedSetupCommand(parts []string) error {
	if len(parts) == 0 {
		return fmt.Errorf("empty setup command")
	}
	switch parts[0] {
	case "preflight":
		return validatePreflightSetupCommand(parts)
	case "eas":
		return validateEASSetupCommand(parts)
	case "expo":
		return validateExpoSetupCommand(parts)
	case "gcloud":
		return validateGCloudSetupCommand(parts)
	case "adb":
		return validateADBSetupCommand(parts)
	case "emulator":
		return validateEmulatorSetupCommand(parts)
	case "sdkmanager":
		return validateSDKManagerSetupCommand(parts)
	case "avdmanager":
		return validateAVDManagerSetupCommand(parts)
	case "npx":
		return validateNPXSetupCommand(parts)
	default:
		return fmt.Errorf("setup command %q is not allowlisted", parts[0])
	}
}

func validateNPXSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an Expo or EAS tool", parts[0])
	}
	switch parts[1] {
	case "expo":
		if len(parts) < 3 {
			return fmt.Errorf("setup command %q is missing an Expo or EAS tool", parts[0])
		}
		return validateExpoSetupCommand(append([]string{"expo"}, parts[2:]...))
	case "eas-cli":
		if len(parts) < 3 {
			return fmt.Errorf("setup command %q is missing an EAS action", strings.Join(parts[:2], " "))
		}
		return validateEASSetupCommand(append([]string{"eas"}, parts[2:]...))
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validatePreflightSetupCommand(parts []string) error {
	if len(parts) < 3 {
		return fmt.Errorf("setup command %q is missing a Preflight action", parts[0])
	}
	if parts[1] == "credentials" && parts[2] == "create" {
		return nil
	}
	return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
}

func validateExpoSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an Expo action", parts[0])
	}
	switch parts[1] {
	case "install", "doctor":
		return nil
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validateEASSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an EAS action", parts[0])
	}
	switch parts[1] {
	case "build", "build:configure", "credentials", "credentials:configure-build", "device:create":
		return nil
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validateGCloudSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing a gcloud group", parts[0])
	}
	switch parts[1] {
	case "auth", "config", "services", "projects":
		return nil
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validateADBSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an adb action", parts[0])
	}
	switch parts[1] {
	case "devices", "version", "start-server", "kill-server":
		return nil
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validateEmulatorSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an emulator action", parts[0])
	}
	switch parts[1] {
	case "-list-avds", "-avd", "-help", "-version":
		return nil
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validateSDKManagerSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an sdkmanager action", parts[0])
	}
	for _, part := range parts[1:] {
		if part == "--uninstall" {
			return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
		}
	}
	switch parts[1] {
	case "--list", "--install", "--licenses", "--version":
		return nil
	default:
		if strings.HasPrefix(parts[1], "platforms;") ||
			strings.HasPrefix(parts[1], "system-images;") ||
			strings.HasPrefix(parts[1], "platform-tools") ||
			strings.HasPrefix(parts[1], "emulator") ||
			strings.HasPrefix(parts[1], "cmdline-tools;") {
			return nil
		}
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

func validateAVDManagerSetupCommand(parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("setup command %q is missing an avdmanager action", parts[0])
	}
	switch parts[1] {
	case "list", "create", "delete":
		return nil
	default:
		return fmt.Errorf("setup command %q is not allowlisted", strings.Join(parts[:2], " "))
	}
}

type redactingTranscriptWriter struct {
	transcript *bytes.Buffer
	stream     io.Writer
	pending    string
}

func (writer *redactingTranscriptWriter) Write(chunk []byte) (int, error) {
	writer.pending += string(chunk)
	for {
		newlineIndex := strings.IndexByte(writer.pending, '\n')
		if newlineIndex < 0 {
			break
		}
		line := writer.pending[:newlineIndex+1]
		writer.pending = writer.pending[newlineIndex+1:]
		writer.writeRedacted(line)
	}
	if shouldFlushSetupPromptFragment(writer.pending) {
		writer.writeRedacted(writer.pending)
		writer.pending = ""
	}
	return len(chunk), nil
}

func (writer *redactingTranscriptWriter) Flush() {
	if writer.pending == "" {
		return
	}
	writer.writeRedacted(writer.pending)
	writer.pending = ""
}

func (writer *redactingTranscriptWriter) writeRedacted(value string) {
	redacted := redactSetupTranscriptText(value)
	writer.transcript.WriteString(redacted)
	if writer.stream != nil {
		_, _ = io.WriteString(writer.stream, redacted)
	}
}

func shouldFlushSetupPromptFragment(value string) bool {
	if value == "" {
		return false
	}
	upper := strings.ToUpper(value)
	for _, sensitiveMarker := range []string{
		"TOKEN",
		"SECRET",
		"PASSWORD",
		"PASSCODE",
		"BEARER",
		"API_KEY",
		"ACCESS_KEY",
	} {
		if strings.Contains(upper, sensitiveMarker) {
			return false
		}
	}
	return strings.Contains(value, "? ") ||
		strings.Contains(value, "(Y/n)") ||
		strings.Contains(value, "(y/N)") ||
		strings.HasSuffix(strings.TrimSpace(value), "?")
}

type redactingCommandWriter struct {
	destination io.Writer
	mu          sync.Mutex
	pending     string
}

func attachRedactedCommandLog(command *exec.Cmd, destination io.Writer) func() {
	writer := &redactingCommandWriter{destination: destination}
	command.Stdout = writer
	command.Stderr = writer
	return writer.Flush
}

func (writer *redactingCommandWriter) Write(chunk []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()

	writer.pending += string(chunk)
	for {
		newlineIndex := strings.IndexByte(writer.pending, '\n')
		if newlineIndex < 0 {
			break
		}
		line := writer.pending[:newlineIndex+1]
		writer.pending = writer.pending[newlineIndex+1:]
		if _, err := io.WriteString(writer.destination, redactSetupTranscriptText(line)); err != nil {
			return 0, err
		}
	}
	return len(chunk), nil
}

func (writer *redactingCommandWriter) Flush() {
	writer.mu.Lock()
	defer writer.mu.Unlock()

	if writer.pending == "" {
		return
	}
	_, _ = io.WriteString(writer.destination, redactSetupTranscriptText(writer.pending))
	writer.pending = ""
}

func recordSetupTranscript(
	client *http.Client,
	options setupOptions,
	read setupWorkflowRead,
	job apiRunnerJob,
	setupRequired map[string]any,
	status string,
	redactedContent string,
	changedFiles []string,
) (setupTranscriptRecordData, error) {
	summary := "EAS setup command completed."
	if status != "completed" {
		summary = "EAS setup command failed."
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, "/api/preflight/v1/setup-transcripts"),
		options.token,
		map[string]any{
			"workflowId":         options.workflowID,
			"sourceBindingId":    job.Payload.SourceBinding.ID,
			"status":             status,
			"summary":            summary,
			"redactedContent":    redactedContent,
			"commands":           stringSliceFromMap(setupRequired, "commands"),
			"changedFiles":       changedFiles,
			"secretReferenceIds": createdCredentialIDsFromSetupTranscript(redactedContent),
			"setupRequired":      setupRequired,
			"actorId":            options.actorID,
			"workspaceId":        setupWorkspaceID(options, read),
		},
	)
	if err != nil {
		return setupTranscriptRecordData{}, err
	}
	var recorded setupTranscriptRecordData
	if err := decodeEnvelopeData(data, &recorded); err != nil {
		return setupTranscriptRecordData{}, err
	}
	if recorded.SetupTranscript.ID == "" {
		return setupTranscriptRecordData{}, fmt.Errorf("setup transcript response did not include an ID")
	}
	return recorded, nil
}

func createdCredentialIDsFromSetupTranscript(redactedContent string) []string {
	matches := regexp.MustCompile(`(?m)^created credential (pfsec_[A-Za-z0-9_-]+)\b`).FindAllStringSubmatch(redactedContent, -1)
	ids := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		id := strings.TrimSpace(match[1])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

func resumeSetupWorkflow(
	client *http.Client,
	options setupOptions,
	read setupWorkflowRead,
	setupTranscriptID string,
	successorSourceBinding *sourceBinding,
) (setupWorkflowRead, error) {
	body := map[string]any{
		"workspaceId":       setupWorkspaceID(options, read),
		"setupTranscriptId": setupTranscriptID,
	}
	if successorSourceBinding != nil {
		body["sourceBinding"] = successorSourceBinding
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, "/api/preflight/v1/workflows/"+options.workflowID+"/resume-setup"),
		options.token,
		body,
	)
	if err != nil {
		return setupWorkflowRead{}, err
	}
	var resumed setupWorkflowRead
	if err := decodeEnvelopeData(data, &resumed); err != nil {
		return setupWorkflowRead{}, err
	}
	return resumed, nil
}

func setupWorkspaceID(options setupOptions, read setupWorkflowRead) string {
	if options.workspaceID != "" {
		return options.workspaceID
	}
	if read.Workflow.WorkspaceID != "" {
		return read.Workflow.WorkspaceID
	}
	return "local"
}

func stringFromMap(value map[string]any, key string) string {
	item, _ := value[key].(string)
	return item
}

func stringSliceFromMap(value map[string]any, key string) []string {
	raw, ok := value[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				items = append(items, text)
			}
		}
		return items
	default:
		return nil
	}
}

func redactSetupTranscriptText(value string) string {
	redacted := regexp.MustCompile(`(?i)\b(EAS_TOKEN|EXPO_TOKEN|SENTRY_AUTH_TOKEN|ASC_API_KEY|APP_STORE_CONNECT_API_KEY|GOOGLE_PLAY_SERVICE_ACCOUNT)\s*=\s*([^\s&]+)`).ReplaceAllString(value, "$1=[REDACTED]")
	redacted = regexp.MustCompile(`(?i)\b(Authorization:\s*Bearer\s+)([^\s]+)`).ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = regexp.MustCompile(`(?i)([?&](?:access_token|token|auth|api_key|secret|signature|key)=)([^&#\s]+)`).ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = regexp.MustCompile(`(?i)(["']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|private[_-]?key|signing[_-]?secret|client[_-]?secret)["']?\s*[:=]\s*["']?)([^"',\s}]+)(["']?)`).ReplaceAllString(redacted, "$1[REDACTED]$3")
	return redacted
}

func runRunner(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printRunnerHelp(stdout)
		return 0
	}

	switch args[0] {
	case "once":
		return runRunnerOnce(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown runner command %q\n", args[0])
		printRunnerHelp(stderr)
		return 2
	}
}

func printRunnerHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight runner <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  once  Register, claim one local work sequence, and exit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options for once:")
	fmt.Fprintln(w, "  --api-url <url>          Preflight API URL or PREFLIGHT_API_URL")
	fmt.Fprintln(w, "  --workspace-id <id>      ForgeGraph workspace ID")
	fmt.Fprintln(w, "  --workspace-root <path>  Workspace root this runner can access")
	fmt.Fprintln(w, "  --host-identity <name>   Stable local host identity")
	fmt.Fprintln(w, "  --name <name>            Runner display name")
	fmt.Fprintln(w, "  --simctl-json <path>     Use a simctl JSON fixture instead of xcrun")
	fmt.Fprintln(w, "  --xcrun-path <path>      xcrun executable path")
	fmt.Fprintln(w, "  --adb-path <path>        adb executable path")
	fmt.Fprintln(w, "  --metro-port <port>      Expo/Metro port")
	fmt.Fprintln(w, "  --metro-status-url <url> Override Metro status probe URL")
	fmt.Fprintln(w, "  --host-mode <mode>       Expo host mode: lan, localhost, tunnel, or tailscale")
}

func runRunnerOnce(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options, err := parseRunnerOnceOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	if err := executeRunnerOnce(options, stdout, client); err != nil {
		fmt.Fprintf(stderr, "runner once failed: %v\n", err)
		return 1
	}
	return 0
}

type runnerOnceOptions struct {
	apiURL         string
	token          string
	workspaceID    string
	workspaceRoot  string
	hostIdentity   string
	name           string
	simctlJSON     string
	xcrunPath      string
	adbPath        string
	metroPort      int
	metroStatusURL string
	hostMode       string
	simulatorUDID  string
}

func parseRunnerOnceOptions(args []string) (runnerOnceOptions, error) {
	hostIdentity, _ := os.Hostname()
	options := runnerOnceOptions{
		apiURL:        os.Getenv("PREFLIGHT_API_URL"),
		token:         os.Getenv("PREFLIGHT_TOKEN"),
		workspaceID:   os.Getenv("PREFLIGHT_WORKSPACE_ID"),
		workspaceRoot: os.Getenv("PREFLIGHT_WORKSPACE_ROOT"),
		hostIdentity:  hostIdentity,
		name:          "Preflight Runner",
		xcrunPath:     "xcrun",
		adbPath:       "adb",
		metroPort:     8091,
		hostMode:      "lan",
		simulatorUDID: os.Getenv("PREFLIGHT_SIMULATOR_UDID"),
	}

	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--api-url requires a value")
			}
			options.apiURL = value
		case "--workspace-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--workspace-id requires a value")
			}
			options.workspaceID = value
		case "--workspace-root":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--workspace-root requires a value")
			}
			options.workspaceRoot = value
		case "--host-identity":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--host-identity requires a value")
			}
			options.hostIdentity = value
		case "--name":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--name requires a value")
			}
			options.name = value
		case "--simctl-json":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--simctl-json requires a value")
			}
			options.simctlJSON = value
		case "--xcrun-path":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--xcrun-path requires a value")
			}
			options.xcrunPath = value
		case "--adb-path":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--adb-path requires a value")
			}
			options.adbPath = value
		case "--metro-port":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--metro-port requires a value")
			}
			port, err := strconv.Atoi(value)
			if err != nil || port <= 0 {
				return runnerOnceOptions{}, fmt.Errorf("--metro-port must be a positive integer")
			}
			options.metroPort = port
		case "--metro-status-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--metro-status-url requires a value")
			}
			options.metroStatusURL = value
		case "--host-mode":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--host-mode requires a value")
			}
			options.hostMode = value
		case "--simulator-udid":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				return runnerOnceOptions{}, fmt.Errorf("--simulator-udid requires a value")
			}
			options.simulatorUDID = value
		default:
			return runnerOnceOptions{}, fmt.Errorf("unknown runner once flag %q", args[index])
		}
	}

	apiOptions := map[string]string{
		"apiURL":      options.apiURL,
		"token":       options.token,
		"workspaceId": firstNonEmpty(options.workspaceID, "local"),
	}
	if err := resolvePreflightAPIOptions(apiOptions); err != nil {
		return runnerOnceOptions{}, fmt.Errorf("load Preflight CLI config failed: %w", err)
	}
	options.apiURL = apiOptions["apiURL"]
	options.token = apiOptions["token"]
	if options.workspaceID == "" {
		options.workspaceID = apiOptions["workspaceId"]
	}

	if options.apiURL == "" {
		return runnerOnceOptions{}, fmt.Errorf("missing Preflight API URL; pass --api-url or set PREFLIGHT_API_URL")
	}
	if options.workspaceID == "" {
		return runnerOnceOptions{}, fmt.Errorf("missing workspace ID; pass --workspace-id or set PREFLIGHT_WORKSPACE_ID")
	}
	if options.workspaceRoot == "" {
		currentDirectory, err := os.Getwd()
		if err != nil {
			return runnerOnceOptions{}, fmt.Errorf("resolve current directory: %w", err)
		}
		options.workspaceRoot = currentDirectory
	}
	if !filepath.IsAbs(options.workspaceRoot) {
		absoluteRoot, err := filepath.Abs(options.workspaceRoot)
		if err != nil {
			return runnerOnceOptions{}, fmt.Errorf("resolve workspace root: %w", err)
		}
		options.workspaceRoot = absoluteRoot
	}
	options.workspaceRoot = canonicalWorkspaceRoot(options.workspaceRoot)
	if strings.TrimSpace(options.hostIdentity) == "" {
		options.hostIdentity = "unknown-host"
	}
	if strings.TrimSpace(options.name) == "" {
		options.name = "Preflight Runner"
	}
	if strings.TrimSpace(options.xcrunPath) == "" {
		options.xcrunPath = "xcrun"
	}
	if strings.TrimSpace(options.adbPath) == "" {
		options.adbPath = "adb"
	}
	if strings.TrimSpace(options.hostMode) == "" {
		options.hostMode = "lan"
	}

	return options, nil
}

func nextFlagValue(args []string, index *int) (string, bool) {
	if *index+1 >= len(args) {
		return "", false
	}
	*index += 1
	return args[*index], true
}

func executeRunnerOnce(options runnerOnceOptions, stdout io.Writer, client *http.Client) error {
	cleaned, err := cleanupExpiredLocalPreflightArtifacts(options.workspaceRoot, localArtifactTTL())
	if err != nil {
		return err
	}
	if cleaned > 0 {
		fmt.Fprintf(stdout, "cleaned %d expired Preflight local artifact directories\n", cleaned)
	}
	cleanedHandles, err := cleanupStaleLocalPreflightProcessHandles(options.workspaceRoot)
	if err != nil {
		return err
	}
	if cleanedHandles > 0 {
		suffix := "s"
		if cleanedHandles == 1 {
			suffix = ""
		}
		fmt.Fprintf(stdout, "cleaned %d stale Preflight local process handle%s\n", cleanedHandles, suffix)
	}

	// Release the in-flight job's target lock on graceful shutdown (^C / SIGTERM)
	// so a cancelled run doesn't leave a target locked until TTL.
	stopShutdownHandler := installRunnerShutdownHandler(stdout)
	defer stopShutdownHandler()

	capabilities := defaultRunnerCapabilities(options.hostMode)
	registration, err := registerRunner(client, options, capabilities)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "registered runner %s\n", registration.Runner.ID)

	if err := heartbeatRunner(client, options, registration, capabilities); err != nil {
		return err
	}

	// Keep the runner-level heartbeat fresh for the whole work sequence. Job
	// claim/complete/heartbeat persist workflow+job state but not the runner row,
	// so without this a runner busy on a long job (cold sim boot, build, maestro)
	// is marked stale (>staleRunnerMs) and rejected on its next claim/write.
	stopHeartbeat := make(chan struct{})
	defer close(stopHeartbeat)
	go func() {
		ticker := time.NewTicker(runnerLivenessHeartbeatInterval())
		defer ticker.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ticker.C:
				_ = heartbeatRunner(client, options, registration, capabilities)
			}
		}
	}()

	if err := reconcileRunnerStartup(client, options, registration); err != nil {
		return err
	}

	// Disk gate: builds that run out of space fail mid-lipo/codegen in
	// confusing ways (the volume hit 100% twice in one fleet-capture day).
	// Under pressure, sweep regenerable caches; if still low, decline to
	// claim — the reason is visible via the heartbeat's freeDiskGb.
	if free, err := freeBytesForPath(options.workspaceRoot); err == nil {
		minFree := runnerMinFreeDiskBytes()
		if minFree > 0 && free <= minFree {
			swept, _ := cleanupBuildStorageUnderPressure(
				options.workspaceRoot, 24*time.Hour, minFree, nil,
			)
			if after, err := freeBytesForPath(options.workspaceRoot); err == nil && after <= minFree {
				fmt.Fprintf(stdout,
					"low disk: %.1f GiB free (< %.0f GiB) after sweeping %d cache entries — declining claims\n",
					float64(after)/float64(bytesPerGiB),
					float64(minFree)/float64(bytesPerGiB),
					swept.Removed,
				)
				return nil
			}
		}
	}

	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		fmt.Fprintln(stdout, "no runner jobs available")
		return nil
	}

	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	return handleRunnerClaim(client, options, registration, claim.Job, stdout, capabilities)
}

func claimAndHandleNextRunnerJob(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	stdout io.Writer,
	capabilities map[string]any,
) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		fmt.Fprintln(stdout, "no runner jobs available")
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	return handleRunnerClaim(client, options, registration, claim.Job, stdout, capabilities)
}

func handleRunnerClaim(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	stdout io.Writer,
	capabilities map[string]any,
) error {
	// Track this as the in-flight job so a shutdown signal can release its lock.
	markRunnerJobActive(client, options, registration, job)
	defer clearRunnerJobActive()

	switch job.Kind {
	case "runner.capabilities.probe":
		if err := completeCapabilityProbe(client, options, registration, job, capabilities); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "completed capability probe %s\n", job.ID)
		return claimAndHandleNextRunnerJob(client, options, registration, stdout, capabilities)
	case "eas.readiness.probe":
		if err := handleEASReadinessProbeJob(client, options, registration, job, stdout); err != nil {
			return err
		}
		return claimAndHandleNextRunnerJob(client, options, registration, stdout, capabilities)
	case "eas.build.dev":
		return handleEASBuildDevJob(client, options, registration, job, stdout)
	case "device.discover":
		if err := handleDeviceDiscoveryJob(client, options, registration, job, stdout); err != nil {
			return err
		}
		return claimAndHandleNextRunnerJob(client, options, registration, stdout, capabilities)
	case "dev_session.start":
		continueWorkflow, err := handleDevSessionStartJob(client, options, registration, job, stdout)
		if err != nil {
			return err
		}
		if !continueWorkflow {
			return nil
		}
		return claimAndHandleNextRunnerJob(client, options, registration, stdout, capabilities)
	case "dev_session.open":
		return handleDevSessionOpenJob(client, options, registration, job, stdout)
	case "dev_session.stop":
		return handleDevSessionStopJob(client, options, registration, job, stdout)
	case "simulator.open":
		return handleSimulatorOpenJob(client, options, registration, job, stdout)
	case "maestro.run":
		return handleMaestroRunJob(client, options, registration, job, stdout)
	case "unity.build.player":
		return handleUnityBuildPlayerJob(client, options, registration, job, stdout)
	case "fastlane.produce", "fastlane.metadata", "fastlane.screenshots":
		return handleFastlaneJob(client, options, registration, job, stdout)
	case "eas.submit":
		return handleEASSubmitJob(client, options, registration, job, stdout)
	case "ota.export", "ota.publish", "ota.fingerprint":
		return handleOtaJob(client, options, registration, job, stdout)
	default:
		return fmt.Errorf("unsupported runner job kind %q", job.Kind)
	}
}

func defaultRunnerCapabilities(hostMode string) map[string]any {
	localTools := []string{
		"adb",
		"avdmanager",
		"eas",
		"emulator",
		"expo",
		"fastlane",
		"gcloud",
		"java",
		"maestro",
		"sdkmanager",
		"simctl",
		"xcrun",
	}
	adapters := []string{
		"android.emulator",
		"android.emulator.discovery",
		"android.emulator.install",
		"android.sdk.management",
		"apple_oauth.management",
		"app_store_connect.api",
		"eas.development",
		"eas.cli",
		"expo.dev_client",
		"expo.dev_server",
		"expo.local_build",
		"fastlane.cli",
		"google_cloud.cli",
		"google_oauth.management",
		"google_play.api",
		"ios.simulator",
		"ios.simulator.boot",
		"ios.simulator.discovery",
		"ios.simulator.install",
		"sentry.api",
		"sentry.source_maps.upload",
	}
	if unityCommandAvailable() {
		localTools = append(localTools, "unity")
		adapters = append(adapters, "unity.editor", "unity.android", "unity.android.build_support")
	}
	// Physical-device development sessions need a dev server the phone can
	// reach; the control plane routes tunnel-required dev_session jobs to
	// runners that advertise this instead of letting a lan runner
	// claim-and-refuse them. Tailscale mode satisfies the same reachability
	// contract (the phone is on the tailnet), so it advertises the same
	// adapter and claim routing is unchanged.
	if mode := strings.TrimSpace(hostMode); mode == "tunnel" || mode == "tailscale" {
		adapters = append(adapters, "expo.dev_server.tunnel")
	}
	// Several agents routinely share one machine (they need distinct
	// --host-identity values to register as separate runners). Report the actual
	// machine so the control plane can cap native builds per physical host
	// rather than per agent — otherwise N agents on one Mac each get their own
	// build slot and thrash the shared module cache.
	machineID, err := os.Hostname()
	if err != nil || strings.TrimSpace(machineID) == "" {
		machineID = "unknown-machine"
	}

	return map[string]any{
		"platforms":             []string{"ios", "android"},
		"localTools":            localTools,
		"adapters":              adapters,
		"machineId":             machineID,
		"runnerContractVersion": contractVersion,
		"runnerJobStream":       true,
		"runnerJobHeartbeat":    true,
		"runnerArtifactUpload":  true,
	}
}

func localArtifactTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("PREFLIGHT_LOCAL_ARTIFACT_TTL"))
	if raw == "" {
		return defaultLocalArtifactTTL
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return defaultLocalArtifactTTL
	}
	return ttl
}

func cleanupExpiredLocalPreflightArtifacts(workspaceRoot string, ttl time.Duration) (int, error) {
	if ttl <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-ttl)
	cleaned := 0
	for _, relativeRoot := range []string{
		filepath.Join(".preflight", "android-open"),
		filepath.Join(".preflight", "dev-sessions"),
		filepath.Join(".preflight", "eas"),
		filepath.Join(".preflight", "maestro"),
		filepath.Join(".preflight", "unity-builds"),
	} {
		root := filepath.Join(workspaceRoot, relativeRoot)
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return cleaned, fmt.Errorf("read local Preflight artifact directory %s: %w", root, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return cleaned, fmt.Errorf("stat local Preflight artifact directory %s: %w", filepath.Join(root, entry.Name()), err)
			}
			if info.ModTime().After(cutoff) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
				return cleaned, fmt.Errorf("remove expired local Preflight artifact directory %s: %w", filepath.Join(root, entry.Name()), err)
			}
			cleaned += 1
		}
	}
	return cleaned, nil
}

func cleanupStaleLocalPreflightProcessHandles(workspaceRoot string) (int, error) {
	if strings.EqualFold(os.Getenv("PREFLIGHT_RECURSIVE_PROCESS_HANDLE_CLEANUP"), "1") ||
		strings.EqualFold(os.Getenv("PREFLIGHT_RECURSIVE_PROCESS_HANDLE_CLEANUP"), "true") {
		return cleanupStaleLocalPreflightProcessHandlesRecursive(workspaceRoot)
	}

	pidPath := filepath.Join(workspaceRoot, ".preflight", "expo-dev-session.pid")
	stale, err := localPidFileIsStale(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !stale {
		return 0, nil
	}
	if err := os.Remove(pidPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("remove stale Preflight process handle %s: %w", pidPath, err)
	}
	return 1, nil
}

func cleanupStaleLocalPreflightProcessHandlesRecursive(workspaceRoot string) (int, error) {
	cleaned := 0
	err := filepath.WalkDir(workspaceRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip unreadable entries instead of aborting the whole reconcile.
			// A workspace root at a volume root (e.g. /Volumes/dev) contains macOS
			// system dirs (.DocumentRevisions-V100, .Spotlight-V100) that require
			// Full Disk Access; permission errors there must not fail the runner.
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules",
				".DocumentRevisions-V100", ".Spotlight-V100", ".Trashes",
				".fseventsd", ".TemporaryItems", ".vol", ".PKInstallSandboxManager",
				".PKInstallSandboxManager-SystemSoftware":
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "expo-dev-session.pid" || filepath.Base(filepath.Dir(path)) != ".preflight" {
			return nil
		}
		stale, err := localPidFileIsStale(path)
		if err != nil {
			return err
		}
		if !stale {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale Preflight process handle %s: %w", path, err)
		}
		cleaned += 1
		return nil
	})
	if err != nil {
		return cleaned, fmt.Errorf("reconcile local Preflight process handles: %w", err)
	}
	return cleaned, nil
}

func localPidFileIsStale(path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read Preflight process handle %s: %w", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || pid <= 0 {
		return true, nil
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return true, nil
	}
	return false, nil
}

type runnerRegistrationData struct {
	Runner apiRunner `json:"runner"`
	Token  string    `json:"token"`
}

type apiRunner struct {
	ID           string         `json:"id"`
	Capabilities map[string]any `json:"capabilities"`
}

type runnerClaimData struct {
	Job apiRunnerJob `json:"job"`
}

type apiRunnerJob struct {
	ID          string           `json:"id"`
	WorkspaceID string           `json:"workspaceId"`
	AppID       string           `json:"appId"`
	WorkflowID  string           `json:"workflowId"`
	Kind        string           `json:"kind"`
	Status      string           `json:"status"`
	TargetID    string           `json:"targetId"`
	Payload     runnerJobPayload `json:"payload"`
	Result      map[string]any   `json:"result"`
}

type runnerJobPayload struct {
	Platform                 string                             `json:"platform"`
	Lane                     string                             `json:"lane"`
	TargetID                 string                             `json:"targetId"`
	ProviderIdentity         string                             `json:"providerIdentity"`
	TargetDisplayName        string                             `json:"targetDisplayName"`
	FlowPath                 string                             `json:"flowPath"`
	IncludeTags              []string                           `json:"includeTags"`
	DeviceProvider           string                             `json:"deviceProvider"`
	EASProfileName           string                             `json:"easProfileName"`
	TargetClass              string                             `json:"targetClass"`
	SourceBinding            runnerJobSourceBinding             `json:"sourceBinding"`
	DevSession               runnerJobDevSession                `json:"devSession"`
	NetworkPolicy            runnerJobNetworkPolicy             `json:"networkPolicy"`
	DevBuild                 map[string]any                     `json:"devBuild"`
	Readiness                map[string]any                     `json:"readiness"`
	UnityProject             map[string]any                     `json:"unityProject"`
	CommandPlan              runnerJobCommandPlan               `json:"commandPlan"`
	BuildProvider            string                             `json:"buildProvider"`
	RequiredSecretReferences []runnerJobRequiredSecretReference `json:"requiredSecretReferences"`
	SecretReferences         []runnerJobSecretReference         `json:"secretReferences"`
	// Fastlane (produce/metadata/screenshots) fields:
	AppIdentifier   string                   `json:"appIdentifier"`
	AppName         string                   `json:"appName"`
	Sku             string                   `json:"sku"`
	PrimaryLanguage string                   `json:"primaryLanguage"`
	CompanyName     string                   `json:"companyName"`
	Action          string                   `json:"action"`
	Metadata        map[string]string        `json:"metadata"`
	Locales         []string                 `json:"locales"`
	Screenshots     []runnerJobScreenshotRef `json:"screenshots"`
	// eas.submit (one-click distribute) fields:
	SubmissionID string `json:"submissionId"`
	EASBuildID   string `json:"easBuildId"`
	ASCAppID     string `json:"ascAppId"`
	Destination  string `json:"destination"`
	Profile      string `json:"profile"`
	// Preflight-native OTA fields:
	AppSlug        string `json:"appSlug"`
	Channel        string `json:"channel"`
	RuntimeVersion string `json:"runtimeVersion"`
	Message        string `json:"message"`
	ExportDir      string `json:"exportDir"`
	BinaryBuildId  string `json:"binaryBuildId"`
	GitCommitSha   string `json:"gitCommitSha"`
	DependsOnJobId string `json:"dependsOnJobId"`
}

type runnerJobCommandPlan struct {
	Tool                 string                     `json:"tool"`
	Command              string                     `json:"command"`
	WorkingDirectory     string                     `json:"workingDirectory"`
	CWD                  string                     `json:"cwd"`
	Executable           runnerJobCommandExecutable `json:"executable"`
	ExecutableCandidates []string                   `json:"executableCandidates"`
	Args                 []string                   `json:"args"`
	Env                  map[string]string          `json:"env"`
	Output               runnerJobCommandPlanOutput `json:"output"`
	LevelForge           map[string]any             `json:"levelForge"`
}

type runnerJobCommandExecutable struct {
	Env        string   `json:"env"`
	Candidates []string `json:"candidates"`
}

type runnerJobCommandPlanOutput struct {
	BuildTarget          string `json:"buildTarget"`
	ArtifactKind         string `json:"artifactKind"`
	BuildOutputDirectory string `json:"buildOutputDirectory"`
	OutputPath           string `json:"outputPath"`
	LogPath              string `json:"logPath"`
}

type runnerJobRequiredSecretReference struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Purpose   string `json:"purpose"`
	Key       string `json:"key"`
	LaneScope string `json:"laneScope"`
	Required  bool   `json:"required"`
}

type runnerJobSecretReference struct {
	ID        string         `json:"id"`
	Provider  string         `json:"provider"`
	Purpose   string         `json:"purpose"`
	Key       string         `json:"key"`
	LaneScope string         `json:"laneScope"`
	Metadata  map[string]any `json:"metadata"`
}

type runnerJobSecretRevealData struct {
	SecretReference runnerJobSecretReference `json:"secretReference"`
	Value           string                   `json:"value"`
	ExpiresAt       string                   `json:"expiresAt"`
}

// runnerJobScreenshotRef is one store screenshot to materialize before a
// fastlane.screenshots run: fetched from URL into
// fastlane/screenshots/<locale>/<filename> under the app directory.
type runnerJobScreenshotRef struct {
	URL      string `json:"url"`
	Locale   string `json:"locale"`
	Filename string `json:"filename"`
}

type runnerJobSourceBinding struct {
	ID                string    `json:"id"`
	WorkspaceRoot     string    `json:"workspaceRoot"`
	PackagePath       string    `json:"packagePath"`
	EASProfileName    string    `json:"easProfileName"`
	EASJSONDigest     string    `json:"easJsonDigest"`
	ExpoConfigDigest  string    `json:"expoConfigDigest"`
	AppScheme         string    `json:"appScheme"`
	ExpoSlug          string    `json:"expoSlug"`
	IOSBundleID       string    `json:"iosBundleId"`
	AndroidPackage    string    `json:"androidPackage"`
	EASProjectID      string    `json:"easProjectId"`
	GitRemoteURL      string    `json:"gitRemoteUrl"`
	GitBranch         string    `json:"gitBranch"`
	GitCommitSHA      string    `json:"gitCommitSha"`
	DirtyWorkspace    *bool     `json:"dirtyWorkspace"`
	ChangedSetupFiles *[]string `json:"changedSetupFiles"`
}

type runnerJobNetworkPolicy struct {
	TunnelRequired bool   `json:"tunnelRequired"`
	LocalOnly      bool   `json:"localOnly"`
	Reason         string `json:"reason"`
}

type runnerJobDevSession struct {
	Status         string `json:"status"`
	URL            string `json:"url"`
	AdvertisedURL  string `json:"advertisedUrl"`
	StatusURL      string `json:"statusUrl"`
	HostMode       string `json:"hostMode"`
	HostIP         string `json:"hostIp"`
	TunnelProvider string `json:"tunnelProvider"`
	DeepLinkURL    string `json:"deepLinkUrl"`
	QRURL          string `json:"qrUrl"`
	QRArtifactID   string `json:"qrArtifactId"`
	InstallURL     string `json:"installUrl"`
	Port           int    `json:"port"`
	ID             string `json:"id"`
	PID            int    `json:"pid"`
	WorkspaceRoot  string `json:"workspaceRoot"`
	PackagePath    string `json:"packagePath"`
}

type runnerTargetsData struct {
	Targets []apiTarget `json:"targets"`
}

type runnerTargetLockData struct {
	Target apiTarget `json:"target"`
}

type apiTarget struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	ProviderIdentity string `json:"providerIdentity"`
	Availability     string `json:"availability"`
}

func registerRunner(client *http.Client, options runnerOnceOptions, capabilities map[string]any) (runnerRegistrationData, error) {
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, "/api/preflight/v1/runners/register"),
		options.token,
		map[string]any{
			"workspaceId":           options.workspaceID,
			"name":                  options.name,
			"hostIdentity":          options.hostIdentity,
			"capabilities":          capabilities,
			"allowedWorkspaceRoots": []string{options.workspaceRoot},
		},
	)
	if err != nil {
		return runnerRegistrationData{}, err
	}

	var registration runnerRegistrationData
	if err := decodeEnvelopeData(data, &registration); err != nil {
		return runnerRegistrationData{}, fmt.Errorf("decode runner registration: %w", err)
	}
	if registration.Runner.ID == "" || registration.Token == "" {
		return runnerRegistrationData{}, fmt.Errorf("runner registration response did not include runner ID and token")
	}
	return registration, nil
}

func heartbeatRunner(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, capabilities map[string]any) error {
	payload := map[string]any{
		"status":       "online",
		"capabilities": capabilities,
	}
	if free, err := freeBytesForPath(options.workspaceRoot); err == nil {
		payload["freeDiskGb"] = float64(free) / float64(bytesPerGiB)
	}
	_, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/heartbeat", registration.Runner.ID)),
		registration.Token,
		payload,
	)
	return err
}

func reconcileRunnerStartup(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData) error {
	_, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/reconcile", registration.Runner.ID)),
		registration.Token,
		map[string]any{
			"reason": "runner_startup",
		},
	)
	return err
}

func claimRunnerJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData) (*runnerClaimData, error) {
	if runnerJobStreamEnabled(registration) {
		available, err := streamRunnerJobAvailable(client, options, registration)
		if err == nil && !available {
			// The stream is only an optimization. A stale stream projection must
			// not hide queued jobs from the authoritative claim endpoint.
		}
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/claim", registration.Runner.ID)),
		registration.Token,
		map[string]any{
			"workspaceRoot": options.workspaceRoot,
			"leaseOwner":    runnerLeaseOwner(options),
		},
	)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	var claim runnerClaimData
	if err := decodeEnvelopeData(data, &claim); err != nil {
		return nil, fmt.Errorf("decode runner claim: %w", err)
	}
	if claim.Job.ID == "" {
		return nil, fmt.Errorf("runner claim response did not include a job ID")
	}
	return &claim, nil
}

type runnerJobStreamEvent struct {
	EventType string       `json:"eventType"`
	Job       apiRunnerJob `json:"job"`
}

func runnerJobStreamEnabled(registration runnerRegistrationData) bool {
	enabled, _ := registration.Runner.Capabilities["runnerJobStream"].(bool)
	return enabled
}

func runnerJobHeartbeatEnabled(registration runnerRegistrationData) bool {
	enabled, ok := registration.Runner.Capabilities["runnerJobHeartbeat"].(bool)
	return !ok || enabled
}

func runnerArtifactUploadEnabled(registration runnerRegistrationData) bool {
	enabled, _ := registration.Runner.Capabilities["runnerArtifactUpload"].(bool)
	return enabled
}

func streamRunnerJobAvailable(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData) (bool, error) {
	endpoint := runnerEndpoint(
		options.apiURL,
		fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/stream", registration.Runner.ID),
	)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return true, err
	}
	query := parsed.Query()
	query.Set("workspaceRoot", options.workspaceRoot)
	parsed.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return true, err
	}
	request.Header.Set("Accept", "text/event-stream")
	if registration.Token != "" {
		request.Header.Set("Authorization", "Bearer "+registration.Token)
	}

	response, err := client.Do(request)
	if err != nil {
		return true, err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return true, fmt.Errorf("runner job stream returned HTTP %d", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
		return true, fmt.Errorf("runner job stream returned %q", response.Header.Get("Content-Type"))
	}

	return readRunnerJobAvailableFromSSE(response.Body)
}

func readRunnerJobAvailableFromSSE(body io.Reader) (bool, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var dataLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			available, decisive, err := runnerJobAvailabilityFromSSEData(dataLines)
			dataLines = nil
			if err != nil {
				return true, err
			}
			if decisive {
				return available, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
	}
	if err := scanner.Err(); err != nil {
		return true, err
	}
	available, decisive, err := runnerJobAvailabilityFromSSEData(dataLines)
	if err != nil {
		return true, err
	}
	if decisive {
		return available, nil
	}
	return true, nil
}

func runnerJobAvailabilityFromSSEData(dataLines []string) (available bool, decisive bool, err error) {
	if len(dataLines) == 0 {
		return false, false, nil
	}
	var event runnerJobStreamEvent
	if err := json.Unmarshal([]byte(strings.Join(dataLines, "\n")), &event); err != nil {
		return true, true, err
	}
	switch event.EventType {
	case "runner.job.available":
		return event.Job.ID != "", true, nil
	case "runner.queue.empty":
		return false, true, nil
	default:
		return false, false, nil
	}
}

func completeCapabilityProbe(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, capabilities map[string]any) error {
	return completeRunnerJob(client, options, registration, job, map[string]any{
		"status":       "ok",
		"capabilities": capabilities,
	})
}

func claimAndHandleDevSessionStart(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, stdout io.Writer) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	if claim.Job.Kind != "dev_session.start" {
		return fmt.Errorf("unsupported runner job kind %q", claim.Job.Kind)
	}
	continueWorkflow, err := handleDevSessionStartJob(client, options, registration, claim.Job, stdout)
	if err != nil {
		return err
	}
	if !continueWorkflow {
		return nil
	}
	if isDevelopmentDevSessionJob(claim.Job) {
		return claimAndHandleDevSessionOpen(client, options, registration, stdout)
	}
	return claimAndHandleSimulatorOpen(client, options, registration, stdout)
}

func handleDevSessionStartJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) (bool, error) {
	defer startJobHeartbeat(client, options, registration, job)()
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		if completeErr := completeSourceBindingMismatchJob(client, options, registration, job, stdout, err); completeErr != nil {
			return false, completeErr
		}
		return false, nil
	}

	// A tunnel-mode runner may claim jobs that don't need the tunnel (simulator
	// lane). Serving those through ngrok adds a fragile external dependency for
	// no benefit — and ngrok allows one agent session, so it also contends with
	// genuine tunnel sessions. Downgrade to LAN unless the job requires tunnel.
	if options.hostMode == "tunnel" &&
		!job.Payload.NetworkPolicy.TunnelRequired &&
		!isDevelopmentDevSessionJob(job) {
		options.hostMode = "lan"
	}

	developmentSession := isDevelopmentDevSessionJob(job)
	providerIdentity := job.Payload.ProviderIdentity
	if providerIdentity == "" {
		providerIdentity = job.TargetID
	}
	if providerIdentity == "" && !developmentSession {
		return false, fmt.Errorf("dev_session.start job did not include a simulator provider identity")
	}

	appDir := appDirectoryForJob(options, job)
	// The prove-app chain (dev_session.start -> simulator.open -> maestro.run) has
	// no dev_session.stop, so Metro from a PRIOR build leaks and holds the metro
	// port, making expo decline to start ("Skipping dev server") for this build.
	// Reap leftover dev servers from other CI checkouts before we resolve the port.
	cleanupStalePreflightDevServers(appDir, stdout)
	// Resolve the metro port up front: reuse our own dev server on the configured
	// port; keep the configured port if it's free; otherwise pick the next free
	// port so a foreign dev server on a multi-app host doesn't make expo decline
	// to start ("Skipping dev server"). Every URL below derives from the result,
	// and the chosen port is recorded in the dev-session payload so simulator.open
	// uses it too.
	if options.metroStatusURL == "" && options.metroPort > 0 {
		configuredStatusURL := runnerLocalDevServerURL(options) + "/status"
		if !preflightOwnedMetroReady(client, appDir, configuredStatusURL) &&
			!localPortIsFree(options.metroPort) {
			if freePort := nextFreeLocalPort(options.metroPort, 64); freePort != 0 {
				fmt.Fprintf(
					stdout,
					"metro port %d is in use by another process; using %d\n",
					options.metroPort,
					freePort,
				)
				options.metroPort = freePort
			}
		}
	}
	localDevServerURL := runnerLocalDevServerURL(options)
	advertisedURL, err := advertisedDevServerURL(options, job)
	if err != nil {
		return false, err
	}

	statusURL := options.metroStatusURL
	if statusURL == "" {
		statusURL = localDevServerURL + "/status"
	}

	if providerIdentity != "" && shouldBootIOSSimulator(job) {
		if err := bootIOSSimulator(options, providerIdentity); err != nil {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status": "failed",
				"devSession": devSessionResultPayload(devSessionResultInput{
					status:           "failed",
					localURL:         localDevServerURL,
					advertisedURL:    advertisedURL,
					statusURL:        statusURL,
					hostMode:         options.hostMode,
					port:             options.metroPort,
					appDir:           appDir,
					targetID:         job.Payload.TargetID,
					providerIdentity: providerIdentity,
					sourceBinding:    job.Payload.SourceBinding,
					devBuild:         job.Payload.DevBuild,
					development:      developmentSession,
				}),
				"failure": map[string]any{
					"code":    devSessionStartFailureCode(err),
					"message": err.Error(),
				},
			}); completeErr != nil {
				return false, completeErr
			}
			fmt.Fprintf(stdout, "failed dev session %s %s\n", job.ID, err.Error())
			return false, nil
		}
	}

	sessionStatus := "reused"
	var startedDevServer *expoDevServerProcess
	if !preflightOwnedMetroReady(client, appDir, statusURL) {
		sessionStatus = "started"
		startedDevServer, err = startExpoDevServer(options, appDir, job)
		if err != nil {
			return false, err
		}
		if err := waitForMetroStatusWithCancellation(
			client,
			statusURL,
			expoDevSessionStartTimeout(),
			runnerJobCancellationCheck(client, options, registration, job),
			runnerPollInterval(),
		); err != nil {
			terminateExpoDevServer(startedDevServer)
			if errors.Is(err, errCommandCancelled) {
				if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
					"status": "cancelled",
					"devSession": devSessionResultPayload(devSessionResultInput{
						status:           "cancelled",
						localURL:         localDevServerURL,
						advertisedURL:    advertisedURL,
						statusURL:        statusURL,
						hostMode:         options.hostMode,
						port:             options.metroPort,
						appDir:           appDir,
						targetID:         job.Payload.TargetID,
						providerIdentity: providerIdentity,
						sourceBinding:    job.Payload.SourceBinding,
						devBuild:         job.Payload.DevBuild,
						development:      developmentSession,
					}),
				}); completeErr != nil {
					return false, completeErr
				}
				fmt.Fprintf(stdout, "cancelled dev session %s\n", job.ID)
				return false, nil
			}
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status": "failed",
				"devSession": devSessionResultPayload(devSessionResultInput{
					status:           "failed",
					localURL:         localDevServerURL,
					advertisedURL:    advertisedURL,
					statusURL:        statusURL,
					hostMode:         options.hostMode,
					port:             options.metroPort,
					appDir:           appDir,
					targetID:         job.Payload.TargetID,
					providerIdentity: providerIdentity,
					sourceBinding:    job.Payload.SourceBinding,
					devBuild:         job.Payload.DevBuild,
					development:      developmentSession,
				}),
				"failure": map[string]any{
					"code":    devSessionStartFailureCode(err),
					"message": err.Error(),
				},
			}); completeErr != nil {
				return false, completeErr
			}
			fmt.Fprintf(stdout, "failed dev session %s %s\n", job.ID, err.Error())
			return false, nil
		}
		if err := validateStartedExpoDevServer(startedDevServer, options.metroPort); err != nil {
			terminateExpoDevServer(startedDevServer)
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status": "failed",
				"devSession": devSessionResultPayload(devSessionResultInput{
					status:           "failed",
					localURL:         localDevServerURL,
					advertisedURL:    advertisedURL,
					statusURL:        statusURL,
					hostMode:         options.hostMode,
					port:             options.metroPort,
					appDir:           appDir,
					targetID:         job.Payload.TargetID,
					providerIdentity: providerIdentity,
					sourceBinding:    job.Payload.SourceBinding,
					devBuild:         job.Payload.DevBuild,
					development:      developmentSession,
				}),
				"failure": map[string]any{
					"code":    devSessionStartFailureCode(err),
					"message": err.Error(),
				},
			}); completeErr != nil {
				return false, completeErr
			}
			fmt.Fprintf(stdout, "failed dev session %s %s\n", job.ID, err.Error())
			return false, nil
		}
	}

	advertisedURL, err = resolveStartedAdvertisedDevServerURL(options, job, appDir, startedDevServer)
	if err != nil {
		if startedDevServer != nil {
			terminateExpoDevServer(startedDevServer)
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status": "failed",
			"devSession": devSessionResultPayload(devSessionResultInput{
				status:           "failed",
				localURL:         localDevServerURL,
				advertisedURL:    advertisedURL,
				statusURL:        statusURL,
				hostMode:         options.hostMode,
				port:             options.metroPort,
				appDir:           appDir,
				targetID:         job.Payload.TargetID,
				providerIdentity: providerIdentity,
				sourceBinding:    job.Payload.SourceBinding,
				devBuild:         job.Payload.DevBuild,
				development:      developmentSession,
			}),
			"failure": map[string]any{
				"code":    devSessionStartFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return false, completeErr
		}
		fmt.Fprintf(stdout, "failed dev session %s %s\n", job.ID, err.Error())
		return false, nil
	}

	devSessionPayload := devSessionResultPayload(devSessionResultInput{
		status:           sessionStatus,
		localURL:         localDevServerURL,
		advertisedURL:    advertisedURL,
		statusURL:        statusURL,
		hostMode:         options.hostMode,
		port:             options.metroPort,
		appDir:           appDir,
		targetID:         job.Payload.TargetID,
		providerIdentity: providerIdentity,
		sourceBinding:    job.Payload.SourceBinding,
		devBuild:         job.Payload.DevBuild,
		development:      developmentSession,
	})
	devSessionArtifacts, err := prepareAndUploadDevSessionArtifacts(client, options, registration, job, appDir, devSessionPayload, startedDevServer)
	if err != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":     "failed",
			"devSession": devSessionPayload,
			"failure": map[string]any{
				"code":    devSessionArtifactFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return false, completeErr
		}
		fmt.Fprintf(stdout, "failed dev session artifact handling %s %s\n", job.ID, err.Error())
		return false, nil
	}
	applyDevSessionArtifacts(devSessionPayload, devSessionArtifacts)

	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":     "ok",
		"devSession": devSessionPayload,
	}); err != nil {
		return false, err
	}
	fmt.Fprintf(stdout, "started dev session %s %s\n", job.ID, advertisedURL)
	return true, nil
}

func claimAndHandleDevSessionOpen(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, stdout io.Writer) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	if claim.Job.Kind != "dev_session.open" {
		return fmt.Errorf("unsupported runner job kind %q", claim.Job.Kind)
	}
	return handleDevSessionOpenJob(client, options, registration, claim.Job, stdout)
}

func handleDevSessionStopJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	appDir := appDirectoryForJob(options, job)
	outcome, err := stopPreflightOwnedDevSession(appDir, job.Payload.DevSession.PID)
	if err != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":     "failed",
			"devSession": devSessionStopResultPayload(job, outcome, "failed"),
			"failure": map[string]any{
				"code":    devSessionStopFailureCode(outcome),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed dev session stop %s %s\n", job.ID, err.Error())
		return nil
	}

	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":     "ok",
		"devSession": devSessionStopResultPayload(job, outcome, "stopped"),
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "stopped dev session %s %s\n", job.ID, outcome)
	return nil
}

func handleDevSessionOpenJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	installURL := job.Payload.DevSession.InstallURL
	if installURL == "" {
		installURL = readMapString(job.Payload.DevBuild, "installUrl")
	}
	if providerIdentity, ok := androidDevelopmentOpenProvider(job); ok {
		openAttempt, err := runAndroidDevelopmentOpen(options, job, providerIdentity, installURL)
		if err != nil {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status":      "failed",
				"openAttempt": openAttempt,
				"failure": map[string]any{
					"code":    androidDevelopmentOpenFailureCode(err),
					"message": err.Error(),
				},
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "failed Android development install/open %s %s\n", job.ID, err.Error())
			return nil
		}
		completed, err := completeRunnerJobWithResponse(client, options, registration, job, map[string]any{
			"status":      "ok",
			"openAttempt": openAttempt,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "opened Android development build %s %s\n", job.ID, providerIdentity)
		if completed.WorkflowProjection.Phase == "maestro_queued" {
			if err := heartbeatRunner(client, options, registration, defaultRunnerCapabilities(options.hostMode)); err != nil {
				return err
			}
			return claimAndHandleMaestroRun(client, options, registration, stdout)
		}
		return nil
	}

	openAttempt := map[string]any{
		"strategy":      "qr_install",
		"outcome":       "manual_required",
		"targetClass":   developmentOpenTargetClass(job),
		"installUrl":    installURL,
		"deepLinkUrl":   job.Payload.DevSession.DeepLinkURL,
		"qrUrl":         job.Payload.DevSession.QRURL,
		"advertisedUrl": job.Payload.DevSession.AdvertisedURL,
		"hostMode":      job.Payload.DevSession.HostMode,
	}
	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":      "ok",
		"openAttempt": openAttempt,
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "recorded development install/open attempt %s %s\n", job.ID, openAttempt["outcome"])
	return nil
}

func androidDevelopmentOpenProvider(job apiRunnerJob) (string, bool) {
	if jobPlatform(job) != "android" {
		return "", false
	}
	if strings.TrimSpace(job.Payload.DevSession.DeepLinkURL) == "" {
		return "", false
	}
	if strings.TrimSpace(job.Payload.DevSession.InstallURL) == "" && readMapString(job.Payload.DevBuild, "installUrl") == "" && readMapString(job.Payload.DevBuild, "buildId") == "" {
		return "", false
	}
	providerIdentity := strings.TrimSpace(job.Payload.ProviderIdentity)
	if providerIdentity == "" {
		return "", false
	}
	targetClass := developmentOpenTargetClass(job)
	if targetClass != "android_emulator" && targetClass != "android_device" {
		return "", false
	}
	return providerIdentity, true
}

func runAndroidDevelopmentOpen(options runnerOnceOptions, job apiRunnerJob, providerIdentity string, installURL string) (map[string]any, error) {
	appDir := appDirectoryForJob(options, job)
	logPath, err := androidDevelopmentOpenLogPath(options, job)
	if err != nil {
		return androidDevelopmentOpenAttemptPayload(job, providerIdentity, installURL, "", ""), err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return androidDevelopmentOpenAttemptPayload(job, providerIdentity, installURL, "", logPath), fmt.Errorf("create Android open log directory: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return androidDevelopmentOpenAttemptPayload(job, providerIdentity, installURL, "", logPath), fmt.Errorf("open Android development log: %w", err)
	}
	defer logFile.Close()

	apkPath, err := resolveAndroidAPKPath(appDir, job, installURL)
	if err != nil {
		return androidDevelopmentOpenAttemptPayload(job, providerIdentity, installURL, "", logPath), err
	}
	openAttempt := androidDevelopmentOpenAttemptPayload(job, providerIdentity, installURL, apkPath, logPath)

	if err := runLoggedADBCommand(logFile, options, "-s", providerIdentity, "install", "-r", apkPath); err != nil {
		return openAttempt, fmt.Errorf("install Android development build: %w", err)
	}
	if err := runLoggedADBCommand(logFile, options, androidDeepLinkOpenArgs(providerIdentity, job.Payload.SourceBinding.AndroidPackage, job.Payload.DevSession.DeepLinkURL)...); err != nil {
		return openAttempt, fmt.Errorf("open Android development deep link: %w", err)
	}

	openAttempt["outcome"] = "opened"
	return openAttempt, nil
}

func androidDevelopmentOpenAttemptPayload(job apiRunnerJob, providerIdentity string, installURL string, apkPath string, logPath string) map[string]any {
	openAttempt := map[string]any{
		"strategy":         "adb_install_deeplink",
		"outcome":          "failed",
		"targetClass":      developmentOpenTargetClass(job),
		"providerIdentity": providerIdentity,
		"installUrl":       installURL,
		"deepLinkUrl":      job.Payload.DevSession.DeepLinkURL,
		"qrUrl":            job.Payload.DevSession.QRURL,
		"advertisedUrl":    job.Payload.DevSession.AdvertisedURL,
		"hostMode":         job.Payload.DevSession.HostMode,
	}
	if apkPath != "" {
		openAttempt["apkPath"] = apkPath
	}
	if logPath != "" {
		openAttempt["logPath"] = logPath
	}
	return openAttempt
}

func androidDevelopmentOpenLogPath(options runnerOnceOptions, job apiRunnerJob) (string, error) {
	root := job.Payload.SourceBinding.WorkspaceRoot
	if root == "" {
		root = options.workspaceRoot
	}
	if root == "" {
		return "", fmt.Errorf("Android development open job did not include a workspace root")
	}
	return filepath.Join(root, ".preflight", "android-open", job.ID, "adb-open.log"), nil
}

func runLoggedADBCommand(logFile *os.File, options runnerOnceOptions, args ...string) error {
	return runLoggedADBCommandWithCancellation(logFile, options, nil, args...)
}

func runLoggedADBCommandWithCancellation(logFile *os.File, options runnerOnceOptions, cancellationCheck func() (bool, error), args ...string) error {
	_, _ = fmt.Fprintf(logFile, "$ %s %s\n", options.adbPath, strings.Join(args, " "))
	command := exec.Command(options.adbPath, args...)
	flushLog := attachRedactedCommandLog(command, logFile)
	err := runCommandWithTimeoutAndCancellation(command, androidDevelopmentOpenTimeout(), cancellationCheck, runnerPollInterval())
	flushLog()
	return err
}

func resolveAndroidAPKPath(appDir string, job apiRunnerJob, installURL string) (string, error) {
	if path, ok := localAndroidAPKPath(installURL); ok {
		if err := ensureAPKExists(path); err != nil {
			return "", err
		}
		return path, nil
	}

	buildID := readMapString(job.Payload.DevBuild, "buildId")
	if buildID == "" {
		return "", fmt.Errorf("Android development build did not include a local APK path or EAS build id")
	}
	output, err := runEASCommandWithTimeoutAndCancellation(
		appDir,
		easBuildTimeout(),
		nil,
		nil,
		"build:download",
		"--build-id",
		buildID,
		"--json",
		"--non-interactive",
	)
	if err != nil {
		return "", fmt.Errorf("download Android development build artifact: %w", err)
	}
	apkPath, err := parseEASBuildDownloadOutput(output)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(apkPath) {
		apkPath = filepath.Join(appDir, apkPath)
	}
	if err := ensureAPKExists(apkPath); err != nil {
		return "", err
	}
	return apkPath, nil
}

func localAndroidAPKPath(installURL string) (string, bool) {
	trimmed := strings.TrimSpace(installURL)
	if trimmed == "" {
		return "", false
	}
	if filepath.IsAbs(trimmed) {
		return trimmed, true
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme != "file" {
		return "", false
	}
	return parsed.Path, true
}

func ensureAPKExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("Android APK artifact is not readable: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("Android APK artifact path is a directory: %s", path)
	}
	return nil
}

func parseEASBuildDownloadOutput(output []byte) (string, error) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("EAS build download output was empty")
	}
	var decoded any
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		path := string(trimmed)
		if strings.HasSuffix(strings.ToLower(path), ".apk") {
			return path, nil
		}
		return "", fmt.Errorf("decode EAS build download JSON output: %w", err)
	}

	switch value := decoded.(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), nil
		}
	case map[string]any:
		if path := readEASDownloadPath(value); path != "" {
			return path, nil
		}
	case []any:
		for _, item := range value {
			if record, ok := item.(map[string]any); ok {
				if path := readEASDownloadPath(record); path != "" {
					return path, nil
				}
			}
		}
	}
	return "", fmt.Errorf("EAS build download output did not include an APK path")
}

func readEASDownloadPath(record map[string]any) string {
	for _, key := range []string{"path", "artifactPath", "applicationArchivePath"} {
		if value := readMapString(record, key); value != "" {
			return value
		}
	}
	if artifacts, ok := record["artifacts"].(map[string]any); ok {
		for _, key := range []string{"applicationArchivePath", "artifactPath", "path"} {
			if value := readMapString(artifacts, key); value != "" {
				return value
			}
		}
	}
	return ""
}

func androidDevelopmentOpenFailureCode(err error) string {
	if err == nil {
		return "android_development_open_failed"
	}
	message := err.Error()
	if strings.Contains(message, "build:download") || strings.Contains(message, "download Android development build artifact") {
		return "android_artifact_download_failed"
	}
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "no such file") {
		return "adb_missing"
	}
	if strings.Contains(message, "timed out") {
		return "android_development_open_timeout"
	}
	return "android_development_open_failed"
}

func developmentOpenTargetClass(job apiRunnerJob) string {
	platform := jobPlatform(job)
	rawTargetClass := strings.TrimSpace(job.Payload.TargetClass)
	targetClass := normalizeTargetClass(rawTargetClass)
	if platform == "android" {
		if rawTargetClass != "" && targetClass == "device" {
			return "android_device"
		}
		return "android_emulator"
	}
	if targetClass == "simulator" {
		return "ios_simulator"
	}
	return "ios_device"
}

func claimAndHandleSimulatorOpen(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, stdout io.Writer) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	if claim.Job.Kind != "simulator.open" {
		return fmt.Errorf("unsupported runner job kind %q", claim.Job.Kind)
	}
	return handleSimulatorOpenJob(client, options, registration, claim.Job, stdout)
}

func handleSimulatorOpenJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	providerIdentity := job.Payload.ProviderIdentity
	if providerIdentity == "" {
		providerIdentity = job.TargetID
	}
	if providerIdentity == "" {
		return fmt.Errorf("simulator.open job did not include a simulator provider identity")
	}

	appDir := appDirectoryForJob(options, job)
	port := job.Payload.DevSession.Port
	if port <= 0 {
		port = options.metroPort
	}
	platform := jobPlatform(job)
	if platform == "ios" {
		// Reap leftover CI builds from prior attempts (lease-expiry reclaims
		// re-spawn expo run:ios on top of orphaned ones) or concurrent CI jobs
		// before starting ours. Concurrent xcodebuild invocations share Xcode's
		// ModuleCache build-session and deadlock (SwiftBuild stalls at 0% CPU),
		// which makes the build wedge, the lease expire, and the job restack —
		// a self-sustaining thrash. simulator.open is serial per host, so nothing
		// for this job is running yet; every CI build process here is an orphan or
		// a competitor and is safe to kill. Serializes iOS builds on the host.
		cleanupStaleCiBuildProcesses(stdout, preflightCiCheckoutSegment(appDir))
		// Reclaim disk before building if the shared volume is low. The build host's
		// APFS container fills across ~14 app checkouts + Xcode DerivedData, and a
		// full disk silently breaks ciCheckout (git fetch), simulator.open (xcodebuild
		// write), and Maestro artifact upload. Only clears IDLE DerivedData so a
		// concurrent runner's in-flight build cache is preserved.
		ensureBuildDiskHeadroom(appDir, stdout)
		if err := ensureXcodeEnvNodeBinary(appDir, stdout); err != nil {
			fmt.Fprintf(stdout, "warning: could not normalize ios/.xcode.env.local: %v\n", err)
		}
		// Make the locked target the only booted simulator: expo's install/open
		// step resolves the generic "booted" device and installs/launches on the
		// wrong sim ("No development build installed") when several are booted.
		// Multi-runner-per-host safety: skip this when another runner is mid-build
		// (a different checkout has a live expo/xcodebuild) — shutting down its
		// booted sim would wedge it. With concurrent builds we rely on expo's
		// explicit --device <udid> targeting instead of the booted-singleton trick.
		if strings.TrimSpace(options.simulatorUDID) != "" {
			fmt.Fprintf(stdout, "pinned to simulator %s; skipping booted-simulator shutdown (sole owner of its sim)\n", options.simulatorUDID)
		} else if concurrentPreflightBuildActive(preflightCiCheckoutSegment(appDir)) {
			fmt.Fprintf(stdout, "concurrent runner build active; skipping booted-simulator shutdown\n")
		} else {
			shutdownOtherBootedIOSSimulators(options, providerIdentity, stdout)
		}
		if err := bootIOSSimulator(options, providerIdentity); err != nil {
			fmt.Fprintf(stdout, "warning: could not boot locked simulator %s: %v\n", providerIdentity, err)
		}
	}
	logPath, err := runExpoAppOpen(
		options,
		platform,
		appDir,
		expoRunDeviceSelector(options, platform, job, providerIdentity),
		port,
		job,
		runnerJobCancellationCheck(client, options, registration, job),
	)
	if err != nil {
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status":        "cancelled",
				"simulatorOpen": simulatorOpenResultPayload(job, platform, providerIdentity, appDir, port, logPath),
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled simulator app open %s\n", job.ID)
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":        "failed",
			"simulatorOpen": simulatorOpenResultPayload(job, platform, providerIdentity, appDir, port, logPath),
			"failure": map[string]any{
				"code":    simulatorOpenFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed simulator app open %s %s\n", job.ID, err.Error())
		return nil
	}
	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":        "ok",
		"simulatorOpen": simulatorOpenResultPayload(job, platform, providerIdentity, appDir, port, logPath),
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "opened simulator app %s\n", job.ID)
	if err := heartbeatRunner(client, options, registration, defaultRunnerCapabilities(options.hostMode)); err != nil {
		return err
	}
	return claimAndHandleMaestroRun(client, options, registration, stdout)
}

// ensureXcodeEnvNodeBinary pins ios/.xcode.env.local to this machine's node so
// React Native pod script phases resolve node regardless of where the project
// was prebuilt. Synced/prebuilt projects otherwise carry the origin machine's
// NODE_BINARY path (e.g. an nvm path) which does not exist on a build runner,
// failing xcodebuild at the "[RNDeps] Replace React Native Dependencies" phase.
func ensureXcodeEnvNodeBinary(appDir string, stdout io.Writer) error {
	iosDir := filepath.Join(appDir, "ios")
	if info, statErr := os.Stat(iosDir); statErr != nil || !info.IsDir() {
		return nil // no native ios project (android, or prebuild not run)
	}
	nodePath, err := exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("node not found on PATH: %w", err)
	}
	target := filepath.Join(iosDir, ".xcode.env.local")
	desired := fmt.Sprintf("export NODE_BINARY=%s\n", nodePath)
	if existing, readErr := os.ReadFile(target); readErr == nil && string(existing) == desired {
		return nil
	}
	if err := os.WriteFile(target, []byte(desired), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "normalized %s -> NODE_BINARY=%s\n", target, nodePath)
	return nil
}

func simulatorOpenResultPayload(job apiRunnerJob, platform string, providerIdentity string, appDir string, port int, logPath string) map[string]any {
	return map[string]any{
		"platform":         platform,
		"targetId":         job.Payload.TargetID,
		"providerIdentity": providerIdentity,
		"appDir":           appDir,
		"port":             port,
		"logPath":          logPath,
	}
}

func simulatorOpenFailureCode(err error) string {
	if err == nil {
		return "simulator_open_failed"
	}
	message := err.Error()
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "no such file") {
		return "expo_cli_missing"
	}
	return "simulator_open_failed"
}

func claimAndHandleMaestroRun(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, stdout io.Writer) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	if claim.Job.Kind != "maestro.run" {
		return fmt.Errorf("unsupported runner job kind %q", claim.Job.Kind)
	}
	return handleMaestroRunJob(client, options, registration, claim.Job, stdout)
}

func handleMaestroRunJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	// Cloud device-farm execution is a defined-but-not-yet-implemented adapter
	// (P4). Local runners only execute local targets; surface a clear failure so
	// the control plane keeps the gate pending rather than mis-running on a sim.
	if job.Payload.DeviceProvider == "cloud" {
		return completeRunnerJob(client, options, registration, job, map[string]any{
			"status": "failed",
			"failure": map[string]any{
				"code":    "cloud_farm_unavailable",
				"message": "cloud device-farm execution is not yet implemented on this runner",
			},
		})
	}

	providerIdentity := job.Payload.ProviderIdentity
	if providerIdentity == "" {
		providerIdentity = job.TargetID
	}
	if providerIdentity == "" {
		return fmt.Errorf("maestro.run job did not include a simulator provider identity")
	}
	flowPath := flowPathForJob(options, job)
	artifacts, err := runMaestroSmoke(
		options,
		job,
		providerIdentity,
		flowPath,
		runnerJobCancellationCheck(client, options, registration, job),
	)
	if err != nil {
		_ = uploadMaestroRunArtifacts(client, options, registration, job, providerIdentity, flowPath, artifacts)
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status":  "cancelled",
				"maestro": maestroResultPayload(job, providerIdentity, flowPath, artifacts),
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled Maestro smoke %s\n", job.ID)
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":  "failed",
			"maestro": maestroResultPayload(job, providerIdentity, flowPath, artifacts),
			"failure": map[string]any{
				"code":    maestroFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed Maestro smoke %s %s\n", job.ID, err.Error())
		return nil
	}
	if err := uploadMaestroRunArtifacts(client, options, registration, job, providerIdentity, flowPath, artifacts); err != nil {
		// The smoke already passed (runMaestroSmoke returned no error). Artifact
		// uploads are diagnostic (logs/junit/screenshots) and post only small
		// metadata records; a transient control-plane deadline here must NOT fail
		// a green test and trigger a full, expensive workflow rebuild. Log it and
		// still report the passing result so the gate advances.
		fmt.Fprintf(stdout, "warning: Maestro artifact upload failed (smoke passed, continuing) %s %s\n", job.ID, err.Error())
	}
	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":  "ok",
		"maestro": maestroResultPayload(job, providerIdentity, flowPath, artifacts),
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "completed Maestro smoke %s\n", job.ID)
	return nil
}

func handleUnityBuildPlayerJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	artifacts, err := runUnityBuildPlayer(
		options,
		job,
		runnerJobCancellationCheck(client, options, registration, job),
	)
	if err != nil {
		_ = uploadUnityBuildArtifacts(client, options, registration, job, artifacts)
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status":     "cancelled",
				"unityBuild": unityBuildResultPayload(artifacts),
				"artifacts":  unityBuildArtifactResultPayloads(artifacts),
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled Unity build %s\n", job.ID)
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":     "failed",
			"unityBuild": unityBuildResultPayload(artifacts),
			"artifacts":  unityBuildArtifactResultPayloads(artifacts),
			"failure": map[string]any{
				"code":    unityBuildFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed Unity build %s %s\n", job.ID, err.Error())
		return nil
	}

	if err := uploadUnityBuildArtifacts(client, options, registration, job, artifacts); err != nil {
		fmt.Fprintf(stdout, "warning: Unity artifact upload failed (build completed, continuing) %s %s\n", job.ID, err.Error())
	}
	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":     "ok",
		"unityBuild": unityBuildResultPayload(artifacts),
		"artifacts":  unityBuildArtifactResultPayloads(artifacts),
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "completed Unity build %s %s\n", job.ID, artifacts.Target)
	return nil
}

type unityBuildArtifacts struct {
	Target          string
	ArtifactKind    string
	OutputPath      string
	OutputDirectory string
	LogPath         string
	BuildSeconds    float64
	LevelForge      map[string]any
	BuildArtifacts  []unityBuildArtifact
}

type unityBuildArtifact struct {
	Kind string
	URI  string
}

func runUnityBuildPlayer(
	options runnerOnceOptions,
	job apiRunnerJob,
	cancellationChecks ...func() (bool, error),
) (unityBuildArtifacts, error) {
	plan := job.Payload.CommandPlan
	if err := validateUnityBuildCommandPlan(plan); err != nil {
		return unityBuildArtifactsFromPlan(options, job), err
	}
	executable, err := resolveUnityExecutable(plan)
	if err != nil {
		return unityBuildArtifactsFromPlan(options, job), err
	}
	artifacts := unityBuildArtifactsFromPlan(options, job)
	if artifacts.LogPath == "" {
		return artifacts, fmt.Errorf("unity.build.player command plan did not include a log path")
	}
	if artifacts.OutputPath == "" {
		return artifacts, fmt.Errorf("unity.build.player command plan did not include a build output path")
	}
	if err := os.MkdirAll(filepath.Dir(artifacts.LogPath), 0o755); err != nil {
		return artifacts, fmt.Errorf("create Unity log directory: %w", err)
	}
	if err := os.MkdirAll(unityOutputDirectoryForPath(artifacts.OutputPath), 0o755); err != nil {
		return artifacts, fmt.Errorf("create Unity build output directory: %w", err)
	}
	logFile, err := os.OpenFile(artifacts.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return artifacts, fmt.Errorf("open Unity build log: %w", err)
	}
	defer logFile.Close()

	command := exec.Command(executable, plan.Args...)
	command.Dir = unityCommandWorkingDirectory(options, job, plan)
	command.Env = unityCommandEnv(os.Environ(), plan.Env)
	flushLog := attachRedactedCommandLog(command, logFile)
	var cancellationCheck func() (bool, error)
	if len(cancellationChecks) > 0 {
		cancellationCheck = cancellationChecks[0]
	}
	startedAt := time.Now()
	err = runCommandWithTimeoutAndCancellation(
		command,
		unityBuildTimeout(),
		cancellationCheck,
		runnerPollInterval(),
	)
	flushLog()
	artifacts.BuildSeconds = time.Since(startedAt).Seconds()
	artifacts.BuildArtifacts = discoverUnityBuildArtifacts(artifacts.ArtifactKind, artifacts.OutputPath)
	if err != nil {
		return artifacts, fmt.Errorf("run Unity batchmode build: %w", err)
	}
	if len(artifacts.BuildArtifacts) == 0 {
		return artifacts, fmt.Errorf("Unity build completed but no %s artifact was found under %s", artifacts.ArtifactKind, artifacts.OutputPath)
	}
	return artifacts, nil
}

func unityBuildArtifactsFromPlan(options runnerOnceOptions, job apiRunnerJob) unityBuildArtifacts {
	plan := job.Payload.CommandPlan
	target := strings.TrimSpace(plan.Output.BuildTarget)
	if target == "" {
		target = unityArgValue(plan.Args, "-lfBuildTarget")
	}
	if target == "" && strings.EqualFold(job.Payload.Platform, "android") {
		target = "Android"
	}
	if target == "" {
		target = job.Payload.Platform
	}
	artifactKind := strings.TrimSpace(plan.Output.ArtifactKind)
	if artifactKind == "" {
		artifactKind = unityArtifactKindForTarget(target)
	}
	outputPath := firstNonEmpty(
		strings.TrimSpace(plan.Output.OutputPath),
		strings.TrimSpace(plan.Output.BuildOutputDirectory),
		unityArgValue(plan.Args, "-lfBuildOutput"),
	)
	logPath := firstNonEmpty(
		strings.TrimSpace(plan.Output.LogPath),
		unityArgValue(plan.Args, "-logFile"),
	)
	return unityBuildArtifacts{
		Target:          target,
		ArtifactKind:    artifactKind,
		OutputPath:      outputPath,
		OutputDirectory: unityOutputDirectoryForPath(outputPath),
		LogPath:         logPath,
		LevelForge:      copyMapAny(plan.LevelForge),
	}
}

func validateUnityBuildCommandPlan(plan runnerJobCommandPlan) error {
	if strings.ToLower(strings.TrimSpace(plan.Tool)) != "unity" {
		return fmt.Errorf("unity.build.player command plan tool must be unity")
	}
	if strings.ToLower(strings.TrimSpace(plan.Command)) != "batchmode" {
		return fmt.Errorf("unity.build.player command plan command must be batchmode")
	}
	for _, required := range []string{
		"-batchmode",
		"-nographics",
		"-quit",
		"-projectPath",
		"-executeMethod",
		"-lfBuildTarget",
		"-lfBuildOutput",
		"-logFile",
	} {
		if !containsString(plan.Args, required) {
			return fmt.Errorf("unity.build.player command plan missing required arg %s", required)
		}
	}
	if method := unityArgValue(plan.Args, "-executeMethod"); method != "LevelForge.Editor.LevelForgeBuild.RunHeadlessBuild" {
		return fmt.Errorf("unity.build.player command plan execute method %q is not allowlisted", method)
	}
	for _, valueArg := range []string{"-projectPath", "-executeMethod", "-lfBuildTarget", "-lfBuildOutput", "-logFile"} {
		if unityArgValue(plan.Args, valueArg) == "" {
			return fmt.Errorf("unity.build.player command plan arg %s requires a value", valueArg)
		}
	}
	return nil
}

func unityArgValue(args []string, name string) string {
	for index := 0; index < len(args)-1; index += 1 {
		if args[index] == name {
			return strings.TrimSpace(args[index+1])
		}
	}
	return ""
}

func resolveUnityExecutable(plan runnerJobCommandPlan) (string, error) {
	for _, candidate := range unityExecutableCandidates(plan) {
		if resolved, ok := resolveExecutableCandidate(candidate); ok {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("Unity editor executable not found; set PREFLIGHT_UNITY_COMMAND or UNITY_EDITOR")
}

func unityExecutableCandidates(plan runnerJobCommandPlan) []string {
	var candidates []string
	if configured := strings.TrimSpace(os.Getenv("PREFLIGHT_UNITY_COMMAND")); configured != "" {
		candidates = append(candidates, configured)
	}
	if envName := strings.TrimSpace(plan.Executable.Env); envName != "" {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			candidates = append(candidates, value)
		}
	}
	candidates = append(candidates, plan.Executable.Candidates...)
	candidates = append(candidates, plan.ExecutableCandidates...)
	if value := strings.TrimSpace(os.Getenv("UNITY_EDITOR")); value != "" {
		candidates = append(candidates, value)
	}
	candidates = append(candidates, "unity", "Unity")
	return candidates
}

func resolveExecutableCandidate(candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}
	if strings.ContainsAny(candidate, "*?[") {
		matches, err := filepath.Glob(candidate)
		if err != nil {
			return "", false
		}
		sort.Strings(matches)
		for _, match := range matches {
			if resolved, ok := resolveExecutableCandidate(match); ok {
				return resolved, true
			}
		}
		return "", false
	}
	if filepath.IsAbs(candidate) || strings.Contains(candidate, string(os.PathSeparator)) {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, true
		}
		return "", false
	}
	resolved, err := exec.LookPath(candidate)
	if err != nil {
		return "", false
	}
	return resolved, true
}

func unityCommandAvailable() bool {
	_, err := resolveUnityExecutable(runnerJobCommandPlan{
		Executable: runnerJobCommandExecutable{
			Env: "UNITY_EDITOR",
			Candidates: []string{
				"/opt/unity/Editor/Unity",
				"/opt/Unity/Editor/Unity",
				"/Applications/Unity/Hub/Editor/*/Unity.app/Contents/MacOS/Unity",
			},
		},
	})
	return err == nil
}

func unityCommandWorkingDirectory(options runnerOnceOptions, job apiRunnerJob, plan runnerJobCommandPlan) string {
	workingDirectory := firstNonEmpty(strings.TrimSpace(plan.WorkingDirectory), strings.TrimSpace(plan.CWD))
	if workingDirectory == "" {
		return appDirectoryForJob(options, job)
	}
	if filepath.IsAbs(workingDirectory) {
		return workingDirectory
	}
	root := job.Payload.SourceBinding.WorkspaceRoot
	if root == "" {
		root = options.workspaceRoot
	}
	return filepath.Join(root, workingDirectory)
}

func unityCommandEnv(base []string, env map[string]string) []string {
	values := map[string]string{
		"CI": "1",
	}
	for key, value := range env {
		values[key] = value
	}
	return upsertEnvValues(append([]string{}, base...), values)
}

func unityBuildTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_UNITY_BUILD_TIMEOUT", defaultUnityBuildTimeout)
}

func unityArtifactKindForTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "android":
		return "android_apk"
	case "ios":
		return "ios_xcode_archive"
	default:
		return "tool_output"
	}
}

func unityOutputDirectoryForPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	extension := strings.ToLower(filepath.Ext(path))
	switch extension {
	case ".apk", ".aab", ".ipa", ".zip":
		return filepath.Dir(path)
	default:
		return path
	}
}

func discoverUnityBuildArtifacts(kind string, outputPath string) []unityBuildArtifact {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return nil
	}
	if info, err := os.Stat(outputPath); err == nil && !info.IsDir() {
		return []unityBuildArtifact{{Kind: unityArtifactKindForPath(kind, outputPath), URI: outputPath}}
	}
	outputDir := unityOutputDirectoryForPath(outputPath)
	var artifacts []unityBuildArtifact
	for _, path := range findFilesWithExtensions(outputDir, ".apk", ".aab", ".ipa", ".zip") {
		artifacts = append(artifacts, unityBuildArtifact{
			Kind: unityArtifactKindForPath(kind, path),
			URI:  path,
		})
	}
	for _, path := range findUnityXcodeArchives(outputDir) {
		artifacts = append(artifacts, unityBuildArtifact{
			Kind: "ios_xcode_archive",
			URI:  path,
		})
	}
	return artifacts
}

func unityArtifactKindForPath(fallback string, path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".apk":
		return "android_apk"
	case ".aab":
		return "android_aab"
	case ".ipa":
		return "ios_ipa"
	case ".zip":
		return firstNonEmpty(fallback, "tool_output")
	default:
		return firstNonEmpty(fallback, "tool_output")
	}
}

func findUnityXcodeArchives(root string) []string {
	var matches []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".xcarchive") {
			matches = append(matches, path)
			return filepath.SkipDir
		}
		return nil
	})
	sort.Strings(matches)
	return matches
}

func uploadUnityBuildArtifacts(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	artifacts unityBuildArtifacts,
) error {
	if !runnerArtifactUploadEnabled(registration) {
		return nil
	}
	metadata := map[string]any{
		"target":        artifacts.Target,
		"artifactKind":  artifacts.ArtifactKind,
		"outputPath":    artifacts.OutputPath,
		"levelForge":    artifacts.LevelForge,
		"buildSeconds":  artifacts.BuildSeconds,
		"unityJobKind":  job.Kind,
		"buildProvider": job.Payload.BuildProvider,
	}
	for _, artifact := range artifacts.BuildArtifacts {
		if err := uploadRunnerArtifact(client, options, registration, job, artifact.Kind, artifact.URI, "release", metadata); err != nil {
			return err
		}
	}
	if artifacts.LogPath != "" {
		if err := uploadRunnerArtifact(client, options, registration, job, "unity_build_log", artifacts.LogPath, "debug", metadata); err != nil {
			return err
		}
	}
	return nil
}

func unityBuildResultPayload(artifacts unityBuildArtifacts) map[string]any {
	result := map[string]any{
		"target":          artifacts.Target,
		"artifactKind":    artifacts.ArtifactKind,
		"outputPath":      artifacts.OutputPath,
		"outputDirectory": artifacts.OutputDirectory,
		"logPath":         artifacts.LogPath,
		"buildSeconds":    artifacts.BuildSeconds,
		"levelForge":      artifacts.LevelForge,
	}
	if len(artifacts.BuildArtifacts) > 0 {
		result["primaryArtifactPath"] = artifacts.BuildArtifacts[0].URI
	}
	return result
}

func unityBuildArtifactResultPayloads(artifacts unityBuildArtifacts) []map[string]any {
	result := make([]map[string]any, 0, len(artifacts.BuildArtifacts))
	for _, artifact := range artifacts.BuildArtifacts {
		entry := map[string]any{
			"kind": artifact.Kind,
			"uri":  artifact.URI,
		}
		if sizeBytes, ok := artifactSizeBytes(artifact.URI); ok {
			entry["sizeBytes"] = sizeBytes
		}
		result = append(result, entry)
	}
	return result
}

func unityBuildFailureCode(err error) string {
	if err == nil {
		return "unity_build_failed"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unity editor executable not found") ||
		strings.Contains(message, "executable file not found") ||
		strings.Contains(message, "no such file") {
		return "unity_missing"
	}
	if strings.Contains(message, "license") || strings.Contains(message, "serial") {
		return "unity_license_unavailable"
	}
	if strings.Contains(message, "timed out") {
		return "unity_build_timeout"
	}
	if strings.Contains(message, "no android_apk artifact") || strings.Contains(message, "no android_aab artifact") {
		return "unity_artifact_missing"
	}
	return "unity_build_failed"
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func copyMapAny(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

// handleOtaJob runs Preflight-native OTA jobs (not EAS Update):
//
//	ota.export      — npx expo export
//	ota.publish     — publish-local.mjs into PREFLIGHT_OTA_STORE
//	ota.fingerprint — npx expo-updates fingerprint:generate
func handleOtaJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	appDir := appDirectoryForJob(options, job)
	p := job.Payload
	platform := strings.TrimSpace(p.Platform)
	if platform == "" {
		platform = "ios"
	}
	channel := strings.TrimSpace(p.Channel)
	if channel == "" {
		channel = "preview"
	}
	appSlug := strings.TrimSpace(p.AppSlug)
	if appSlug == "" {
		appSlug = strings.TrimSpace(p.SourceBinding.ExpoSlug)
	}
	if appSlug == "" {
		appSlug = "app"
	}
	exportDir := strings.TrimSpace(p.ExportDir)
	if exportDir == "" {
		exportDir = "dist"
	}
	if !filepath.IsAbs(exportDir) {
		exportDir = filepath.Join(appDir, exportDir)
	}
	runtimeVersion := strings.TrimSpace(p.RuntimeVersion)
	if runtimeVersion == "" {
		runtimeVersion = appSlug + "-p0"
	}
	message := strings.TrimSpace(p.Message)
	if message == "" {
		message = fmt.Sprintf("ota %s %s", job.Kind, time.Now().UTC().Format(time.RFC3339))
	}

	var (
		output []byte
		err    error
		result map[string]any
	)

	switch job.Kind {
	case "ota.export":
		output, err = runOtaExport(appDir, platform, exportDir, channel, runtimeVersion, runnerJobCancellationCheck(client, options, registration, job))
		result = map[string]any{
			"exportDir":      exportDir,
			"runtimeVersion": runtimeVersion,
			"platform":       platform,
			"channel":        channel,
			"appSlug":        appSlug,
			"output":         truncateRunnerOutput(string(output)),
		}
	case "ota.publish":
		updateID, pubOut, pubErr := runOtaPublish(options, appDir, exportDir, appSlug, channel, platform, runtimeVersion, message, runnerJobCancellationCheck(client, options, registration, job))
		output, err = pubOut, pubErr
		result = map[string]any{
			"updateId":       updateID,
			"exportDir":      exportDir,
			"runtimeVersion": runtimeVersion,
			"platform":       platform,
			"channel":        channel,
			"appSlug":        appSlug,
			"storeRoot":      otaStoreRoot(),
			"output":         truncateRunnerOutput(string(output)),
		}
	case "ota.fingerprint":
		fp, fpOut, fpErr := runOtaFingerprint(appDir, platform, runnerJobCancellationCheck(client, options, registration, job))
		output, err = fpOut, fpErr
		result = map[string]any{
			"fingerprintHash": fp,
			"runtimeVersion":  runtimeVersion,
			"platform":        platform,
			"appSlug":         appSlug,
			"output":          truncateRunnerOutput(string(output)),
		}
	default:
		return fmt.Errorf("unsupported ota job kind %q", job.Kind)
	}

	if err != nil {
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status": "cancelled",
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled ota job %s\n", job.ID)
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status": "failed",
			"failure": map[string]any{
				"code":    otaFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed ota job %s %s\n", job.ID, err.Error())
		return nil
	}

	result["status"] = "ok"
	if completeErr := completeRunnerJob(client, options, registration, job, result); completeErr != nil {
		return completeErr
	}
	fmt.Fprintf(stdout, "completed ota job %s (%s)\n", job.ID, job.Kind)
	return nil
}

func otaFailureCode(err error) string {
	if err == nil {
		return "ota_failed"
	}
	message := err.Error()
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "not found") {
		return "expo_missing"
	}
	if strings.Contains(message, "command timed out") {
		return "ota_timeout"
	}
	if strings.Contains(message, "ota-store") || strings.Contains(message, "PREFLIGHT_OTA_STORE") {
		return "ota_store_unavailable"
	}
	return "ota_failed"
}

func otaStoreRoot() string {
	if v := strings.TrimSpace(os.Getenv("PREFLIGHT_OTA_STORE")); v != "" {
		return v
	}
	if _, err := os.Stat("/Volumes/PreflightBuild"); err == nil {
		return "/Volumes/PreflightBuild/ota-store"
	}
	return filepath.Join(os.TempDir(), "preflight-ota-store")
}

func findOtaPublishScript(options runnerOnceOptions) (string, error) {
	if v := strings.TrimSpace(os.Getenv("PREFLIGHT_OTA_PUBLISH_SCRIPT")); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v, nil
		}
	}
	candidates := []string{
		filepath.Join(options.workspaceRoot, "packages/ota/scripts/publish-local.mjs"),
		filepath.Join(options.workspaceRoot, "preflight-app/packages/ota/scripts/publish-local.mjs"),
		"/Volumes/dev/preflight-app/packages/ota/scripts/publish-local.mjs",
	}
	// Walk up from workspace root a few levels.
	dir := options.workspaceRoot
	for i := 0; i < 4 && dir != "" && dir != "/"; i++ {
		candidates = append(candidates, filepath.Join(dir, "packages/ota/scripts/publish-local.mjs"))
		dir = filepath.Dir(dir)
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("publish-local.mjs not found (set PREFLIGHT_OTA_PUBLISH_SCRIPT)")
}

func runOtaExport(appDir, platform, exportDir, channel, runtimeVersion string, cancelled func() (bool, error)) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(exportDir), 0o755); err != nil {
		return nil, err
	}
	appVariant := "development"
	switch channel {
	case "preview":
		appVariant = "preview"
	case "production":
		appVariant = "production"
	}
	// Relative output for expo when under appDir.
	outArg := exportDir
	if rel, err := filepath.Rel(appDir, exportDir); err == nil && !strings.HasPrefix(rel, "..") {
		outArg = rel
	}
	args := []string{"expo", "export", "--platform", platform, "--output-dir", outArg, "--clear"}
	cmd := exec.Command("npx", args...)
	cmd.Dir = appDir
	cmd.Env = append(os.Environ(),
		"APP_VARIANT="+appVariant,
		"PREFLIGHT_OTA_RUNTIME_VERSION="+runtimeVersion,
		"EXPO_NO_TELEMETRY=1",
		"EXPO_NO_DOTENV=1",
	)
	return runCommandCollectOutput(cmd, 20*time.Minute, cancelled)
}

func runOtaPublish(options runnerOnceOptions, appDir, exportDir, appSlug, channel, platform, runtimeVersion, message string, cancelled func() (bool, error)) (string, []byte, error) {
	script, err := findOtaPublishScript(options)
	if err != nil {
		return "", nil, err
	}
	if _, err := os.Stat(exportDir); err != nil {
		return "", nil, fmt.Errorf("export dir missing for ota.publish: %s: %w", exportDir, err)
	}
	args := []string{
		"--experimental-strip-types", script,
		"--slug", appSlug,
		"--app-dir", appDir,
		"--export-dir", exportDir,
		"--channel", channel,
		"--platform", platform,
		"--runtime-version", runtimeVersion,
		"--message", message,
		"--skip-export",
	}
	cmd := exec.Command("node", args...)
	cmd.Dir = filepath.Dir(script)
	cmd.Env = append(os.Environ(),
		"PREFLIGHT_OTA_STORE="+otaStoreRoot(),
		"PREFLIGHT_OTA_RUNTIME_VERSION="+runtimeVersion,
		"EXPO_NO_TELEMETRY=1",
	)
	out, err := runCommandCollectOutput(cmd, 15*time.Minute, cancelled)
	updateID := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "PREFLIGHT_OTA_UPDATE_ID=") {
			updateID = strings.TrimPrefix(line, "PREFLIGHT_OTA_UPDATE_ID=")
			break
		}
	}
	return updateID, out, err
}

func runOtaFingerprint(appDir, platform string, cancelled func() (bool, error)) (string, []byte, error) {
	args := []string{"expo-updates", "fingerprint:generate", "--platform", platform}
	cmd := exec.Command("npx", args...)
	cmd.Dir = appDir
	cmd.Env = append(os.Environ(), "EXPO_NO_TELEMETRY=1")
	out, err := runCommandCollectOutput(cmd, 10*time.Minute, cancelled)
	hash := ""
	// Best-effort: last non-empty line or JSON hash field.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		hash = strings.TrimSpace(lines[len(lines)-1])
	}
	var parsed map[string]any
	if json.Unmarshal(out, &parsed) == nil {
		if h, ok := parsed["hash"].(string); ok && h != "" {
			hash = h
		}
	}
	return hash, out, err
}

func runCommandCollectOutput(cmd *exec.Cmd, timeout time.Duration, cancelled func() (bool, error)) ([]byte, error) {
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return buf.Bytes(), err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return buf.Bytes(), err
		case <-timer.C:
			_ = cmd.Process.Kill()
			return buf.Bytes(), fmt.Errorf("command timed out after %s", timeout)
		case <-ticker.C:
			if cancelled != nil {
				isCancelled, cerr := cancelled()
				if cerr != nil {
					// Treat probe errors as non-fatal; keep running.
					continue
				}
				if isCancelled {
					_ = cmd.Process.Kill()
					return buf.Bytes(), errCommandCancelled
				}
			}
		}
	}
}

// handleFastlaneJob executes fastlane (produce/metadata/screenshots) for the
// claimed job. v1 uses the runner host's fastlane environment (FASTLANE_SESSION,
// FASTLANE_USER/PRODUCE_USERNAME, FASTLANE_TEAM_ID, and the ASC API key under
// ~/.appstoreconnect) — credentials are not materialized from Preflight yet.
func handleFastlaneJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	appDir := appDirectoryForJob(options, job)
	ascKeyPath, keyErr := writeASCApiKeyFile(appDir)
	if keyErr != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":  "failed",
			"failure": map[string]any{"code": "fastlane_asc_key_unavailable", "message": keyErr.Error()},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed fastlane job %s %s\n", job.ID, keyErr.Error())
		return nil
	}
	args, prepErr := fastlanePlanArgs(appDir, job, ascKeyPath)
	if prepErr != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":  "failed",
			"failure": map[string]any{"code": "fastlane_payload_invalid", "message": prepErr.Error()},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed fastlane job %s %s\n", job.ID, prepErr.Error())
		return nil
	}

	output, err := runFastlaneCommand(
		appDir,
		runnerJobCancellationCheck(client, options, registration, job),
		args...,
	)
	if err != nil {
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status": "cancelled",
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled fastlane job %s\n", job.ID)
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status": "failed",
			"failure": map[string]any{
				"code":    fastlaneFailureCode(err),
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed fastlane job %s %s\n", job.ID, err.Error())
		return nil
	}

	if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
		"status": "ok",
		"fastlane": map[string]any{
			"kind":          job.Kind,
			"appIdentifier": job.Payload.AppIdentifier,
			"platform":      job.Payload.Platform,
			"output":        truncateRunnerOutput(string(output)),
		},
	}); completeErr != nil {
		return completeErr
	}
	fmt.Fprintf(stdout, "completed fastlane job %s (%s)\n", job.ID, job.Kind)
	return nil
}

// handleEASSubmitJob runs the one-click distribute: `eas build:submit --id
// <easBuildId>` against an already-FINISHED EAS build. The submit profile in
// the app's eas.json resolves ASC credentials via EXPO_ASC_* env placeholders,
// which this handler materializes from the runner's PREFLIGHT_ASC_* env.
// NOTE: eas-cli's own error/success message is unreliable for submits — the
// server-side ASC reconciler is the source of truth for the final state; this
// handler reports transport-level success/failure only.
func handleEASSubmitJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()

	easBuildID := strings.TrimSpace(job.Payload.EASBuildID)
	if easBuildID == "" {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":  "failed",
			"failure": map[string]any{"code": "eas_submit_payload_invalid", "message": "eas.submit requires easBuildId"},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed eas.submit job %s missing easBuildId\n", job.ID)
		return nil
	}

	appDir := appDirectoryForJob(options, job)

	// A server-initiated distribute points at a Preflight CI checkout that may be
	// absent or stale (cleaned under disk pressure — the dir can exist without a
	// .git or eas.json). Make it match the source binding's commit before we
	// read eas.json. Clone/reset only, no dependency install: submit reads
	// eas.json/app.config and needs no node_modules, and a frozen install here
	// would fail on any lockfile drift.
	checkoutRoot := strings.TrimSpace(job.Payload.SourceBinding.WorkspaceRoot)
	if checkoutRoot == "" {
		checkoutRoot = options.workspaceRoot
	}
	if checkoutErr := ensureEASSubmitCheckout(checkoutRoot, job.Payload.SourceBinding); checkoutErr != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":  "failed",
			"failure": map[string]any{"code": "eas_submit_checkout_failed", "message": checkoutErr.Error()},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed eas.submit job %s checkout: %s\n", job.ID, checkoutErr.Error())
		return nil
	}

	easEnv, err := easSecretEnvForJob(client, options, registration, job)
	if err != nil {
		return err
	}

	// Headless ASC auth: write the API key JSON next to the app and expose the
	// EXPO_ASC_* env the fleet's eas.json submit profiles reference. Missing
	// ASC env is not fatal here — the submit profile may embed credentials.
	if ascKeyPath, keyErr := writeASCApiKeyFile(appDir); keyErr != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":  "failed",
			"failure": map[string]any{"code": "asc_auth_failed", "message": keyErr.Error()},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed eas.submit job %s %s\n", job.ID, keyErr.Error())
		return nil
	} else if ascKeyPath != "" {
		easEnv["EXPO_ASC_API_KEY_PATH"] = ascKeyPath
		if keyID := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_KEY_ID")); keyID != "" {
			easEnv["EXPO_ASC_KEY_ID"] = keyID
		}
		if issuerID := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_ISSUER_ID")); issuerID != "" {
			easEnv["EXPO_ASC_ISSUER_ID"] = issuerID
		}
	}

	// eas-cli reads the App Store Connect API key ONLY from eas.json's submit
	// profile — not from env vars (the EXPO_ASC_* above) and not from CLI flags
	// (build:submit has none). So a non-interactive submit fails with "App Store
	// Connect API Keys cannot be set up in --non-interactive mode" unless the
	// key is present in eas.json. Inject it from the runner's PREFLIGHT_ASC_*
	// env into the checkout's eas.json before submitting.
	if err := ensureEASSubmitASCKey(appDir, strings.TrimSpace(job.Payload.Profile)); err != nil {
		fmt.Fprintf(stdout, "warning: eas.submit job %s could not inject ASC key into eas.json: %v\n", job.ID, err)
	}

	args := []string{
		"build:submit",
		"--platform", jobPlatformForEAS(job),
		"--id", easBuildID,
		"--non-interactive",
		"--wait",
	}
	if profile := strings.TrimSpace(job.Payload.Profile); profile != "" {
		args = append(args, "--profile", profile)
	}

	output, err := runEASCommandWithTimeoutAndCancellation(
		appDir,
		easSubmitTimeout(),
		runnerJobCancellationCheck(client, options, registration, job),
		easEnv,
		args...,
	)
	if err != nil {
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status": "cancelled",
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled eas.submit job %s\n", job.ID)
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status": "failed",
			"failure": map[string]any{
				"code":    easSubmitFailureCode(err),
				"message": err.Error(),
			},
			"output": truncateRunnerOutput(string(output)),
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed eas.submit job %s %s\n", job.ID, err.Error())
		return nil
	}

	result := map[string]any{
		"status":       "ok",
		"submissionId": job.Payload.SubmissionID,
		"easBuildId":   easBuildID,
		"output":       truncateRunnerOutput(string(output)),
	}
	if ascSubmissionID := parseEASSubmitSubmissionID(string(output)); ascSubmissionID != "" {
		result["ascSubmissionId"] = ascSubmissionID
	}
	if completeErr := completeRunnerJob(client, options, registration, job, result); completeErr != nil {
		return completeErr
	}
	fmt.Fprintf(stdout, "completed eas.submit job %s (build %s)\n", job.ID, easBuildID)
	return nil
}

func easSubmitTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("PREFLIGHT_EAS_SUBMIT_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return 30 * time.Minute
}

func easSubmitFailureCode(err error) string {
	if err == nil {
		return "eas_submit_failed"
	}
	message := err.Error()
	if strings.Contains(message, "executable file not found") {
		return "eas_cli_missing"
	}
	if strings.Contains(message, "command timed out") {
		return "eas_submit_timeout"
	}
	if strings.Contains(message, "Invalid username and password") ||
		strings.Contains(message, "authentication") ||
		strings.Contains(message, "401") {
		return "asc_auth_failed"
	}
	return "eas_submit_failed"
}

// parseEASSubmitSubmissionID pulls the EAS submission id out of eas-cli's
// output (the /accounts/<acct>/projects/<proj>/submissions/<uuid> URL it
// prints, or a bare "Submission ID" line). Best-effort: empty when absent.
func parseEASSubmitSubmissionID(output string) string {
	if match := regexp.MustCompile(`/submissions/([0-9a-fA-F-]{36})`).FindStringSubmatch(output); len(match) == 2 {
		return match[1]
	}
	if match := regexp.MustCompile(`(?i)submission(?:\s+id)?[:\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`).FindStringSubmatch(output); len(match) == 2 {
		return match[1]
	}
	return ""
}

func fastlaneFailureCode(err error) string {
	if err == nil {
		return "fastlane_failed"
	}
	message := err.Error()
	if strings.Contains(message, "executable file not found") {
		return "fastlane_missing"
	}
	if strings.Contains(message, "command timed out") {
		return "fastlane_timeout"
	}
	if strings.Contains(message, "Invalid username and password") ||
		strings.Contains(message, "session") ||
		strings.Contains(message, "401") {
		return "fastlane_auth_failed"
	}
	return "fastlane_failed"
}

func truncateRunnerOutput(output string) string {
	const max = 4000
	output = strings.TrimSpace(output)
	if len(output) > max {
		return output[len(output)-max:]
	}
	return output
}

// fastlanePlanArgs builds the policy-shaped `fastlane` argument list for the job
// kind and writes any metadata files deliver/supply expect.
func fastlanePlanArgs(appDir string, job apiRunnerJob, ascKeyPath string) ([]string, error) {
	p := job.Payload
	apiKeyArgs := []string{}
	if ascKeyPath != "" {
		apiKeyArgs = []string{"--api_key_path", ascKeyPath}
	}
	switch job.Kind {
	case "fastlane.produce":
		if strings.TrimSpace(p.AppIdentifier) == "" {
			return nil, fmt.Errorf("fastlane.produce requires appIdentifier")
		}
		name := p.AppName
		if strings.TrimSpace(name) == "" {
			name = p.AppIdentifier
		}
		args := []string{
			"produce", "create",
			"--app_identifier", p.AppIdentifier,
			"--app_name", name,
		}
		if strings.TrimSpace(p.Sku) != "" {
			args = append(args, "--sku", p.Sku)
		} else {
			args = append(args, "--sku", p.AppIdentifier)
		}
		lang := p.PrimaryLanguage
		if strings.TrimSpace(lang) == "" {
			lang = "English"
		}
		args = append(args, "--language", lang)
		if strings.TrimSpace(p.CompanyName) != "" {
			args = append(args, "--company_name", p.CompanyName)
		}
		// Android (Play) app creation goes through Google Play, not produce.
		if p.Platform == "android" {
			args = append(args, "--platforms", "android")
		}
		return args, nil
	case "fastlane.metadata":
		if strings.TrimSpace(p.AppIdentifier) == "" {
			return nil, fmt.Errorf("fastlane.metadata requires appIdentifier")
		}
		if p.Platform == "android" {
			metadataDir := filepath.Join(appDir, "fastlane", "metadata", "android")
			if err := writeAndroidMetadataFiles(metadataDir, p.Metadata); err != nil {
				return nil, err
			}
			return []string{
				"supply",
				"--package_name", p.AppIdentifier,
				"--skip_upload_apk", "--skip_upload_aab",
				"--metadata_path", metadataDir,
			}, nil
		}
		metadataDir := filepath.Join(appDir, "fastlane", "metadata")
		if err := writeAppleMetadataFiles(metadataDir, p.Metadata); err != nil {
			return nil, err
		}
		return append([]string{
			"deliver",
			"--app_identifier", p.AppIdentifier,
			"--skip_binary_upload", "--skip_screenshots", "--force",
			// Precheck can't run with API-key auth (IAP check aborts the
			// whole run after the upload already succeeded) and adds nothing
			// to a metadata/asset push — skip it entirely.
			"--run_precheck_before_submit", "false",
			"--metadata_path", metadataDir,
		}, apiKeyArgs...), nil
	case "fastlane.screenshots":
		if strings.TrimSpace(p.AppIdentifier) == "" {
			return nil, fmt.Errorf("fastlane.screenshots requires appIdentifier")
		}
		screenshotsDir := filepath.Join(appDir, "fastlane", "screenshots")
		if err := materializeScreenshots(screenshotsDir, p.Screenshots); err != nil {
			return nil, err
		}
		// Without any deliver config in cwd, deliver prompts "Do you want to
		// setup deliver?" and crashes in non-interactive mode. An empty
		// Deliverfile satisfies it; all real config comes from CLI flags.
		if err := ensureEmptyDeliverfile(filepath.Join(appDir, "fastlane")); err != nil {
			return nil, err
		}
		if p.Platform == "android" {
			return []string{
				"supply",
				"--package_name", p.AppIdentifier,
				"--skip_upload_apk", "--skip_upload_aab", "--skip_upload_metadata",
				"--screenshots_path", screenshotsDir,
			}, nil
		}
		return append([]string{
			"deliver",
			"--app_identifier", p.AppIdentifier,
			"--skip_binary_upload", "--skip_metadata", "--force",
			// The Preflight listing is the source of truth: replace whatever
			// screenshot set ASC has (also avoids "Screenshot Set Already
			// Exists" collisions from earlier partial runs).
			"--overwrite_screenshots",
			// Precheck can't run with API-key auth (IAP check aborts the
			// whole run after the upload already succeeded) and adds nothing
			// to a metadata/asset push — skip it entirely.
			"--run_precheck_before_submit", "false",
			"--screenshots_path", screenshotsDir,
		}, apiKeyArgs...), nil
	default:
		return nil, fmt.Errorf("unsupported fastlane job kind %q", job.Kind)
	}
}

// ensureEmptyDeliverfile creates fastlane/Deliverfile if absent so `deliver`
// never falls into its interactive "setup deliver?" prompt (which crashes
// under non-interactive runners). Config is passed via CLI flags instead.
func ensureEmptyDeliverfile(fastlaneDir string) error {
	if err := os.MkdirAll(fastlaneDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(fastlaneDir, "Deliverfile")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte("# generated by preflight runner: config comes from CLI flags\n"), 0o644)
}

// materializeScreenshots downloads the payload's screenshot refs into
// screenshotsDir/<locale>/<filename> so `deliver --screenshots_path` /
// `supply --screenshots_path` can upload them. The refs point at Preflight's
// public R2-serve route (unguessable keys), so a plain GET suffices. A run
// with refs but zero materialized files is an error — deliver would silently
// upload nothing.
func materializeScreenshots(screenshotsDir string, refs []runnerJobScreenshotRef) error {
	if len(refs) == 0 {
		return nil
	}
	// The dir persists across jobs; stale PNGs from earlier publishes would be
	// swept up by deliver (the listing is the source of truth), so start clean.
	if err := os.RemoveAll(screenshotsDir); err != nil {
		return fmt.Errorf("clean screenshots dir: %w", err)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	written := 0
	for _, ref := range refs {
		if strings.TrimSpace(ref.URL) == "" {
			continue
		}
		locale := strings.TrimSpace(ref.Locale)
		if locale == "" {
			locale = "en-US"
		}
		filename := filepath.Base(strings.TrimSpace(ref.Filename))
		if filename == "" || filename == "." {
			filename = filepath.Base(ref.URL)
		}
		dir := filepath.Join(screenshotsDir, locale)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		resp, err := client.Get(ref.URL)
		if err != nil {
			return fmt.Errorf("download screenshot %s: %w", filename, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("download screenshot %s: HTTP %d", filename, resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("download screenshot %s: %w", filename, err)
		}
		if err := os.WriteFile(filepath.Join(dir, filename), data, 0o644); err != nil {
			return err
		}
		written++
	}
	if written == 0 {
		return fmt.Errorf("no screenshots could be materialized from %d refs", len(refs))
	}
	return nil
}

// writeAppleMetadataFiles writes the en-US text files `fastlane deliver` reads.
func writeAppleMetadataFiles(metadataDir string, metadata map[string]string) error {
	dir := filepath.Join(metadataDir, "en-US")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fields := map[string]string{
		"name":             metadata["name"],
		"subtitle":         metadata["subtitle"],
		"description":      metadata["description"],
		"keywords":         metadata["keywords"],
		"promotional_text": metadata["promotionalText"],
		"release_notes":    metadata["releaseNotes"],
		"marketing_url":    metadata["marketingUrl"],
		"support_url":      metadata["supportUrl"],
		"privacy_url":      metadata["privacyUrl"],
	}
	for file, value := range fields {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, file+".txt"), []byte(value), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// writeAndroidMetadataFiles writes the en-US text files `fastlane supply` reads.
func writeAndroidMetadataFiles(metadataDir string, metadata map[string]string) error {
	dir := filepath.Join(metadataDir, "en-US")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fields := map[string]string{
		"title":             metadata["name"],
		"short_description": metadata["subtitle"],
		"full_description":  metadata["description"],
	}
	notesDir := filepath.Join(dir, "changelogs")
	if strings.TrimSpace(metadata["releaseNotes"]) != "" {
		if err := os.MkdirAll(notesDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(notesDir, "default.txt"), []byte(metadata["releaseNotes"]), 0o644); err != nil {
			return err
		}
	}
	for file, value := range fields {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, file+".txt"), []byte(value), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// writeASCApiKeyFile materializes a fastlane `--api_key_path` JSON from the host
// App Store Connect API key (PREFLIGHT_ASC_KEY_ID/_ISSUER_ID/_KEY_PATH). Returns
// "" when not configured (e.g. produce, which uses FASTLANE_SESSION instead).
func writeASCApiKeyFile(appDir string) (string, error) {
	keyID := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_KEY_ID"))
	issuerID := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_ISSUER_ID"))
	keyPath := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_KEY_PATH"))
	if keyID == "" || issuerID == "" || keyPath == "" {
		return "", nil
	}
	if strings.HasPrefix(keyPath, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			keyPath = filepath.Join(home, keyPath[2:])
		}
	}
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read ASC API key %q: %w", keyPath, err)
	}
	data, err := json.Marshal(map[string]any{
		"key_id":    keyID,
		"issuer_id": issuerID,
		"key":       string(pem),
		"duration":  1200,
		"in_house":  false,
	})
	if err != nil {
		return "", err
	}
	dir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "asc_api_key.json")
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return "", err
	}
	return out, nil
}

// ensureEASSubmitASCKey injects App Store Connect API key credentials into the
// checkout's eas.json submit profile so `eas build:submit --non-interactive`
// can authenticate. eas-cli reads the ASC key ONLY from eas.json (not env, not
// flags), so the fleet's runner-provided PREFLIGHT_ASC_* env is otherwise
// unusable for submit. No-op when the env is incomplete, there is no eas.json,
// or the profile already declares its own ascApiKeyPath.
func ensureEASSubmitASCKey(appDir, profile string) error {
	keyID := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_KEY_ID"))
	issuerID := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_ISSUER_ID"))
	keyPath := strings.TrimSpace(os.Getenv("PREFLIGHT_ASC_KEY_PATH"))
	if keyID == "" || issuerID == "" || keyPath == "" {
		return nil
	}
	if strings.HasPrefix(keyPath, "~/") {
		if home, homeErr := os.UserHomeDir(); homeErr == nil {
			keyPath = filepath.Join(home, keyPath[2:])
		}
	}
	if profile == "" {
		profile = "production"
	}
	easJSONPath := filepath.Join(appDir, "eas.json")
	raw, err := os.ReadFile(easJSONPath)
	if err != nil {
		return nil // no eas.json here — let eas-cli surface its own error
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	nestedMap := func(parent map[string]any, key string) map[string]any {
		if existing, ok := parent[key].(map[string]any); ok {
			return existing
		}
		created := map[string]any{}
		parent[key] = created
		return created
	}
	ios := nestedMap(nestedMap(nestedMap(doc, "submit"), profile), "ios")
	if _, ok := ios["ascApiKeyPath"]; ok {
		return nil // app declares its own ASC key — respect it
	}
	ios["ascApiKeyPath"] = keyPath
	ios["ascApiKeyId"] = keyID
	ios["ascApiKeyIssuerId"] = issuerID
	// An appleId in the submit profile forces Apple-ID (app-specific-password)
	// auth, which cannot be set up non-interactively and shadows the API key.
	delete(ios, "appleId")
	patched, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(easJSONPath, append(patched, '\n'), 0o644)
}

func runFastlaneCommand(appDir string, cancellationCheck func() (bool, error), args ...string) ([]byte, error) {
	executable := "fastlane"
	if configured := strings.TrimSpace(os.Getenv("PREFLIGHT_FASTLANE_COMMAND")); configured != "" {
		executable = configured
	} else if resolved, err := exec.LookPath("fastlane"); err == nil {
		executable = resolved
	}
	command := exec.Command(executable, args...)
	command.Dir = appDir
	command.Env = upsertEnvValues(os.Environ(), map[string]string{
		"FASTLANE_SKIP_UPDATE_CHECK": "1",
		"FASTLANE_DISABLE_COLORS":    "1",
		"SKIP_SLOW_FASTLANE_WARNING": "1",
	})
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := runCommandWithTimeoutAndCancellation(
		command,
		fastlaneTimeout(),
		cancellationCheck,
		runnerPollInterval(),
	)
	if err != nil {
		return output.Bytes(), fmt.Errorf("fastlane %s failed: %w: %s", strings.Join(args, " "), err, redactCommandOutput(strings.TrimSpace(output.String()), nil))
	}
	return output.Bytes(), nil
}

func fastlaneTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("PREFLIGHT_FASTLANE_TIMEOUT_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return 10 * time.Minute
}

func maestroFailureCode(err error) string {
	if err == nil {
		return "maestro_run_failed"
	}
	message := err.Error()
	if strings.Contains(message, "command timed out") {
		return "maestro_timeout"
	}
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "no such file") {
		return "maestro_missing"
	}
	return "maestro_run_failed"
}

func maestroResultPayload(job apiRunnerJob, providerIdentity string, flowPath string, artifacts maestroRunArtifacts) map[string]any {
	return map[string]any{
		"platform":         jobPlatform(job),
		"targetId":         job.Payload.TargetID,
		"providerIdentity": providerIdentity,
		"flowPath":         job.Payload.FlowPath,
		"resolvedFlowPath": flowPath,
		"outputDir":        artifacts.OutputDir,
		"debugOutputDir":   artifacts.DebugOutputDir,
		"reportPath":       artifacts.ReportPath,
		"logPath":          artifacts.LogPath,
		"debugLogPath":     artifacts.DebugLogPath,
		"commandPaths":     artifacts.CommandPaths,
		"screenshotPaths":  artifacts.ScreenshotPaths,
		"videoPaths":       artifacts.VideoPaths,
	}
}

func uploadMaestroRunArtifacts(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	providerIdentity string,
	flowPath string,
	artifacts maestroRunArtifacts,
) error {
	if !runnerArtifactUploadEnabled(registration) {
		return nil
	}

	metadata := map[string]any{
		"flowPath":         job.Payload.FlowPath,
		"resolvedFlowPath": flowPath,
		"outputDir":        artifacts.OutputDir,
		"debugOutputDir":   artifacts.DebugOutputDir,
		"targetId":         job.Payload.TargetID,
		"providerIdentity": providerIdentity,
	}
	for _, artifact := range maestroArtifactUploads(artifacts) {
		if strings.TrimSpace(artifact.URI) == "" {
			continue
		}
		if err := uploadRunnerArtifact(client, options, registration, job, artifact.Kind, artifact.URI, "diagnostic", metadata); err != nil {
			return err
		}
	}
	return nil
}

type runnerArtifactUpload struct {
	Kind string
	URI  string
}

func maestroArtifactUploads(artifacts maestroRunArtifacts) []runnerArtifactUpload {
	uploads := []runnerArtifactUpload{
		{Kind: "maestro_report", URI: artifacts.ReportPath},
		{Kind: "log", URI: artifacts.LogPath},
		{Kind: "log", URI: artifacts.DebugLogPath},
	}
	for _, path := range artifacts.CommandPaths {
		uploads = append(uploads, runnerArtifactUpload{Kind: "tool_output", URI: path})
	}
	for _, path := range artifacts.ScreenshotPaths {
		uploads = append(uploads, runnerArtifactUpload{Kind: "screenshot", URI: path})
	}
	for _, path := range artifacts.VideoPaths {
		uploads = append(uploads, runnerArtifactUpload{Kind: "video", URI: path})
	}
	return uploads
}

func uploadRunnerArtifact(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	kind string,
	uri string,
	retentionClass string,
	metadata map[string]any,
) error {
	_, err := uploadRunnerArtifactRecord(client, options, registration, job, kind, uri, retentionClass, metadata)
	return err
}

func uploadRunnerArtifactRecord(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	kind string,
	uri string,
	retentionClass string,
	metadata map[string]any,
) (runnerArtifactSummary, error) {
	payload := map[string]any{
		"kind":           kind,
		"uri":            uri,
		"retentionClass": retentionClass,
		"metadata":       metadata,
		// Runner artifact content (logs, transcripts) is emitted through the
		// redaction writers (attachRedactedCommandLog / redactSetupTranscriptText),
		// which strip tokens and secrets. Declare it so the control plane accepts
		// the upload (it rejects artifacts that do not assert redacted: true).
		"redacted": true,
	}
	if sizeBytes, ok := artifactSizeBytes(uri); ok {
		payload["sizeBytes"] = sizeBytes
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/%s/artifacts", registration.Runner.ID, job.ID)),
		registration.Token,
		payload,
	)
	if err != nil {
		return runnerArtifactSummary{}, err
	}
	var uploaded runnerArtifactEnvelopeData
	if err := decodeEnvelopeData(data, &uploaded); err != nil {
		return runnerArtifactSummary{}, fmt.Errorf("decode runner artifact upload response failed: %w", err)
	}
	return uploaded.Artifact, nil
}

func artifactSizeBytes(uri string) (int64, bool) {
	if strings.TrimSpace(uri) == "" {
		return 0, false
	}
	path := uri
	if parsed, err := url.Parse(uri); err == nil && parsed.Scheme == "file" {
		path = parsed.Path
	} else if parsed != nil && parsed.Scheme != "" {
		return 0, false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return 0, false
	}
	return info.Size(), true
}

type runnerArtifactSummary struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	URI  string `json:"uri"`
}

type runnerArtifactEnvelopeData struct {
	Artifact runnerArtifactSummary `json:"artifact"`
}

type devSessionArtifacts struct {
	QRPayloadPath string
	QRArtifactID  string
	LogPath       string
}

func prepareAndUploadDevSessionArtifacts(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	appDir string,
	devSession map[string]any,
	startedDevServer *expoDevServerProcess,
) (devSessionArtifacts, error) {
	artifacts := devSessionArtifacts{}
	qrPayloadPath, err := writeDevSessionQRPayload(appDir, job, devSession)
	if err != nil {
		return artifacts, err
	}
	artifacts.QRPayloadPath = qrPayloadPath
	if startedDevServer != nil && startedDevServer.logPath != "" {
		artifacts.LogPath = startedDevServer.logPath
	}
	if !runnerArtifactUploadEnabled(registration) {
		return artifacts, nil
	}
	metadata := devSessionArtifactMetadata(devSession)
	if qrPayloadPath != "" {
		artifact, err := uploadRunnerArtifactRecord(client, options, registration, job, "qr_code", qrPayloadPath, "diagnostic", metadata)
		if err != nil {
			return artifacts, err
		}
		artifacts.QRArtifactID = artifact.ID
	}
	if artifacts.LogPath != "" {
		if _, err := uploadRunnerArtifactRecord(client, options, registration, job, "log", artifacts.LogPath, "diagnostic", metadata); err != nil {
			return artifacts, err
		}
	}
	return artifacts, nil
}

func writeDevSessionQRPayload(appDir string, job apiRunnerJob, devSession map[string]any) (string, error) {
	if !devSessionReady(readMapString(devSession, "status")) || readMapString(devSession, "qrUrl") == "" {
		return "", nil
	}
	runDir := filepath.Join(appDir, ".preflight", "dev-sessions", job.ID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", fmt.Errorf("create dev session artifact directory: %w", err)
	}
	payload := map[string]any{
		"jobId":            job.ID,
		"workflowId":       job.WorkflowID,
		"platform":         jobPlatform(job),
		"lane":             job.Payload.Lane,
		"targetId":         readMapString(devSession, "targetId"),
		"providerIdentity": readMapString(devSession, "providerIdentity"),
		"status":           readMapString(devSession, "status"),
		"advertisedUrl":    readMapString(devSession, "advertisedUrl"),
		"deepLinkUrl":      readMapString(devSession, "deepLinkUrl"),
		"qrUrl":            readMapString(devSession, "qrUrl"),
		"installUrl":       readMapString(devSession, "installUrl"),
		"hostMode":         readMapString(devSession, "hostMode"),
		"hostIp":           readMapString(devSession, "hostIp"),
		"statusUrl":        readMapString(devSession, "statusUrl"),
		"sourceBinding": map[string]any{
			"workspaceRoot": job.Payload.SourceBinding.WorkspaceRoot,
			"packagePath":   job.Payload.SourceBinding.PackagePath,
			"appScheme":     job.Payload.SourceBinding.AppScheme,
			"expoSlug":      job.Payload.SourceBinding.ExpoSlug,
		},
	}
	content, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode dev session QR payload: %w", err)
	}
	path := filepath.Join(runDir, "qr-payload.json")
	if err := os.WriteFile(path, []byte(redactSetupTranscriptText(string(content))+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write dev session QR payload artifact: %w", err)
	}
	return path, nil
}

func devSessionArtifactMetadata(devSession map[string]any) map[string]any {
	metadata := map[string]any{}
	for _, key := range []string{
		"status",
		"advertisedUrl",
		"deepLinkUrl",
		"qrUrl",
		"installUrl",
		"hostMode",
		"hostIp",
		"statusUrl",
		"targetId",
		"providerIdentity",
	} {
		if value := readMapString(devSession, key); value != "" {
			metadata[key] = value
		}
	}
	if health, ok := devSession["health"].(map[string]any); ok {
		metadata["health"] = health
	}
	return metadata
}

func applyDevSessionArtifacts(devSession map[string]any, artifacts devSessionArtifacts) {
	if artifacts.QRPayloadPath != "" {
		devSession["qrPayloadPath"] = artifacts.QRPayloadPath
	}
	if artifacts.QRArtifactID != "" {
		devSession["qrArtifactId"] = artifacts.QRArtifactID
	}
	if artifacts.LogPath != "" {
		devSession["logPath"] = artifacts.LogPath
	}
}

func devSessionArtifactFailureCode(err error) string {
	if err == nil {
		return "artifact_upload_failed"
	}
	if strings.Contains(err.Error(), "write dev session QR payload") ||
		strings.Contains(err.Error(), "create dev session artifact directory") {
		return "artifact_write_failed"
	}
	return "artifact_upload_failed"
}

func completeRunnerJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, result map[string]any) error {
	_, err := completeRunnerJobWithResponse(client, options, registration, job, result)
	// Post-job hygiene (P6): when the volume is under pressure, sweep stale
	// regenerable caches now instead of failing the NEXT build mid-lipo.
	// Pressure-gated so healthy runners pay nothing.
	if minFree := runnerMinFreeDiskBytes(); minFree > 0 {
		if swept, sweepErr := cleanupBuildStorageUnderPressure(
			options.workspaceRoot, 24*time.Hour, minFree, nil,
		); sweepErr == nil && swept.Removed > 0 {
			fmt.Printf("post-job cache sweep: removed %d stale entries (%.1f GiB free)\n",
				swept.Removed, float64(swept.FreeBytes)/float64(bytesPerGiB))
		}
	}

	return err
}

// activeRunnerJob tracks the job currently being handled so a graceful-shutdown
// signal handler can fail it (which makes the server fail the workflow and
// release its target locks) instead of leaving a stale lock held until TTL.
// This only covers graceful shutdown (SIGINT/SIGTERM/^C); SIGKILL and crashes
// can only be recovered server-side by reclaiming locks when the runner's
// heartbeat goes stale (see the field report in preflight-app).
var activeRunnerJob struct {
	mu           sync.Mutex
	set          bool
	client       *http.Client
	options      runnerOnceOptions
	registration runnerRegistrationData
	job          apiRunnerJob
}

func markRunnerJobActive(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob) {
	activeRunnerJob.mu.Lock()
	activeRunnerJob.set = true
	activeRunnerJob.client = client
	activeRunnerJob.options = options
	activeRunnerJob.registration = registration
	activeRunnerJob.job = job
	activeRunnerJob.mu.Unlock()
}

func clearRunnerJobActive() {
	activeRunnerJob.mu.Lock()
	activeRunnerJob.set = false
	activeRunnerJob.mu.Unlock()
}

// releaseActiveRunnerJobOnShutdown fails the in-flight job so the server fails
// its workflow and releases any target locks the runner acquired. Best-effort:
// errors are ignored because we are already on the way out.
func releaseActiveRunnerJobOnShutdown(reason string) {
	activeRunnerJob.mu.Lock()
	defer activeRunnerJob.mu.Unlock()
	if !activeRunnerJob.set {
		return
	}
	_ = completeRunnerJob(activeRunnerJob.client, activeRunnerJob.options, activeRunnerJob.registration, activeRunnerJob.job, map[string]any{
		"status": "failed",
		"failure": map[string]any{
			"code":    "runner_interrupted",
			"message": reason,
		},
	})
	activeRunnerJob.set = false
}

// installRunnerShutdownHandler wires SIGINT/SIGTERM to release the in-flight
// job's target lock before exiting. Returns a stop func to remove the handler
// once the runner finishes normally. Exit code 130 = terminated by Ctrl-C.
func installRunnerShutdownHandler(stderr io.Writer) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigCh:
			fmt.Fprintf(stderr, "received %s — releasing in-flight target lock before exit\n", sig)
			releaseActiveRunnerJobOnShutdown(fmt.Sprintf("runner interrupted (%s)", sig))
			os.Exit(130)
		case <-done:
			return
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

type runnerJobCompletionData struct {
	Job                apiRunnerJob               `json:"job"`
	WorkflowProjection proveAppWorkflowProjection `json:"workflowProjection"`
}

func completeRunnerJobWithResponse(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, result map[string]any) (runnerJobCompletionData, error) {
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/%s/complete", registration.Runner.ID, job.ID)),
		registration.Token,
		map[string]any{"result": result},
	)
	if err != nil {
		return runnerJobCompletionData{}, err
	}
	var completed runnerJobCompletionData
	if err := decodeEnvelopeData(data, &completed); err != nil {
		return runnerJobCompletionData{}, fmt.Errorf("decode runner job completion: %w", err)
	}
	return completed, nil
}

func revealRunnerJobSecret(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, secretRefID string) (runnerJobSecretRevealData, error) {
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/%s/secrets/%s/reveal", registration.Runner.ID, job.ID, secretRefID)),
		registration.Token,
		map[string]any{},
	)
	if err != nil {
		return runnerJobSecretRevealData{}, err
	}
	var reveal runnerJobSecretRevealData
	if err := decodeEnvelopeData(data, &reveal); err != nil {
		return runnerJobSecretRevealData{}, fmt.Errorf("decode runner secret reveal: %w", err)
	}
	if reveal.Value == "" {
		return runnerJobSecretRevealData{}, fmt.Errorf("runner secret reveal did not include a value")
	}
	return reveal, nil
}

func readRunnerJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob) (apiRunnerJob, error) {
	data, err := getPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/%s", registration.Runner.ID, job.ID)),
		registration.Token,
	)
	if err != nil {
		return apiRunnerJob{}, err
	}
	var read runnerClaimData
	if err := decodeEnvelopeData(data, &read); err != nil {
		return apiRunnerJob{}, fmt.Errorf("decode runner job: %w", err)
	}
	if read.Job.ID == "" {
		return apiRunnerJob{}, fmt.Errorf("runner job read response did not include a job ID")
	}
	return read.Job, nil
}

func heartbeatRunnerJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob) (apiRunnerJob, error) {
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/%s/heartbeat", registration.Runner.ID, job.ID)),
		registration.Token,
		map[string]any{},
	)
	if err != nil {
		return apiRunnerJob{}, err
	}
	var read runnerClaimData
	if err := decodeEnvelopeData(data, &read); err != nil {
		return apiRunnerJob{}, fmt.Errorf("decode runner job heartbeat: %w", err)
	}
	if read.Job.ID == "" {
		return apiRunnerJob{}, fmt.Errorf("runner job heartbeat response did not include a job ID")
	}
	return read.Job, nil
}

func runnerJobCancellationCheck(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob) func() (bool, error) {
	return func() (bool, error) {
		var read apiRunnerJob
		var err error
		if runnerJobHeartbeatEnabled(registration) {
			read, err = heartbeatRunnerJob(client, options, registration, job)
			if err != nil {
				read, err = readRunnerJob(client, options, registration, job)
			}
		} else {
			read, err = readRunnerJob(client, options, registration, job)
		}
		if err != nil {
			return false, nil
		}
		return read.Status == "cancelled", nil
	}
}

func claimAndHandleDevelopmentAfterReadiness(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, stdout io.Writer) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	return handleDevelopmentLaneClaim(client, options, registration, claim.Job, stdout, true)
}

func handleEASReadinessProbeJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	appDir := appDirectoryForJob(options, job)
	profileName := easProfileNameForJob(job)
	easEnv, err := easSecretEnvForJob(client, options, registration, job)
	if err != nil {
		return err
	}
	if jobRequiresPreflightExpoToken(job) && strings.TrimSpace(easEnv["EXPO_TOKEN"]) == "" {
		setupRequired := expoTokenCredentialSetupRequired(options, job, "expo_token_secret_required", "Create a Preflight-owned Expo API token before EAS runs.")
		if err := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":        "setup_required",
			"setupRequired": setupRequired,
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "EAS setup required %s %s\n", job.ID, setupRequired["code"])
		return nil
	}
	readiness, setupRequired := probeEASDevelopmentReadinessWithEnv(appDir, job.Payload.SourceBinding, profileName, job.Payload.TargetClass, jobPlatform(job), easEnv)
	if setupRequired != nil {
		setupRequired = contextualizeExpoTokenSetupRequired(setupRequired, options, job)
		if err := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":        "setup_required",
			"setupRequired": setupRequired,
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "EAS setup required %s %s\n", job.ID, setupRequired["code"])
		return nil
	}

	result := map[string]any{
		"status":    "ok",
		"readiness": readiness,
	}
	if devBuild, ok := readiness["devBuild"].(map[string]any); ok {
		result["devBuild"] = devBuild
	}
	if err := completeRunnerJob(client, options, registration, job, result); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified EAS readiness %s %s\n", job.ID, profileName)
	return nil
}

func handleEASBuildDevJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	appDir := appDirectoryForJob(options, job)
	profileName := easProfileNameForJob(job)
	// Production builds are produced only through CI. A runner outside a CI
	// context must refuse the production profile rather than minting a store
	// build locally — the Mobile Production Build workflow is the sanctioned path.
	if isProductionBuildProfile(profileName) && !runningInCI() {
		setupRequired := map[string]any{
			"code": "production_build_ci_only",
			"message": "Production builds run only through CI. Trigger the Mobile Production Build workflow " +
				"instead of building the production profile on a runner.",
			"commands": []string{"gh workflow run mobile-production.yml"},
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":        "setup_required",
			"easBuild":      easBuildResultPayload(job, profileName),
			"setupRequired": setupRequired,
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "production build refused (CI-only) %s %s\n", job.ID, profileName)
		return nil
	}
	easEnv, err := easSecretEnvForJob(client, options, registration, job)
	if err != nil {
		return err
	}
	if jobRequiresPreflightExpoToken(job) && strings.TrimSpace(easEnv["EXPO_TOKEN"]) == "" {
		setupRequired := expoTokenCredentialSetupRequired(options, job, "expo_token_secret_required", "Create a Preflight-owned Expo API token before EAS runs.")
		if err := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":        "setup_required",
			"easBuild":      easBuildResultPayload(job, profileName),
			"setupRequired": setupRequired,
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "EAS setup required %s %s\n", job.ID, setupRequired["code"])
		return nil
	}
	buildArgs := easBuildCommandArgs(job, profileName)
	output, err := runEASCommandWithTimeoutAndCancellation(
		appDir,
		easBuildTimeout(),
		runnerJobCancellationCheck(client, options, registration, job),
		easEnv,
		buildArgs...,
	)
	if err != nil {
		if errors.Is(err, errCommandCancelled) {
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status":   "cancelled",
				"easBuild": easBuildResultPayload(job, profileName),
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "cancelled EAS development build %s\n", job.ID)
			return nil
		}
		wrappedErr := fmt.Errorf("run EAS development build: %w", err)
		if setupRequired := easBuildSetupRequired(wrappedErr, job, profileName); setupRequired != nil {
			setupRequired = contextualizeExpoTokenSetupRequired(setupRequired, options, job)
			if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
				"status":        "setup_required",
				"easBuild":      easBuildResultPayload(job, profileName),
				"setupRequired": setupRequired,
			}); completeErr != nil {
				return completeErr
			}
			fmt.Fprintf(stdout, "EAS setup required %s %s\n", job.ID, setupRequired["code"])
			return nil
		}
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":   "failed",
			"easBuild": easBuildResultPayload(job, profileName),
			"failure": map[string]any{
				"code":    easBuildFailureCode(wrappedErr),
				"message": wrappedErr.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed EAS development build %s %s\n", job.ID, wrappedErr.Error())
		return nil
	}

	devBuild, err := parseEASBuildOutput(output, profileName)
	if err != nil {
		return err
	}
	artifacts, err := writeEASBuildArtifacts(options, job, buildArgs, output, easEnv)
	if err != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":   "failed",
			"easBuild": easBuildResultPayload(job, profileName),
			"failure": map[string]any{
				"code":    "artifact_write_failed",
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed EAS artifact write %s %s\n", job.ID, err.Error())
		return nil
	}
	if err := uploadEASBuildArtifacts(client, options, registration, job, devBuild, artifacts); err != nil {
		if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
			"status":   "failed",
			"easBuild": easBuildResultPayload(job, profileName),
			"failure": map[string]any{
				"code":    "artifact_upload_failed",
				"message": err.Error(),
			},
		}); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "failed EAS artifact upload %s %s\n", job.ID, err.Error())
		return nil
	}
	devBuild["outputPath"] = artifacts.OutputPath
	devBuild["logPath"] = artifacts.LogPath
	if err := completeRunnerJob(client, options, registration, job, map[string]any{
		"status":   "ok",
		"devBuild": devBuild,
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "completed EAS development build %s %s\n", job.ID, devBuild["buildId"])
	return claimAndHandlePostEASBuildDev(client, options, registration, stdout)
}

func easBuildCommandArgs(job apiRunnerJob, profileName string) []string {
	return []string{
		"build",
		"--platform",
		jobPlatformForEAS(job),
		"--profile",
		profileName,
		"--json",
		"--non-interactive",
		"--wait",
	}
}

type easBuildArtifacts struct {
	OutputPath string
	LogPath    string
}

func writeEASBuildArtifacts(options runnerOnceOptions, job apiRunnerJob, args []string, output []byte, env map[string]string) (easBuildArtifacts, error) {
	root := job.Payload.SourceBinding.WorkspaceRoot
	if root == "" {
		root = options.workspaceRoot
	}
	runDir := filepath.Join(root, ".preflight", "eas", job.ID)
	artifacts := easBuildArtifacts{
		OutputPath: filepath.Join(runDir, "eas-build-output.json"),
		LogPath:    filepath.Join(runDir, "eas-build.log"),
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return easBuildArtifacts{}, fmt.Errorf("create EAS artifact directory: %w", err)
	}
	redactedOutput := redactCommandOutput(string(output), env)
	if err := os.WriteFile(artifacts.OutputPath, []byte(redactedOutput), 0o644); err != nil {
		return easBuildArtifacts{}, fmt.Errorf("write EAS build output artifact: %w", err)
	}
	logContent := strings.Join([]string{
		"$ eas " + strings.Join(args, " "),
		redactedOutput,
	}, "\n")
	if err := os.WriteFile(artifacts.LogPath, []byte(logContent), 0o644); err != nil {
		return easBuildArtifacts{}, fmt.Errorf("write EAS build log artifact: %w", err)
	}
	return artifacts, nil
}

func uploadEASBuildArtifacts(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	devBuild map[string]any,
	artifacts easBuildArtifacts,
) error {
	if !runnerArtifactUploadEnabled(registration) {
		return nil
	}
	metadata := map[string]any{
		"platform":    jobPlatformForEAS(job),
		"profile":     easProfileNameForJob(job),
		"targetClass": job.Payload.TargetClass,
	}
	if buildID := readMapString(devBuild, "buildId"); buildID != "" {
		metadata["buildId"] = buildID
	}
	for _, artifact := range []runnerArtifactUpload{
		{Kind: "tool_output", URI: artifacts.OutputPath},
		{Kind: "log", URI: artifacts.LogPath},
	} {
		if err := uploadRunnerArtifact(client, options, registration, job, artifact.Kind, artifact.URI, "diagnostic", metadata); err != nil {
			return err
		}
	}
	return nil
}

func easSecretEnvForJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob) (map[string]string, error) {
	env := map[string]string{}
	for _, secretReference := range job.Payload.SecretReferences {
		key := strings.TrimSpace(secretReference.Key)
		if key == "" {
			continue
		}
		if !isSafeEnvironmentKey(key) {
			return nil, fmt.Errorf("secret reference %s has invalid environment key %q", secretReference.ID, key)
		}
		reveal, err := revealRunnerJobSecret(client, options, registration, job, secretReference.ID)
		if err != nil {
			return nil, fmt.Errorf("reveal secret %s for job %s: %w", secretReference.ID, job.ID, err)
		}
		env[key] = reveal.Value
	}
	return env, nil
}

func jobRequiresPreflightExpoToken(job apiRunnerJob) bool {
	for _, required := range job.Payload.RequiredSecretReferences {
		if required.Required &&
			required.Provider == "expo" &&
			required.Purpose == "api_token" &&
			required.Key == "EXPO_TOKEN" {
			return true
		}
	}
	return false
}

func expoTokenCredentialSetupRequired(options runnerOnceOptions, job apiRunnerJob, code string, message string) map[string]any {
	return setupRequired(code, message, expoTokenCredentialCreateCommand(options, job))
}

func contextualizeExpoTokenSetupRequired(setupRequired map[string]any, options runnerOnceOptions, job apiRunnerJob) map[string]any {
	code := stringFromMap(setupRequired, "code")
	if code != "expo_token_auth_failed" && code != "expo_token_secret_required" {
		return setupRequired
	}
	contextualized := map[string]any{}
	for key, value := range setupRequired {
		contextualized[key] = value
	}
	contextualized["commands"] = []string{expoTokenCredentialCreateCommand(options, job)}
	return contextualized
}

func expoTokenCredentialCreateCommand(options runnerOnceOptions, job apiRunnerJob) string {
	workspaceID := strings.TrimSpace(options.workspaceID)
	if workspaceID == "" {
		workspaceID = strings.TrimSpace(job.WorkspaceID)
	}
	parts := []string{
		"preflight",
		"credentials",
		"create",
	}
	if strings.TrimSpace(options.apiURL) != "" {
		parts = append(parts, "--api-url", strings.TrimSpace(options.apiURL))
	}
	if workspaceID != "" {
		parts = append(parts, "--workspace-id", workspaceID)
	}
	if strings.TrimSpace(job.AppID) != "" {
		parts = append(parts, "--app-id", strings.TrimSpace(job.AppID))
	}
	parts = append(
		parts,
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
	)
	return strings.Join(parts, " ")
}

func isSafeEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	for index, r := range key {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' && index > 0 || r == '_' {
			continue
		}
		return false
	}
	return true
}

func claimAndHandlePostEASBuildDev(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, stdout io.Writer) error {
	claim, err := claimRunnerJob(client, options, registration)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil
	}
	fmt.Fprintf(stdout, "claimed job %s %s\n", claim.Job.ID, claim.Job.Kind)
	return handleDevelopmentLaneClaim(client, options, registration, claim.Job, stdout, false)
}

func handleDevelopmentLaneClaim(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	stdout io.Writer,
	allowBuild bool,
) error {
	switch job.Kind {
	case "eas.build.dev":
		if !allowBuild {
			return fmt.Errorf("unsupported runner job kind %q", job.Kind)
		}
		return handleEASBuildDevJob(client, options, registration, job, stdout)
	case "device.discover":
		if err := handleDeviceDiscoveryJob(client, options, registration, job, stdout); err != nil {
			return err
		}
		return claimAndHandleDevSessionStart(client, options, registration, stdout)
	case "dev_session.start":
		continueWorkflow, err := handleDevSessionStartJob(client, options, registration, job, stdout)
		if err != nil {
			return err
		}
		if !continueWorkflow {
			return nil
		}
		if isDevelopmentDevSessionJob(job) {
			return claimAndHandleDevSessionOpen(client, options, registration, stdout)
		}
		return claimAndHandleSimulatorOpen(client, options, registration, stdout)
	case "dev_session.open":
		return handleDevSessionOpenJob(client, options, registration, job, stdout)
	case "dev_session.stop":
		return handleDevSessionStopJob(client, options, registration, job, stdout)
	default:
		return fmt.Errorf("unsupported runner job kind %q", job.Kind)
	}
}

func easBuildResultPayload(job apiRunnerJob, profileName string) map[string]any {
	return map[string]any{
		"profile":     profileName,
		"platform":    jobPlatformForEAS(job),
		"targetClass": readMapString(job.Payload.Readiness, "targetClass"),
	}
}

func easBuildFailureCode(err error) string {
	if err == nil {
		return "eas_build_failed"
	}
	message := err.Error()
	if strings.Contains(message, "command timed out") {
		return "eas_build_timeout"
	}
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "no such file") {
		return "eas_cli_missing"
	}
	return "eas_build_failed"
}

func easBuildSetupRequired(err error, job apiRunnerJob, profileName string) map[string]any {
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "EXPO_TOKEN") ||
		strings.Contains(strings.ToLower(message), "not logged in") ||
		strings.Contains(strings.ToLower(message), "not authenticated") {
		return expoTokenCredentialSetupRequired(
			runnerOnceOptions{},
			job,
			"expo_token_auth_failed",
			"Create or rotate Preflight's Expo API token; EAS rejected EXPO_TOKEN.",
		)
	}
	if strings.Contains(message, "Failed to set up credentials") ||
		strings.Contains(message, "couldn't find any credentials suitable for internal distribution") ||
		strings.Contains(message, "Run this command again in interactive mode") {
		platform := jobPlatformForEAS(job)
		return setupRequired(
			"eas_credentials_setup_required",
			fmt.Sprintf(
				"Run EAS build interactively so Expo can configure %s internal-distribution credentials.",
				developmentPlatformLabel(platform),
			),
			fmt.Sprintf("eas build --platform %s --profile %s", platform, profileName),
		)
	}
	return nil
}

func handleDeviceDiscoveryJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}

	targets, err := reportDiscoveryTargets(client, options, registration, job)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "reported %d %s target(s)\n", len(targets.Targets), discoveryTargetLabel(job))

	target := firstAvailableTarget(targets.Targets)
	if target == nil {
		return fmt.Errorf("no available %s targets reported", discoveryTargetLabel(job))
	}

	lockData, err := postPreflightJSON(
		client,
		runnerEndpoint(
			options.apiURL,
			fmt.Sprintf(
				"/api/preflight/v1/runners/%s/jobs/%s/targets/%s/lock",
				registration.Runner.ID,
				job.ID,
				target.ID,
			),
		),
		registration.Token,
		map[string]any{
			"lockOwner": runnerLeaseOwner(options),
		},
	)
	if err != nil {
		return err
	}

	var locked runnerTargetLockData
	if err := decodeEnvelopeData(lockData, &locked); err != nil {
		return fmt.Errorf("decode target lock: %w", err)
	}
	fmt.Fprintf(stdout, "locked target %s %s\n", locked.Target.ID, locked.Target.DisplayName)
	return nil
}

func reportDiscoveryTargets(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob) (runnerTargetsData, error) {
	if job.Payload.Platform == "android" {
		adbDevicesOutput, err := loadADBDevices(options)
		if err != nil {
			return runnerTargetsData{}, err
		}
		data, err := postPreflightJSON(
			client,
			runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/targets/android-emulators", registration.Runner.ID)),
			registration.Token,
			map[string]any{
				"adbDevicesOutput": string(adbDevicesOutput),
			},
		)
		if err != nil {
			return runnerTargetsData{}, err
		}
		var targets runnerTargetsData
		if err := decodeEnvelopeData(data, &targets); err != nil {
			return runnerTargetsData{}, fmt.Errorf("decode Android emulator targets: %w", err)
		}
		return targets, nil
	}

	simctlInventory, err := loadSimctlInventory(options)
	if err != nil {
		return runnerTargetsData{}, err
	}
	data, err := postPreflightJSON(
		client,
		runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/targets/ios-simulators", registration.Runner.ID)),
		registration.Token,
		map[string]any{
			"simctlInventory": simctlInventory,
		},
	)
	if err != nil {
		return runnerTargetsData{}, err
	}
	var targets runnerTargetsData
	if err := decodeEnvelopeData(data, &targets); err != nil {
		return runnerTargetsData{}, fmt.Errorf("decode iOS simulator targets: %w", err)
	}

	// Also register physically-connected iPhones (best-effort; ignored when
	// devicectl is unavailable or no device is attached).
	if devicectlOutput, derr := loadDevicectlDevices(options); derr == nil {
		if deviceData, perr := postPreflightJSON(
			client,
			runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/targets/ios-devices", registration.Runner.ID)),
			registration.Token,
			map[string]any{"devicectlOutput": devicectlOutput},
		); perr == nil {
			var deviceTargets runnerTargetsData
			if decodeEnvelopeData(deviceData, &deviceTargets) == nil {
				targets.Targets = append(targets.Targets, deviceTargets.Targets...)
			}
		}
	}
	return targets, nil
}

// loadDevicectlDevices returns `xcrun devicectl list devices` JSON for attached
// physical devices. Returns ("", nil) gracefully when devicectl is unavailable.
func loadDevicectlDevices(options runnerOnceOptions) (string, error) {
	out, err := exec.Command(options.xcrunPath, "devicectl", "list", "devices", "--json-output", "-").Output()
	if err != nil {
		return "", err
	}
	if !json.Valid(out) {
		return "", fmt.Errorf("devicectl output is not valid JSON")
	}
	return string(out), nil
}

func discoveryTargetLabel(job apiRunnerJob) string {
	if job.Payload.Platform == "android" {
		return "Android emulator"
	}
	return "iOS simulator"
}

// shutdownOtherBootedIOSSimulators shuts down every booted simulator except the
// locked target, so a tool that resolves the generic "booted" device (expo's
// install/open) can't pick the wrong sim when several are booted.
func shutdownOtherBootedIOSSimulators(
	options runnerOnceOptions,
	keepUDID string,
	logWriter io.Writer,
) {
	output, err := exec.Command(
		options.xcrunPath, "simctl", "list", "devices", "booted", "--json",
	).Output()
	if err != nil {
		return
	}
	var parsed struct {
		Devices map[string][]struct {
			UDID  string `json:"udid"`
			State string `json:"state"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(output, &parsed); err != nil {
		return
	}
	for _, devices := range parsed.Devices {
		for _, device := range devices {
			if device.State != "Booted" || device.UDID == "" {
				continue
			}
			if strings.EqualFold(device.UDID, keepUDID) {
				continue
			}
			_ = exec.Command(options.xcrunPath, "simctl", "shutdown", device.UDID).Run()
			if logWriter != nil {
				fmt.Fprintf(logWriter, "shut down extra booted simulator %s\n", device.UDID)
			}
		}
	}
}

func bootIOSSimulator(options runnerOnceOptions, providerIdentity string) error {
	_ = exec.Command(options.xcrunPath, "simctl", "boot", providerIdentity).Run()
	output, err := exec.Command(options.xcrunPath, "simctl", "bootstatus", providerIdentity, "-b").CombinedOutput()
	if err != nil {
		return fmt.Errorf("boot iOS simulator %s: %w: %s", providerIdentity, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func appDirectoryForJob(options runnerOnceOptions, job apiRunnerJob) string {
	root := job.Payload.SourceBinding.WorkspaceRoot
	if root == "" {
		root = options.workspaceRoot
	}
	packagePath := job.Payload.SourceBinding.PackagePath
	if packagePath == "" || packagePath == "." {
		return root
	}
	return filepath.Join(root, packagePath)
}

type sourceBindingMismatchError struct {
	field    string
	expected string
	actual   string
}

func (err *sourceBindingMismatchError) Error() string {
	if err == nil {
		return ""
	}
	if err.actual == "" {
		return fmt.Sprintf("%s expected %s but local value was empty", err.field, err.expected)
	}
	return fmt.Sprintf("%s expected %s but local value was %s", err.field, err.expected, err.actual)
}

// ciCheckoutRootSegment marks workspace roots that Preflight owns for
// CI-driven builds. Only paths containing this segment are eligible for
// automatic clone/fetch/checkout — the runner never mutates a developer's
// working tree under the ordinary runner workspace root.
const ciCheckoutRootSegment = ".preflight-ci"

// pathHasSegment reports whether any path component of p equals segment.
func pathHasSegment(p string, segment string) bool {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == segment {
			return true
		}
	}
	return false
}

// gitRun runs git (optionally with -C dir) and returns combined output, folding
// any stderr into the error so checkout failures are diagnosable in job logs.
func gitRun(dir string, args ...string) (string, error) {
	full := args
	if strings.TrimSpace(dir) != "" {
		full = append([]string{"-C", dir}, args...)
	}
	output, err := exec.Command("git", full...).CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		return trimmed, fmt.Errorf("%w: %s", err, trimmed)
	}
	return trimmed, nil
}

// ensureCiCheckout makes a Preflight-owned CI workspace root match the source
// binding's git commit before validation runs. It is a no-op for any path that
// is not under a .preflight-ci/ root, so developer checkouts under the runner
// workspace root are never touched. On a CI root it clones the repo when
// missing and fetches + force-checks-out the requested commit (detached HEAD),
// skipping the network round-trip when HEAD already matches.
func ensureCiCheckout(bindingRoot string, binding runnerJobSourceBinding) error {
	if strings.TrimSpace(bindingRoot) == "" {
		return nil
	}
	abs, err := filepath.Abs(bindingRoot)
	if err != nil {
		return nil
	}
	if !pathHasSegment(abs, ciCheckoutRootSegment) {
		return nil
	}
	remote := strings.TrimSpace(binding.GitRemoteURL)
	sha := strings.TrimSpace(binding.GitCommitSHA)
	branch := strings.TrimSpace(binding.GitBranch)
	if remote == "" || (sha == "" && branch == "") {
		// Nothing to sync against — leave the directory as-is.
		return nil
	}

	if _, statErr := os.Stat(filepath.Join(abs, ".git")); statErr != nil {
		if mkErr := os.MkdirAll(filepath.Dir(abs), 0o755); mkErr != nil {
			return fmt.Errorf("create parent: %w", mkErr)
		}
		if _, cloneErr := gitRun("", "clone", remote, abs); cloneErr != nil {
			return fmt.Errorf("clone %s: %w", remote, cloneErr)
		}
	}

	// Always fetch and hard-reset to the requested ref. reset --hard restores
	// tracked files to the exact commit, discarding any lockfile/file drift a
	// prior build's install left behind, so a frozen install is reproducible.
	// (A prior non-frozen fallback could otherwise corrupt the lockfile and
	// poison every later build of this checkout.)
	if _, fetchErr := gitRun(abs, "fetch", "--tags", "--force", "origin"); fetchErr != nil {
		return fmt.Errorf("fetch: %w", fetchErr)
	}
	ref := sha
	if ref == "" {
		ref = "origin/" + branch
	}
	if _, rErr := gitRun(abs, "reset", "--hard", ref); rErr != nil {
		return fmt.Errorf("reset %s: %w", ref, rErr)
	}

	// A fresh CI checkout has no node_modules, so metro/dev-build would fail.
	resolved, _ := gitOutput(abs, "rev-parse", "HEAD")
	if err := ensureCiDependencies(abs, resolved, binding.PackagePath); err != nil {
		return err
	}
	return nil
}

// ensureEASSubmitCheckout makes a Preflight-owned CI checkout match the source
// binding's commit before `eas build:submit` runs. Distribute is
// server-initiated, so unlike a build/dev job there is no live developer CWD —
// the derived checkout may be missing or stale (the dir can survive a cleanup
// without its .git or eas.json). It clones/resets to the commit and installs JS
// dependencies via ensureCiDependencies: `eas build:submit` evaluates the
// app's Expo config (app.config.ts), which imports packages, so node_modules
// must be present. ensureCiDependencies is drift-tolerant (frozen install, then
// a non-frozen fallback), so a checkout whose committed lockfile has drifted
// still resolves. No-op for developer checkouts (non-.preflight-ci roots) and
// when there is no git ref to sync to.
func ensureEASSubmitCheckout(workspaceRoot string, binding runnerJobSourceBinding) error {
	if strings.TrimSpace(workspaceRoot) == "" {
		return nil
	}
	abs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return nil
	}
	if !pathHasSegment(abs, ciCheckoutRootSegment) {
		return nil // developer checkout — never touch it
	}
	remote := strings.TrimSpace(binding.GitRemoteURL)
	sha := strings.TrimSpace(binding.GitCommitSHA)
	branch := strings.TrimSpace(binding.GitBranch)
	if remote == "" || (sha == "" && branch == "") {
		return nil
	}
	if _, statErr := os.Stat(filepath.Join(abs, ".git")); statErr != nil {
		// The dir can survive a cleanup as a stale, non-git checkout (files but
		// no .git). `git clone` refuses a non-empty target, so clear it first —
		// safe because this only runs on a Preflight-owned .preflight-ci root.
		if _, dirErr := os.Stat(abs); dirErr == nil {
			if rmErr := os.RemoveAll(abs); rmErr != nil {
				return fmt.Errorf("clear stale checkout %s: %w", abs, rmErr)
			}
		}
		if mkErr := os.MkdirAll(filepath.Dir(abs), 0o755); mkErr != nil {
			return fmt.Errorf("create parent: %w", mkErr)
		}
		if _, cloneErr := gitRun("", "clone", remote, abs); cloneErr != nil {
			return fmt.Errorf("clone %s: %w", remote, cloneErr)
		}
	}
	if _, fetchErr := gitRun(abs, "fetch", "--tags", "--force", "origin"); fetchErr != nil {
		return fmt.Errorf("fetch: %w", fetchErr)
	}
	// A stored "HEAD" placeholder is not a resolvable ref — fall back to branch.
	ref := sha
	if ref == "" || strings.EqualFold(ref, "HEAD") {
		ref = "origin/" + branch
	}
	if _, resetErr := gitRun(abs, "reset", "--hard", ref); resetErr != nil {
		return fmt.Errorf("reset %s: %w", ref, resetErr)
	}
	// eas build:submit reads app.config.ts, which imports packages — install
	// deps so the config evaluates. Drift-tolerant (frozen → non-frozen).
	resolved, _ := gitOutput(abs, "rev-parse", "HEAD")
	if depErr := ensureCiDependencies(abs, resolved, binding.PackagePath); depErr != nil {
		return depErr
	}
	return nil
}

// ensureCiDependencies installs JS dependencies in a Preflight-owned CI
// checkout so dev-session/build jobs have a ready workspace. A per-commit
// success marker means repeat jobs in a workflow chain don't reinstall, but a
// failed/partial prior install (marker absent) is always repaired — checking
// only "node_modules exists" would keep a broken partial install. The package
// manager is detected from the committed lockfile (pnpm/yarn/npm).
func ensureCiDependencies(repoRoot string, headSha string, packagePath string) error {
	marker := filepath.Join(repoRoot, ".preflight", "ci-deps.sha")
	if headSha != "" {
		if data, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(data)) == headSha {
			return nil
		}
	}
	// Install at the workspace root by default. For a NON-workspace repo (no
	// root manifest, but the app has its own package.json), install standalone
	// in the app dir so the app isn't held hostage to a missing root workspace.
	installDir := repoRoot
	appDir := repoRoot
	if packagePath != "" && packagePath != "." {
		appDir = filepath.Join(repoRoot, packagePath)
	}
	atWorkspaceRoot := true
	if !fileExists(filepath.Join(repoRoot, "package.json")) &&
		fileExists(filepath.Join(appDir, "package.json")) {
		installDir = appDir
		atWorkspaceRoot = false
	}

	pm, frozen, nonFrozen := "pnpm", []string{"install", "--frozen-lockfile"}, []string{"install"}
	switch {
	case fileExists(filepath.Join(installDir, "yarn.lock")):
		pm, frozen, nonFrozen = "yarn", []string{"install", "--frozen-lockfile"}, []string{"install"}
	case fileExists(filepath.Join(installDir, "package-lock.json")):
		pm, frozen, nonFrozen = "npm", []string{"ci"}, []string{"install"}
	}
	// In a pnpm monorepo, scope the install to the target app's workspace
	// package (+ its deps) so a broken SIBLING package (e.g. apps/web) doesn't
	// fail the whole install and block the mobile build.
	if pm == "pnpm" && atWorkspaceRoot && packagePath != "" && packagePath != "." {
		filter := []string{"--filter", "./" + strings.TrimPrefix(packagePath, "./") + "..."}
		frozen = append(filter, frozen...)
		nonFrozen = append(append([]string{}, filter...), nonFrozen...)
	}
	if _, err := runCmd(installDir, pm, frozen...); err != nil {
		// Lockfile drift shouldn't hard-fail a CI build — fall back to a
		// non-frozen install (reset --hard restores the lockfile next run).
		if _, err2 := runCmd(installDir, pm, nonFrozen...); err2 != nil {
			// A failing lifecycle script (e.g. a workspace-lint postinstall like
			// `sherif`) shouldn't block a build — retry skipping scripts so the
			// dependency tree still gets installed.
			noScripts := append(append([]string{}, nonFrozen...), "--ignore-scripts")
			if _, err3 := runCmd(installDir, pm, noScripts...); err3 != nil {
				return fmt.Errorf("install deps (%s): %w", pm, err2)
			}
		}
	}
	if headSha != "" {
		_ = os.MkdirAll(filepath.Dir(marker), 0o755)
		_ = os.WriteFile(marker, []byte(headSha), 0o644)
	}
	return nil
}

// runCmd runs an arbitrary command in dir, folding combined output into the
// error for diagnosability in job logs. CI=1 is set so package managers act
// non-interactively: without it, pnpm aborts destructive-but-required steps
// like modules-dir rebuilds with ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY.
func runCmd(dir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CI=1")
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		return trimmed, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, trimmed)
	}
	return trimmed, nil
}

func validateRunnerJobSourceBinding(options runnerOnceOptions, job apiRunnerJob) error {
	binding := job.Payload.SourceBinding
	if runnerJobSourceBindingEmpty(binding) {
		return nil
	}

	appDir := appDirectoryForJob(options, job)
	absoluteAppDir, err := filepath.Abs(appDir)
	if err != nil {
		return sourceBindingMismatch("packagePath", appDir, err.Error())
	}
	bindingRoot := binding.WorkspaceRoot
	if bindingRoot == "" {
		bindingRoot = options.workspaceRoot
	}
	// CI-driven builds target a Preflight-owned checkout under .preflight-ci/;
	// sync it to the requested commit before validating. No-op for developer
	// working trees, which are never under a CI root.
	if err := ensureCiCheckout(bindingRoot, binding); err != nil {
		return sourceBindingMismatch("ciCheckout", bindingRoot, err.Error())
	}
	// For a Preflight-owned CI checkout the runner just checked out the exact
	// commit, so the git-identity checks below are authoritative. The content
	// digests / dirty-state / app-config comparisons are skipped: they assume a
	// client computed them against the same tree, but CI omits them (sends a
	// placeholder digest for persistence) and install legitimately mutates the
	// tree (lockfile, node_modules, .preflight/ artifacts).
	isCiRoot := func() bool {
		abs, absErr := filepath.Abs(bindingRoot)
		return absErr == nil && pathHasSegment(abs, ciCheckoutRootSegment)
	}()
	if strings.TrimSpace(bindingRoot) != "" {
		absoluteBindingRoot, err := filepath.Abs(bindingRoot)
		if err != nil {
			return sourceBindingMismatch("workspaceRoot", bindingRoot, err.Error())
		}
		if !pathWithin(absoluteBindingRoot, absoluteAppDir) {
			return sourceBindingMismatch("packagePath", "inside "+absoluteBindingRoot, absoluteAppDir)
		}
	}
	if strings.TrimSpace(options.workspaceRoot) != "" {
		absoluteRunnerRoot, err := filepath.Abs(options.workspaceRoot)
		if err != nil {
			return sourceBindingMismatch("runnerWorkspaceRoot", options.workspaceRoot, err.Error())
		}
		if !pathWithin(absoluteRunnerRoot, absoluteAppDir) && !pathWithin(absoluteAppDir, absoluteRunnerRoot) {
			return sourceBindingMismatch("runnerWorkspaceRoot", "covering "+absoluteAppDir, absoluteRunnerRoot)
		}
	}

	if !isCiRoot {
		easProfileEnv := easProfileEnvForJob(appDir, job)
		resolvedExpoConfig := resolveExpoConfig(appDir, easProfileEnv)
		if expected := strings.TrimSpace(binding.ExpoConfigDigest); expected != "" {
			if err := compareSourceBindingValue("expoConfigDigest", expected, resolvedExpoConfig.digest); err != nil {
				return err
			}
		}
		if expected := strings.TrimSpace(binding.EASJSONDigest); expected != "" {
			if err := compareSourceBindingValue("easJsonDigest", expected, digestIfExists(filepath.Join(appDir, "eas.json"))); err != nil {
				return err
			}
		}
		if binding.DirtyWorkspace != nil || binding.ChangedSetupFiles != nil {
			dirtyWorkspace, changedSetupFiles := sourceBindingGitState(bindingRoot, absoluteAppDir)
			if binding.ChangedSetupFiles != nil {
				if err := compareSourceBindingFileList(
					"changedSetupFiles",
					*binding.ChangedSetupFiles,
					changedSetupFiles,
				); err != nil {
					return err
				}
			}
			if binding.DirtyWorkspace != nil {
				if err := compareSourceBindingValue("dirtyWorkspace", fmt.Sprint(*binding.DirtyWorkspace), fmt.Sprint(dirtyWorkspace)); err != nil {
					return err
				}
			}
		}

		appIdentity := resolvedExpoConfig.identity
		if err := compareSourceBindingValue("appScheme", binding.AppScheme, appIdentity.scheme); err != nil {
			return err
		}
		if err := compareSourceBindingValue("expoSlug", binding.ExpoSlug, appIdentity.slug); err != nil {
			return err
		}
		if err := compareSourceBindingValue("iosBundleId", binding.IOSBundleID, appIdentity.iosBundleID); err != nil {
			return err
		}
		if err := compareSourceBindingValue("androidPackage", binding.AndroidPackage, appIdentity.androidPackage); err != nil {
			return err
		}
		if err := compareSourceBindingValue("easProjectId", binding.EASProjectID, appIdentity.easProjectID); err != nil {
			return err
		}
		if err := compareSourceBindingValue("easProfileName", binding.EASProfileName, actualEASProfileNameForJob(appDir, job)); err != nil {
			return err
		}
	}

	if expected := strings.TrimSpace(binding.GitRemoteURL); expected != "" {
		actual, err := gitOutput(bindingRoot, "config", "--get", "remote.origin.url")
		if err != nil {
			return sourceBindingMismatch("gitRemoteUrl", expected, err.Error())
		}
		if err := compareSourceBindingValue("gitRemoteUrl", expected, actual); err != nil {
			return err
		}
	}
	// gitBranch is skipped for CI roots: ensureCiCheckout does `git reset --hard
	// <sha>` which leaves HEAD on the clone's local branch name (or detached),
	// so the local branch name is not meaningful — gitCommitSha is authoritative.
	if expected := strings.TrimSpace(binding.GitBranch); expected != "" && !isCiRoot {
		actual, err := gitOutput(bindingRoot, "rev-parse", "--abbrev-ref", "HEAD")
		if err != nil {
			return sourceBindingMismatch("gitBranch", expected, err.Error())
		}
		if err := compareSourceBindingValue("gitBranch", expected, actual); err != nil {
			return err
		}
	}
	if expected := strings.TrimSpace(binding.GitCommitSHA); expected != "" {
		actual, err := gitOutput(bindingRoot, "rev-parse", "HEAD")
		if err != nil {
			return sourceBindingMismatch("gitCommitSha", expected, err.Error())
		}
		if err := compareSourceBindingValue("gitCommitSha", expected, actual); err != nil {
			return err
		}
	}

	return nil
}

func easProfileEnvForJob(appDir string, job apiRunnerJob) map[string]string {
	profileName := strings.TrimSpace(job.Payload.SourceBinding.EASProfileName)
	if profileName == "" {
		profileName = strings.TrimSpace(job.Payload.EASProfileName)
	}
	if profileName == "" {
		return nil
	}
	easConfig, err := loadEASJSON(appDir)
	if err != nil {
		return nil
	}
	profile, ok := easConfig.Build[profileName]
	if !ok {
		return nil
	}
	return easProfileEnv(profile, jobPlatform(job))
}

func actualEASProfileNameForJob(appDir string, job apiRunnerJob) string {
	if profileName := strings.TrimSpace(job.Payload.EASProfileName); profileName != "" {
		return profileName
	}
	profileName := strings.TrimSpace(job.Payload.SourceBinding.EASProfileName)
	if profileName == "" {
		return ""
	}
	easConfig, err := loadEASJSON(appDir)
	if err != nil {
		return ""
	}
	if _, ok := easConfig.Build[profileName]; !ok {
		return ""
	}
	return profileName
}

func runnerJobSourceBindingEmpty(binding runnerJobSourceBinding) bool {
	return strings.TrimSpace(binding.ID) == "" &&
		strings.TrimSpace(binding.WorkspaceRoot) == "" &&
		strings.TrimSpace(binding.PackagePath) == "" &&
		strings.TrimSpace(binding.EASProfileName) == "" &&
		strings.TrimSpace(binding.EASJSONDigest) == "" &&
		strings.TrimSpace(binding.ExpoConfigDigest) == "" &&
		strings.TrimSpace(binding.AppScheme) == "" &&
		strings.TrimSpace(binding.ExpoSlug) == "" &&
		strings.TrimSpace(binding.IOSBundleID) == "" &&
		strings.TrimSpace(binding.AndroidPackage) == "" &&
		strings.TrimSpace(binding.EASProjectID) == "" &&
		strings.TrimSpace(binding.GitRemoteURL) == "" &&
		strings.TrimSpace(binding.GitBranch) == "" &&
		strings.TrimSpace(binding.GitCommitSHA) == "" &&
		binding.DirtyWorkspace == nil &&
		binding.ChangedSetupFiles == nil
}

func normalizeSourceBindingFileList(values []string) []string {
	if values == nil {
		return []string{}
	}
	seen := map[string]bool{}
	files := make([]string, 0, len(values))
	for _, value := range values {
		normalized := filepath.ToSlash(strings.TrimSpace(value))
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		files = append(files, normalized)
	}
	sort.Strings(files)
	return files
}

func compareSourceBindingFileList(field string, expected []string, actual []string) error {
	expectedList := normalizeSourceBindingFileList(expected)
	actualList := normalizeSourceBindingFileList(actual)
	expectedValue := strings.Join(expectedList, ",")
	actualValue := strings.Join(actualList, ",")
	if expectedValue != actualValue {
		return sourceBindingMismatch(field, expectedValue, actualValue)
	}
	return nil
}

func compareSourceBindingValue(field string, expected string, actual string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	actual = strings.TrimSpace(actual)
	if expected != actual {
		return sourceBindingMismatch(field, expected, actual)
	}
	return nil
}

func sourceBindingMismatch(field string, expected string, actual string) error {
	return &sourceBindingMismatchError{
		field:    field,
		expected: expected,
		actual:   actual,
	}
}

func completeSourceBindingMismatchJob(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
	stdout io.Writer,
	err error,
) error {
	var mismatch *sourceBindingMismatchError
	if !errors.As(err, &mismatch) {
		return err
	}
	if completeErr := completeRunnerJob(client, options, registration, job, map[string]any{
		"status": "failed",
		"sourceBinding": map[string]any{
			"id":          job.Payload.SourceBinding.ID,
			"packagePath": job.Payload.SourceBinding.PackagePath,
			"mismatch": map[string]any{
				"field":    mismatch.field,
				"expected": mismatch.expected,
				"actual":   mismatch.actual,
			},
		},
		"failure": map[string]any{
			"code":    "source_binding_mismatch",
			"message": mismatch.Error(),
		},
	}); completeErr != nil {
		return completeErr
	}
	fmt.Fprintf(stdout, "source binding mismatch %s %s\n", job.ID, mismatch.Error())
	return nil
}

func pathWithin(root string, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func expoConfigDigest(appDir string) string {
	path := expoConfigPath(appDir)
	if path == "" {
		return ""
	}
	return digestIfExists(path)
}

func expoConfigPath(appDir string) string {
	for _, name := range []string{"app.config.ts", "app.config.js", "app.json"} {
		path := filepath.Join(appDir, name)
		if fileExists(path) {
			return path
		}
	}
	return ""
}

func gitOutput(workspaceRoot string, args ...string) (string, error) {
	if strings.TrimSpace(workspaceRoot) == "" {
		return "", fmt.Errorf("workspace root is empty")
	}
	command := exec.Command("git", append([]string{"-C", workspaceRoot}, args...)...)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func metroStatusReady(client *http.Client, statusURL string) bool {
	response, err := client.Get(statusURL)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false
	}
	body, err := io.ReadAll(response.Body)
	return err == nil && strings.Contains(string(body), "packager-status:running")
}

func preflightOwnedMetroReady(client *http.Client, appDir string, statusURL string) bool {
	pidPath := filepath.Join(appDir, ".preflight", "expo-dev-session.pid")
	pidContent, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidContent)))
	if err != nil || pid <= 0 {
		_ = os.Remove(pidPath)
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil {
		_ = os.Remove(pidPath)
		return false
	}
	return metroStatusReady(client, statusURL)
}

func stopPreflightOwnedDevSession(appDir string, expectedPID int) (string, error) {
	pidPath := filepath.Join(appDir, ".preflight", "expo-dev-session.pid")
	pidContent, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "already_stopped", nil
		}
		return "failed", fmt.Errorf("read Expo dev session pid: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidContent)))
	if err != nil || pid <= 0 {
		_ = os.Remove(pidPath)
		return "already_stopped", nil
	}
	if expectedPID > 0 && pid != expectedPID {
		return "pid_mismatch", fmt.Errorf("Preflight pid file points at %d, expected %d", pid, expectedPID)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		_ = os.Remove(pidPath)
		return "already_stopped", nil
	}
	terminateCommandProcess(pid)
	_ = os.Remove(pidPath)
	return "terminated", nil
}

func devSessionStopResultPayload(job apiRunnerJob, outcome string, status string) map[string]any {
	devSession := job.Payload.DevSession
	payload := map[string]any{
		"id":            devSession.ID,
		"status":        status,
		"url":           devSession.URL,
		"advertisedUrl": devSession.AdvertisedURL,
		"statusUrl":     devSession.StatusURL,
		"hostMode":      devSession.HostMode,
		"hostIp":        devSession.HostIP,
		"port":          devSession.Port,
		"shutdown": map[string]any{
			"outcome": outcome,
		},
	}
	if devSession.PID > 0 {
		payload["pid"] = devSession.PID
	}
	return payload
}

func devSessionStopFailureCode(outcome string) string {
	if outcome == "pid_mismatch" {
		return "dev_session_pid_mismatch"
	}
	return "dev_session_stop_failed"
}

func waitForMetroStatus(client *http.Client, statusURL string, timeout time.Duration) error {
	return waitForMetroStatusWithCancellation(client, statusURL, timeout, nil, 0)
}

func waitForMetroStatusWithCancellation(
	client *http.Client,
	statusURL string,
	timeout time.Duration,
	cancellationCheck func() (bool, error),
	pollInterval time.Duration,
) error {
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if cancellationCheck != nil {
			cancelled, err := cancellationCheck()
			if err != nil {
				return err
			}
			if cancelled {
				return errCommandCancelled
			}
		}
		if metroStatusReady(client, statusURL) {
			return nil
		}
		select {
		case <-timer.C:
			return fmt.Errorf("Metro did not become ready at %s", statusURL)
		case <-ticker.C:
		}
	}
}

type expoDevServerProcess struct {
	command   *exec.Cmd
	pid       int
	logPath   string
	logOffset int64
}

func startExpoDevServer(options runnerOnceOptions, appDir string, job apiRunnerJob) (*expoDevServerProcess, error) {
	logDir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("create Preflight log directory: %w", err)
	}
	logPath := filepath.Join(logDir, "expo-dev-session.log")
	var logOffset int64
	if info, err := os.Stat(logPath); err == nil {
		logOffset = info.Size()
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open Expo dev session log: %w", err)
	}

	command := exec.Command("npx", "expo", "start", "--dev-client", "--host", expoHostArg(options.hostMode), "--port", strconv.Itoa(options.metroPort))
	command.Dir = appDir
	command.Env = expoCommandEnv(job)
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start Expo dev server: %w", err)
	}
	process := &expoDevServerProcess{
		command:   command,
		pid:       command.Process.Pid,
		logPath:   logPath,
		logOffset: logOffset,
	}
	if err := os.WriteFile(filepath.Join(logDir, "expo-dev-session.pid"), []byte(strconv.Itoa(command.Process.Pid)), 0o644); err != nil {
		_ = logFile.Close()
		terminateExpoDevServer(process)
		return nil, fmt.Errorf("write Expo dev session pid: %w", err)
	}
	if err := logFile.Close(); err != nil {
		terminateExpoDevServer(process)
		return nil, fmt.Errorf("close Expo dev session log: %w", err)
	}
	return process, nil
}

func validateStartedExpoDevServer(process *expoDevServerProcess, port int) error {
	if process == nil || process.logPath == "" {
		return nil
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		content, err := os.ReadFile(process.logPath)
		if err != nil {
			return nil
		}
		if process.logOffset > 0 {
			if process.logOffset >= int64(len(content)) {
				content = nil
			} else {
				content = content[process.logOffset:]
			}
		}
		logOutput := string(content)
		if strings.Contains(logOutput, "Skipping dev server") ||
			(strings.Contains(logOutput, "is running") &&
				strings.Contains(logOutput, "another window")) {
			return fmt.Errorf(
				"Metro port %d is already serving a non-Preflight dev server",
				port,
			)
		}
		if strings.TrimSpace(logOutput) != "" || !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func terminateExpoDevServer(process *expoDevServerProcess) {
	if process == nil || process.command == nil || process.pid <= 0 {
		return
	}
	terminateCommandProcess(process.pid)
	_ = process.command.Wait()
}

// preflightCiCheckoutSegment extracts the "<repo>" name that follows
// "/.preflight-ci/" in a path or process command line, or "" if absent.
func preflightCiCheckoutSegment(s string) string {
	const marker = "/.preflight-ci/"
	idx := strings.Index(s, marker)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(marker):]
	if end := strings.IndexAny(rest, "/ "); end >= 0 {
		return rest[:end]
	}
	return rest
}

// cleanupStalePreflightDevServers kills leftover `expo start --dev-client` Metro
// processes from PRIOR preflight CI builds (a different .preflight-ci checkout
// than the current job). The prove-app chain has no dev_session.stop, so without
// this each completed build leaks its Metro, which then holds the metro port and
// makes expo decline to start for the next build. Serial-runner safe: it never
// touches a dev server for the current job's own checkout (so same-app reuse and
// concurrent builds of the SAME app are preserved).
func cleanupStalePreflightDevServers(currentAppDir string, stdout io.Writer) {
	currentSeg := preflightCiCheckoutSegment(currentAppDir)
	out, err := exec.Command("ps", "-eo", "pid=,command=").Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")
	// Multi-runner-per-host safety: a dev server is only a leak if NO build is
	// actively running for its app. A concurrent runner building a different app
	// has a live `expo run:ios`/`xcodebuild` for that app plus its dev server —
	// reaping that server would wedge the other runner. Collect segments with an
	// active build and spare their dev servers.
	activeBuildSegs := map[string]bool{}
	for _, line := range lines {
		if !strings.Contains(line, "/.preflight-ci/") {
			continue
		}
		if strings.Contains(line, "expo run:ios") || strings.Contains(line, "xcodebuild") {
			if s := preflightCiCheckoutSegment(line); s != "" {
				activeBuildSegs[s] = true
			}
		}
	}
	for _, line := range lines {
		if !strings.Contains(line, "/.preflight-ci/") ||
			!strings.Contains(line, "--dev-client") ||
			!strings.Contains(line, "start") {
			continue
		}
		seg := preflightCiCheckoutSegment(line)
		if seg == "" || (currentSeg != "" && seg == currentSeg) || activeBuildSegs[seg] {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		pid, convErr := strconv.Atoi(fields[0])
		if convErr != nil || pid <= 0 {
			continue
		}
		fmt.Fprintf(stdout, "reaping stale preflight dev server for %s (pid %d)\n", seg, pid)
		terminateCommandProcess(pid)
	}
}

// cleanupStaleCiBuildProcesses kills leftover `expo run:ios` and `xcodebuild`
// processes from PRIOR or CONCURRENT preflight CI builds. On a single macOS host,
// parallel xcodebuild invocations share Xcode's ModuleCache build-session file and
// deadlock (SwiftBuild stalls mid-compile at 0% CPU), and lease-expiry reclaims
// re-spawn expo run:ios on top of the orphaned attempt — stacking builds until the
// host thrashes. simulator.open runs serially per runner host, so when a build
// reaches this point nothing for the current job exists yet: every matching CI
// build process is an orphan or a competing build and is safe to reap. Non-CI
// builds (no /.preflight-ci/ in the command, e.g. a developer's local build) are
// never touched. Killing the expo/xcodebuild process group cascades to its clang
// children; the shared SwiftBuild XPC service idles once xcodebuild exits.
// concurrentPreflightBuildActive reports whether another runner on this host is
// mid-build: a live `expo run:ios`/`xcodebuild` for a .preflight-ci checkout whose
// segment differs from the current job's. Used to avoid host-wide simulator
// shutdowns that would wedge a concurrent runner.
func concurrentPreflightBuildActive(currentSegment string) bool {
	out, err := exec.Command("ps", "-eo", "command=").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "/.preflight-ci/") {
			continue
		}
		if !strings.Contains(line, "expo run:ios") && !strings.Contains(line, "xcodebuild") {
			continue
		}
		seg := preflightCiCheckoutSegment(line)
		if seg != "" && seg != currentSegment {
			return true
		}
	}
	return false
}

func cleanupStaleCiBuildProcesses(stdout io.Writer, currentSegment string) {
	out, err := exec.Command("ps", "-eo", "pid=,ppid=,command=").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "/.preflight-ci/") {
			continue
		}
		if !strings.Contains(line, "expo run:ios") && !strings.Contains(line, "xcodebuild") {
			continue
		}
		seg := preflightCiCheckoutSegment(line)
		// Multi-runner-per-host safety: only reap builds for THIS job's checkout
		// (orphans/re-spawns of the same app). A build for a DIFFERENT app is a
		// concurrent runner's in-flight work — killing it would wedge the other
		// runner. When currentSegment is empty (unknown), fall back to the legacy
		// reap-all behavior for single-runner hosts.
		if currentSegment != "" && seg != currentSegment {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		pid, convErr := strconv.Atoi(fields[0])
		if convErr != nil || pid <= 0 {
			continue
		}
		// Only reap true orphans. A build whose runner died is reparented to
		// launchd (ppid 1); a build with a live parent belongs to another
		// runner working the same checkout (duplicate-claim races) — killing
		// it made two runners "reap" each other's in-flight xcodebuild.
		ppid, convErr := strconv.Atoi(fields[1])
		if convErr != nil || ppid != 1 {
			continue
		}
		fmt.Fprintf(stdout, "reaping stale CI build process for %s (pid %d)\n", seg, pid)
		terminateCommandProcess(pid)
	}
}

// ensureBuildDiskHeadroom clears Xcode DerivedData when free space on the build
// volume is low. The farm shares one APFS container across ~14 CI checkouts +
// DerivedData; a full disk silently fails git fetch ("No space left on device"),
// xcodebuild, and artifact upload. Called right after the build reap (no in-flight
// build), so DerivedData has no live consumer. Only clears under pressure, so warm
// incremental builds keep their cache the rest of the time.
func ensureBuildDiskHeadroom(buildDir string, stdout io.Writer) {
	const minFreeBytes = 20 * 1024 * 1024 * 1024 // 20 GiB
	probe := buildDir
	if probe == "" {
		probe = "/"
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(probe, &stat); err != nil {
		return
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	if freeBytes >= minFreeBytes {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	derivedData := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData")
	entries, err := os.ReadDir(derivedData)
	if err != nil {
		return
	}
	// Multi-runner-per-host safety: only clear IDLE DerivedData. A concurrent
	// runner's in-flight build touches its DerivedData subtree constantly, so a
	// recent mtime means "active build, do not wipe". Clearing only entries
	// untouched for >15m reclaims stale caches without yanking a live build.
	const idleCutoff = 15 * time.Minute
	now := time.Now()
	fmt.Fprintf(stdout, "disk headroom low (%.1f GiB free); clearing idle Xcode DerivedData\n", float64(freeBytes)/(1024*1024*1024))
	for _, entry := range entries {
		path := filepath.Join(derivedData, entry.Name())
		if info, statErr := os.Stat(path); statErr == nil && now.Sub(info.ModTime()) < idleCutoff {
			fmt.Fprintf(stdout, "  keeping active DerivedData %s (modified %s ago)\n", entry.Name(), now.Sub(info.ModTime()).Round(time.Second))
			continue
		}
		_ = os.RemoveAll(path)
	}
}

func devSessionStartFailureCode(err error) string {
	if err == nil {
		return "dev_session_start_failed"
	}
	message := err.Error()
	if strings.Contains(message, "Metro did not become ready") {
		return "metro_start_timeout"
	}
	if strings.Contains(message, "Expo tunnel URL") {
		return "expo_tunnel_url_missing"
	}
	if strings.Contains(message, "non-Preflight dev server") {
		return "metro_port_owned_by_other_project"
	}
	if strings.Contains(message, "boot iOS simulator") {
		return "simulator_boot_failed"
	}
	return "dev_session_start_failed"
}

func shouldBootIOSSimulator(job apiRunnerJob) bool {
	if jobPlatform(job) != "ios" {
		return false
	}
	if job.Payload.Lane == "simulator" || job.Payload.TargetClass == "simulator" {
		return true
	}
	return job.Payload.Lane == "" && !isDevelopmentDevSessionJob(job)
}

func runExpoIOSOpen(appDir string, providerIdentity string, port int) (string, error) {
	return runExpoAppOpen(runnerOnceOptions{}, "ios", appDir, providerIdentity, port, apiRunnerJob{})
}

func runExpoAppOpen(options runnerOnceOptions, platform string, appDir string, providerIdentity string, port int, job apiRunnerJob, cancellationChecks ...func() (bool, error)) (string, error) {
	logDir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return "", fmt.Errorf("create Preflight log directory: %w", err)
	}
	logPath := filepath.Join(logDir, fmt.Sprintf("expo-run-%s.log", platform))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return "", fmt.Errorf("open Expo run:%s log: %w", platform, err)
	}
	defer logFile.Close()
	var cancellationCheck func() (bool, error)
	if len(cancellationChecks) > 0 {
		cancellationCheck = cancellationChecks[0]
	}

	command := exec.Command("npx", expoRunArgs(platform, providerIdentity, port)...)
	command.Dir = appDir
	command.Env = expoCommandEnv(job)
	if platform == "ios" {
		// Run the simulator headlessly. `expo run:ios` opens the Simulator.app GUI
		// via `osascript`/System Events, which fails on a runner with no Aqua/window
		// session (launchd or ssh). All actual install/launch is done through simctl,
		// which is headless — so we shim `osascript` on PATH to report Simulator as
		// already running. expo then skips the GUI open and proceeds via simctl.
		if shimDir, shimErr := ensureHeadlessOsascriptShim(); shimErr == nil {
			command.Env = prependPathEnv(command.Env, shimDir)
		} else {
			fmt.Fprintf(logFile, "warning: could not install headless osascript shim: %v\n", shimErr)
		}
	}
	flushExpoRunLog := attachRedactedCommandLog(command, logFile)
	if err := runExpoPrebuild(logFile, appDir, platform, job, cancellationCheck); err != nil {
		return logPath, err
	}
	if platform == "android" {
		if err := refreshAndroidAutolinkingState(logFile, appDir, job, cancellationCheck); err != nil {
			return logPath, err
		}
	}
	if err := runCommandWithTimeoutAndCancellation(command, simulatorOpenTimeout(), cancellationCheck, runnerPollInterval()); err != nil {
		flushExpoRunLog()
		if !canContinueAfterExpoIOSOpenFailure(logPath, options, providerIdentity, job) {
			return logPath, fmt.Errorf("run Expo %s install/open: %w", platform, err)
		}
		_, _ = fmt.Fprintf(logFile, "warning: expo run:ios reported a development-client open failure after installing the app; continuing with Preflight simctl openurl fallback: %v\n", err)
	}
	flushExpoRunLog()
	if err := openExpoDevelopmentClient(logFile, options, platform, providerIdentity, port, job, cancellationCheck); err != nil {
		return logPath, err
	}
	return logPath, nil
}

func canContinueAfterExpoIOSOpenFailure(logPath string, options runnerOnceOptions, providerIdentity string, job apiRunnerJob) bool {
	if strings.TrimSpace(options.xcrunPath) == "" {
		return false
	}
	bundleID := strings.TrimSpace(job.Payload.SourceBinding.IOSBundleID)
	if bundleID == "" {
		return false
	}
	logOutput, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(logOutput), "No development build") {
		return false
	}
	openProviderIdentity := strings.TrimSpace(job.Payload.ProviderIdentity)
	if openProviderIdentity == "" {
		openProviderIdentity = strings.TrimSpace(job.TargetID)
	}
	if openProviderIdentity == "" {
		openProviderIdentity = strings.TrimSpace(providerIdentity)
	}
	if openProviderIdentity == "" {
		return false
	}
	command := exec.Command(options.xcrunPath, "simctl", "get_app_container", openProviderIdentity, bundleID, "app")
	return command.Run() == nil
}

// ensureHeadlessOsascriptShim writes a tiny `osascript` shim into a dedicated
// bin dir and returns that dir for prepending to a command's PATH. The shim
// reports Simulator.app as already running (count -> 1) and no-ops everything
// else, so GUI-dependent tooling (expo run:ios) proceeds via simctl on a host
// with no Aqua/window session.
func ensureHeadlessOsascriptShim() (string, error) {
	dir := filepath.Join(os.TempDir(), "preflight-headless-bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	shimPath := filepath.Join(dir, "osascript")
	// expo run:ios probes Simulator.app via AppleScript before installing through
	// simctl: it counts "Simulator" processes (non-zero => already running, so it
	// skips the GUI open) and reads the Simulator app bundle id. Answer both so
	// expo proceeds straight to its headless simctl boot/install/launch.
	script := "#!/bin/sh\n" +
		"# Preflight headless shim: simulators run via simctl, no Simulator.app GUI.\n" +
		"case \"$*\" in\n" +
		"  *\"count processes\"*) echo 1 ;;\n" +
		"  *\"id of app\"*) echo com.apple.iphonesimulator ;;\n" +
		"  *) : ;;\n" +
		"esac\n" +
		"exit 0\n"
	if existing, err := os.ReadFile(shimPath); err != nil || string(existing) != script {
		if err := os.WriteFile(shimPath, []byte(script), 0o755); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(shimPath, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// prependPathEnv returns env with dir prepended to its PATH entry (adding PATH
// if absent).
func prependPathEnv(env []string, dir string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			out = append(out, "PATH="+dir+string(os.PathListSeparator)+kv[len("PATH="):])
			found = true
		} else {
			out = append(out, kv)
		}
	}
	if !found {
		out = append(out, "PATH="+dir)
	}
	return out
}

func resolveStartedAdvertisedDevServerURL(options runnerOnceOptions, job apiRunnerJob, appDir string, process *expoDevServerProcess) (string, error) {
	if options.hostMode != "tunnel" {
		return advertisedDevServerURL(options, job)
	}
	logPath := filepath.Join(appDir, ".preflight", "expo-dev-session.log")
	logOffset := int64(0)
	if process != nil {
		logPath = process.logPath
		logOffset = process.logOffset
	}
	return waitForExpoTunnelDevServerURL(logPath, logOffset, options.metroPort, expoDevSessionStartTimeout(), runnerPollInterval())
}

func waitForExpoTunnelDevServerURL(logPath string, logOffset int64, metroPort int, timeout time.Duration, pollInterval time.Duration) (string, error) {
	if pollInterval <= 0 {
		pollInterval = defaultRunnerPollInterval
	}
	if timeout <= 0 {
		timeout = defaultExpoDevSessionStartTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		// Expo CLI does not print the tunnel URL to a non-TTY log, so the
		// authoritative source is the local Metro manifest's hostUri. The log
		// scrape stays as a fallback for older CLI versions that did print it.
		if tunnelURL, ok := expoTunnelDevServerURLFromManifest(metroPort); ok {
			return tunnelURL, nil
		}
		if tunnelURL, ok := expoTunnelDevServerURLFromLog(logPath, logOffset); ok {
			return tunnelURL, nil
		}
		select {
		case <-timer.C:
			return "", fmt.Errorf("Expo tunnel URL was not written to %s", logPath)
		case <-ticker.C:
		}
	}
}

func expoTunnelDevServerURLFromManifest(metroPort int) (string, bool) {
	if metroPort <= 0 {
		return "", false
	}
	client := &http.Client{Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d", metroPort), nil)
	if err != nil {
		return "", false
	}
	request.Header.Set("expo-platform", "ios")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", false
	}
	var manifest struct {
		HostURI     string `json:"hostUri"`
		LaunchAsset struct {
			URL string `json:"url"`
		} `json:"launchAsset"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", false
	}
	for _, candidate := range []string{manifest.HostURI, manifest.LaunchAsset.URL} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if !strings.Contains(candidate, "://") {
			candidate = "exp://" + candidate
		}
		if parsed, err := url.Parse(candidate); err == nil && parsed.Host != "" {
			trimmed := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
			if isRemoteExpoDevServerURL(trimmed) {
				return trimmed, true
			}
		}
	}
	return "", false
}

var expoDevelopmentClientURLRegexp = regexp.MustCompile(`expo-development-client/\?url=([^\s"'<>]+)`)
var remoteDevServerURLRegexp = regexp.MustCompile(`\b(?:https?|exp)://[^\s"'<>]+`)

func expoTunnelDevServerURLFromLog(logPath string, logOffset int64) (string, bool) {
	content, err := os.ReadFile(logPath)
	if err != nil {
		return "", false
	}
	if logOffset > 0 {
		if logOffset >= int64(len(content)) {
			content = nil
		} else {
			content = content[logOffset:]
		}
	}
	return expoTunnelDevServerURLFromLogContent(string(content))
}

func expoTunnelDevServerURLFromLogContent(content string) (string, bool) {
	for _, match := range expoDevelopmentClientURLRegexp.FindAllStringSubmatch(content, -1) {
		if len(match) < 2 {
			continue
		}
		encodedURL := strings.Split(strings.TrimRight(match[1], ".,;)]}"), "&")[0]
		decodedURL, err := url.QueryUnescape(encodedURL)
		if err != nil {
			continue
		}
		if isRemoteExpoDevServerURL(decodedURL) {
			return decodedURL, true
		}
	}
	for _, match := range remoteDevServerURLRegexp.FindAllString(content, -1) {
		candidate := strings.TrimRight(match, ".,;)]}")
		if isRemoteExpoDevServerURL(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func isRemoteExpoDevServerURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "exp" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	// ngrok failure output includes "https://status.ngrok.com/" — never a dev
	// server. Matching it produced sessions advertising the ngrok status page.
	if strings.EqualFold(host, "status.ngrok.com") {
		return false
	}
	return true
}

func runExpoPrebuild(logFile *os.File, appDir string, platform string, job apiRunnerJob, cancellationCheck func() (bool, error)) error {
	_, _ = fmt.Fprintf(logFile, "$ npx expo prebuild --platform %s\n", platform)
	command := exec.Command("npx", "expo", "prebuild", "--platform", platform)
	command.Dir = appDir
	command.Env = expoCommandEnv(job)
	flushLog := attachRedactedCommandLog(command, logFile)
	err := runCommandWithTimeoutAndCancellation(command, simulatorOpenTimeout(), cancellationCheck, runnerPollInterval())
	flushLog()
	if err != nil {
		return fmt.Errorf("run Expo %s prebuild: %w", platform, err)
	}
	return nil
}

func refreshAndroidAutolinkingState(logFile *os.File, appDir string, job apiRunnerJob, cancellationCheck func() (bool, error)) error {
	androidDir := filepath.Join(appDir, "android")
	gradleWrapper := filepath.Join(androidDir, "gradlew")
	if _, err := os.Stat(gradleWrapper); err != nil {
		return fmt.Errorf("find Android Gradle wrapper after prebuild: %w", err)
	}
	if err := runAndroidGradleCommand(logFile, androidDir, job, cancellationCheck, "--stop"); err != nil {
		return fmt.Errorf("stop Android Gradle daemon: %w", err)
	}
	if err := resetAndroidAutolinkingOutputs(appDir); err != nil {
		return fmt.Errorf("reset Android autolinking outputs: %w", err)
	}
	if err := runAndroidGradleCommand(
		logFile,
		androidDir,
		job,
		cancellationCheck,
		":app:generateReactNativeEntryPoint",
		":app:generateAutolinkingPackageList",
		":app:generateAutolinkingNewArchitectureFiles",
		"--rerun-tasks",
	); err != nil {
		return fmt.Errorf("regenerate Android autolinking outputs: %w", err)
	}
	return nil
}

func resetAndroidAutolinkingOutputs(appDir string) error {
	androidDir := filepath.Join(appDir, "android")
	for _, path := range []string{
		filepath.Join(androidDir, "build", "generated", "autolinking"),
		filepath.Join(androidDir, "app", "build", "generated", "autolinking"),
	} {
		if err := removePathWithin(androidDir, path); err != nil {
			return err
		}
	}
	return nil
}

func removePathWithin(root string, target string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve root path: %w", err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return fmt.Errorf("resolve target relative path: %w", err)
	}
	if rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("refuse to remove path outside Android directory: %s", target)
	}
	if err := os.RemoveAll(targetAbs); err != nil {
		return fmt.Errorf("remove %s: %w", target, err)
	}
	return nil
}

func runAndroidGradleCommand(logFile *os.File, androidDir string, job apiRunnerJob, cancellationCheck func() (bool, error), args ...string) error {
	_, _ = fmt.Fprintf(logFile, "$ ./gradlew %s\n", strings.Join(args, " "))
	command := exec.Command("./gradlew", args...)
	command.Dir = androidDir
	command.Env = expoCommandEnv(job)
	flushLog := attachRedactedCommandLog(command, logFile)
	err := runCommandWithTimeoutAndCancellation(command, simulatorOpenTimeout(), cancellationCheck, runnerPollInterval())
	flushLog()
	if err != nil {
		return err
	}
	return nil
}

func expoRunDeviceSelector(options runnerOnceOptions, platform string, job apiRunnerJob, providerIdentity string) string {
	if platform == "android" {
		if avdName := androidAVDNameForSerial(options, providerIdentity); avdName != "" {
			return avdName
		}
	}
	if platform == "android" && strings.TrimSpace(job.Payload.TargetDisplayName) != "" {
		return strings.TrimSpace(job.Payload.TargetDisplayName)
	}
	return providerIdentity
}

func androidAVDNameForSerial(options runnerOnceOptions, providerIdentity string) string {
	if strings.TrimSpace(providerIdentity) == "" {
		return ""
	}
	command := exec.Command(options.adbPath, "-s", providerIdentity, "emu", "avd", "name")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := runCommandWithTimeout(command, defaultAndroidDeviceNameTimeout); err != nil {
		return ""
	}
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "OK" {
			return line
		}
	}
	return ""
}

func expoRunArgs(platform string, providerIdentity string, port int) []string {
	if platform == "android" {
		return expoRunAndroidArgs(providerIdentity, port)
	}
	return expoRunIOSArgs(providerIdentity, port)
}

func expoRunIOSArgs(providerIdentity string, port int) []string {
	return []string{"expo", "run:ios", "--device", providerIdentity, "--no-bundler"}
}

func expoRunAndroidArgs(providerIdentity string, port int) []string {
	return []string{"expo", "run:android", "--device", providerIdentity, "--no-build-cache", "--no-bundler"}
}

func openExpoDevelopmentClient(logFile *os.File, options runnerOnceOptions, platform string, providerIdentity string, port int, job apiRunnerJob, cancellationCheck func() (bool, error)) error {
	deepLinkURL := simulatorDeepLinkURL(job, port)
	if strings.TrimSpace(deepLinkURL) == "" {
		return nil
	}
	openProviderIdentity := strings.TrimSpace(job.Payload.ProviderIdentity)
	if openProviderIdentity == "" {
		openProviderIdentity = strings.TrimSpace(job.TargetID)
	}
	if openProviderIdentity == "" {
		openProviderIdentity = providerIdentity
	}
	switch platform {
	case "android":
		if strings.TrimSpace(options.adbPath) == "" {
			return fmt.Errorf("open Android development client: adb path is empty")
		}
		return runLoggedADBCommandWithCancellation(logFile, options, cancellationCheck, androidDeepLinkOpenArgs(openProviderIdentity, job.Payload.SourceBinding.AndroidPackage, deepLinkURL)...)
	case "ios":
		if strings.TrimSpace(options.xcrunPath) == "" {
			return fmt.Errorf("open iOS development client: xcrun path is empty")
		}
		if err := bootIOSSimulator(options, openProviderIdentity); err != nil {
			return fmt.Errorf("boot iOS simulator before dev-client open: %w", err)
		}
		if bundleID := strings.TrimSpace(job.Payload.SourceBinding.IOSBundleID); bundleID != "" {
			// Prefer the URL scheme the installed dev build actually registers.
			// The source-binding scheme is unreliable when app.config computes
			// it per build variant (e.g. `${BASE_SCHEME}-dev`) — static config
			// extraction misses the non-literal and falls back to exp+<slug>,
			// which the installed app doesn't register, so `openurl` fails and
			// the bundle never loads. The installed Info.plist is ground truth.
			if installedScheme := installedAppDevClientScheme(logFile, options, openProviderIdentity, bundleID); installedScheme != "" {
				if rebuilt := rebuildDeepLinkWithScheme(deepLinkURL, installedScheme); rebuilt != "" && rebuilt != deepLinkURL {
					fmt.Fprintf(logFile, "using dev-client scheme %q from installed app (was %q)\n", installedScheme, deepLinkURL)
					deepLinkURL = rebuilt
				}
			}
			runOptionalLoggedXcrunCommand(logFile, options, "simctl", "terminate", openProviderIdentity, bundleID)
		}
		if err := runLoggedXcrunCommandWithCancellation(logFile, options, cancellationCheck, "simctl", "openurl", openProviderIdentity, deepLinkURL); err != nil {
			return err
		}
		// Newer iOS simulators (observed on iOS 26) raise an "Open in <App>?"
		// confirmation when the dev-client deep link is delivered via
		// `simctl openurl`. If it isn't accepted, the dev client sits on its
		// launcher, never loads the JS bundle, and the Maestro smoke times out
		// waiting for the app's first screen. Best-effort accept it here so the
		// bundle starts loading before maestro.run begins.
		acceptIOSDevClientOpenDialog(logFile, openProviderIdentity)
		return nil
	default:
		return nil
	}
}

// installedAppDevClientScheme returns a URL scheme that the installed dev build
// actually registers (CFBundleURLSchemes in its Info.plist), suitable for the
// development-client deep link. Returns "" on any failure so the caller keeps
// the source-binding-derived scheme.
func installedAppDevClientScheme(logFile *os.File, options runnerOnceOptions, udid string, bundleID string) string {
	if strings.TrimSpace(options.xcrunPath) == "" {
		return ""
	}
	containerOut, err := exec.Command(options.xcrunPath, "simctl", "get_app_container", udid, bundleID, "app").Output()
	if err != nil {
		fmt.Fprintf(logFile, "dev-client scheme: get_app_container failed: %v\n", err)
		return ""
	}
	appPath := strings.TrimSpace(string(containerOut))
	if appPath == "" {
		return ""
	}
	plistPath := filepath.Join(appPath, "Info.plist")
	jsonOut, err := exec.Command("plutil", "-convert", "json", "-o", "-", plistPath).Output()
	if err != nil {
		fmt.Fprintf(logFile, "dev-client scheme: plutil read of %s failed: %v\n", plistPath, err)
		return ""
	}
	var info struct {
		URLTypes []struct {
			Schemes []string `json:"CFBundleURLSchemes"`
		} `json:"CFBundleURLTypes"`
	}
	if err := json.Unmarshal(jsonOut, &info); err != nil {
		fmt.Fprintf(logFile, "dev-client scheme: parse Info.plist failed: %v\n", err)
		return ""
	}
	var schemes []string
	for _, t := range info.URLTypes {
		schemes = append(schemes, t.Schemes...)
	}
	return chooseDevClientScheme(schemes, bundleID)
}

// chooseDevClientScheme picks the best registered scheme for a development-client
// deep link: the canonical expo scheme (exp+...) that the Expo CLI itself uses,
// then the app's own custom scheme, then anything non-empty. The bundle-id
// scheme is the last resort.
func chooseDevClientScheme(schemes []string, bundleID string) string {
	bundleID = strings.TrimSpace(bundleID)
	for _, s := range schemes {
		if strings.HasPrefix(strings.TrimSpace(s), "exp+") {
			return strings.TrimSpace(s)
		}
	}
	for _, s := range schemes {
		t := strings.TrimSpace(s)
		if t != "" && t != bundleID {
			return t
		}
	}
	for _, s := range schemes {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// rebuildDeepLinkWithScheme swaps the scheme of an existing development-client
// deep link, preserving the `://expo-development-client/?url=...` remainder.
func rebuildDeepLinkWithScheme(deepLinkURL string, scheme string) string {
	idx := strings.Index(deepLinkURL, "://")
	if idx <= 0 {
		return ""
	}
	return strings.TrimSpace(scheme) + deepLinkURL[idx:]
}

// acceptIOSDevClientOpenDialog dismisses the iOS "Open in <App>?" deep-link
// confirmation by tapping "Open" via a one-shot Maestro flow. It is non-fatal
// and the tap is optional: when no dialog is present (e.g. the `expo run:ios`
// open path already foregrounded the app) it is a harmless no-op, so this never
// regresses apps that launch cleanly.
func acceptIOSDevClientOpenDialog(logFile *os.File, udid string) {
	maestroPath, err := exec.LookPath("maestro")
	if err != nil {
		fmt.Fprintf(logFile, "skip dev-client open-dialog accept: maestro not on PATH: %v\n", err)
		return
	}
	flow, err := os.CreateTemp("", "pf-accept-open-*.yaml")
	if err != nil {
		fmt.Fprintf(logFile, "skip dev-client open-dialog accept: temp flow: %v\n", err)
		return
	}
	flowPath := flow.Name()
	defer os.Remove(flowPath)
	const flowBody = "appId: com.apple.springboard\n---\n- tapOn:\n    text: \"Open\"\n    optional: true\n"
	if _, err := flow.WriteString(flowBody); err != nil {
		_ = flow.Close()
		fmt.Fprintf(logFile, "skip dev-client open-dialog accept: write flow: %v\n", err)
		return
	}
	_ = flow.Close()
	command := exec.Command(maestroPath, "--device", udid, "--platform", "ios", "test", flowPath)
	command.Env = maestroCommandEnv(os.Environ())
	flush := attachRedactedCommandLog(command, logFile)
	if err := runCommandWithTimeoutAndCancellation(command, 2*time.Minute, nil, runnerPollInterval()); err != nil {
		fmt.Fprintf(logFile, "dev-client open-dialog accept tap reported: %v (continuing)\n", err)
	}
	flush()
}

func androidDeepLinkOpenArgs(providerIdentity string, androidPackage string, deepLinkURL string) []string {
	args := []string{
		"-s",
		providerIdentity,
		"shell",
		"am",
		"start",
		"-a",
		"android.intent.action.VIEW",
		"-d",
		deepLinkURL,
	}
	if strings.TrimSpace(androidPackage) != "" {
		args = append(args, "-p", strings.TrimSpace(androidPackage))
	}
	return args
}

func simulatorDeepLinkURL(job apiRunnerJob, port int) string {
	if strings.TrimSpace(job.Payload.DevSession.DeepLinkURL) != "" {
		return strings.TrimSpace(job.Payload.DevSession.DeepLinkURL)
	}
	advertisedURL := strings.TrimSpace(job.Payload.DevSession.AdvertisedURL)
	if advertisedURL == "" {
		advertisedURL = strings.TrimSpace(job.Payload.DevSession.URL)
	}
	if advertisedURL == "" && port > 0 {
		if isAndroidEmulatorJob(job) {
			advertisedURL = androidEmulatorDevServerURL(port)
		} else {
			advertisedURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		}
	}
	if advertisedURL == "" {
		return ""
	}
	return developmentDeepLinkURL(job.Payload.SourceBinding, advertisedURL)
}

func runLoggedXcrunCommand(logFile *os.File, options runnerOnceOptions, args ...string) error {
	return runLoggedXcrunCommandWithCancellation(logFile, options, nil, args...)
}

func runLoggedXcrunCommandWithCancellation(logFile *os.File, options runnerOnceOptions, cancellationCheck func() (bool, error), args ...string) error {
	_, _ = fmt.Fprintf(logFile, "$ %s %s\n", options.xcrunPath, strings.Join(args, " "))
	command := exec.Command(options.xcrunPath, args...)
	flushLog := attachRedactedCommandLog(command, logFile)
	err := runCommandWithTimeoutAndCancellation(command, androidDevelopmentOpenTimeout(), cancellationCheck, runnerPollInterval())
	flushLog()
	return err
}

func runOptionalLoggedXcrunCommand(logFile *os.File, options runnerOnceOptions, args ...string) {
	_, _ = fmt.Fprintf(logFile, "$ %s %s\n", options.xcrunPath, strings.Join(args, " "))
	command := exec.Command(options.xcrunPath, args...)
	flushLog := attachRedactedCommandLog(command, logFile)
	err := runCommandWithTimeout(command, androidDevelopmentOpenTimeout())
	flushLog()
	if err != nil {
		_, _ = fmt.Fprintf(logFile, "optional xcrun command failed: %v\n", err)
	}
}

func expoCommandEnv(job apiRunnerJob) []string {
	env := append([]string{}, os.Environ()...)
	env = upsertEnv(env, "EXPO_NO_INTERACTIVE", "1")
	if expoDevelopmentVariant(job) {
		env = upsertEnv(env, "APP_VARIANT", "development")
	}
	return env
}

func expoDevelopmentVariant(job apiRunnerJob) bool {
	lane := strings.TrimSpace(job.Payload.Lane)
	if lane == "simulator" || lane == "development" {
		return true
	}
	profile := strings.TrimSpace(job.Payload.EASProfileName)
	if profile == "" {
		profile = strings.TrimSpace(job.Payload.SourceBinding.EASProfileName)
	}
	if profile == "development" || profile == "development-device" {
		return true
	}
	return strings.Contains(job.Payload.SourceBinding.AndroidPackage, ".dev") ||
		strings.Contains(job.Payload.SourceBinding.IOSBundleID, ".dev")
}

func upsertEnv(env []string, key string, value string) []string {
	prefix := key + "="
	for index, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func flowPathForJob(options runnerOnceOptions, job apiRunnerJob) string {
	flowPath := job.Payload.FlowPath
	if flowPath == "" {
		flowPath = filepath.Join(job.Payload.SourceBinding.PackagePath, ".maestro", "01-app-launches.yaml")
	}
	if filepath.IsAbs(flowPath) {
		return flowPath
	}
	root := job.Payload.SourceBinding.WorkspaceRoot
	if root == "" {
		root = options.workspaceRoot
	}
	return filepath.Join(root, flowPath)
}

type maestroRunArtifacts struct {
	OutputDir       string
	DebugOutputDir  string
	ReportPath      string
	LogPath         string
	DebugLogPath    string
	CommandPaths    []string
	ScreenshotPaths []string
	VideoPaths      []string
}

func runMaestroSmoke(
	options runnerOnceOptions,
	job apiRunnerJob,
	providerIdentity string,
	flowPath string,
	cancellationChecks ...func() (bool, error),
) (maestroRunArtifacts, error) {
	root := job.Payload.SourceBinding.WorkspaceRoot
	if root == "" {
		root = options.workspaceRoot
	}
	relativeRunDir := filepath.Join(".preflight", "maestro", job.ID)
	relativeOutputDir := filepath.Join(relativeRunDir, "runtime-artifacts")
	relativeReportPath := filepath.Join(relativeRunDir, "junit.xml")
	runDir := filepath.Join(root, relativeRunDir)
	outputDir := filepath.Join(root, relativeOutputDir)
	reportPath := filepath.Join(root, relativeReportPath)
	artifacts := maestroRunArtifacts{
		OutputDir:      outputDir,
		DebugOutputDir: outputDir,
		ReportPath:     reportPath,
		LogPath:        filepath.Join(runDir, "maestro-run.log"),
		DebugLogPath:   filepath.Join(outputDir, "maestro.log"),
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return maestroRunArtifacts{}, fmt.Errorf("create Maestro output directory: %w", err)
	}
	logFile, err := os.OpenFile(artifacts.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return maestroRunArtifacts{}, fmt.Errorf("open Maestro run log: %w", err)
	}
	defer logFile.Close()

	command := exec.Command(
		"maestro",
		"--platform",
		jobPlatform(job),
		"--device",
		providerIdentity,
		"test",
		"--test-output-dir="+relativeOutputDir,
		"--debug-output="+relativeOutputDir,
		"--format",
		"junit",
		"--output",
		relativeReportPath,
	)
	command.Args = append(command.Args, maestroDevSessionEnvArgs(job)...)
	// Select a tier (e.g. smoke / full) when the job requests one.
	var tags []string
	for _, t := range job.Payload.IncludeTags {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	if len(tags) > 0 {
		command.Args = append(command.Args, "--include-tags", strings.Join(tags, ","))
	}
	command.Args = append(command.Args, flowPath)
	command.Dir = root
	command.Env = maestroCommandEnv(os.Environ())
	flushLog := attachRedactedCommandLog(command, logFile)
	var cancellationCheck func() (bool, error)
	if len(cancellationChecks) > 0 {
		cancellationCheck = cancellationChecks[0]
	}
	err = runCommandWithTimeoutAndCancellation(
		command,
		maestroSmokeTimeout(),
		cancellationCheck,
		runnerPollInterval(),
	)
	flushLog()
	if err != nil {
		artifacts.CommandPaths = findFilesWithPrefixAndExtension(outputDir, "commands-", ".json")
		artifacts.ScreenshotPaths = findFilesWithExtensions(outputDir, ".png")
		artifacts.VideoPaths = findFilesWithExtensions(outputDir, ".mp4", ".mov")
		return artifacts, fmt.Errorf("run Maestro smoke flow: %w", err)
	}
	artifacts.CommandPaths = findFilesWithPrefixAndExtension(outputDir, "commands-", ".json")
	artifacts.ScreenshotPaths = findFilesWithExtensions(outputDir, ".png")
	artifacts.VideoPaths = findFilesWithExtensions(outputDir, ".mp4", ".mov")
	return artifacts, nil
}

func maestroDevSessionEnvArgs(job apiRunnerJob) []string {
	values := map[string]string{
		"FG_DEV_CLIENT_URL":       preferredDevSessionURL(job.Payload.DevSession),
		"FG_DEV_CLIENT_DEEP_LINK": strings.TrimSpace(job.Payload.DevSession.DeepLinkURL),
		"FG_DEV_CLIENT_QR_URL":    strings.TrimSpace(job.Payload.DevSession.QRURL),
	}
	args := make([]string, 0, len(values)*2)
	for _, key := range []string{
		"FG_DEV_CLIENT_URL",
		"FG_DEV_CLIENT_DEEP_LINK",
		"FG_DEV_CLIENT_QR_URL",
	} {
		value := values[key]
		if value == "" {
			continue
		}
		args = append(args, "-e", key+"="+value)
	}
	return args
}

func preferredDevSessionURL(devSession runnerJobDevSession) string {
	if value := strings.TrimSpace(devSession.AdvertisedURL); value != "" {
		return value
	}
	return strings.TrimSpace(devSession.URL)
}

func maestroCommandEnv(base []string) []string {
	env := append([]string{}, base...)
	return upsertEnvValues(env, map[string]string{
		"MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED": "true",
		"MAESTRO_CLI_NO_ANALYTICS":                   "true",
		"MAESTRO_DISABLE_UPDATE_CHECK":               "true",
	})
}

func upsertEnvValues(base []string, values map[string]string) []string {
	pending := make(map[string]string, len(values))
	for key, value := range values {
		pending[key] = value
	}
	for index, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		value, shouldSet := pending[key]
		if !shouldSet {
			continue
		}
		base[index] = key + "=" + value
		delete(pending, key)
	}
	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		base = append(base, key+"="+pending[key])
	}
	return base
}

func maestroSmokeTimeout() time.Duration {
	configured := strings.TrimSpace(os.Getenv("PREFLIGHT_MAESTRO_TIMEOUT"))
	if configured == "" {
		return defaultMaestroSmokeTimeout
	}
	timeout, err := time.ParseDuration(configured)
	if err != nil || timeout <= 0 {
		return defaultMaestroSmokeTimeout
	}
	return timeout
}

func easReadinessTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_EAS_READINESS_TIMEOUT", defaultEASReadinessTimeout)
}

func easBuildTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_EAS_BUILD_TIMEOUT", defaultEASBuildTimeout)
}

func expoConfigTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_EXPO_CONFIG_TIMEOUT", defaultExpoConfigTimeout)
}

func expoDevSessionStartTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_EXPO_START_TIMEOUT", defaultExpoDevSessionStartTimeout)
}

func androidDevelopmentOpenTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_ANDROID_OPEN_TIMEOUT", defaultAndroidDevelopmentOpenTimeout)
}

func simulatorOpenTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_SIMULATOR_OPEN_TIMEOUT", defaultSimulatorOpenTimeout)
}

func runnerPollInterval() time.Duration {
	return durationFromEnv("PREFLIGHT_RUNNER_POLL_INTERVAL", defaultRunnerPollInterval)
}

func runnerLivenessHeartbeatInterval() time.Duration {
	return durationFromEnv(
		"PREFLIGHT_RUNNER_LIVENESS_INTERVAL",
		defaultRunnerLivenessHeartbeatInterval,
	)
}

func runnerJobHeartbeatInterval() time.Duration {
	return durationFromEnv(
		"PREFLIGHT_RUNNER_JOB_HEARTBEAT_INTERVAL",
		defaultRunnerJobHeartbeatInterval,
	)
}

// startJobHeartbeat keeps the JOB lease fresh for the lifetime of a long-running
// handler (build, dev-session, simulator boot, maestro). The runner-row
// heartbeat (see runOnce) keeps the runner alive, but the job lease is otherwise
// only renewed as a side effect of cancellation polls — so a multi-minute step
// can outlive it and the server rejects the next write with HTTP 409
// (runner_job_not_running). Call as `defer startJobHeartbeat(...)()` at the top
// of the handler: it starts the ticker goroutine now and returns the stop func.
func startJobHeartbeat(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
) func() {
	if !runnerJobHeartbeatEnabled(registration) {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(runnerJobHeartbeatInterval())
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _ = heartbeatRunnerJob(client, options, registration, job)
			}
		}
	}()
	return func() { close(stop) }
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	configured := strings.TrimSpace(os.Getenv(name))
	if configured == "" {
		return fallback
	}
	duration, err := time.ParseDuration(configured)
	if err != nil || duration <= 0 {
		return fallback
	}
	return duration
}

func runCommandWithTimeout(command *exec.Cmd, timeout time.Duration) error {
	return runCommandWithTimeoutAndCancellation(command, timeout, nil, 0)
}

func runCommandWithTimeoutAndCancellation(
	command *exec.Cmd,
	timeout time.Duration,
	cancellationCheck func() (bool, error),
	pollInterval time.Duration,
) error {
	if timeout <= 0 {
		return command.Run()
	}
	if pollInterval <= 0 {
		pollInterval = defaultRunnerPollInterval
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var ticker *time.Ticker
	var tick <-chan time.Time
	if cancellationCheck != nil {
		ticker = time.NewTicker(pollInterval)
		defer ticker.Stop()
		tick = ticker.C
	}
	for {
		select {
		case err := <-done:
			return err
		case <-tick:
			cancelled, err := cancellationCheck()
			if err != nil {
				return err
			}
			if cancelled {
				terminateCommandProcess(command.Process.Pid)
				<-done
				return errCommandCancelled
			}
		case <-timer.C:
			terminateCommandProcess(command.Process.Pid)
			return fmt.Errorf("command timed out after %s", timeout)
		}
	}
}

func terminateCommandProcess(pid int) {
	signalCommandProcessGroup(pid, syscall.SIGTERM)
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		signalCommandProcessGroup(pid, syscall.SIGKILL)
	}
}

func signalCommandProcessGroup(pid int, signal syscall.Signal) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, signal); err != nil {
		_ = syscall.Kill(pid, signal)
	}
}

func findFilesWithExtensions(root string, extensions ...string) []string {
	wanted := map[string]bool{}
	for _, extension := range extensions {
		wanted[strings.ToLower(extension)] = true
	}
	var matches []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if wanted[strings.ToLower(filepath.Ext(path))] {
			matches = append(matches, path)
		}
		return nil
	})
	sort.Strings(matches)
	return matches
}

func findFilesWithPrefixAndExtension(root string, prefix string, extension string) []string {
	var matches []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.HasPrefix(name, prefix) && strings.EqualFold(filepath.Ext(name), extension) {
			matches = append(matches, path)
		}
		return nil
	})
	sort.Strings(matches)
	return matches
}

type devSessionResultInput struct {
	status           string
	localURL         string
	advertisedURL    string
	statusURL        string
	hostMode         string
	port             int
	appDir           string
	targetID         string
	providerIdentity string
	sourceBinding    runnerJobSourceBinding
	devBuild         map[string]any
	development      bool
}

func devSessionResultPayload(input devSessionResultInput) map[string]any {
	payload := map[string]any{
		"status":        input.status,
		"url":           input.localURL,
		"advertisedUrl": input.advertisedURL,
		"statusUrl":     input.statusURL,
		"hostMode":      input.hostMode,
		"health": map[string]any{
			"metroStatus":    devSessionMetroStatus(input.status),
			"localStatusUrl": input.statusURL,
		},
		"warnings": devSessionWarnings(input.hostMode),
		"port":     input.port,
		"appDir":   input.appDir,
	}
	if hostIP := devSessionHostIP(input.advertisedURL); hostIP != "" {
		payload["hostIp"] = hostIP
	}
	if input.hostMode == "tunnel" {
		payload["tunnelProvider"] = "expo-cli-ngrok"
	}
	if input.hostMode == "tailscale" {
		payload["tunnelProvider"] = "tailscale"
	}
	if input.targetID != "" {
		payload["targetId"] = input.targetID
	}
	if input.providerIdentity != "" {
		payload["providerIdentity"] = input.providerIdentity
	}
	if input.advertisedURL != "" && devSessionReady(input.status) {
		deepLinkURL := developmentDeepLinkURL(input.sourceBinding, input.advertisedURL)
		payload["deepLinkUrl"] = deepLinkURL
		payload["qrUrl"] = developmentQRURL(input.sourceBinding, input.advertisedURL)
	}
	if input.development {
		payload["installUrl"] = readMapString(input.devBuild, "installUrl")
	}
	return payload
}

func devSessionReady(status string) bool {
	return status == "started" || status == "reused"
}

func devSessionMetroStatus(status string) string {
	if devSessionReady(status) {
		return "running"
	}
	return "unknown"
}

func devSessionWarnings(hostMode string) []string {
	if hostMode == "tunnel" {
		return []string{"expo_tunnel_routes_through_external_infrastructure"}
	}
	return []string{}
}

func devSessionHostIP(advertisedURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(advertisedURL))
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

func isDevelopmentDevSessionJob(job apiRunnerJob) bool {
	return job.Payload.Lane == "development" || len(job.Payload.DevBuild) > 0
}

func advertisedDevServerURL(options runnerOnceOptions, job apiRunnerJob) (string, error) {
	if isDevelopmentDevSessionJob(job) && options.hostMode == "lan" {
		host, err := lanHost()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("http://%s:%d", host, options.metroPort), nil
	}
	// Tailscale mode: Metro runs exactly like lan, but the advertised URL is
	// the runner's tailnet address so a phone on the tailnet reaches it
	// directly — no ngrok, no manifest scrape.
	if isDevelopmentDevSessionJob(job) && options.hostMode == "tailscale" {
		host, err := tailscaleHost()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("http://%s:%d", host, options.metroPort), nil
	}
	if options.hostMode == "localhost" {
		return runnerLocalDevServerURL(options), nil
	}
	if isAndroidEmulatorJob(job) {
		return androidEmulatorDevServerURL(options.metroPort), nil
	}
	return fmt.Sprintf("http://127.0.0.1:%d", options.metroPort), nil
}

func runnerLocalDevServerURL(options runnerOnceOptions) string {
	if options.hostMode == "localhost" {
		return fmt.Sprintf("http://localhost:%d", options.metroPort)
	}
	return fmt.Sprintf("http://127.0.0.1:%d", options.metroPort)
}

func isAndroidEmulatorJob(job apiRunnerJob) bool {
	return jobPlatform(job) == "android" && !isDevelopmentDevSessionJob(job)
}

func androidEmulatorDevServerURL(port int) string {
	return fmt.Sprintf("http://10.0.2.2:%d", port)
}

// localPortIsFree reports whether a TCP port can be bound on loopback.
func localPortIsFree(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// nextFreeLocalPort returns the first free TCP port in [start, start+span), or 0.
func nextFreeLocalPort(start int, span int) int {
	for port := start; port < start+span && port < 65536; port++ {
		if localPortIsFree(port) {
			return port
		}
	}
	return 0
}

func lanHost() (string, error) {
	if override := strings.TrimSpace(os.Getenv("PREFLIGHT_LAN_HOST")); override != "" {
		return override, nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("discover LAN host address: %w", err)
	}
	for _, address := range addresses {
		ipNet, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() {
			continue
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("could not determine a LAN host address; set PREFLIGHT_LAN_HOST or use --host-mode tunnel")
}

// expoHostArg maps the runner host mode to the value passed to
// `expo start --host`. Expo only understands lan/localhost/tunnel; tailscale
// mode starts Metro exactly like lan and differs only in the advertised URL.
func expoHostArg(hostMode string) string {
	if hostMode == "tailscale" {
		return "lan"
	}
	return hostMode
}

func tailscaleHost() (string, error) {
	if override := strings.TrimSpace(os.Getenv("PREFLIGHT_TAILSCALE_HOST")); override != "" {
		return override, nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("discover Tailscale host address: %w", err)
	}
	if host, ok := tailscaleHostFromAddrs(addresses); ok {
		return host, nil
	}
	return "", fmt.Errorf("no Tailscale (100.64.0.0/10) interface address found; is Tailscale up? Set PREFLIGHT_TAILSCALE_HOST to override")
}

// Tailscale assigns every node an IPv4 address in the CGNAT range
// 100.64.0.0/10, so the tailnet address is discoverable from interfaces
// without shelling out to the tailscale CLI.
var tailscaleCGNAT = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func tailscaleHostFromAddrs(addresses []net.Addr) (string, bool) {
	for _, address := range addresses {
		ipNet, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || !tailscaleCGNAT.Contains(ip) {
			continue
		}
		return ip.String(), true
	}
	return "", false
}

func developmentDeepLinkURL(sourceBinding runnerJobSourceBinding, advertisedURL string) string {
	scheme := appSchemeForDevelopmentClient(sourceBinding)
	return fmt.Sprintf("%s://expo-development-client/?url=%s", scheme, url.QueryEscape(advertisedURL))
}

func developmentQRURL(sourceBinding runnerJobSourceBinding, advertisedURL string) string {
	scheme := appSchemeForDevelopmentClient(sourceBinding)
	return fmt.Sprintf(
		"https://qr.expo.dev/development-client?appScheme=%s&url=%s",
		url.QueryEscape(scheme),
		url.QueryEscape(advertisedURL),
	)
}

func appSchemeForDevelopmentClient(sourceBinding runnerJobSourceBinding) string {
	if strings.TrimSpace(sourceBinding.AppScheme) != "" {
		return strings.TrimSpace(sourceBinding.AppScheme)
	}
	if strings.TrimSpace(sourceBinding.ExpoSlug) != "" {
		return "exp+" + strings.TrimSpace(sourceBinding.ExpoSlug)
	}
	return "exp"
}

func probeEASDevelopmentReadiness(appDir string, sourceBinding runnerJobSourceBinding, profileName string, targetClass string, platform string) (map[string]any, map[string]any) {
	return probeEASDevelopmentReadinessWithEnv(appDir, sourceBinding, profileName, targetClass, platform, nil)
}

func probeEASDevelopmentReadinessWithEnv(appDir string, sourceBinding runnerJobSourceBinding, profileName string, targetClass string, platform string, env map[string]string) (map[string]any, map[string]any) {
	platform = normalizeEASPlatform(platform)
	pkg, err := readPackageJSON(filepath.Join(appDir, "package.json"))
	if err != nil {
		return nil, setupRequired(
			"expo_app_unreadable",
			"Preflight could not read the Expo app package.json.",
			"verify package.json",
		)
	}
	if !hasDependency(pkg, "expo-dev-client") {
		return nil, setupRequired(
			"expo_dev_client_missing",
			"Install expo-dev-client before creating EAS development builds.",
			"npx expo install expo-dev-client",
		)
	}

	easConfig, err := loadEASJSON(appDir)
	if err != nil {
		return nil, setupRequired(
			"eas_json_missing",
			"Run EAS build configuration with the human present before Preflight can build.",
			fmt.Sprintf("npx eas-cli build:configure --platform %s", platform),
		)
	}
	profile, ok := easConfig.Build[profileName]
	if !ok {
		return nil, setupRequired(
			"eas_profile_missing",
			fmt.Sprintf("Add an EAS build profile named %q for the %s Development lane.", profileName, developmentPlatformLabel(platform)),
			"edit eas.json",
		)
	}
	if !easProfileDevelopmentClient(profile) {
		return nil, setupRequired(
			"eas_profile_not_dev_client",
			fmt.Sprintf("EAS profile %q must set developmentClient to true.", profileName),
			"edit eas.json",
		)
	}
	if profile.Distribution != "" && profile.Distribution != "internal" {
		return nil, setupRequired(
			"eas_profile_distribution_not_internal",
			fmt.Sprintf("EAS profile %q must use internal distribution for development builds.", profileName),
			"edit eas.json",
		)
	}
	if platform == "ios" && targetClass == "device" && profile.IOS.Simulator != nil && *profile.IOS.Simulator {
		return nil, setupRequired(
			"eas_profile_targets_simulator",
			fmt.Sprintf("EAS profile %q builds for iOS Simulator, not physical iPhone devices.", profileName),
			"add development-device profile to eas.json",
		)
	}

	account, err := runEASCommandWithEnv(appDir, env, "whoami")
	if err != nil {
		return nil, setupRequired(
			"expo_token_auth_failed",
			"Create or rotate Preflight's Expo API token; EAS rejected EXPO_TOKEN.",
			"preflight credentials create --provider expo --purpose api_token --key EXPO_TOKEN --lane development --value-env EXPO_TOKEN",
		)
	}
	buildListOutput, err := runEASCommandWithEnv(
		appDir,
		env,
		easBuildListArgs(platform, profileName, targetClass)...,
	)
	if err != nil {
		return nil, setupRequired(
			"eas_project_setup_required",
			"Run EAS build setup with the human present so Preflight can use non-interactive builds.",
			fmt.Sprintf("npx eas-cli build:configure --platform %s", platform),
		)
	}

	readiness := map[string]any{
		"ready":               true,
		"account":             strings.TrimSpace(string(account)),
		"platform":            platform,
		"easProfileName":      profileName,
		"easProfileEnvDigest": digestJSON(easProfileEnv(profile, platform)),
		"easJsonDigest":       sourceBinding.EASJSONDigest,
		"developmentClient":   easProfileDevelopmentClient(profile),
		"distribution":        profile.Distribution,
		"targetClass":         normalizeTargetClass(targetClass),
		"nonInteractive":      true,
	}
	if platform == "ios" {
		readiness["iosSimulator"] = profile.IOS.Simulator != nil && *profile.IOS.Simulator
	} else {
		readiness["androidArtifact"] = "apk"
	}
	if devBuild, ok := reusableDevBuildFromEASBuildList(buildListOutput, profileName, targetClass); ok {
		readiness["devBuild"] = devBuild
	}
	return readiness, nil
}

func easBuildListArgs(platform string, profileName string, targetClass string) []string {
	args := []string{
		"build:list",
		"--platform",
		platform,
		"--build-profile",
		profileName,
		"--status",
		"finished",
	}
	if platform == "ios" && normalizeTargetClass(targetClass) == "simulator" {
		args = append(args, "--simulator")
	} else {
		args = append(args, "--distribution", "internal")
	}
	return append(args, "--limit", "1", "--json", "--non-interactive")
}

func reusableDevBuildFromEASBuildList(output []byte, profileName string, targetClass string) (map[string]any, bool) {
	devBuild, err := parseEASBuildOutput(output, profileName)
	if err != nil {
		return nil, false
	}
	if readMapString(devBuild, "installUrl") == "" {
		return nil, false
	}
	if easBuildArtifactExpired(readMapString(devBuild, "expirationDate")) {
		return nil, false
	}
	devBuild["targetClass"] = normalizeTargetClass(targetClass)
	devBuild["reused"] = true
	return devBuild, true
}

func easBuildArtifactExpired(expirationDate string) bool {
	if strings.TrimSpace(expirationDate) == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, expirationDate)
	if err != nil {
		return true
	}
	return !expiresAt.After(time.Now())
}

func normalizeEASPlatform(platform string) string {
	if platform == "android" {
		return "android"
	}
	return "ios"
}

func developmentPlatformLabel(platform string) string {
	if platform == "android" {
		return "Android"
	}
	return "iOS"
}

func runEASCommand(appDir string, args ...string) ([]byte, error) {
	return runEASCommandWithEnv(appDir, nil, args...)
}

func runEASCommandWithEnv(appDir string, env map[string]string, args ...string) ([]byte, error) {
	return runEASCommandWithTimeoutAndCancellation(
		appDir,
		easReadinessTimeout(),
		nil,
		env,
		args...,
	)
}

func runEASCommandWithTimeoutAndCancellation(
	appDir string,
	timeout time.Duration,
	cancellationCheck func() (bool, error),
	env map[string]string,
	args ...string,
) ([]byte, error) {
	executable, commandArgs := easCommand(args...)
	command := exec.Command(executable, commandArgs...)
	command.Dir = appDir
	command.Env = easCommandEnv(os.Environ(), env)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := runCommandWithTimeoutAndCancellation(
		command,
		timeout,
		cancellationCheck,
		runnerPollInterval(),
	)
	if err != nil {
		return output.Bytes(), fmt.Errorf("%s %s failed: %w: %s", filepath.Base(executable), strings.Join(commandArgs, " "), err, redactCommandOutput(strings.TrimSpace(output.String()), env))
	}
	return output.Bytes(), nil
}

func easCommandEnv(base []string, env map[string]string) []string {
	values := map[string]string{
		"CI":                  "1",
		"EXPO_NO_INTERACTIVE": "1",
	}
	for key, value := range env {
		values[key] = value
	}
	return upsertEnvValues(base, values)
}

func redactCommandOutput(output string, env map[string]string) string {
	redacted := redactSetupTranscriptText(output)
	for _, value := range env {
		if len(value) < 4 {
			continue
		}
		redacted = strings.ReplaceAll(redacted, value, "[REDACTED]")
	}
	return redacted
}

func easCommand(args ...string) (string, []string) {
	if configured := strings.TrimSpace(os.Getenv("PREFLIGHT_EAS_COMMAND")); configured != "" {
		return configured, args
	}
	if easPath, err := exec.LookPath("eas"); err == nil {
		return easPath, args
	}
	return "npx", append([]string{"eas-cli"}, args...)
}

func parseEASBuildOutput(output []byte, profileName string) (map[string]any, error) {
	var decoded any
	if err := decodeEASJSONOutput(output, &decoded); err != nil {
		return nil, fmt.Errorf("decode EAS build JSON output: %w", err)
	}

	record, ok := decoded.(map[string]any)
	if !ok {
		if builds, buildsOK := decoded.([]any); buildsOK && len(builds) > 0 {
			record, ok = builds[0].(map[string]any)
		}
	}
	if !ok {
		return nil, fmt.Errorf("EAS build output did not contain a build object")
	}

	buildID := readMapString(record, "id")
	if buildID == "" {
		return nil, fmt.Errorf("EAS build output did not include a build id")
	}
	artifacts, _ := record["artifacts"].(map[string]any)
	installURL := readMapString(artifacts, "buildUrl")
	if installURL == "" {
		installURL = readMapString(record, "installUrl")
	}

	return map[string]any{
		"buildId":        buildID,
		"profile":        profileName,
		"platform":       readMapString(record, "platform"),
		"status":         readMapString(record, "status"),
		"installUrl":     installURL,
		"buildPageUrl":   readMapString(record, "url"),
		"expirationDate": readMapString(record, "expirationDate"),
	}, nil
}

func decodeEASJSONOutput(output []byte, target any) error {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return io.EOF
	}
	if err := json.Unmarshal(trimmed, target); err == nil {
		return nil
	}
	var lastErr error
	for index, char := range trimmed {
		if char != '{' && char != '[' {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(trimmed[index:]))
		if err := decoder.Decode(target); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("EAS output did not include JSON")
}

func loadSimctlInventory(options runnerOnceOptions) (json.RawMessage, error) {
	var content []byte
	var err error
	if options.simctlJSON != "" {
		content, err = os.ReadFile(options.simctlJSON)
		if err != nil {
			return nil, fmt.Errorf("read simctl inventory fixture: %w", err)
		}
	} else {
		content, err = exec.Command(options.xcrunPath, "simctl", "list", "devices", "--json").Output()
		if err != nil {
			return nil, fmt.Errorf("run xcrun simctl list devices --json: %w", err)
		}
	}

	if !json.Valid(content) {
		return nil, fmt.Errorf("simctl inventory is not valid JSON")
	}
	// Multi-runner-per-host: when pinned to a specific simulator, report ONLY
	// that device so the control plane locks this runner to its own sim and two
	// runners never contend for the same simulator.
	if udid := strings.TrimSpace(options.simulatorUDID); udid != "" {
		if filtered, err := filterSimctlInventoryToUDID(content, udid); err == nil {
			return filtered, nil
		}
	}
	return json.RawMessage(content), nil
}

// filterSimctlInventoryToUDID returns a simctl `list devices --json` payload
// containing only the device whose udid matches, preserving the {"devices":
// {"<runtime>": [...]}} shape (empty runtimes dropped).
func filterSimctlInventoryToUDID(content []byte, udid string) (json.RawMessage, error) {
	var parsed struct {
		Devices map[string][]map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil {
		return nil, err
	}
	out := map[string][]map[string]any{}
	for runtime, devices := range parsed.Devices {
		for _, d := range devices {
			if s, _ := d["udid"].(string); strings.EqualFold(strings.TrimSpace(s), udid) {
				out[runtime] = append(out[runtime], d)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pinned simulator udid %q not found in inventory", udid)
	}
	marshaled, err := json.Marshal(map[string]any{"devices": out})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(marshaled), nil
}

func loadADBDevices(options runnerOnceOptions) ([]byte, error) {
	content, err := exec.Command(options.adbPath, "devices", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("run adb devices -l: %w", err)
	}
	return content, nil
}

func firstAvailableTarget(targets []apiTarget) *apiTarget {
	for index := range targets {
		if targets[index].Availability == "available" && strings.Contains(strings.ToLower(targets[index].DisplayName), "iphone") {
			return &targets[index]
		}
	}
	for index := range targets {
		if targets[index].Availability == "available" {
			return &targets[index]
		}
	}
	return nil
}

func runnerLeaseOwner(options runnerOnceOptions) string {
	return "preflight-cli:" + options.hostIdentity
}

func runnerEndpoint(apiURL string, path string) string {
	return strings.TrimRight(apiURL, "/") + path
}

func getPreflightJSON(client *http.Client, endpoint string, token string) (json.RawMessage, error) {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build Preflight request: %w", err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	return doPreflightJSON(client, request)
}

func getPreflightWorkspaceJSON(client *http.Client, endpoint string, token string, workspaceID string) (json.RawMessage, error) {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build Preflight request: %w", err)
	}
	addPreflightAuthHeaders(request, token, workspaceID)

	return doPreflightJSON(client, request)
}

func postPreflightJSON(client *http.Client, endpoint string, token string, payload any) (json.RawMessage, error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Preflight request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("build Preflight request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	return doPreflightJSON(client, request)
}

func postPreflightWorkspaceJSON(client *http.Client, endpoint string, token string, workspaceID string, payload any) (json.RawMessage, error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Preflight request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("build Preflight request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	addPreflightAuthHeaders(request, token, workspaceID)

	return doPreflightJSON(client, request)
}

func addPreflightAuthHeaders(request *http.Request, token string, workspaceID string) {
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if workspaceID != "" {
		request.Header.Set("x-preflight-workspace-id", workspaceID)
	}
	request.Header.Set("x-preflight-user-id", "preflight-cli")
}

func doPreflightJSON(client *http.Client, request *http.Request) (json.RawMessage, error) {
	// Retry transient failures (network/transport errors and 5xx) so a brief
	// control-plane blip doesn't abort a whole `runner once` sequence and orphan
	// an in-flight build. 4xx (auth, validation, conflict) returns immediately.
	// Control-plane writes are idempotent (upserts / terminal-state guards), so
	// re-sending is safe. The request body is rewound via GetBody (set by
	// http.NewRequest for bytes.Reader bodies).
	const maxAttempts = 4
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			if request.GetBody != nil {
				body, err := request.GetBody()
				if err != nil {
					return nil, lastErr
				}
				request.Body = body
			}
			time.Sleep(preflightRequestRetryBackoff(attempt))
		}
		data, status, err := doPreflightJSONOnce(client, request)
		if err == nil {
			return data, nil
		}
		lastErr = err
		retryable := status == 0 || (status >= 500 && status <= 599)
		if !retryable || attempt == maxAttempts {
			return nil, err
		}
	}
	return nil, lastErr
}

func preflightRequestRetryBackoff(attempt int) time.Duration {
	delay := 500 * time.Millisecond * (1 << (attempt - 2))
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	return delay
}

func preflightRequestTimeout() time.Duration {
	return durationFromEnv("PREFLIGHT_API_REQUEST_TIMEOUT", 20*time.Second)
}

// doPreflightJSONOnce performs a single request attempt and returns the response
// status code alongside the decoded data so the caller can decide retryability.
func doPreflightJSONOnce(
	client *http.Client,
	request *http.Request,
) (json.RawMessage, int, error) {
	ctx, cancel := context.WithTimeout(request.Context(), preflightRequestTimeout())
	defer cancel()
	request = request.Clone(ctx)
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("read Preflight response: %w", err)
	}

	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, response.StatusCode, fmt.Errorf("decode Preflight response envelope: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if envelope.Error != nil {
			return nil, response.StatusCode, fmt.Errorf("Preflight API returned HTTP %d (%s): %s", response.StatusCode, envelope.Error.Code, envelope.Error.Message)
		}
		return nil, response.StatusCode, fmt.Errorf("Preflight API returned HTTP %d", response.StatusCode)
	}
	if envelope.Error != nil {
		return nil, response.StatusCode, fmt.Errorf("Preflight API error (%s): %s", envelope.Error.Code, envelope.Error.Message)
	}
	return envelope.Data, response.StatusCode, nil
}

func decodeEnvelopeData(data json.RawMessage, output any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("response data was empty")
	}
	return json.Unmarshal(trimmed, output)
}

type preflightCLIConfig struct {
	APIVersion        string            `json:"apiVersion,omitempty"`
	APIURL            string            `json:"apiUrl,omitempty"`
	Token             string            `json:"token,omitempty"`
	WorkspaceID       string            `json:"workspaceId,omitempty"`
	WorkspaceBindings map[string]string `json:"workspaceBindings,omitempty"`
}

func loadPreflightCLIConfig() (preflightCLIConfig, error) {
	path, err := preflightCLIConfigPath()
	if err != nil {
		return preflightCLIConfig{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return preflightCLIConfig{
				APIVersion:        "v1",
				WorkspaceBindings: map[string]string{},
			}, nil
		}
		return preflightCLIConfig{}, err
	}
	var config preflightCLIConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return preflightCLIConfig{}, err
	}
	if config.APIVersion == "" {
		config.APIVersion = "v1"
	}
	if config.WorkspaceBindings == nil {
		config.WorkspaceBindings = map[string]string{}
	}
	return config, nil
}

func savePreflightCLIConfig(config preflightCLIConfig) error {
	path, err := preflightCLIConfigPath()
	if err != nil {
		return err
	}
	if config.APIVersion == "" {
		config.APIVersion = "v1"
	}
	if config.WorkspaceBindings == nil {
		config.WorkspaceBindings = map[string]string{}
	}
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func preflightCLIConfigPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv("PREFLIGHT_CONFIG_PATH")); path != "" {
		return path, nil
	}
	if home := strings.TrimSpace(os.Getenv("PREFLIGHT_CONFIG_HOME")); home != "" {
		return filepath.Join(home, "config.json"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "preflight", "config.json"), nil
	}
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		return "", fmt.Errorf("HOME is not set; set PREFLIGHT_CONFIG_PATH")
	}
	return filepath.Join(home, ".config", "preflight", "config.json"), nil
}

func preflightAppConfigBindingKey(appDir string) (string, error) {
	absoluteAppDir, err := filepath.Abs(appDir)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absoluteAppDir), nil
}

func preflightSourceBindingConfigKey(binding sourceBinding) string {
	if binding.WorkspaceRoot == "" {
		return filepath.Clean(binding.PackagePath)
	}
	return filepath.Clean(filepath.Join(binding.WorkspaceRoot, binding.PackagePath))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func runProveApp(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight prove-app")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Create and watch a source-bound mobile proof workflow.")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Options:")
		fmt.Fprintln(stdout, "  --workspace-id <id>     ForgeGraph workspace ID (default: local)")
		fmt.Fprintln(stdout, "  --app-dir <path>        Expo app directory (default: .)")
		fmt.Fprintln(stdout, "  --platform ios|android  Platform to prove (default: ios)")
		fmt.Fprintln(stdout, "  --lane <lane>           simulator or development (default: simulator)")
		fmt.Fprintln(stdout, "  --build-strategy <name> local or eas development build strategy")
		fmt.Fprintln(stdout, "  --priority <n>          scheduling priority; higher is claimed first (default: 0)")
		fmt.Fprintln(stdout, "  --local-readiness       Validate local Expo/EAS/Maestro readiness without API calls")
		fmt.Fprintln(stdout, "  --interactive-setup     Allow EAS credential prompts during a standalone build run")
		fmt.Fprintln(stdout, "  --secret-ref <id>       Attach a Preflight-owned secret reference to runner jobs")
		fmt.Fprintln(stdout, "  --wait-for-runner       Create the workflow even when no runner is currently available")
		return 0
	}

	options := proveAppOptions{
		apiURL:       os.Getenv("PREFLIGHT_API_URL"),
		token:        os.Getenv("PREFLIGHT_TOKEN"),
		workspaceID:  "local",
		appDir:       ".",
		platform:     "ios",
		lane:         "simulator",
		pollInterval: defaultRunnerPollInterval,
		watchTimeout: defaultProveAppWatchTimeout,
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return 2
			}
			options.apiURL = args[index+1]
			index += 1
		case "--workspace-id":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--workspace-id requires a value")
				return 2
			}
			options.workspaceID = args[index+1]
			options.workspaceExplicit = true
			index += 1
		case "--app-dir":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--app-dir requires a value")
				return 2
			}
			options.appDir = args[index+1]
			index += 1
		case "--platform":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--platform requires a value")
				return 2
			}
			options.platform = args[index+1]
			index += 1
		case "--lane":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--lane requires a value")
				return 2
			}
			options.lane = args[index+1]
			options.laneExplicit = true
			index += 1
		case "--priority":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--priority requires a value")
				return 2
			}
			parsedPriority, parseErr := strconv.Atoi(args[index+1])
			if parseErr != nil {
				fmt.Fprintf(stderr, "--priority must be an integer: %v\n", parseErr)
				return 2
			}
			options.priority = parsedPriority
			index += 1
		case "--json":
			options.json = true
		case "--watch":
			options.watch = true
		case "--wait-for-runner":
			options.waitForRunner = true
		case "--local-readiness":
			options.localReadiness = true
		case "--standalone-plan":
			options.standalonePlan = true
		case "--standalone-run":
			options.standalonePlan = true
			options.standaloneRun = true
		case "--interactive-setup":
			options.interactiveSetup = true
		case "--target-kind":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--target-kind requires a value")
				return 2
			}
			options.targetKind = value
		case "--target-key":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--target-key requires a value")
				return 2
			}
			options.targetKey = value
		case "--target-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--target-id requires a value")
				return 2
			}
			options.targetID = value
		case "--workflow-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--workflow-id requires a value")
				return 2
			}
			options.workflowID = value
		case "--port":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--port requires a value")
				return 2
			}
			port, err := strconv.Atoi(value)
			if err != nil || port <= 0 {
				fmt.Fprintln(stderr, "--port must be a positive integer")
				return 2
			}
			options.port = port
		case "--flow-path":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--flow-path requires a value")
				return 2
			}
			options.flowPath = value
		case "--artifact-dir":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--artifact-dir requires a value")
				return 2
			}
			options.artifactDir = value
		case "--build-profile":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--build-profile requires a value")
				return 2
			}
			options.buildProfile = value
		case "--build-strategy":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--build-strategy requires a value")
				return 2
			}
			if value != "local" && value != "eas" {
				fmt.Fprintln(stderr, "--build-strategy must be local or eas")
				return 2
			}
			options.buildStrategy = value
		case "--version":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--version requires a value")
				return 2
			}
			options.version = value
		case "--build-number":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--build-number requires a value")
				return 2
			}
			options.buildNumber = value
		case "--message":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--message requires a value")
				return 2
			}
			options.message = value
		case "--secret-ref":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--secret-ref requires a value")
				return 2
			}
			options.secretReferenceIDs = append(options.secretReferenceIDs, value)
		case "--poll-interval":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--poll-interval requires a value")
				return 2
			}
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				fmt.Fprintln(stderr, "--poll-interval must be a positive duration")
				return 2
			}
			options.pollInterval = duration
		case "--watch-timeout":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--watch-timeout requires a value")
				return 2
			}
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				fmt.Fprintln(stderr, "--watch-timeout must be a positive duration")
				return 2
			}
			options.watchTimeout = duration
		default:
			fmt.Fprintf(stderr, "unknown prove-app flag %q\n", args[index])
			return 2
		}
	}

	apiURLBeforeConfig := strings.TrimRight(strings.TrimSpace(options.apiURL), "/")
	config, err := loadPreflightCLIConfig()
	if err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return 1
	}
	loadedAPIURLFromConfig := false
	if strings.TrimSpace(options.apiURL) == "" {
		options.apiURL = config.APIURL
		loadedAPIURLFromConfig = strings.TrimSpace(options.apiURL) != ""
		apiURLBeforeConfig = strings.TrimRight(strings.TrimSpace(options.apiURL), "/")
	}
	if strings.TrimSpace(options.token) == "" {
		options.token = config.Token
	}
	configMatchesAPIURL := preflightConfigAppliesToAPIURL(config, apiURLBeforeConfig, loadedAPIURLFromConfig)
	if configMatchesAPIURL && config.WorkspaceID != "" && options.workspaceID == "local" {
		options.workspaceID = config.WorkspaceID
	}
	applyProveAppTargetLaneInference(&options)

	sourceBinding, err := discoverSourceBinding(options)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if options.localReadiness {
		return printLocalReadinessReport(options, sourceBinding, stdout, stderr)
	}
	if options.apiURL == "" {
		fmt.Fprintln(stderr, "missing Preflight API URL; pass --api-url or set PREFLIGHT_API_URL")
		return 2
	}
	if configMatchesAPIURL && !options.workspaceExplicit {
		if boundWorkspaceID := config.WorkspaceBindings[preflightSourceBindingConfigKey(sourceBinding)]; boundWorkspaceID != "" {
			options.workspaceID = boundWorkspaceID
		}
	}

	if options.standalonePlan {
		if options.lane == "development" {
			return createStandaloneDevelopmentBuildPlan(options, sourceBinding, stdout, stderr, client)
		}
		return createStandaloneSimulatorProofPlan(options, sourceBinding, stdout, stderr, client)
	}

	if err := verifyPreflightAPICompatibility(client, options.apiURL, options.token); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if err := verifyPreflightRunnerCapacity(client, options, sourceBinding); err != nil {
		if !options.waitForRunner {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "%s\ncontinuing because --wait-for-runner was set\n", err.Error())
	}

	workflowRequest := map[string]any{
		"workspaceId":   options.workspaceID,
		"sourceBinding": sourceBinding,
	}
	if options.lane == "development" {
		workflowRequest["targetClass"] = proveAppTargetClass(options)
	}
	if len(options.secretReferenceIDs) > 0 {
		workflowRequest["secretReferenceIds"] = append([]string{}, options.secretReferenceIDs...)
	}
	if options.priority != 0 {
		workflowRequest["priority"] = options.priority
	}

	requestBody, err := json.Marshal(workflowRequest)
	if err != nil {
		fmt.Fprintf(stderr, "failed to encode workflow request: %v\n", err)
		return 1
	}

	endpoint := strings.TrimRight(options.apiURL, "/") + "/api/preflight/v1/workflows/prove-app"
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		fmt.Fprintf(stderr, "invalid Preflight API URL: %v\n", err)
		return 2
	}
	request.Header.Set("Content-Type", "application/json")
	if options.token != "" {
		request.Header.Set("Authorization", "Bearer "+options.token)
	}

	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(stderr, "prove-app workflow creation failed: %v\n", err)
		return 1
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Fprintf(stderr, "prove-app workflow creation returned HTTP %d\n", response.StatusCode)
		return 1
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Fprintf(stderr, "failed to read workflow response: %v\n", err)
		return 1
	}

	var envelope proveAppCreateEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		fmt.Fprintf(stderr, "failed to decode workflow response: %v\n", err)
		return 1
	}
	if envelope.Data.Workflow.ID == "" {
		fmt.Fprintln(stderr, "prove-app workflow response did not include a workflow ID")
		return 1
	}

	if options.json {
		_, _ = fmt.Fprintln(stdout, string(body))
	} else {
		fmt.Fprintf(
			stdout,
			"created workflow %s %s\n",
			envelope.Data.Workflow.ID,
			envelope.Data.Workflow.Status,
		)
	}

	if options.watch {
		return watchProveAppWorkflow(
			options,
			envelope.Data.Workflow.ID,
			stdout,
			stderr,
			client,
		)
	}

	return 0
}

func proveAppTargetClass(options proveAppOptions) string {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(strings.TrimSpace(options.targetKind)))
	if normalized == "ios_simulator" || normalized == "simulator" {
		return "simulator"
	}
	if normalized == "android_emulator" || normalized == "emulator" {
		return "emulator"
	}
	return "device"
}

type proveAppOptions struct {
	apiURL             string
	token              string
	workspaceID        string
	workspaceExplicit  bool
	appDir             string
	platform           string
	lane               string
	laneExplicit       bool
	localReadiness     bool
	standalonePlan     bool
	standaloneRun      bool
	interactiveSetup   bool
	targetKind         string
	targetKey          string
	targetID           string
	workflowID         string
	port               int
	flowPath           string
	artifactDir        string
	buildProfile       string
	buildStrategy      string
	version            string
	buildNumber        string
	message            string
	json               bool
	watch              bool
	waitForRunner      bool
	pollInterval       time.Duration
	watchTimeout       time.Duration
	secretReferenceIDs []string
	priority           int
}

type localReadinessReport struct {
	Ready           bool                   `json:"ready"`
	SourceBinding   sourceBinding          `json:"sourceBinding"`
	MaestroFlowPath string                 `json:"maestroFlowPath,omitempty"`
	Checks          []localReadinessCheck  `json:"checks"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type localReadinessCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func printLocalReadinessReport(options proveAppOptions, binding sourceBinding, stdout io.Writer, stderr io.Writer) int {
	report := buildLocalReadinessReport(options, binding)
	if options.json {
		content, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode local readiness failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
	} else {
		status := "blocked"
		if report.Ready {
			status = "ready"
		}
		fmt.Fprintf(stdout, "local readiness %s %s %s\n", status, binding.PackageName, binding.PackagePath)
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "- %s: %s", check.Name, check.Status)
			if check.Message != "" {
				fmt.Fprintf(stdout, " %s", check.Message)
			}
			fmt.Fprintln(stdout)
		}
	}
	if !report.Ready {
		return 1
	}
	return 0
}

func applyProveAppTargetLaneInference(options *proveAppOptions) {
	if options == nil || options.laneExplicit || options.lane != "simulator" {
		return
	}
	if isPhysicalDevelopmentTargetKind(options.platform, options.targetKind) {
		options.lane = "development"
	}
}

func isPhysicalDevelopmentTargetKind(platform string, targetKind string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(strings.TrimSpace(targetKind)))
	switch platform {
	case "ios":
		return normalized == "iphone" || normalized == "ios_device" || normalized == "device"
	case "android":
		return normalized == "android_phone" || normalized == "android_device" || normalized == "phone" || normalized == "device"
	default:
		return false
	}
}

func buildLocalReadinessReport(options proveAppOptions, binding sourceBinding) localReadinessReport {
	appDir := sourceBindingAppDirectory(binding)
	report := localReadinessReport{
		Ready:         true,
		SourceBinding: binding,
		Checks:        []localReadinessCheck{},
		Metadata: map[string]interface{}{
			"platform": binding.Platform,
			"lane":     binding.Lane,
		},
	}
	addCheck := func(name string, ok bool, message string) {
		status := "ok"
		if !ok {
			status = "blocked"
			report.Ready = false
		}
		report.Checks = append(report.Checks, localReadinessCheck{
			Name:    name,
			Status:  status,
			Message: message,
		})
	}

	pkg, err := readPackageJSON(filepath.Join(appDir, "package.json"))
	if err != nil {
		addCheck("package_json", false, "package.json is not readable")
	} else {
		addCheck("expo_app", isExpoPackage(pkg), "package.json identifies an Expo app")
		addCheck("expo_dev_client", hasDependency(pkg, "expo-dev-client"), "expo-dev-client dependency is installed")
	}

	addCheck("app_scheme", binding.AppScheme != "" || binding.ExpoSlug != "", "Expo scheme or slug is available for development-client links")
	if binding.Platform == "android" {
		addCheck("android_package", binding.AndroidPackage != "", "Android package is available from Expo config")
	} else {
		addCheck("ios_bundle_id", binding.IOSBundleID != "", "iOS bundle identifier is available from Expo config")
	}
	addCheck("eas_project", binding.EASProjectID != "", "EAS project ID is available from Expo config")

	easConfig, err := loadEASJSON(appDir)
	if err != nil {
		addCheck("eas_json", false, "eas.json is not readable")
	} else {
		profile, ok := easConfig.Build[binding.EASProfileName]
		addCheck("eas_profile", ok && binding.EASProfileName != "", fmt.Sprintf("selected EAS profile %q", binding.EASProfileName))
		if ok {
			addCheck("eas_development_client", easProfileDevelopmentClient(profile), "EAS profile enables developmentClient")
			addCheck("eas_internal_distribution", profile.Distribution == "" || profile.Distribution == "internal", "EAS profile uses internal distribution")
			if binding.Platform == "ios" {
				simulator := profile.IOS.Simulator != nil && *profile.IOS.Simulator
				if binding.Lane == "development" {
					addCheck("eas_ios_device_profile", !simulator, "iOS development lane uses a physical-device profile")
				} else {
					addCheck("eas_ios_simulator_profile", simulator, "iOS simulator lane uses a simulator profile")
				}
			}
			if binding.Platform == "android" {
				addCheck("eas_android_apk", easProfileAndroidInstallable(profile), "Android development build is installable as an APK")
			}
		}
	}

	flowPath := localReadinessMaestroFlowPath(options, appDir)
	report.MaestroFlowPath = flowPath
	flowContent, err := os.ReadFile(flowPath)
	if err != nil {
		addCheck("maestro_flow", false, "Maestro launch flow is not readable")
	} else {
		expectedAppID := binding.IOSBundleID
		if binding.Platform == "android" {
			expectedAppID = binding.AndroidPackage
		}
		addCheck("maestro_flow", true, "Maestro launch flow is readable")
		if expectedAppID != "" {
			addCheck("maestro_app_id", strings.Contains(string(flowContent), expectedAppID), "Maestro flow references the selected native app ID")
		}
	}

	return report
}

func sourceBindingAppDirectory(binding sourceBinding) string {
	if binding.WorkspaceRoot == "" {
		return filepath.Clean(binding.PackagePath)
	}
	if binding.PackagePath == "" || binding.PackagePath == "." {
		return binding.WorkspaceRoot
	}
	return filepath.Join(binding.WorkspaceRoot, binding.PackagePath)
}

func localReadinessMaestroFlowPath(options proveAppOptions, appDir string) string {
	if strings.TrimSpace(options.flowPath) == "" {
		return filepath.Join(appDir, ".maestro", "01-app-launches.yaml")
	}
	if filepath.IsAbs(options.flowPath) {
		return options.flowPath
	}
	return filepath.Join(appDir, options.flowPath)
}

type simulatorProofPlanCommand struct {
	ID      string            `json:"id"`
	Title   string            `json:"title"`
	Kind    string            `json:"kind"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	CWD     string            `json:"cwd"`
	Env     map[string]string `json:"env"`
}

type simulatorProofPlanData struct {
	WorkflowID    string                      `json:"workflowId"`
	Platform      string                      `json:"platform"`
	TargetKind    string                      `json:"targetKind"`
	TargetKey     string                      `json:"targetKey"`
	AdvertisedURL string                      `json:"advertisedUrl"`
	DevSession    map[string]any              `json:"devSession"`
	TargetSession map[string]any              `json:"targetSession"`
	TargetRun     map[string]any              `json:"targetRun"`
	Commands      []simulatorProofPlanCommand `json:"commands"`
}

type developmentBuildPlanCommand struct {
	simulatorProofPlanCommand
	StdoutArtifactPath string `json:"stdoutArtifactPath"`
}

type developmentBuildPlanData struct {
	WorkflowID      string                        `json:"workflowId"`
	Platform        string                        `json:"platform"`
	TargetKind      string                        `json:"targetKind"`
	RequiredSecrets []string                      `json:"requiredSecrets"`
	Build           map[string]any                `json:"build"`
	Installation    map[string]any                `json:"installation"`
	Commands        []developmentBuildPlanCommand `json:"commands"`
}

type developmentSessionPlanData struct {
	WorkflowID    string                      `json:"workflowId"`
	Platform      string                      `json:"platform"`
	TargetKind    string                      `json:"targetKind"`
	TargetID      string                      `json:"targetId"`
	AdvertisedURL string                      `json:"advertisedUrl"`
	DeepLinkURL   string                      `json:"deepLinkUrl"`
	QRURL         string                      `json:"qrUrl"`
	DevSession    map[string]any              `json:"devSession"`
	TargetSession map[string]any              `json:"targetSession"`
	Commands      []simulatorProofPlanCommand `json:"commands"`
}

func createStandaloneSimulatorProofPlan(options proveAppOptions, binding sourceBinding, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if options.lane != "simulator" {
		fmt.Fprintln(stderr, "--standalone-plan currently supports --lane simulator")
		return 2
	}
	targetKind := strings.TrimSpace(options.targetKind)
	if targetKind == "" {
		if options.platform == "android" {
			targetKind = "android_emulator"
		} else {
			targetKind = "ios_simulator"
		}
	}
	if strings.TrimSpace(options.targetKey) == "" {
		fmt.Fprintln(stderr, "missing --target-key")
		return 2
	}
	port := options.port
	if port == 0 {
		port = 8081
	}
	workflowID := strings.TrimSpace(options.workflowID)
	if workflowID == "" {
		workflowID = "pfw_" + sanitizeID(binding.PackageName) + "_" + options.platform + "_sim"
	}
	appDirectory := filepath.Clean(filepath.Join(binding.WorkspaceRoot, binding.PackagePath))
	flowPath := strings.TrimSpace(options.flowPath)
	if flowPath == "" {
		flowPath = filepath.Join(appDirectory, ".maestro", "01-app-launches.yaml")
	}
	artifactDir := strings.TrimSpace(options.artifactDir)
	if artifactDir == "" {
		artifactDir = filepath.Join(appDirectory, ".preflight", "simulator-proofs", workflowID)
	}
	appScheme := strings.TrimSpace(binding.AppScheme)
	if appScheme == "" && binding.ExpoSlug != "" {
		appScheme = "exp+" + binding.ExpoSlug
	}
	if appScheme == "" {
		fmt.Fprintln(stderr, "app scheme could not be derived; pass an Expo app scheme in app config")
		return 2
	}

	payload := map[string]any{
		"workspaceId":       options.workspaceID,
		"workflowId":        workflowID,
		"platform":          options.platform,
		"targetKind":        targetKind,
		"targetKey":         options.targetKey,
		"appDirectory":      appDirectory,
		"appScheme":         appScheme,
		"port":              port,
		"flowPath":          flowPath,
		"artifactDirectory": artifactDir,
	}
	endpoint := runnerEndpoint(
		options.apiURL,
		"/api/preflight/v1/apps/"+url.PathEscape(binding.AppID)+"/simulator-proof-plans",
	)
	data, err := postPreflightWorkspaceJSON(client, endpoint, options.token, options.workspaceID, payload)
	if err != nil {
		fmt.Fprintf(stderr, "standalone simulator proof plan failed: %v\n", err)
		return 1
	}
	if options.json && !options.standaloneRun {
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	var plan simulatorProofPlanData
	if err := decodeEnvelopeData(data, &plan); err != nil {
		fmt.Fprintf(stderr, "decode simulator proof plan failed: %v\n", err)
		return 1
	}
	if options.standaloneRun {
		return executeStandaloneSimulatorProofPlan(options, binding, plan, stdout, stderr, client)
	}
	fmt.Fprintf(stdout, "simulator proof plan %s %s %s %s\n", plan.WorkflowID, plan.Platform, plan.TargetKind, plan.AdvertisedURL)
	for _, command := range plan.Commands {
		fmt.Fprintf(stdout, "%s %s\n", command.Command, strings.Join(command.Args, " "))
	}
	return 0
}

func createStandaloneDevelopmentBuildPlan(options proveAppOptions, binding sourceBinding, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	targetKind := strings.TrimSpace(options.targetKind)
	if targetKind == "" {
		if options.platform == "android" {
			targetKind = "android_phone"
		} else {
			targetKind = "iphone"
		}
	}
	targetID := firstNonEmpty(options.targetID, options.targetKey)
	if options.standaloneRun && targetID == "" {
		fmt.Fprintln(stderr, "missing --target-id")
		return 2
	}
	workflowID := strings.TrimSpace(options.workflowID)
	if workflowID == "" {
		workflowID = "pfw_" + sanitizeID(binding.PackageName) + "_" + options.platform + "_dev"
	}
	appDirectory := filepath.Clean(filepath.Join(binding.WorkspaceRoot, binding.PackagePath))
	artifactDir := strings.TrimSpace(options.artifactDir)
	if artifactDir == "" {
		artifactDir = filepath.Join(appDirectory, ".preflight", "development-builds", workflowID)
	}
	version, err := standaloneDevelopmentBuildVersion(options, appDirectory)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	buildProfile := strings.TrimSpace(options.buildProfile)
	if buildProfile == "" {
		buildProfile = strings.TrimSpace(binding.EASProfileName)
	}
	if buildProfile == "" {
		buildProfile = "development"
	}
	readinessOptions := options
	readinessOptions.buildProfile = ""
	readinessBinding, err := discoverSourceBinding(readinessOptions)
	if err != nil {
		fmt.Fprintf(stderr, "discover development readiness binding failed: %v\n", err)
		return 1
	}
	developmentReadiness, err := readStandaloneDevelopmentReadiness(readinessOptions, readinessBinding)
	if err != nil {
		fmt.Fprintf(stderr, "read development readiness failed: %v\n", err)
		return 1
	}

	payload := map[string]any{
		"workspaceId":          options.workspaceID,
		"workflowId":           workflowID,
		"platform":             options.platform,
		"targetKind":           targetKind,
		"appDirectory":         appDirectory,
		"buildProfile":         buildProfile,
		"version":              version,
		"artifactDirectory":    artifactDir,
		"developmentReadiness": developmentReadiness,
	}
	if targetID != "" {
		payload["targetId"] = targetID
	}
	if strings.TrimSpace(options.buildNumber) != "" {
		payload["buildNumber"] = strings.TrimSpace(options.buildNumber)
	}
	if strings.TrimSpace(options.message) != "" {
		payload["message"] = strings.TrimSpace(options.message)
	}

	endpoint := runnerEndpoint(
		options.apiURL,
		"/api/preflight/v1/apps/"+url.PathEscape(binding.AppID)+"/development-build-plans",
	)
	data, err := postPreflightWorkspaceJSON(client, endpoint, options.token, options.workspaceID, payload)
	if err != nil {
		fmt.Fprintf(stderr, "standalone development build plan failed: %v\n", err)
		return 1
	}
	if options.json && !options.standaloneRun {
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	var response struct {
		Plan developmentBuildPlanData `json:"plan"`
	}
	if err := decodeEnvelopeData(data, &response); err != nil {
		fmt.Fprintf(stderr, "decode development build plan failed: %v\n", err)
		return 1
	}
	plan := response.Plan
	if plan.WorkflowID == "" {
		if err := decodeEnvelopeData(data, &plan); err != nil {
			fmt.Fprintf(stderr, "decode development build plan failed: %v\n", err)
			return 1
		}
	}
	if options.standaloneRun {
		return executeStandaloneDevelopmentBuildPlan(options, binding, plan, stdout, stderr, client)
	}
	fmt.Fprintf(stdout, "development build plan %s %s %s\n", plan.WorkflowID, plan.Platform, plan.TargetKind)
	for _, command := range plan.Commands {
		fmt.Fprintf(stdout, "%s %s\n", command.Command, strings.Join(command.Args, " "))
	}
	return 0
}

func readStandaloneDevelopmentReadiness(options proveAppOptions, binding sourceBinding) (map[string]any, error) {
	appDirectory := sourceBindingAppDirectory(binding)
	packageConfig, err := readPackageJSON(filepath.Join(appDirectory, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	easConfig, err := loadEASJSON(appDirectory)
	if err != nil {
		return nil, fmt.Errorf("read eas.json: %w", err)
	}
	flowPath := localReadinessMaestroFlowPath(options, appDirectory)
	flowContent, err := os.ReadFile(flowPath)
	if err != nil {
		return nil, fmt.Errorf("read Maestro flow: %w", err)
	}
	return map[string]any{
		"sourceBinding": binding,
		"packageJson":   packageConfig,
		"easJson":       easConfig,
		"maestroFlows": []map[string]string{
			{"path": flowPath, "content": string(flowContent)},
		},
	}, nil
}

func standaloneDevelopmentBuildVersion(options proveAppOptions, appDirectory string) (string, error) {
	if version := strings.TrimSpace(options.version); version != "" {
		return version, nil
	}
	pkg, err := readPackageJSON(filepath.Join(appDirectory, "package.json"))
	if err == nil && strings.TrimSpace(pkg.Version) != "" {
		return strings.TrimSpace(pkg.Version), nil
	}
	return "", fmt.Errorf("missing --version and package.json version")
}

func executeStandaloneDevelopmentBuildPlan(options proveAppOptions, binding sourceBinding, plan developmentBuildPlanData, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	easBuildID := ""
	var finalEASBuild map[string]any
	completedCommands := make([]developmentBuildPlanCommand, 0, len(plan.Commands))
	for _, plannedCommand := range plan.Commands {
		_, record, err := runStandaloneDevelopmentBuildCommandForPlan(plannedCommand, easBuildID, options.interactiveSetup)
		if err != nil {
			fmt.Fprintf(stderr, "run %s failed: %v\n", standaloneCommandLabel(plannedCommand.simulatorProofPlanCommand), err)
			return 1
		}
		completedCommands = append(completedCommands, plannedCommand)
		if record == nil {
			continue
		}
		if plannedCommand.ID == "eas_build" {
			easBuildID = readMapString(record, "id")
			if easBuildID == "" {
				fmt.Fprintln(stderr, "EAS build output did not include a build id")
				return 1
			}
		}
		if plannedCommand.ID == "eas_build" || plannedCommand.ID == "eas_build_view" {
			finalEASBuild = record
		}
	}
	if finalEASBuild == nil {
		fmt.Fprintln(stderr, "development build plan did not produce EAS build JSON")
		return 1
	}

	planBuildID := readMapString(plan.Build, "id")
	planInstallationID := readMapString(plan.Installation, "id")
	targetID := firstNonEmpty(options.targetID, options.targetKey, readMapString(plan.Installation, "targetId"))
	version := firstNonEmpty(readMapString(plan.Build, "version"), options.version)
	if planBuildID == "" || planInstallationID == "" || targetID == "" || version == "" {
		fmt.Fprintln(stderr, "development build result is missing plan build, installation, target, or version")
		return 1
	}
	payload := map[string]any{
		"workspaceId":        options.workspaceID,
		"planBuildId":        planBuildID,
		"planInstallationId": planInstallationID,
		"workflowId":         plan.WorkflowID,
		"targetId":           targetID,
		"platform":           plan.Platform,
		"buildProfile":       readMapString(plan.Build, "profile"),
		"version":            version,
		"easBuild":           finalEASBuild,
	}
	if buildNumber := readMapString(plan.Build, "buildNumber"); buildNumber != "" {
		payload["buildNumber"] = buildNumber
	}
	endpoint := runnerEndpoint(
		options.apiURL,
		"/api/preflight/v1/apps/"+url.PathEscape(binding.AppID)+"/development-build-results",
	)
	if _, err := postPreflightWorkspaceJSON(client, endpoint, options.token, options.workspaceID, payload); err != nil {
		fmt.Fprintf(stderr, "post development build result failed: %v\n", err)
		return 1
	}
	for _, plannedCommand := range completedCommands {
		if err := postStandaloneDevelopmentBuildArtifact(client, options, binding.AppID, plan, plannedCommand, easBuildID); err != nil {
			fmt.Fprintf(stderr, "post EAS artifact failed: %v\n", err)
			return 1
		}
	}
	if readMapString(plan.Build, "profile") == "preview" {
		fmt.Fprintf(stdout, "preview build run %s posted %s\n", plan.WorkflowID, readMapString(finalEASBuild, "id"))
		return 0
	}
	if code := executeStandaloneDevelopmentSessionPlan(options, binding, plan, targetID, stdout, stderr, client); code != 0 {
		return code
	}
	fmt.Fprintf(stdout, "development build run %s posted %s\n", plan.WorkflowID, readMapString(finalEASBuild, "id"))
	return 0
}

func executeStandaloneDevelopmentSessionPlan(options proveAppOptions, binding sourceBinding, buildPlan developmentBuildPlanData, targetID string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	appDirectory := filepath.Clean(filepath.Join(binding.WorkspaceRoot, binding.PackagePath))
	port := options.port
	if port == 0 {
		port = 8081
	}
	payload := map[string]any{
		"workspaceId":  options.workspaceID,
		"workflowId":   buildPlan.WorkflowID,
		"platform":     buildPlan.Platform,
		"targetKind":   buildPlan.TargetKind,
		"targetId":     targetID,
		"appDirectory": appDirectory,
		"appScheme":    binding.AppScheme,
		"port":         port,
		"buildId":      readMapString(buildPlan.Build, "id"),
	}
	endpoint := runnerEndpoint(
		options.apiURL,
		"/api/preflight/v1/apps/"+url.PathEscape(binding.AppID)+"/development-session-plans",
	)
	data, err := postPreflightWorkspaceJSON(client, endpoint, options.token, options.workspaceID, payload)
	if err != nil {
		fmt.Fprintf(stderr, "standalone development session plan failed: %v\n", err)
		return 1
	}
	var response struct {
		Plan developmentSessionPlanData `json:"plan"`
	}
	if err := decodeEnvelopeData(data, &response); err != nil {
		fmt.Fprintf(stderr, "decode development session plan failed: %v\n", err)
		return 1
	}
	plan := response.Plan
	if plan.WorkflowID == "" {
		if err := decodeEnvelopeData(data, &plan); err != nil {
			fmt.Fprintf(stderr, "decode development session plan failed: %v\n", err)
			return 1
		}
	}
	for _, plannedCommand := range plan.Commands {
		if plannedCommand.Kind != "long_running" {
			if err := runStandalonePlannedCommand(plannedCommand, simulatorOpenTimeout(), stderr); err != nil {
				fmt.Fprintf(stderr, "run %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
				return 1
			}
			continue
		}
		logPath := standaloneDevelopmentSessionLogPath(appDirectory, plan.WorkflowID)
		logFile, err := openStandaloneDevelopmentSessionLog(logPath)
		if err != nil {
			fmt.Fprintf(stderr, "open development session log failed: %v\n", err)
			return 1
		}
		defer logFile.Close()
		command, observedOutput, err := startStandaloneObservedPlannedCommandWithOutput(plannedCommand, io.MultiWriter(stderr, logFile), defaultExpoDevSessionStartTimeout)
		if err != nil {
			fmt.Fprintf(stderr, "start %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
			return 1
		}
		defer terminateProcessGroup(command)
		_ = logFile.Sync()
		replacements := standaloneDevelopmentSessionReplacements(observedOutput)
		runningDevSession := substituteStandaloneRuntimePlaceholders(mapWith(plan.DevSession, map[string]any{
			"status": "running",
			"pid":    command.Process.Pid,
		}), replacements).(map[string]any)
		artifacts, err := prepareStandaloneDevelopmentSessionArtifacts(client, options, binding, buildPlan, plan, runningDevSession, appDirectory, logPath)
		if err != nil {
			fmt.Fprintf(stderr, "prepare development session artifacts failed: %v\n", err)
			return 1
		}
		applyDevSessionArtifacts(runningDevSession, artifacts)
		if err := postStandaloneRuntimeState(client, options, binding.AppID, "dev-sessions", runningDevSession); err != nil {
			fmt.Fprintf(stderr, "post development dev session failed: %v\n", err)
			return 1
		}
		if len(plan.TargetSession) > 0 {
			targetSession := substituteStandaloneRuntimePlaceholders(mapWith(plan.TargetSession, map[string]any{
				"status": "opening",
			}), replacements).(map[string]any)
			if err := postStandaloneRuntimeState(client, options, binding.AppID, "target-sessions", targetSession); err != nil {
				fmt.Fprintf(stderr, "post development target session failed: %v\n", err)
				return 1
			}
		}
		fmt.Fprintf(stdout, "development session %s started tunnel server pid %d\n", plan.WorkflowID, command.Process.Pid)
	}
	return 0
}

func terminateProcessGroup(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	_ = command.Wait()
}

func prepareStandaloneDevelopmentSessionArtifacts(
	client *http.Client,
	options proveAppOptions,
	binding sourceBinding,
	buildPlan developmentBuildPlanData,
	sessionPlan developmentSessionPlanData,
	devSession map[string]any,
	appDir string,
	logPath string,
) (devSessionArtifacts, error) {
	artifacts := devSessionArtifacts{
		LogPath: strings.TrimSpace(logPath),
	}
	qrPayloadPath, err := writeStandaloneDevSessionQRPayload(appDir, binding, buildPlan, sessionPlan, devSession)
	if err != nil {
		return artifacts, err
	}
	artifacts.QRPayloadPath = qrPayloadPath
	if qrPayloadPath != "" {
		artifactID, err := postStandaloneDevSessionQRArtifact(client, options, binding.AppID, buildPlan, sessionPlan, devSession, qrPayloadPath)
		if err != nil {
			return artifacts, err
		}
		artifacts.QRArtifactID = artifactID
	}
	if artifacts.LogPath != "" {
		if err := postStandaloneDevSessionLogArtifact(client, options, binding.AppID, buildPlan, sessionPlan, devSession, artifacts.LogPath); err != nil {
			return artifacts, err
		}
	}
	return artifacts, nil
}

func standaloneDevelopmentSessionLogPath(appDir string, workflowID string) string {
	return filepath.Join(appDir, ".preflight", "dev-sessions", workflowID, "expo-start.log")
}

func openStandaloneDevelopmentSessionLog(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("missing log path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create standalone dev session log directory: %w", err)
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
}

func writeStandaloneDevSessionQRPayload(
	appDir string,
	binding sourceBinding,
	buildPlan developmentBuildPlanData,
	sessionPlan developmentSessionPlanData,
	devSession map[string]any,
) (string, error) {
	if readMapString(devSession, "qrUrl") == "" {
		return "", nil
	}
	payload := map[string]any{
		"workflowId":    sessionPlan.WorkflowID,
		"appId":         binding.AppID,
		"buildId":       readMapString(buildPlan.Build, "id"),
		"targetId":      sessionPlan.TargetID,
		"targetKind":    sessionPlan.TargetKind,
		"status":        readMapString(devSession, "status"),
		"advertisedUrl": readMapString(devSession, "advertisedUrl"),
		"deepLinkUrl":   readMapString(devSession, "deepLinkUrl"),
		"qrUrl":         readMapString(devSession, "qrUrl"),
		"installUrl":    readMapString(devSession, "installUrl"),
		"hostMode":      readMapString(devSession, "hostMode"),
		"sourceBinding": map[string]any{
			"workspaceRoot": binding.WorkspaceRoot,
			"packagePath":   binding.PackagePath,
			"appScheme":     binding.AppScheme,
			"expoSlug":      binding.ExpoSlug,
		},
	}
	content, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode standalone dev session QR payload: %w", err)
	}
	path := filepath.Join(appDir, ".preflight", "dev-sessions", sessionPlan.WorkflowID, "qr-payload.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create standalone dev session QR artifact directory: %w", err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", fmt.Errorf("write standalone dev session QR payload artifact: %w", err)
	}
	return path, nil
}

func postStandaloneDevSessionQRArtifact(
	client *http.Client,
	options proveAppOptions,
	appID string,
	buildPlan developmentBuildPlanData,
	sessionPlan developmentSessionPlanData,
	devSession map[string]any,
	path string,
) (string, error) {
	payload := map[string]any{
		"kind":           "qr_code",
		"uri":            path,
		"retentionClass": "diagnostic",
		"redacted":       true,
		"contentType":    "application/json",
		"metadata":       devSessionArtifactMetadata(devSession),
	}
	for key, value := range map[string]string{
		"workflowId":   sessionPlan.WorkflowID,
		"buildId":      readMapString(buildPlan.Build, "id"),
		"devSessionId": readMapString(devSession, "id"),
		"targetId":     sessionPlan.TargetID,
	} {
		if strings.TrimSpace(value) != "" {
			payload[key] = value
		}
	}
	if sizeBytes, ok := artifactSizeBytes(path); ok {
		payload["sizeBytes"] = sizeBytes
	}
	data, err := postStandaloneRuntimeStateData(client, options, appID, "runtime-artifacts", payload)
	if err != nil {
		return "", err
	}
	var created struct {
		ID       string `json:"id"`
		Artifact struct {
			ID string `json:"id"`
		} `json:"artifact"`
	}
	if err := decodeEnvelopeData(data, &created); err != nil {
		return "", err
	}
	if created.ID != "" {
		return created.ID, nil
	}
	return created.Artifact.ID, nil
}

func postStandaloneDevSessionLogArtifact(
	client *http.Client,
	options proveAppOptions,
	appID string,
	buildPlan developmentBuildPlanData,
	sessionPlan developmentSessionPlanData,
	devSession map[string]any,
	path string,
) error {
	payload := map[string]any{
		"kind":           "log",
		"uri":            path,
		"retentionClass": "diagnostic",
		"redacted":       true,
		"contentType":    "text/plain",
		"metadata":       devSessionArtifactMetadata(devSession),
	}
	for key, value := range map[string]string{
		"workflowId":   sessionPlan.WorkflowID,
		"buildId":      readMapString(buildPlan.Build, "id"),
		"devSessionId": readMapString(devSession, "id"),
		"targetId":     sessionPlan.TargetID,
	} {
		if strings.TrimSpace(value) != "" {
			payload[key] = value
		}
	}
	if sizeBytes, ok := artifactSizeBytes(path); ok {
		payload["sizeBytes"] = sizeBytes
	}
	return postStandaloneRuntimeState(client, options, appID, "runtime-artifacts", payload)
}

func standaloneDevelopmentSessionReplacements(observedOutput string) map[string]string {
	replacements := map[string]string{}
	if tunnelURL, ok := expoTunnelDevServerURLFromLogContent(observedOutput); ok {
		replacements["EXPO_TUNNEL_URL"] = tunnelURL
	}
	return replacements
}

func substituteStandaloneRuntimePlaceholders(value any, replacements map[string]string) any {
	if len(replacements) == 0 {
		return value
	}
	switch typed := value.(type) {
	case string:
		result := typed
		for key, replacement := range replacements {
			result = strings.ReplaceAll(result, "${"+key+"}", replacement)
			result = strings.ReplaceAll(result, url.QueryEscape("${"+key+"}"), url.QueryEscape(replacement))
		}
		return result
	case map[string]any:
		next := make(map[string]any, len(typed))
		for key, nested := range typed {
			next[key] = substituteStandaloneRuntimePlaceholders(nested, replacements)
		}
		return next
	case []any:
		next := make([]any, len(typed))
		for index, nested := range typed {
			next[index] = substituteStandaloneRuntimePlaceholders(nested, replacements)
		}
		return next
	default:
		return value
	}
}

func postStandaloneDevelopmentBuildArtifact(client *http.Client, options proveAppOptions, appID string, plan developmentBuildPlanData, plannedCommand developmentBuildPlanCommand, easBuildID string) error {
	path := strings.TrimSpace(plannedCommand.StdoutArtifactPath)
	if path == "" {
		return nil
	}
	payload := map[string]any{
		"kind":           "tool_output",
		"uri":            path,
		"retentionClass": "diagnostic",
		"redacted":       true,
		"metadata": map[string]any{
			"commandId":    plannedCommand.ID,
			"command":      plannedCommand.Command,
			"args":         substituteStandaloneCommandArgs(plannedCommand.Args, map[string]string{"EAS_BUILD_ID": easBuildID}),
			"platform":     plan.Platform,
			"targetKind":   plan.TargetKind,
			"buildProfile": readMapString(plan.Build, "profile"),
		},
	}
	for key, value := range map[string]string{
		"workflowId": plan.WorkflowID,
		"buildId":    readMapString(plan.Build, "id"),
		"targetId":   readMapString(plan.Installation, "targetId"),
	} {
		if strings.TrimSpace(value) != "" {
			payload[key] = value
		}
	}
	if contentType := standaloneArtifactContentType(path); contentType != "" {
		payload["contentType"] = contentType
	}
	if sizeBytes, ok := artifactSizeBytes(path); ok {
		payload["sizeBytes"] = sizeBytes
	}
	return postStandaloneRuntimeState(client, options, appID, "runtime-artifacts", payload)
}

func runStandaloneDevelopmentBuildCommandForPlan(plannedCommand developmentBuildPlanCommand, easBuildID string, interactiveSetup bool) ([]byte, map[string]any, error) {
	if plannedCommand.ID == "eas_build_view" {
		return pollStandaloneDevelopmentBuildView(plannedCommand, easBuildID)
	}
	if interactiveSetup && plannedCommand.ID == "eas_build" {
		if _, err := runStandaloneDevelopmentBuildCommand(plannedCommand, easBuildID, true); err != nil {
			return nil, nil, err
		}
		platform := standaloneCommandFlagValue(plannedCommand.Args, "--platform")
		lookupCommand := plannedCommand
		lookupCommand.ID = "eas_build_list"
		lookupCommand.Args = []string{"build:list", "--platform", platform, "--limit", "1", "--json", "--non-interactive"}
		return runStandaloneDevelopmentBuildCommandForPlan(lookupCommand, "", false)
	}
	output, err := runStandaloneDevelopmentBuildCommand(plannedCommand, easBuildID, false)
	if err != nil {
		return output, nil, err
	}
	if err := writeStandaloneCommandArtifact(plannedCommand.StdoutArtifactPath, output, plannedCommand.Env); err != nil {
		return output, nil, err
	}
	record, err := decodeStandaloneEASBuildRecord(output)
	if err != nil {
		return output, nil, fmt.Errorf("decode %s JSON: %w", standaloneCommandLabel(plannedCommand.simulatorProofPlanCommand), err)
	}
	return output, record, nil
}

func standaloneCommandFlagValue(args []string, name string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return ""
}

func pollStandaloneDevelopmentBuildView(plannedCommand developmentBuildPlanCommand, easBuildID string) ([]byte, map[string]any, error) {
	deadline := time.Now().Add(easBuildTimeout())
	var lastOutput []byte
	var lastRecord map[string]any
	for {
		output, err := runStandaloneDevelopmentBuildCommand(plannedCommand, easBuildID, false)
		if err != nil {
			return output, nil, err
		}
		record, err := decodeStandaloneEASBuildRecord(output)
		if err != nil {
			return output, nil, fmt.Errorf("decode %s JSON: %w", standaloneCommandLabel(plannedCommand.simulatorProofPlanCommand), err)
		}
		lastOutput = output
		lastRecord = record
		if isTerminalEASBuildStatus(readMapString(record, "status")) {
			if err := writeStandaloneCommandArtifact(plannedCommand.StdoutArtifactPath, output, plannedCommand.Env); err != nil {
				return output, nil, err
			}
			return output, record, nil
		}
		if !time.Now().Before(deadline) {
			if err := writeStandaloneCommandArtifact(plannedCommand.StdoutArtifactPath, lastOutput, plannedCommand.Env); err != nil {
				return lastOutput, nil, err
			}
			return lastOutput, lastRecord, fmt.Errorf("EAS build %s did not reach a terminal status before timeout; last status %q", easBuildID, readMapString(lastRecord, "status"))
		}
		time.Sleep(easBuildPollInterval())
	}
}

func decodeStandaloneEASBuildRecord(output []byte) (map[string]any, error) {
	var decoded any
	if err := decodeEASJSONOutput(output, &decoded); err != nil {
		return nil, err
	}
	record, ok := firstEASBuildRecord(decoded)
	if !ok {
		return nil, fmt.Errorf("EAS output did not include a build object")
	}
	return record, nil
}

func runStandaloneDevelopmentBuildCommand(plannedCommand developmentBuildPlanCommand, easBuildID string, interactive bool) ([]byte, error) {
	env, err := resolveStandalonePlanEnv(plannedCommand.Env)
	if err != nil {
		return nil, err
	}
	args := substituteStandaloneCommandArgs(plannedCommand.Args, map[string]string{
		"EAS_BUILD_ID": easBuildID,
	})
	if interactive {
		args = slices.DeleteFunc(args, func(arg string) bool {
			return arg == "--non-interactive" || arg == "--json"
		})
	}
	command := exec.Command(plannedCommand.Command, args...)
	if strings.TrimSpace(plannedCommand.CWD) != "" {
		command.Dir = plannedCommand.CWD
	}
	command.Env = easCommandEnv(os.Environ(), env)
	if interactive {
		command.Env = slices.DeleteFunc(command.Env, func(entry string) bool {
			return strings.HasPrefix(entry, "CI=") || strings.HasPrefix(entry, "EXPO_NO_INTERACTIVE=")
		})
	}
	var output bytes.Buffer
	if interactive {
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
	} else {
		command.Stdout = &output
		command.Stderr = &output
	}
	timeout := easReadinessTimeout()
	if plannedCommand.ID == "eas_build" {
		timeout = easBuildTimeout()
	}
	runErr := error(nil)
	if interactive {
		runErr = runInteractiveCommandWithTimeout(command, timeout)
	} else {
		runErr = runCommandWithTimeout(command, timeout)
	}
	if runErr != nil {
		return output.Bytes(), fmt.Errorf("%s %s failed: %w: %s", plannedCommand.Command, strings.Join(args, " "), runErr, redactCommandOutput(strings.TrimSpace(output.String()), env))
	}
	return output.Bytes(), nil
}

func runInteractiveCommandWithTimeout(command *exec.Cmd, timeout time.Duration) error {
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = command.Process.Kill()
		<-done
		return context.DeadlineExceeded
	}
}

func isTerminalEASBuildStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "errored", "canceled", "cancelled":
		return true
	default:
		return false
	}
}

func easBuildPollInterval() time.Duration {
	return durationFromEnv("PREFLIGHT_EAS_BUILD_POLL_INTERVAL", defaultRunnerPollInterval)
}

func substituteStandaloneCommandArgs(args []string, values map[string]string) []string {
	substituted := make([]string, 0, len(args))
	for _, arg := range args {
		value := arg
		for key, replacement := range values {
			value = strings.ReplaceAll(value, "${"+key+"}", replacement)
		}
		substituted = append(substituted, value)
	}
	return substituted
}

func resolveStandalonePlanEnv(planEnv map[string]string) (map[string]string, error) {
	resolved := make(map[string]string, len(planEnv))
	for key, value := range planEnv {
		secretName, ok := preflightSecretPlaceholder(value)
		if !ok {
			resolved[key] = value
			continue
		}
		secretValue, envName := standaloneSecretValue(secretName)
		if secretValue == "" {
			if secretName == "expoToken" {
				continue
			}
			return nil, fmt.Errorf("missing Preflight secret %s; set %s", secretName, envName)
		}
		resolved[key] = secretValue
	}
	return resolved, nil
}

func preflightSecretPlaceholder(value string) (string, bool) {
	const prefix = "${PREFLIGHT_SECRET:"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, "}") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, prefix), "}"))
	return name, name != ""
}

func standaloneSecretValue(secretName string) (string, string) {
	envKey := camelTokenToEnvKey(secretName)
	candidates := []string{
		envKey,
		"PREFLIGHT_SECRET_" + envKey,
		"PREFLIGHT_SECRET_" + strings.ToUpper(strings.ReplaceAll(secretName, "-", "_")),
	}
	if secretName == "expoToken" {
		candidates = append([]string{"EXPO_TOKEN", "PREFLIGHT_SECRET_EXPO_TOKEN"}, candidates...)
	}
	for _, candidate := range candidates {
		if value := strings.TrimSpace(os.Getenv(candidate)); value != "" {
			return value, candidate
		}
	}
	return "", candidates[0]
}

func camelTokenToEnvKey(value string) string {
	var builder strings.Builder
	for index, char := range value {
		if char >= 'A' && char <= 'Z' && index > 0 {
			builder.WriteByte('_')
		}
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char - 'a' + 'A')
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func writeStandaloneCommandArtifact(path string, output []byte, env map[string]string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	resolvedEnv, _ := resolveStandalonePlanEnv(env)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(redactCommandOutput(string(output), resolvedEnv)), 0o644)
}

func firstEASBuildRecord(decoded any) (map[string]any, bool) {
	record, ok := decoded.(map[string]any)
	if ok {
		return record, true
	}
	builds, ok := decoded.([]any)
	if !ok || len(builds) == 0 {
		return nil, false
	}
	record, ok = builds[0].(map[string]any)
	return record, ok
}

func executeStandaloneSimulatorProofPlan(options proveAppOptions, binding sourceBinding, plan simulatorProofPlanData, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	var longRunning []*exec.Cmd
	defer func() {
		for _, command := range longRunning {
			if command.Process == nil {
				continue
			}
			terminateCommandProcess(command.Process.Pid)
			_ = command.Wait()
		}
	}()

	for _, plannedCommand := range plan.Commands {
		switch plannedCommand.ID {
		case "expo_start":
			command, err := startStandalonePlannedCommand(plannedCommand, stderr)
			if err != nil {
				fmt.Fprintf(stderr, "start %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
				return 1
			}
			longRunning = append(longRunning, command)
			if err := postStandaloneRuntimeState(client, options, binding.AppID, "dev-sessions", mapWith(plan.DevSession, map[string]any{
				"status": "running",
				"pid":    command.Process.Pid,
			})); err != nil {
				fmt.Fprintf(stderr, "post dev session state failed: %v\n", err)
				return 1
			}
		case "open_development_client":
			if err := runStandalonePlannedCommand(plannedCommand, simulatorOpenTimeout(), stderr); err != nil {
				fmt.Fprintf(stderr, "run %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
				return 1
			}
			if err := postStandaloneRuntimeState(client, options, binding.AppID, "target-sessions", mapWith(plan.TargetSession, map[string]any{
				"status": "open",
			})); err != nil {
				fmt.Fprintf(stderr, "post target session state failed: %v\n", err)
				return 1
			}
		case "maestro":
			if err := postStandaloneRuntimeState(client, options, binding.AppID, "target-runs", mapWith(plan.TargetRun, map[string]any{
				"status": "running",
			})); err != nil {
				fmt.Fprintf(stderr, "post target run start failed: %v\n", err)
				return 1
			}
			artifacts := standaloneMaestroArtifacts(plannedCommand, plan.TargetRun)
			if err := runStandalonePlannedCommandWithLog(plannedCommand, maestroSmokeTimeout(), stderr, artifacts.LogPath); err != nil {
				artifacts = collectStandaloneMaestroArtifacts(artifacts)
				_ = postStandaloneMaestroArtifacts(client, options, binding.AppID, plan.TargetRun, artifacts)
				_ = postStandaloneRuntimeState(client, options, binding.AppID, "target-runs", mapWith(plan.TargetRun, map[string]any{
					"status":        "failed",
					"completedAt":   time.Now().UTC().Format(time.RFC3339Nano),
					"resultSummary": standaloneMaestroResultSummary(artifacts, map[string]any{"error": err.Error()}),
					"metadata":      standaloneMaestroMetadata(plan.TargetRun, artifacts),
				}))
				fmt.Fprintf(stderr, "run %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
				return 1
			}
			artifacts = collectStandaloneMaestroArtifacts(artifacts)
			if err := postStandaloneMaestroArtifacts(client, options, binding.AppID, plan.TargetRun, artifacts); err != nil {
				_ = postStandaloneRuntimeState(client, options, binding.AppID, "target-runs", mapWith(plan.TargetRun, map[string]any{
					"status":        "failed",
					"completedAt":   time.Now().UTC().Format(time.RFC3339Nano),
					"resultSummary": standaloneMaestroResultSummary(artifacts, map[string]any{"error": err.Error()}),
					"metadata":      standaloneMaestroMetadata(plan.TargetRun, artifacts),
				}))
				fmt.Fprintf(stderr, "post Maestro artifacts failed: %v\n", err)
				return 1
			}
			if err := postStandaloneRuntimeState(client, options, binding.AppID, "target-runs", mapWith(plan.TargetRun, map[string]any{
				"status":        "passed",
				"completedAt":   time.Now().UTC().Format(time.RFC3339Nano),
				"resultSummary": standaloneMaestroResultSummary(artifacts, map[string]any{}),
				"metadata":      standaloneMaestroMetadata(plan.TargetRun, artifacts),
			})); err != nil {
				fmt.Fprintf(stderr, "post target run completion failed: %v\n", err)
				return 1
			}
		default:
			if plannedCommand.Kind == "long_running" {
				command, err := startStandalonePlannedCommand(plannedCommand, stderr)
				if err != nil {
					fmt.Fprintf(stderr, "start %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
					return 1
				}
				longRunning = append(longRunning, command)
				continue
			}
			if err := runStandalonePlannedCommand(plannedCommand, simulatorOpenTimeout(), stderr); err != nil {
				fmt.Fprintf(stderr, "run %s failed: %v\n", standaloneCommandLabel(plannedCommand), err)
				return 1
			}
		}
	}
	fmt.Fprintf(stdout, "simulator proof run %s passed\n", plan.WorkflowID)
	return 0
}

type standaloneMaestroRunArtifacts struct {
	ReportPath      string
	OutputDir       string
	LogPath         string
	CommandPaths    []string
	ScreenshotPaths []string
	VideoPaths      []string
}

func standaloneMaestroArtifacts(command simulatorProofPlanCommand, targetRun map[string]any) standaloneMaestroRunArtifacts {
	artifacts := standaloneMaestroRunArtifacts{
		ReportPath: readMapString(targetRun, "reportArtifactId"),
	}
	for index := 0; index < len(command.Args); index += 1 {
		switch command.Args[index] {
		case "--output":
			if index+1 < len(command.Args) {
				artifacts.ReportPath = command.Args[index+1]
				index += 1
			}
		case "--test-output-dir", "--debug-output":
			if index+1 < len(command.Args) && artifacts.OutputDir == "" {
				artifacts.OutputDir = command.Args[index+1]
				index += 1
			}
		}
	}
	if artifacts.OutputDir == "" {
		if metadata, ok := targetRun["metadata"].(map[string]any); ok {
			artifacts.OutputDir = readMapString(metadata, "testOutputDirectory")
		}
	}
	if artifacts.ReportPath != "" {
		artifacts.LogPath = filepath.Join(filepath.Dir(artifacts.ReportPath), "maestro.log")
	} else if artifacts.OutputDir != "" {
		artifacts.LogPath = filepath.Join(filepath.Dir(artifacts.OutputDir), "maestro.log")
	}
	return artifacts
}

func collectStandaloneMaestroArtifacts(artifacts standaloneMaestroRunArtifacts) standaloneMaestroRunArtifacts {
	artifacts.CommandPaths = findFilesWithPrefixAndExtension(artifacts.OutputDir, "commands-", ".json")
	artifacts.ScreenshotPaths = findFilesWithExtensions(artifacts.OutputDir, ".png")
	artifacts.VideoPaths = findFilesWithExtensions(artifacts.OutputDir, ".mp4", ".mov")
	return artifacts
}

func standaloneMaestroResultSummary(artifacts standaloneMaestroRunArtifacts, base map[string]any) map[string]any {
	summary := make(map[string]any, len(base)+2)
	for key, value := range base {
		summary[key] = value
	}
	if artifacts.ReportPath != "" {
		summary["reportPath"] = artifacts.ReportPath
	}
	if artifacts.OutputDir != "" {
		summary["outputDir"] = artifacts.OutputDir
	}
	return summary
}

func standaloneMaestroMetadata(targetRun map[string]any, artifacts standaloneMaestroRunArtifacts) map[string]any {
	metadata := map[string]any{}
	if existing, ok := targetRun["metadata"].(map[string]any); ok {
		for key, value := range existing {
			metadata[key] = value
		}
	}
	if artifacts.OutputDir != "" {
		metadata["testOutputDirectory"] = artifacts.OutputDir
	}
	if artifacts.LogPath != "" {
		metadata["logPath"] = artifacts.LogPath
	}
	if len(artifacts.CommandPaths) > 0 {
		metadata["commandPaths"] = append([]string{}, artifacts.CommandPaths...)
	}
	if len(artifacts.ScreenshotPaths) > 0 {
		metadata["screenshotPaths"] = append([]string{}, artifacts.ScreenshotPaths...)
	}
	if len(artifacts.VideoPaths) > 0 {
		metadata["videoPaths"] = append([]string{}, artifacts.VideoPaths...)
	}
	return metadata
}

func postStandaloneMaestroArtifacts(client *http.Client, options proveAppOptions, appID string, targetRun map[string]any, artifacts standaloneMaestroRunArtifacts) error {
	metadata := standaloneMaestroMetadata(targetRun, artifacts)
	for _, artifact := range standaloneMaestroArtifactUploads(artifacts) {
		if strings.TrimSpace(artifact.URI) == "" {
			continue
		}
		payload := map[string]any{
			"kind":           artifact.Kind,
			"uri":            artifact.URI,
			"retentionClass": "diagnostic",
			"redacted":       true,
			"metadata":       metadata,
		}
		for key, value := range map[string]string{
			"targetRunId": readMapString(targetRun, "id"),
			"workflowId":  readMapString(targetRun, "workflowId"),
			"runnerJobId": readMapString(targetRun, "runnerJobId"),
			"targetId":    readMapString(targetRun, "targetId"),
		} {
			if strings.TrimSpace(value) != "" {
				payload[key] = value
			}
		}
		if contentType := standaloneArtifactContentType(artifact.URI); contentType != "" {
			payload["contentType"] = contentType
		}
		if sizeBytes, ok := artifactSizeBytes(artifact.URI); ok {
			payload["sizeBytes"] = sizeBytes
		}
		if err := postStandaloneRuntimeState(client, options, appID, "runtime-artifacts", payload); err != nil {
			return err
		}
	}
	return nil
}

func standaloneMaestroArtifactUploads(artifacts standaloneMaestroRunArtifacts) []runnerArtifactUpload {
	uploads := []runnerArtifactUpload{
		{Kind: "maestro_report", URI: artifacts.ReportPath},
		{Kind: "log", URI: artifacts.LogPath},
	}
	for _, path := range artifacts.CommandPaths {
		uploads = append(uploads, runnerArtifactUpload{Kind: "tool_output", URI: path})
	}
	for _, path := range artifacts.ScreenshotPaths {
		uploads = append(uploads, runnerArtifactUpload{Kind: "screenshot", URI: path})
	}
	for _, path := range artifacts.VideoPaths {
		uploads = append(uploads, runnerArtifactUpload{Kind: "video", URI: path})
	}
	return uploads
}

func standaloneArtifactContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".log", ".txt":
		return "text/plain"
	case ".xml":
		return "application/xml"
	case ".png":
		return "image/png"
	case ".mp4":
		return "video/mp4"
	case ".mov":
		return "video/quicktime"
	default:
		return ""
	}
}

func startStandalonePlannedCommand(plannedCommand simulatorProofPlanCommand, stderr io.Writer) (*exec.Cmd, error) {
	command := standalonePlannedExecCommand(plannedCommand, stderr)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command, nil
}

func startStandaloneObservedPlannedCommand(plannedCommand simulatorProofPlanCommand, stderr io.Writer, startupTimeout time.Duration) (*exec.Cmd, error) {
	command, _, err := startStandaloneObservedPlannedCommandWithOutput(plannedCommand, stderr, startupTimeout)
	return command, err
}

func startStandaloneObservedPlannedCommandWithOutput(plannedCommand simulatorProofPlanCommand, stderr io.Writer, startupTimeout time.Duration) (*exec.Cmd, string, error) {
	command := standalonePlannedExecCommandWithoutOutput(plannedCommand)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	stderrPipe, err := command.StderrPipe()
	if err != nil {
		return nil, "", err
	}
	if err := command.Start(); err != nil {
		return nil, "", err
	}

	capturedOutput := &synchronizedBuffer{}
	outputWriter := io.MultiWriter(stderr, capturedOutput)
	outputSeen := make(chan struct{})
	outputClosed := make(chan struct{}, 2)
	signalOutput := sync.Once{}
	go copyCommandOutput(outputWriter, stdoutPipe, outputSeen, outputClosed, &signalOutput)
	go copyCommandOutput(outputWriter, stderrPipe, outputSeen, outputClosed, &signalOutput)

	timeout := time.NewTimer(startupTimeout)
	defer timeout.Stop()
	closedPipes := 0
	for {
		select {
		case <-outputSeen:
			return command, capturedOutput.String(), nil
		case <-outputClosed:
			closedPipes += 1
			if closedPipes == 2 {
				terminateProcessGroup(command)
				return nil, capturedOutput.String(), fmt.Errorf("%s exited before emitting startup output", standaloneCommandLabel(plannedCommand))
			}
		case <-timeout.C:
			terminateProcessGroup(command)
			return nil, capturedOutput.String(), fmt.Errorf("%s did not emit startup output within %s", standaloneCommandLabel(plannedCommand), startupTimeout)
		}
	}
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(chunk []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(chunk)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func copyCommandOutput(dst io.Writer, src io.Reader, outputSeen chan<- struct{}, outputClosed chan<- struct{}, signalOutput *sync.Once) {
	defer func() {
		outputClosed <- struct{}{}
	}()
	buffer := make([]byte, 32*1024)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			_, _ = dst.Write(buffer[:n])
			signalOutput.Do(func() {
				close(outputSeen)
			})
		}
		if err != nil {
			return
		}
	}
}

func runStandalonePlannedCommand(plannedCommand simulatorProofPlanCommand, timeout time.Duration, stderr io.Writer) error {
	command := standalonePlannedExecCommand(plannedCommand, stderr)
	return runCommandWithTimeout(command, timeout)
}

func runStandalonePlannedCommandWithLog(plannedCommand simulatorProofPlanCommand, timeout time.Duration, stderr io.Writer, logPath string) error {
	if strings.TrimSpace(logPath) == "" {
		return runStandalonePlannedCommand(plannedCommand, timeout, stderr)
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	_, _ = fmt.Fprintf(logFile, "$ %s %s\n", plannedCommand.Command, strings.Join(plannedCommand.Args, " "))
	command := standalonePlannedExecCommand(plannedCommand, io.MultiWriter(stderr, logFile))
	return runCommandWithTimeout(command, timeout)
}

func standalonePlannedExecCommand(plannedCommand simulatorProofPlanCommand, stderr io.Writer) *exec.Cmd {
	command := standalonePlannedExecCommandWithoutOutput(plannedCommand)
	command.Stdout = stderr
	command.Stderr = stderr
	return command
}

func standalonePlannedExecCommandWithoutOutput(plannedCommand simulatorProofPlanCommand) *exec.Cmd {
	command := exec.Command(plannedCommand.Command, plannedCommand.Args...)
	if strings.TrimSpace(plannedCommand.CWD) != "" {
		command.Dir = plannedCommand.CWD
	}
	command.Env = upsertEnvValues(os.Environ(), plannedCommand.Env)
	return command
}

func standaloneCommandLabel(plannedCommand simulatorProofPlanCommand) string {
	if strings.TrimSpace(plannedCommand.ID) != "" {
		return plannedCommand.ID
	}
	if strings.TrimSpace(plannedCommand.Command) != "" {
		return plannedCommand.Command
	}
	return "planned command"
}

func postStandaloneRuntimeState(client *http.Client, options proveAppOptions, appID string, collection string, payload map[string]any) error {
	_, err := postStandaloneRuntimeStateData(client, options, appID, collection, payload)
	return err
}

func postStandaloneRuntimeStateData(client *http.Client, options proveAppOptions, appID string, collection string, payload map[string]any) (json.RawMessage, error) {
	endpoint := runnerEndpoint(
		options.apiURL,
		"/api/preflight/v1/apps/"+url.PathEscape(appID)+"/"+collection,
	)
	return postPreflightWorkspaceJSON(client, endpoint, options.token, options.workspaceID, payload)
}

func mapWith(base map[string]any, overrides map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(overrides))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range overrides {
		merged[key] = value
	}
	return merged
}

type preflightCapabilitiesData struct {
	APIVersion                string   `json:"apiVersion"`
	SupportedContractVersions []string `json:"supportedContractVersions"`
	Auth                      struct {
		Authenticated bool `json:"authenticated"`
	} `json:"auth"`
}

func verifyPreflightAPICompatibility(client *http.Client, apiURL string, token string) error {
	endpoint := runnerEndpoint(apiURL, "/api/preflight/v1/capabilities")
	data, err := getPreflightJSON(client, endpoint, token)
	if err != nil {
		return fmt.Errorf(
			"api_unreachable: Preflight capability probe failed: %w\nnext: preflight capabilities --api-url %s",
			err,
			strings.TrimRight(apiURL, "/"),
		)
	}

	var capabilities preflightCapabilitiesData
	if err := decodeEnvelopeData(data, &capabilities); err != nil {
		return fmt.Errorf(
			"api_incompatible: Preflight capability response could not be decoded: %w\nnext: point PREFLIGHT_API_URL at a ForgeGraph Preflight API that serves contract %s",
			err,
			contractVersion,
		)
	}
	if capabilities.APIVersion != "v1" {
		return fmt.Errorf(
			"api_incompatible: Preflight API version %q is not supported by this CLI\nnext: point PREFLIGHT_API_URL at /api/preflight/v1 or upgrade the preflight CLI",
			capabilities.APIVersion,
		)
	}
	if !capabilities.Auth.Authenticated {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf(
				"auth_required: Preflight API authentication is required before creating workflows\nnext: preflight login --api-url %s --token-env PREFLIGHT_TOKEN",
				strings.TrimRight(apiURL, "/"),
			)
		}
		return fmt.Errorf(
			"auth_required: Preflight API rejected the configured token\nnext: refresh the token and run preflight login --api-url %s --token-env PREFLIGHT_TOKEN",
			strings.TrimRight(apiURL, "/"),
		)
	}
	if !supportsContractVersion(capabilities.SupportedContractVersions, contractVersion) {
		return fmt.Errorf(
			"api_incompatible: Preflight API does not advertise contract %s\nnext: upgrade ForgeGraph Preflight API or use a matching preflight CLI",
			contractVersion,
		)
	}
	return nil
}

func supportsContractVersion(versions []string, expected string) bool {
	for _, version := range versions {
		if version == expected {
			return true
		}
	}
	return false
}

type preflightRunnerCapacityData struct {
	Capacity preflightRunnerCapacity `json:"capacity"`
}

type preflightRunnerCapacity struct {
	Status              string   `json:"status"`
	WorkspaceID         string   `json:"workspaceId"`
	MatchingRunnerCount int      `json:"matchingRunnerCount"`
	RunnerIDs           []string `json:"runnerIds"`
	NextAction          string   `json:"nextAction"`
}

func verifyPreflightRunnerCapacity(client *http.Client, options proveAppOptions, binding sourceBinding) error {
	endpoint, err := preflightRunnerCapacityEndpoint(options, binding)
	if err != nil {
		return fmt.Errorf("runner_required: build runner capacity request: %w", err)
	}
	data, err := getPreflightJSON(client, endpoint, options.token)
	if err != nil {
		return fmt.Errorf(
			"runner_required: Preflight runner capacity probe failed: %w\nnext: %s",
			err,
			preflightRunnerStartCommand(options, binding),
		)
	}
	var capacityData preflightRunnerCapacityData
	if err := decodeEnvelopeData(data, &capacityData); err != nil {
		return fmt.Errorf(
			"runner_required: Preflight runner capacity response could not be decoded: %w\nnext: %s",
			err,
			preflightRunnerStartCommand(options, binding),
		)
	}
	if capacityData.Capacity.Status == "ready" {
		return nil
	}
	code := capacityData.Capacity.Status
	if code == "" {
		code = "runner_required"
	}
	nextAction := capacityData.Capacity.NextAction
	if nextAction == "" {
		nextAction = preflightRunnerStartCommand(options, binding)
	}
	return fmt.Errorf(
		"%s: no active Preflight runner can access %s\nnext: %s",
		code,
		binding.WorkspaceRoot,
		nextAction,
	)
}

func preflightRunnerCapacityEndpoint(options proveAppOptions, binding sourceBinding) (string, error) {
	parsed, err := url.Parse(runnerEndpoint(options.apiURL, "/api/preflight/v1/runners/capacity"))
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("workspaceId", options.workspaceID)
	query.Set("workspaceRoot", binding.WorkspaceRoot)
	query.Set("platform", options.platform)
	query.Set("lane", options.lane)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func preflightRunnerStartCommand(options proveAppOptions, binding sourceBinding) string {
	return fmt.Sprintf(
		"preflight runner --api-url %s --workspace-id %s --workspace-root %s",
		strings.TrimRight(options.apiURL, "/"),
		options.workspaceID,
		binding.WorkspaceRoot,
	)
}

type proveAppCreateEnvelope struct {
	Data proveAppCreateData `json:"data"`
}

type proveAppCreateData struct {
	Workflow proveAppWorkflowSummary `json:"workflow"`
}

type proveAppWorkflowRead struct {
	Workflow           proveAppWorkflowSummary    `json:"workflow"`
	WorkflowProjection proveAppWorkflowProjection `json:"workflowProjection"`
}

type proveAppWorkflowSummary struct {
	ID       string `json:"id"`
	AppID    string `json:"appId"`
	Status   string `json:"status"`
	Platform string `json:"platform"`
	Lane     string `json:"lane"`
}

type proveAppWorkflowProjection struct {
	WorkflowID     string `json:"workflowId"`
	Status         string `json:"status"`
	Phase          string `json:"phase"`
	BlockerCode    string `json:"blockerCode"`
	BlockerMessage string `json:"blockerMessage"`
}

func watchProveAppWorkflow(options proveAppOptions, workflowID string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if code, completed := watchProveAppWorkflowSSE(options, workflowID, stdout, stderr, client); completed {
		return code
	}
	return pollProveAppWorkflow(options, workflowID, stdout, stderr, client)
}

func watchProveAppWorkflowSSE(options proveAppOptions, workflowID string, stdout io.Writer, stderr io.Writer, client *http.Client) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), options.watchTimeout)
	defer cancel()
	endpoint := strings.TrimRight(options.apiURL, "/") + "/api/preflight/v1/workflows/" + workflowID + "/events"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		fmt.Fprintf(stderr, "invalid Preflight API URL: %v\n", err)
		return 1, true
	}
	request.Header.Set("Accept", "text/event-stream")
	if options.token != "" {
		request.Header.Set("Authorization", "Bearer "+options.token)
	}

	response, err := client.Do(request)
	if err != nil {
		return 0, false
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, false
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
		return 0, false
	}

	lastLine := ""
	status, err := readProveAppWorkflowSSE(response.Body, workflowID, &lastLine, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "prove-app workflow event stream failed: %v\n", err)
		return 1, true
	}
	if isTerminalWorkflowStatus(status) {
		if status == "failed" || status == "cancelled" {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func pollProveAppWorkflow(options proveAppOptions, workflowID string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	deadline := time.Now().Add(options.watchTimeout)
	endpoint := strings.TrimRight(options.apiURL, "/") + "/api/preflight/v1/workflows/" + workflowID
	lastLine := ""

	for {
		data, err := getPreflightJSON(client, endpoint, options.token)
		if err != nil {
			fmt.Fprintf(stderr, "prove-app workflow watch failed: %v\n", err)
			return 1
		}
		var read proveAppWorkflowRead
		if err := decodeEnvelopeData(data, &read); err != nil {
			fmt.Fprintf(stderr, "failed to decode workflow watch response: %v\n", err)
			return 1
		}

		status := read.WorkflowProjection.Status
		if status == "" {
			status = read.Workflow.Status
		}
		phase := read.WorkflowProjection.Phase
		line := proveAppWatchLine(workflowID, status, phase)
		if line != lastLine {
			fmt.Fprintln(stdout, line)
			lastLine = line
		}

		if isTerminalWorkflowStatus(status) {
			if status == "failed" || status == "cancelled" {
				return 1
			}
			return 0
		}
		if !time.Now().Before(deadline) {
			fmt.Fprintf(stderr, "prove-app workflow watch timed out after %s\n", options.watchTimeout)
			return 1
		}
		time.Sleep(options.pollInterval)
	}
}

type proveAppSSEData struct {
	WorkflowID         string                     `json:"workflowId"`
	WorkflowProjection proveAppWorkflowProjection `json:"workflowProjection"`
}

func readProveAppWorkflowSSE(body io.Reader, workflowID string, lastLine *string, stdout io.Writer) (string, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var dataLines []string
	lastStatus := ""
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			status, err := handleProveAppSSEData(dataLines, workflowID, lastLine, stdout)
			dataLines = nil
			if err != nil {
				return "", err
			}
			if status != "" {
				lastStatus = status
				if isTerminalWorkflowStatus(status) {
					return status, nil
				}
			}
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	status, err := handleProveAppSSEData(dataLines, workflowID, lastLine, stdout)
	if err != nil {
		return "", err
	}
	if status != "" {
		return status, nil
	}
	return lastStatus, nil
}

func handleProveAppSSEData(dataLines []string, fallbackWorkflowID string, lastLine *string, stdout io.Writer) (string, error) {
	if len(dataLines) == 0 {
		return "", nil
	}
	var data proveAppSSEData
	if err := json.Unmarshal([]byte(strings.Join(dataLines, "\n")), &data); err != nil {
		return "", err
	}
	status := data.WorkflowProjection.Status
	if status == "" {
		return "", nil
	}
	workflowID := data.WorkflowID
	if workflowID == "" {
		workflowID = fallbackWorkflowID
	}
	line := proveAppWatchLine(workflowID, status, data.WorkflowProjection.Phase)
	if line != *lastLine {
		fmt.Fprintln(stdout, line)
		*lastLine = line
	}
	return status, nil
}

func proveAppWatchLine(workflowID string, status string, phase string) string {
	if phase == "" {
		return fmt.Sprintf("workflow %s %s", workflowID, status)
	}
	return fmt.Sprintf("workflow %s %s %s", workflowID, status, phase)
}

func isTerminalWorkflowStatus(status string) bool {
	switch status {
	case "passed", "passed_with_warnings", "failed", "cancelled":
		return true
	default:
		return false
	}
}

type sourceBinding struct {
	AppID               string   `json:"appId"`
	PackageName         string   `json:"packageName"`
	PackageManager      string   `json:"packageManager"`
	WorkspaceRoot       string   `json:"workspaceRoot"`
	PackagePath         string   `json:"packagePath"`
	WorkflowIntent      string   `json:"workflowIntent"`
	BuildStrategy       string   `json:"buildStrategy,omitempty"`
	Platform            string   `json:"platform"`
	Lane                string   `json:"lane"`
	ExpoConfigDigest    string   `json:"expoConfigDigest"`
	EASJSONDigest       string   `json:"easJsonDigest,omitempty"`
	EASProfileName      string   `json:"easProfileName,omitempty"`
	EASProfileEnvDigest string   `json:"easProfileEnvDigest,omitempty"`
	AppScheme           string   `json:"appScheme,omitempty"`
	ExpoSlug            string   `json:"expoSlug,omitempty"`
	IOSBundleID         string   `json:"iosBundleId,omitempty"`
	AndroidPackage      string   `json:"androidPackage,omitempty"`
	EASProjectID        string   `json:"easProjectId,omitempty"`
	GitRemoteURL        string   `json:"gitRemoteUrl,omitempty"`
	GitBranch           string   `json:"gitBranch,omitempty"`
	GitCommitSHA        string   `json:"gitCommitSha,omitempty"`
	DirtyWorkspace      bool     `json:"dirtyWorkspace"`
	ChangedSetupFiles   []string `json:"changedSetupFiles"`
}

type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Main            string            `json:"main"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type easJSON struct {
	Build map[string]easBuildProfile `json:"build"`
}

type easBuildProfile struct {
	Extends           string                 `json:"extends"`
	DevelopmentClient *bool                  `json:"developmentClient"`
	Distribution      string                 `json:"distribution"`
	Env               map[string]string      `json:"env"`
	IOS               easBuildIOSProfile     `json:"ios"`
	Android           easBuildAndroidProfile `json:"android"`
}

type easBuildIOSProfile struct {
	Simulator *bool             `json:"simulator"`
	Env       map[string]string `json:"env"`
}

type easBuildAndroidProfile struct {
	BuildType string            `json:"buildType"`
	Env       map[string]string `json:"env"`
}

type selectedEASProfile struct {
	name      string
	env       map[string]string
	envDigest string
}

type expoAppIdentity struct {
	name           string
	scheme         string
	slug           string
	iosBundleID    string
	androidPackage string
	easProjectID   string
}

func readPackageJSON(path string) (packageJSON, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return packageJSON{}, err
	}
	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return packageJSON{}, err
	}
	return pkg, nil
}

func loadEASJSON(appDir string) (easJSON, error) {
	content, err := os.ReadFile(filepath.Join(appDir, "eas.json"))
	if err != nil {
		return easJSON{}, err
	}
	var config easJSON
	if err := json.Unmarshal(content, &config); err != nil {
		return easJSON{}, err
	}
	if config.Build == nil {
		config.Build = map[string]easBuildProfile{}
	}
	config.Build = resolveEASBuildProfiles(config.Build)
	return config, nil
}

func resolveEASBuildProfiles(build map[string]easBuildProfile) map[string]easBuildProfile {
	resolved := make(map[string]easBuildProfile, len(build))
	for name := range build {
		profile, ok := resolveEASBuildProfile(build, name, map[string]bool{}, 0)
		if !ok {
			profile = build[name]
		}
		profile.Extends = ""
		resolved[name] = profile
	}
	return resolved
}

func resolveEASBuildProfile(build map[string]easBuildProfile, name string, visiting map[string]bool, depth int) (easBuildProfile, bool) {
	profile, ok := build[name]
	if !ok {
		return easBuildProfile{}, false
	}
	parentName := strings.TrimSpace(profile.Extends)
	if parentName == "" {
		return profile, true
	}
	if depth >= 5 || visiting[name] {
		return profile, false
	}
	visiting[name] = true
	parent, ok := resolveEASBuildProfile(build, parentName, visiting, depth+1)
	delete(visiting, name)
	if !ok {
		return profile, true
	}
	return mergeEASBuildProfiles(parent, profile), true
}

func mergeEASBuildProfiles(base easBuildProfile, override easBuildProfile) easBuildProfile {
	merged := base
	merged.Extends = ""
	if override.DevelopmentClient != nil {
		merged.DevelopmentClient = override.DevelopmentClient
	}
	if override.Distribution != "" {
		merged.Distribution = override.Distribution
	}
	merged.Env = mergeStringMap(base.Env, override.Env)
	merged.IOS = mergeEASBuildIOSProfiles(base.IOS, override.IOS)
	merged.Android = mergeEASBuildAndroidProfiles(base.Android, override.Android)
	return merged
}

func mergeEASBuildIOSProfiles(base easBuildIOSProfile, override easBuildIOSProfile) easBuildIOSProfile {
	merged := base
	if override.Simulator != nil {
		merged.Simulator = override.Simulator
	}
	merged.Env = mergeStringMap(base.Env, override.Env)
	return merged
}

func mergeEASBuildAndroidProfiles(base easBuildAndroidProfile, override easBuildAndroidProfile) easBuildAndroidProfile {
	merged := base
	if override.BuildType != "" {
		merged.BuildType = override.BuildType
	}
	merged.Env = mergeStringMap(base.Env, override.Env)
	return merged
}

func mergeStringMap(base map[string]string, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(map[string]string, len(base)+len(override))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func readExpoAppIdentity(appDir string) expoAppIdentity {
	for _, name := range []string{"app.config.ts", "app.config.js", "app.json"} {
		content, err := os.ReadFile(filepath.Join(appDir, name))
		if err != nil {
			continue
		}
		if name == "app.json" {
			var appJSON map[string]any
			if err := json.Unmarshal(content, &appJSON); err == nil {
				config := appJSON
				if expo, ok := appJSON["expo"].(map[string]any); ok {
					config = expo
				}
				return expoAppIdentity{
					name:           readMapString(config, "name"),
					scheme:         readMapString(config, "scheme"),
					slug:           readMapString(config, "slug"),
					iosBundleID:    readNestedMapString(config, "ios", "bundleIdentifier"),
					androidPackage: readNestedMapString(config, "android", "package"),
					easProjectID:   readNestedMapString(config, "extra", "eas", "projectId"),
				}
			}
		}
		return expoAppIdentity{
			name:           extractQuotedConfigProperty(string(content), "name"),
			scheme:         extractQuotedConfigProperty(string(content), "scheme"),
			slug:           extractQuotedConfigProperty(string(content), "slug"),
			iosBundleID:    extractQuotedConfigProperty(string(content), "bundleIdentifier"),
			androidPackage: extractQuotedConfigProperty(string(content), "package"),
			easProjectID:   extractQuotedConfigProperty(string(content), "projectId"),
		}
	}
	return expoAppIdentity{}
}

func readNestedMapString(record map[string]any, keys ...string) string {
	var current any = record
	for _, key := range keys {
		currentMap, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = currentMap[key]
	}
	value, _ := current.(string)
	return value
}

type expoConfigResolution struct {
	identity expoAppIdentity
	digest   string
}

func resolveExpoConfig(appDir string, env map[string]string) expoConfigResolution {
	// The digest MUST be computed the same way every time, on every machine, so a
	// source binding recorded at prove-app validates on any runner. Always digest
	// the raw expo config FILE: it is deterministic and independent of whether
	// `npx expo config` succeeds (it can flake/timeout) and of expo version/env —
	// previously a CLI success digested the evaluated JSON while a CLI failure fell
	// back to the file, so prove and validate could disagree on identical source
	// and fail with a spurious source_binding_mismatch. The evaluated config is
	// still used (when available) for the app identity, which genuinely needs it.
	fileDigest := digestIfExists(expoConfigPath(appDir))
	if config, ok := resolveExpoConfigWithExpoCLI(appDir, env); ok {
		return expoConfigResolution{
			identity: expoIdentityFromConfig(config),
			digest:   fileDigest,
		}
	}
	return expoConfigResolution{
		identity: readExpoAppIdentity(appDir),
		digest:   fileDigest,
	}
}

func resolveExpoConfigWithExpoCLI(appDir string, env map[string]string) (map[string]any, bool) {
	if !shouldUseExpoConfigCLI(appDir) {
		return nil, false
	}
	command := exec.Command("npx", "expo", "config", "--json", "--type", "public")
	command.Dir = appDir
	command.Env = expoConfigCommandEnv(os.Environ(), env)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := runCommandWithTimeout(command, expoConfigTimeout()); err != nil {
		return nil, false
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &decoded); err != nil {
		return nil, false
	}
	return normalizeExpoConfigRecord(decoded), true
}

func shouldUseExpoConfigCLI(appDir string) bool {
	if strings.TrimSpace(os.Getenv("PREFLIGHT_FORCE_EXPO_CONFIG_CLI")) == "1" {
		return true
	}
	current := appDir
	for {
		if fileExists(filepath.Join(current, "node_modules", ".bin", "expo")) {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}

func expoConfigCommandEnv(base []string, env map[string]string) []string {
	values := map[string]string{
		"EXPO_NO_INTERACTIVE": "1",
		"EXPO_NO_TELEMETRY":   "1",
	}
	for key, value := range env {
		values[key] = value
	}
	return upsertEnvValues(base, values)
}

func normalizeExpoConfigRecord(decoded map[string]any) map[string]any {
	if expo, ok := decoded["expo"].(map[string]any); ok {
		return expo
	}
	return decoded
}

func expoIdentityFromConfig(config map[string]any) expoAppIdentity {
	return expoAppIdentity{
		name:           readMapString(config, "name"),
		scheme:         readMapString(config, "scheme"),
		slug:           readMapString(config, "slug"),
		iosBundleID:    readNestedMapString(config, "ios", "bundleIdentifier"),
		androidPackage: readNestedMapString(config, "android", "package"),
		easProjectID:   readNestedMapString(config, "extra", "eas", "projectId"),
	}
}

func extractQuotedConfigProperty(content string, property string) string {
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(property) + `\s*:\s*["']([^"']+)["']`)
	matches := pattern.FindStringSubmatch(content)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func buildAllRequiredOAuthClientConfigurePayloads(options map[string]string, redirectURIs []string, javascriptOrigins []string, scopes []string, secretRefs []string) ([]map[string]any, error) {
	absoluteAppDir, err := filepath.Abs(options["appDir"])
	if err != nil {
		return nil, fmt.Errorf("resolve app directory: %w", err)
	}

	pkg, err := readPackageJSON(filepath.Join(absoluteAppDir, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("package.json not found in %s", absoluteAppDir)
	}
	if !isExpoPackage(pkg) {
		return nil, fmt.Errorf("%s is not an Expo app package", absoluteAppDir)
	}

	appID := strings.TrimSpace(options["appId"])
	if appID == "" {
		appID = "pfapp_" + sanitizeID(pkg.Name)
	}

	easConfig, _ := loadEASJSON(absoluteAppDir)
	iosIdentity := resolveExpoConfig(absoluteAppDir, selectEASProfile(easConfig, "ios", "development").env).identity
	androidIdentity := resolveExpoConfig(absoluteAppDir, selectEASProfile(easConfig, "android", "development").env).identity
	appName := strings.TrimSpace(iosIdentity.name)
	if appName == "" {
		appName = androidIdentity.name
	}

	basePayload := func(provider string, clientKind string, identity expoAppIdentity) map[string]any {
		payload := map[string]any{
			"workspaceId":        options["workspaceId"],
			"appId":              appID,
			"provider":           provider,
			"clientKind":         clientKind,
			"displayName":        defaultOAuthClientConfigureDisplayName(appName, pkg.Name, clientKind),
			"secretReferenceIds": append([]string{}, secretRefs...),
		}
		if options["providerAccountId"] != "" {
			payload["providerAccountId"] = options["providerAccountId"]
		}
		if options["providerDisplayName"] != "" {
			payload["providerDisplayName"] = options["providerDisplayName"]
		}
		if provider == "google_oauth" {
			payload["scopes"] = append([]string{}, scopes...)
			if options["googleCloudProjectId"] != "" {
				payload["googleCloudProjectId"] = options["googleCloudProjectId"]
			}
		}
		if provider == "apple_oauth" && options["appleTeamId"] != "" {
			payload["appleTeamId"] = options["appleTeamId"]
		}

		switch clientKind {
		case "google_ios", "apple_app_id":
			payload["bundleId"] = identity.iosBundleID
		case "google_android":
			payload["androidPackage"] = identity.androidPackage
			if options["androidSha1Fingerprint"] != "" {
				payload["androidSha1Fingerprint"] = options["androidSha1Fingerprint"]
			}
		case "google_web":
			payload["redirectUris"] = append([]string{}, redirectURIs...)
			payload["javascriptOrigins"] = append([]string{}, javascriptOrigins...)
		case "apple_services_id":
			payload["bundleId"] = identity.iosBundleID
			payload["redirectUris"] = append([]string{}, redirectURIs...)
			if options["appleServicesId"] != "" {
				payload["appleServicesId"] = options["appleServicesId"]
			}
		}

		return payload
	}

	return []map[string]any{
		basePayload("google_oauth", "google_ios", iosIdentity),
		basePayload("apple_oauth", "apple_app_id", iosIdentity),
		basePayload("google_oauth", "google_android", androidIdentity),
		basePayload("google_oauth", "google_web", iosIdentity),
		basePayload("apple_oauth", "apple_services_id", iosIdentity),
	}, nil
}

func applyOAuthClientConfigureAppDefaults(options map[string]string) error {
	absoluteAppDir, err := filepath.Abs(options["appDir"])
	if err != nil {
		return fmt.Errorf("resolve app directory: %w", err)
	}

	pkg, err := readPackageJSON(filepath.Join(absoluteAppDir, "package.json"))
	if err != nil {
		return fmt.Errorf("package.json not found in %s", absoluteAppDir)
	}
	if !isExpoPackage(pkg) {
		return fmt.Errorf("%s is not an Expo app package", absoluteAppDir)
	}

	if strings.TrimSpace(options["appId"]) == "" {
		options["appId"] = "pfapp_" + sanitizeID(pkg.Name)
	}

	platform, err := normalizeOAuthClientConfigurePlatform(options["platform"], options["clientKind"])
	if err != nil {
		return err
	}
	if strings.TrimSpace(options["clientKind"]) == "" {
		if clientKind, ok := defaultOAuthClientKindForPlatform(options["provider"], platform); ok {
			options["clientKind"] = clientKind
		}
	}

	easConfig, _ := loadEASJSON(absoluteAppDir)
	selectedProfile := selectedEASProfile{}
	if platform != "" {
		selectedProfile = selectEASProfile(easConfig, platform, "development")
	}
	appIdentity := resolveExpoConfig(absoluteAppDir, selectedProfile.env).identity
	applyOAuthClientIdentityDefaults(options, appIdentity)

	if strings.TrimSpace(options["displayName"]) == "" && strings.TrimSpace(options["clientKind"]) != "" {
		options["displayName"] = defaultOAuthClientConfigureDisplayName(appIdentity.name, pkg.Name, options["clientKind"])
	}

	return nil
}

func normalizeOAuthClientConfigurePlatform(platform string, clientKind string) (string, error) {
	platform = strings.TrimSpace(platform)
	switch platform {
	case "", "ios", "android":
	default:
		return "", fmt.Errorf("--platform must be ios or android")
	}
	if platform != "" {
		return platform, nil
	}

	switch strings.TrimSpace(clientKind) {
	case "google_ios", "apple_app_id":
		return "ios", nil
	case "google_android":
		return "android", nil
	default:
		return "", nil
	}
}

func defaultOAuthClientKindForPlatform(provider string, platform string) (string, bool) {
	switch strings.TrimSpace(provider) {
	case "google_oauth":
		switch platform {
		case "ios":
			return "google_ios", true
		case "android":
			return "google_android", true
		}
	case "apple_oauth":
		switch platform {
		case "ios":
			return "apple_app_id", true
		case "android":
			return "apple_services_id", true
		}
	}
	return "", false
}

func applyOAuthClientIdentityDefaults(options map[string]string, identity expoAppIdentity) {
	switch strings.TrimSpace(options["clientKind"]) {
	case "google_ios", "apple_app_id":
		if strings.TrimSpace(options["bundleId"]) == "" {
			options["bundleId"] = identity.iosBundleID
		}
	case "google_android":
		if strings.TrimSpace(options["androidPackage"]) == "" {
			options["androidPackage"] = identity.androidPackage
		}
	case "apple_services_id":
		if strings.TrimSpace(options["bundleId"]) == "" {
			options["bundleId"] = identity.iosBundleID
		}
	}
}

func defaultOAuthClientConfigureDisplayName(appName string, packageName string, clientKind string) string {
	appName = strings.TrimSpace(appName)
	if appName == "" {
		appName = packageNameDisplayName(packageName)
	}
	if appName == "" {
		appName = "Mobile App"
	}
	kindName := oauthClientKindDisplayName(clientKind)
	if kindName == "" {
		return appName + " OAuth"
	}
	return appName + " " + kindName
}

func packageNameDisplayName(packageName string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(packageName), "@")
	parts := strings.FieldsFunc(trimmed, func(value rune) bool {
		return value == '/' || value == '-' || value == '_' || value == '.'
	})
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		labels = append(labels, titleASCIIToken(part))
	}
	return strings.Join(labels, " ")
}

func titleASCIIToken(value string) string {
	if value == "" {
		return ""
	}
	if len(value) == 1 {
		return strings.ToUpper(value)
	}
	return strings.ToUpper(value[:1]) + strings.ToLower(value[1:])
}

func oauthClientKindDisplayName(clientKind string) string {
	switch strings.TrimSpace(clientKind) {
	case "google_ios":
		return "Google iOS OAuth"
	case "google_android":
		return "Google Android OAuth"
	case "google_web":
		return "Google Web OAuth"
	case "apple_app_id":
		return "Apple App ID"
	case "apple_services_id":
		return "Apple Services ID"
	default:
		return ""
	}
}

func discoverSourceBinding(options proveAppOptions) (sourceBinding, error) {
	if options.platform != "ios" && options.platform != "android" {
		return sourceBinding{}, fmt.Errorf("--platform must be ios or android")
	}
	if options.lane != "simulator" && options.lane != "development" {
		return sourceBinding{}, fmt.Errorf("--lane must be simulator or development")
	}

	absoluteAppDir, err := filepath.Abs(options.appDir)
	if err != nil {
		return sourceBinding{}, fmt.Errorf("resolve app directory: %w", err)
	}

	packageFile := filepath.Join(absoluteAppDir, "package.json")
	pkg, err := readPackageJSON(packageFile)
	if err != nil {
		return sourceBinding{}, fmt.Errorf("package.json not found in %s", absoluteAppDir)
	}
	if !isExpoPackage(pkg) {
		return sourceBinding{}, fmt.Errorf("%s is not an Expo app package", absoluteAppDir)
	}

	workspaceRoot := findWorkspaceRoot(absoluteAppDir)
	packagePath, err := filepath.Rel(workspaceRoot, absoluteAppDir)
	if err != nil || packagePath == "" {
		packagePath = "."
	}
	easConfig, _ := loadEASJSON(absoluteAppDir)
	selectedEASProfile := selectEASProfile(easConfig, options.platform, options.lane)
	resolvedExpoConfig := resolveExpoConfig(absoluteAppDir, selectedEASProfile.env)
	appIdentity := resolvedExpoConfig.identity
	dirtyWorkspace, changedSetupFiles := sourceBindingGitState(workspaceRoot, absoluteAppDir)
	gitRemoteURL, gitBranch, gitCommitSHA := sourceBindingGitIdentity(workspaceRoot)

	return sourceBinding{
		AppID:               "pfapp_" + sanitizeID(pkg.Name),
		PackageName:         pkg.Name,
		PackageManager:      detectPackageManager(workspaceRoot),
		WorkspaceRoot:       workspaceRoot,
		PackagePath:         packagePath,
		WorkflowIntent:      "prove-app",
		BuildStrategy:       options.buildStrategy,
		Platform:            options.platform,
		Lane:                options.lane,
		ExpoConfigDigest:    resolvedExpoConfig.digest,
		EASJSONDigest:       digestIfExists(filepath.Join(absoluteAppDir, "eas.json")),
		EASProfileName:      selectedEASProfile.name,
		EASProfileEnvDigest: selectedEASProfile.envDigest,
		AppScheme:           appIdentity.scheme,
		ExpoSlug:            appIdentity.slug,
		IOSBundleID:         appIdentity.iosBundleID,
		AndroidPackage:      appIdentity.androidPackage,
		EASProjectID:        appIdentity.easProjectID,
		GitRemoteURL:        gitRemoteURL,
		GitBranch:           gitBranch,
		GitCommitSHA:        gitCommitSHA,
		DirtyWorkspace:      dirtyWorkspace,
		ChangedSetupFiles:   changedSetupFiles,
	}, nil
}

func sourceBindingGitIdentity(workspaceRoot string) (string, string, string) {
	remoteURL, _ := gitOutput(workspaceRoot, "config", "--get", "remote.origin.url")
	branch, _ := gitOutput(workspaceRoot, "rev-parse", "--abbrev-ref", "HEAD")
	commitSHA, _ := gitOutput(workspaceRoot, "rev-parse", "HEAD")
	if branch == "HEAD" {
		branch = ""
	}
	return remoteURL, branch, commitSHA
}

func sourceBindingGitState(workspaceRoot string, appDir string) (bool, []string) {
	changedFiles := filterRunnerManagedPaths(
		workspaceRoot,
		appDir,
		gitChangedFiles(workspaceRoot),
	)
	if len(changedFiles) == 0 {
		return false, []string{}
	}
	return true, changedPreflightSetupFiles(workspaceRoot, appDir, changedFiles)
}

// filterRunnerManagedPaths drops paths the runner itself regenerates during a
// build — the native projects from `expo prebuild` (ios/, android/), Preflight's
// own artifact dir (.preflight/), and Expo caches (.expo/). These are not source
// for reproducibility, and including them made every build dirty its own
// workspace and dead-end at source-binding validation (dirtyWorkspace mismatch).
// Genuine source changes (eas.json, app.config, src/) are still detected.
func filterRunnerManagedPaths(
	workspaceRoot string,
	appDir string,
	changed []string,
) []string {
	packagePath, err := filepath.Rel(workspaceRoot, appDir)
	if err != nil {
		packagePath = ""
	}
	packagePath = filepath.ToSlash(packagePath)
	if packagePath == "." {
		packagePath = ""
	}
	// EAS job logs and build metadata are written at the workspace root even
	// when the Expo package lives below it (for example apps/mobile).
	prefixes := []string{".preflight/"}
	for _, dir := range []string{"ios", "android", ".preflight", ".expo"} {
		if packagePath == "" {
			prefixes = append(prefixes, dir+"/")
		} else {
			prefixes = append(prefixes, packagePath+"/"+dir+"/")
		}
	}
	kept := make([]string, 0, len(changed))
	for _, path := range changed {
		managed := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(path, prefix) {
				managed = true
				break
			}
		}
		if !managed {
			kept = append(kept, path)
		}
	}
	return kept
}

func gitChangedFiles(workspaceRoot string) []string {
	if strings.TrimSpace(workspaceRoot) == "" {
		return nil
	}
	command := exec.Command(
		"git",
		"-C",
		workspaceRoot,
		"status",
		"--porcelain=v1",
		"--untracked-files=all",
	)
	output, err := command.Output()
	if err != nil {
		return nil
	}
	return parseGitStatusPaths(string(output))
}

func parseGitStatusPaths(output string) []string {
	seen := map[string]bool{}
	var paths []string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		if renameIndex := strings.LastIndex(path, " -> "); renameIndex >= 0 {
			path = path[renameIndex+4:]
		}
		path = strings.Trim(path, `"`)
		path = filepath.ToSlash(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func changedPreflightSetupFiles(workspaceRoot string, appDir string, changedFiles []string) []string {
	packagePath, err := filepath.Rel(workspaceRoot, appDir)
	if err != nil {
		return []string{}
	}
	packagePath = filepath.ToSlash(packagePath)
	prefix := ""
	if packagePath != "." {
		prefix = strings.TrimSuffix(packagePath, "/") + "/"
	}

	setupFiles := []string{}
	for _, path := range changedFiles {
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		appRelativePath := path
		if prefix != "" {
			appRelativePath = strings.TrimPrefix(path, prefix)
		}
		if !isPreflightSetupFile(appRelativePath) {
			continue
		}
		setupFiles = append(setupFiles, path)
	}
	return setupFiles
}

func isPreflightSetupFile(appRelativePath string) bool {
	appRelativePath = filepath.ToSlash(strings.TrimPrefix(appRelativePath, "./"))
	switch appRelativePath {
	case "package.json",
		"app.json",
		"app.config.json",
		"app.config.js",
		"app.config.ts",
		"eas.json",
		"metro.config.js",
		"babel.config.js",
		"expo-env.d.ts":
		return true
	}
	if strings.HasPrefix(appRelativePath, "ios/") {
		return strings.HasSuffix(appRelativePath, ".xcodeproj/project.pbxproj") ||
			appRelativePath == "ios/Podfile" ||
			appRelativePath == "ios/Podfile.lock" ||
			strings.HasSuffix(appRelativePath, ".entitlements")
	}
	if strings.HasPrefix(appRelativePath, "android/") {
		return appRelativePath == "android/app/build.gradle" ||
			appRelativePath == "android/build.gradle" ||
			appRelativePath == "android/settings.gradle" ||
			appRelativePath == "android/gradle.properties" ||
			strings.HasSuffix(appRelativePath, ".keystore.properties")
	}
	return false
}

func isExpoPackage(pkg packageJSON) bool {
	if pkg.Main == "expo-router/entry" {
		return true
	}
	if _, ok := pkg.Dependencies["expo"]; ok {
		return true
	}
	_, ok := pkg.DevDependencies["expo"]
	return ok
}

func hasDependency(pkg packageJSON, name string) bool {
	if _, ok := pkg.Dependencies[name]; ok {
		return true
	}
	_, ok := pkg.DevDependencies[name]
	return ok
}

func selectEASProfile(config easJSON, platform string, lane string) selectedEASProfile {
	if len(config.Build) == 0 {
		return selectedEASProfile{}
	}

	if lane == "development" && platform == "ios" {
		for _, name := range []string{"development-device", "dev-device", "development"} {
			if profile, ok := config.Build[name]; ok && !easProfileIsIOSSimulator(profile) {
				return makeSelectedEASProfile(name, profile, platform)
			}
		}
		for name, profile := range config.Build {
			if easProfileDevelopmentClient(profile) && !easProfileIsIOSSimulator(profile) {
				return makeSelectedEASProfile(name, profile, platform)
			}
		}
	}

	if lane == "development" && platform == "android" {
		for _, name := range []string{"development-android", "dev-android", "android-development", "development"} {
			if profile, ok := config.Build[name]; ok && easProfileDevelopmentClient(profile) && easProfileAndroidInstallable(profile) {
				return makeSelectedEASProfile(name, profile, platform)
			}
		}
		for name, profile := range config.Build {
			if easProfileDevelopmentClient(profile) && easProfileAndroidInstallable(profile) {
				return makeSelectedEASProfile(name, profile, platform)
			}
		}
	}

	// The simulator lane needs an iOS simulator build. Apps from the gmacko
	// template keep a device-only "development" profile (ios.simulator=false)
	// alongside a sibling "development-simulator" profile; without this branch
	// the generic fallback below grabs "development" and the readiness check
	// blocks on eas_ios_simulator_profile. Prefer a named simulator profile,
	// then any simulator-capable profile (e.g. a "development" that itself sets
	// ios.simulator=true, as some apps do).
	if lane == "simulator" && platform == "ios" {
		for _, name := range []string{"development-simulator", "dev-simulator", "simulator", "development"} {
			if profile, ok := config.Build[name]; ok && easProfileIsIOSSimulator(profile) {
				return makeSelectedEASProfile(name, profile, platform)
			}
		}
		for name, profile := range config.Build {
			if easProfileDevelopmentClient(profile) && easProfileIsIOSSimulator(profile) {
				return makeSelectedEASProfile(name, profile, platform)
			}
		}
	}

	if profile, ok := config.Build["development"]; ok {
		return makeSelectedEASProfile("development", profile, platform)
	}
	for name, profile := range config.Build {
		if easProfileDevelopmentClient(profile) {
			return makeSelectedEASProfile(name, profile, platform)
		}
	}
	return selectedEASProfile{}
}

func makeSelectedEASProfile(name string, profile easBuildProfile, platform string) selectedEASProfile {
	env := easProfileEnv(profile, platform)
	return selectedEASProfile{
		name:      name,
		env:       env,
		envDigest: digestJSON(env),
	}
}

func easProfileEnv(profile easBuildProfile, platform string) map[string]string {
	env := map[string]string{}
	for key, value := range profile.Env {
		env[key] = value
	}
	var platformEnv map[string]string
	if platform == "android" {
		platformEnv = profile.Android.Env
	} else {
		platformEnv = profile.IOS.Env
	}
	for key, value := range platformEnv {
		env[key] = value
	}
	return env
}

func easProfileIsIOSSimulator(profile easBuildProfile) bool {
	return profile.IOS.Simulator != nil && *profile.IOS.Simulator
}

func easProfileDevelopmentClient(profile easBuildProfile) bool {
	return profile.DevelopmentClient != nil && *profile.DevelopmentClient
}

func easProfileAndroidInstallable(profile easBuildProfile) bool {
	return profile.Android.BuildType == "" || profile.Android.BuildType == "apk"
}

func findWorkspaceRoot(appDir string) string {
	current := appDir
	for {
		if fileExists(filepath.Join(current, "pnpm-workspace.yaml")) {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return appDir
		}
		current = parent
	}
}

func detectPackageManager(workspaceRoot string) string {
	if fileExists(filepath.Join(workspaceRoot, "pnpm-lock.yaml")) || fileExists(filepath.Join(workspaceRoot, "pnpm-workspace.yaml")) {
		return "pnpm"
	}
	if fileExists(filepath.Join(workspaceRoot, "yarn.lock")) {
		return "yarn"
	}
	return "npm"
}

func digestIfExists(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestJSON(value any) string {
	content, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func sanitizeID(value string) string {
	value = strings.TrimPrefix(value, "@")
	replacer := strings.NewReplacer("/", "_", "-", "_", ".", "_")
	return replacer.Replace(value)
}

func setupRequired(code string, message string, commands ...string) map[string]any {
	commandValues := make([]string, 0, len(commands))
	commandValues = append(commandValues, commands...)
	return map[string]any{
		"code":     code,
		"message":  message,
		"commands": commandValues,
	}
}

func easProfileNameForJob(job apiRunnerJob) string {
	if job.Payload.EASProfileName != "" {
		return job.Payload.EASProfileName
	}
	if job.Payload.SourceBinding.EASProfileName != "" {
		return job.Payload.SourceBinding.EASProfileName
	}
	return "development-device"
}

// isProductionBuildProfile reports whether an EAS profile name denotes a
// production/store build (which is restricted to CI).
func isProductionBuildProfile(profileName string) bool {
	p := strings.ToLower(strings.TrimSpace(profileName))
	return p == "production" ||
		strings.HasPrefix(p, "production-") ||
		strings.HasSuffix(p, "-production")
}

// runningInCI reports whether the runner is executing inside a CI environment.
func runningInCI() bool {
	for _, key := range []string{"CI", "GITHUB_ACTIONS", "EAS_BUILD"} {
		v := strings.TrimSpace(os.Getenv(key))
		if v != "" && v != "0" && strings.ToLower(v) != "false" {
			return true
		}
	}
	return false
}

func jobPlatform(job apiRunnerJob) string {
	if job.Payload.Platform == "android" {
		return "android"
	}
	return "ios"
}

func jobPlatformForEAS(job apiRunnerJob) string {
	return jobPlatform(job)
}

func normalizeTargetClass(value string) string {
	if value == "simulator" || value == "emulator" {
		return value
	}
	return "device"
}

func readMapString(record map[string]any, key string) string {
	if record == nil {
		return ""
	}
	value, _ := record[key].(string)
	return value
}

// --- apps / status: App Store release-program visibility ---
//
// Thin client over the server's release-status envelope
// (GET /api/preflight/v1/release-status + /apps/{id}/release-status). The web
// Overview page reads the same envelope — CLI and web can't disagree.

const releaseStatusSchemaVersion = 1

type cliReleaseStageResult struct {
	Key           string            `json:"key"`
	Status        string            `json:"status"`
	BlockerReason string            `json:"blockerReason"`
	Owner         string            `json:"owner"`
	Evidence      map[string]string `json:"evidence"`
}

type cliFleetReleaseRow struct {
	AppID                 string `json:"appId"`
	Slug                  string `json:"slug"`
	Name                  string `json:"name"`
	Platform              string `json:"platform"`
	CurrentStage          string `json:"currentStage"`
	NextStage             string `json:"nextStage"`
	NextOwner             string `json:"nextOwner"`
	BlockerReason         string `json:"blockerReason"`
	TestflightState       string `json:"testflightState"`
	StoreSubmissionStatus string `json:"storeSubmissionStatus"`
	LatestStoreBuildID    string `json:"latestStoreBuildId"`
	LastAscSyncAt         string `json:"lastAscSyncAt"`
	EASProjectID          string `json:"easProjectId"`
	GithubRepoURL         string `json:"githubRepoUrl"`
	Submittable           bool   `json:"submittable"`
	SubmitBlockerReason   string `json:"submitBlockerReason"`
}

type cliAppReleaseStatus struct {
	SchemaVersion int `json:"schemaVersion"`
	App           struct {
		ID            string `json:"id"`
		Slug          string `json:"slug"`
		Name          string `json:"name"`
		BundleID      string `json:"bundleId"`
		AscAppID      string `json:"ascAppId"`
		EASProjectID  string `json:"easProjectId"`
		LastAscSyncAt string `json:"lastAscSyncAt"`
	} `json:"app"`
	Platform string `json:"platform"`
	Stage    struct {
		Current string `json:"current"`
		Next    *struct {
			Key           string `json:"key"`
			BlockerReason string `json:"blockerReason"`
			Owner         string `json:"owner"`
		} `json:"next"`
	} `json:"stage"`
	Ladder       []cliReleaseStageResult `json:"ladder"`
	LatestBuilds []struct {
		ID          string `json:"id"`
		Platform    string `json:"platform"`
		Profile     string `json:"profile"`
		Status      string `json:"status"`
		Version     string `json:"version"`
		BuildNumber string `json:"buildNumber"`
		CompletedAt string `json:"completedAt"`
	} `json:"latestBuilds"`
	Submissions []struct {
		ID            string `json:"id"`
		Destination   string `json:"destination"`
		Status        string `json:"status"`
		Version       string `json:"version"`
		AscBuildState string `json:"ascBuildState"`
		SubmittedAt   string `json:"submittedAt"`
	} `json:"submissions"`
	StoreListing struct {
		Complete bool     `json:"complete"`
		Missing  []string `json:"missing"`
	} `json:"storeListing"`
	Checklist []struct {
		Key    string `json:"key"`
		Status string `json:"status"`
		Note   string `json:"note"`
	} `json:"checklist"`
	Links struct {
		Asc string `json:"asc"`
		Eas string `json:"eas"`
	} `json:"links"`
}

type releaseStatusCLIOptions struct {
	apiURL   string
	token    string
	platform string
	jsonOut  bool
	rest     []string
}

func parseReleaseStatusCLIOptions(args []string, stderr io.Writer) (releaseStatusCLIOptions, bool) {
	config, _ := loadPreflightCLIConfig()
	options := releaseStatusCLIOptions{
		apiURL:   firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL),
		token:    firstNonEmpty(os.Getenv("PREFLIGHT_TOKEN"), config.Token),
		platform: "ios",
	}
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--api-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return options, false
			}
			options.apiURL = value
		case "--platform":
			value, ok := nextFlagValue(args, &index)
			if !ok || (value != "ios" && value != "android") {
				fmt.Fprintln(stderr, "--platform requires ios or android")
				return options, false
			}
			options.platform = value
		case "--json":
			options.jsonOut = true
		default:
			options.rest = append(options.rest, args[index])
		}
	}
	if options.token == "" {
		fmt.Fprintln(stderr, "not signed in; run `preflight login` or set PREFLIGHT_TOKEN")
		return options, false
	}
	return options, true
}

func runApps(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printAppsHelp(stdout)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "list":
		return runAppsList(args[1:], stdout, stderr, client)
	case "status":
		return runAppsStatus(args[1:], stdout, stderr, client)
	case "checklist":
		return runAppsChecklist(args[1:], stdout, stderr, client)
	case "doctor":
		return runAppsDoctor(args[1:], stdout, stderr, client)
	case "submit-for-review":
		return runAppsSubmitForReview(args[1:], stdout, stderr, client)
	case "screenshots":
		return runAppsScreenshots(args[1:], stdout, stderr, client)
	case "scan-bundle":
		return runAppsScanBundle(args[1:], stdout, stderr)
	case "review":
		return runAppsReview(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown apps subcommand %q\n", args[0])
		printAppsHelp(stderr)
		return 2
	}
}

func printAppsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  preflight apps list [--platform ios|android] [--json]")
	fmt.Fprintln(w, "  preflight apps status <app-id|slug|name> [--platform ...] [--json]")
	fmt.Fprintln(w, "  preflight apps checklist set <app-id|slug> --key <key> --status <pending|done|blocked|not_applicable> [--note <text>] [--platform ...]")
	fmt.Fprintln(w, "  preflight apps doctor [--path <app-dir>] [--json]   build-health checks (lockfile/sentry/eas.json)")
	fmt.Fprintln(w, "  preflight apps scan-bundle <bundle|.app|.ipa>       scan a built artifact for store poison (localhost/E2E)")
	fmt.Fprintln(w, "  preflight apps submit-for-review <app-id|slug|name>  submit the uploaded build to App Review (R6; gated)")
	fmt.Fprintln(w, "  preflight apps screenshots --scheme <s> --sim <udid> [--flow f.yaml] [--app <id> --upload]  capture App Store screenshots (R5)")
	fmt.Fprintln(w, "  preflight apps review compile <flow.review.yaml>     compile a TrueFlight review workflow → Maestro flow + reviewer guide")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Release-program status: where each app sits on the ladder")
	fmt.Fprintln(w, "identity -> compliance -> asc_record -> store_build -> testflight -> metadata -> submitted -> released.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "`apps status` exits 2 when the next action is user-owned (portal/agreement work).")
}

func fetchFleetReleaseRows(client *http.Client, options releaseStatusCLIOptions) ([]cliFleetReleaseRow, error) {
	endpoint := strings.TrimRight(options.apiURL, "/") + "/api/preflight/v1/release-status?platform=" + url.QueryEscape(options.platform)
	data, err := getPreflightJSON(client, endpoint, options.token)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Apps []cliFleetReleaseRow `json:"apps"`
	}
	if err := decodeEnvelopeData(data, &payload); err != nil {
		return nil, fmt.Errorf("decode release-status response: %w", err)
	}
	return payload.Apps, nil
}

func runAppsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options, ok := parseReleaseStatusCLIOptions(args, stderr)
	if !ok {
		return 2
	}
	rows, err := fetchFleetReleaseRows(client, options)
	if err != nil {
		fmt.Fprintf(stderr, "fetch release status failed: %v\n", err)
		return 1
	}
	if options.jsonOut {
		content, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode release status failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
		return 0
	}
	writer := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "APP\tSTAGE\tNEXT\tOWNER\tTESTFLIGHT\tREVIEW\tBLOCKER")
	for _, row := range rows {
		name := row.Name
		if name == "" {
			name = row.AppID
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			emptyDash(row.CurrentStage),
			emptyDash(row.NextStage),
			emptyDash(row.NextOwner),
			emptyDash(row.TestflightState),
			emptyDash(row.StoreSubmissionStatus),
			truncateForTable(row.BlockerReason, 72),
		)
	}
	writer.Flush()
	return 0
}

// resolveReleaseAppID turns an app reference (pf_app id, slug, or name) into
// the registry id via the fleet endpoint.
func resolveReleaseAppID(client *http.Client, options releaseStatusCLIOptions, ref string) (string, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "", fmt.Errorf("app reference is required")
	}
	rows, err := fetchFleetReleaseRows(client, options)
	if err != nil {
		return "", err
	}
	lowered := strings.ToLower(trimmed)
	var matches []cliFleetReleaseRow
	for _, row := range rows {
		if row.AppID == trimmed {
			return row.AppID, nil
		}
		if strings.ToLower(row.Slug) == lowered || strings.ToLower(row.Name) == lowered {
			matches = append(matches, row)
		}
	}
	if len(matches) == 1 {
		return matches[0].AppID, nil
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, match.AppID)
		}
		return "", fmt.Errorf("app reference %q is ambiguous: %s", ref, strings.Join(ids, ", "))
	}
	return "", fmt.Errorf("no app matches %q (try `preflight apps list`)", ref)
}

func runAppsStatus(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options, ok := parseReleaseStatusCLIOptions(args, stderr)
	if !ok {
		return 2
	}
	if len(options.rest) != 1 {
		fmt.Fprintln(stderr, "Usage: preflight apps status <app-id|slug|name> [--platform ios|android] [--json]")
		return 2
	}
	appID, err := resolveReleaseAppID(client, options, options.rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve app failed: %v\n", err)
		return 1
	}
	endpoint := strings.TrimRight(options.apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) +
		"/release-status?platform=" + url.QueryEscape(options.platform)
	data, err := getPreflightJSON(client, endpoint, options.token)
	if err != nil {
		fmt.Fprintf(stderr, "fetch release status failed: %v\n", err)
		return 1
	}
	var payload struct {
		ReleaseStatus cliAppReleaseStatus `json:"releaseStatus"`
	}
	if err := decodeEnvelopeData(data, &payload); err != nil {
		fmt.Fprintf(stderr, "decode release status failed: %v\n", err)
		return 1
	}
	status := payload.ReleaseStatus
	if status.SchemaVersion > releaseStatusSchemaVersion {
		fmt.Fprintf(stderr, "warning: server envelope schema v%d is newer than this CLI (v%d) — upgrade preflight\n",
			status.SchemaVersion, releaseStatusSchemaVersion)
	}
	if options.jsonOut {
		content, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode release status failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
	} else {
		printAppReleaseStatus(stdout, status)
	}
	// Scripts detect "human action needed" without parsing output.
	if status.Stage.Next != nil && status.Stage.Next.Owner == "user" {
		return 2
	}
	return 0
}

// runAppsSubmitForReview fires the explicit R6 action: submit an app's uploaded
// build to App Review. The server gates it on the ladder preconditions, so a
// non-ready app comes back as a clear error rather than a botched submission.
func runAppsSubmitForReview(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options, ok := parseReleaseStatusCLIOptions(args, stderr)
	if !ok {
		return 2
	}
	// --all / --fire arrive in rest (unknown flags); split them from the app arg.
	all, fire := false, false
	var positional []string
	for _, r := range options.rest {
		switch r {
		case "--all":
			all = true
		case "--fire", "--confirm":
			fire = true
		default:
			positional = append(positional, r)
		}
	}
	options.rest = positional

	if all {
		return runFleetSubmitForReview(options, fire, stdout, stderr, client)
	}

	if len(options.rest) != 1 {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  preflight apps submit-for-review <app-id|slug|name>   submit one app")
		fmt.Fprintln(stderr, "  preflight apps submit-for-review --all [--fire]       submit every R5-ready app (dry-run without --fire)")
		return 2
	}
	appID, err := resolveReleaseAppID(client, options, options.rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve app failed: %v\n", err)
		return 1
	}
	endpoint := strings.TrimRight(options.apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/submit-for-review"
	data, err := postPreflightJSON(client, endpoint, options.token, map[string]any{
		"requestedBy": "cli",
	})
	if err != nil {
		fmt.Fprintf(stderr, "submit-for-review failed: %v\n", err)
		return 1
	}
	if options.jsonOut {
		fmt.Fprintln(stdout, string(data))
		return 0
	}
	var payload struct {
		Submission struct {
			ID      string `json:"id"`
			Status  string `json:"status"`
			Version string `json:"version"`
		} `json:"submission"`
		Review struct {
			ReviewSubmissionID string `json:"reviewSubmissionId"`
			AppStoreVersionID  string `json:"appStoreVersionId"`
		} `json:"review"`
	}
	if err := decodeEnvelopeData(data, &payload); err != nil {
		fmt.Fprintf(stderr, "decode response failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Submitted %s v%s for App Review\n", appID, payload.Submission.Version)
	fmt.Fprintf(stdout, "  review submission: %s\n", payload.Review.ReviewSubmissionID)
	fmt.Fprintf(stdout, "  app store version: %s\n", payload.Review.AppStoreVersionID)
	fmt.Fprintf(stdout, "  status: %s — the reconciler advances it (in_review → approved → released)\n", payload.Submission.Status)
	return 0
}

// runFleetSubmitForReview enumerates the fleet, shows which apps are R5-ready to
// submit (and why the rest aren't), and — only with --fire — submits each ready
// app through the same gated route (which re-checks readiness server-side, so a
// stale fleet snapshot can never push a half-baked app to Apple).
func runFleetSubmitForReview(options releaseStatusCLIOptions, fire bool, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	rows, err := fetchFleetReleaseRows(client, options)
	if err != nil {
		fmt.Fprintf(stderr, "fetch fleet failed: %v\n", err)
		return 1
	}
	var ready, blocked []cliFleetReleaseRow
	for _, r := range rows {
		if r.Submittable {
			ready = append(ready, r)
		} else {
			blocked = append(blocked, r)
		}
	}
	fmt.Fprintf(stdout, "Fleet submit-for-review — %d ready, %d not ready\n\n", len(ready), len(blocked))

	if len(ready) == 0 {
		fmt.Fprintln(stdout, "No apps are ready to submit — all gated on earlier ladder rungs:")
		shown := 0
		for _, r := range blocked {
			if r.SubmitBlockerReason == "" {
				continue
			}
			fmt.Fprintf(stdout, "  %-30s %s\n", firstNonEmpty(r.Name, r.AppID), r.SubmitBlockerReason)
			if shown++; shown >= 15 {
				break
			}
		}
		return 0
	}

	fmt.Fprintln(stdout, "Ready to submit:")
	for _, r := range ready {
		fmt.Fprintf(stdout, "  %s (%s)\n", firstNonEmpty(r.Name, r.AppID), r.AppID)
	}
	if !fire {
		fmt.Fprintf(stdout, "\nDry-run. Re-run with --fire to submit these %d app(s) for App Review.\n", len(ready))
		return 0
	}

	fmt.Fprintf(stdout, "\nSubmitting %d app(s) for App Review...\n", len(ready))
	failures := 0
	for _, r := range ready {
		endpoint := strings.TrimRight(options.apiURL, "/") +
			"/api/preflight/v1/apps/" + url.PathEscape(r.AppID) + "/submit-for-review"
		if _, err := postPreflightJSON(client, endpoint, options.token, map[string]any{"requestedBy": "cli-fleet"}); err != nil {
			fmt.Fprintf(stderr, "  x %-30s %v\n", firstNonEmpty(r.Name, r.AppID), err)
			failures++
			continue
		}
		fmt.Fprintf(stdout, "  ok %-30s submitted for App Review\n", firstNonEmpty(r.Name, r.AppID))
	}
	fmt.Fprintf(stdout, "\nSubmitted %d/%d (%d failed)\n", len(ready)-failures, len(ready), failures)
	if failures > 0 {
		return 1
	}
	return 0
}

func printAppReleaseStatus(stdout io.Writer, status cliAppReleaseStatus) {
	title := status.App.Name
	if title == "" {
		title = status.App.ID
	}
	fmt.Fprintf(stdout, "%s (%s, %s)\n", title, status.App.BundleID, status.Platform)
	if status.App.AscAppID != "" {
		fmt.Fprintf(stdout, "ASC: %s", status.App.AscAppID)
		if status.App.LastAscSyncAt != "" {
			fmt.Fprintf(stdout, " (synced %s)", status.App.LastAscSyncAt)
		}
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout)
	for _, stage := range status.Ladder {
		marker := " "
		switch stage.Status {
		case "done":
			marker = "✓"
		case "blocked":
			marker = "✗"
		case "not_applicable":
			marker = "-"
		default:
			marker = "…"
		}
		line := fmt.Sprintf("%s %-12s %s", marker, stage.Key, stage.Status)
		if stage.Owner != "" && stage.Status != "done" && stage.Status != "not_applicable" {
			line += " [" + stage.Owner + "]"
		}
		fmt.Fprintln(stdout, line)
		if stage.BlockerReason != "" {
			fmt.Fprintf(stdout, "    %s\n", stage.BlockerReason)
		}
	}
	if next := status.Stage.Next; next != nil {
		fmt.Fprintf(stdout, "\nNext: %s (owner: %s)\n", next.Key, next.Owner)
		if next.BlockerReason != "" {
			fmt.Fprintf(stdout, "  %s\n", next.BlockerReason)
		}
	} else {
		fmt.Fprintln(stdout, "\nReleased — ladder complete.")
	}
	if len(status.LatestBuilds) > 0 {
		fmt.Fprintln(stdout, "\nLatest builds:")
		for _, build := range status.LatestBuilds {
			fmt.Fprintf(stdout, "  %s/%s %s (%s) %s\n", build.Platform, build.Profile, build.Version, emptyDash(build.BuildNumber), build.Status)
		}
	}
	if len(status.Submissions) > 0 {
		fmt.Fprintln(stdout, "\nSubmissions:")
		for _, submission := range status.Submissions {
			fmt.Fprintf(stdout, "  %s %s %s (asc: %s)\n", submission.Destination, submission.Version, submission.Status, emptyDash(submission.AscBuildState))
		}
	}
	if !status.StoreListing.Complete {
		fmt.Fprintf(stdout, "\nStore listing missing: %s\n", strings.Join(status.StoreListing.Missing, ", "))
	}
	if status.Links.Asc != "" {
		fmt.Fprintf(stdout, "\n%s\n", status.Links.Asc)
	}
}

func runAppsChecklist(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] != "set" {
		fmt.Fprintln(stderr, "Usage: preflight apps checklist set <app-id|slug> --key <key> --status <status> [--note <text>] [--platform ios|android]")
		return 2
	}
	var key, statusValue, note string
	filtered := make([]string, 0, len(args[1:]))
	rest := args[1:]
	for index := 0; index < len(rest); index += 1 {
		switch rest[index] {
		case "--key":
			value, ok := nextFlagValue(rest, &index)
			if !ok {
				fmt.Fprintln(stderr, "--key requires a value")
				return 2
			}
			key = value
		case "--status":
			value, ok := nextFlagValue(rest, &index)
			if !ok {
				fmt.Fprintln(stderr, "--status requires a value")
				return 2
			}
			statusValue = value
		case "--note":
			value, ok := nextFlagValue(rest, &index)
			if !ok {
				fmt.Fprintln(stderr, "--note requires a value")
				return 2
			}
			note = value
		default:
			filtered = append(filtered, rest[index])
		}
	}
	options, ok := parseReleaseStatusCLIOptions(filtered, stderr)
	if !ok {
		return 2
	}
	if len(options.rest) != 1 || key == "" || statusValue == "" {
		fmt.Fprintln(stderr, "Usage: preflight apps checklist set <app-id|slug> --key <key> --status <status> [--note <text>] [--platform ios|android]")
		return 2
	}
	appID, err := resolveReleaseAppID(client, options, options.rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve app failed: %v\n", err)
		return 1
	}
	endpoint := strings.TrimRight(options.apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/release-checklist"
	payload := map[string]any{
		"key":      key,
		"status":   statusValue,
		"platform": options.platform,
	}
	if note != "" {
		payload["note"] = note
	}
	data, err := putPreflightJSON(client, endpoint, options.token, payload)
	if err != nil {
		fmt.Fprintf(stderr, "update checklist failed: %v\n", err)
		return 1
	}
	var response struct {
		Item struct {
			Key    string `json:"key"`
			Status string `json:"status"`
		} `json:"item"`
	}
	if err := decodeEnvelopeData(data, &response); err != nil {
		fmt.Fprintf(stderr, "decode checklist response: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s %s = %s\n", appID, response.Item.Key, response.Item.Status)
	return 0
}

// runStatusAlias: `preflight status [<app>]` — sugar for apps status / apps list.
func runStatusAlias(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	positional := []string{}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") {
			positional = append(positional, arg)
		}
	}
	if len(positional) > 0 {
		return runAppsStatus(args, stdout, stderr, client)
	}
	return runAppsList(args, stdout, stderr, client)
}

func putPreflightJSON(client *http.Client, endpoint string, token string, payload any) (json.RawMessage, error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Preflight request: %w", err)
	}
	request, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("build Preflight request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return doPreflightJSON(client, request)
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

func truncateForTable(value string, max int) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\n", " ")
	if len(value) <= max {
		return value
	}
	return value[:max-1] + "…"
}

// canonicalWorkspaceRoot resolves symlinks in a runner's workspace root.
//
// Job eligibility compares workspace roots as STRINGS (the server's
// runnerCanAccessJobWorkspaceRoot -> pathIsWithin does a prefix match), so a
// runner registering a symlinked root is structurally ineligible for every job
// even though the directory is identical on disk.
//
// Observed 2026-08-02: gmacko-mini registered `$HOME/dev`, a symlink to
// `/Volumes/dev`. Jobs bind `/Volumes/dev/...`, the prefixes never matched, and
// three healthy runners idled at "no runner jobs available" for hours while the
// queue backed up on another host. Resolving here makes a symlinked root behave
// exactly like the real one.
//
// Falls back to the input when the path cannot be resolved (e.g. the volume is
// not mounted yet) — a best-effort normalization must never stop a runner from
// starting.
func canonicalWorkspaceRoot(root string) string {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || strings.TrimSpace(resolved) == "" {
		return root
	}
	return resolved
}
