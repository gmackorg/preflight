package main

// PREFLT-66 CLI commands for the Preflight features that replace EAS:
// signing credentials, signing targets, build profiles, store builds, push and
// OTA. Every command is a thin client over /api/preflight/v1 (see the control
// plane's apps/nextjs/src/app/api/preflight/v1/**); authentication, the API URL
// and the workspace follow the other commands (--api-url / PREFLIGHT_API_URL,
// PREFLIGHT_TOKEN or the saved login, --workspace-id or the saved binding).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

// apiFlag declares one command flag: value flags store into options[key];
// boolean flags store "true"; repeatable flags append to a list.
type apiFlag struct {
	name       string
	key        string
	boolean    bool
	repeatable bool
}

type apiCommandInput struct {
	options map[string]string
	lists   map[string][]string
	json    bool
}

// parseAPICommand parses flags for a control-plane command. --api-url,
// --workspace-id and --json are always accepted. Returns false (after printing
// the problem) when the arguments are unusable.
func parseAPICommand(command string, args []string, flags []apiFlag, stderr io.Writer) (apiCommandInput, bool) {
	input := apiCommandInput{
		options: map[string]string{
			"apiURL":      os.Getenv("PREFLIGHT_API_URL"),
			"workspaceId": firstNonEmpty(os.Getenv("PREFLIGHT_WORKSPACE_ID"), "local"),
		},
		lists: map[string][]string{},
	}
	all := append([]apiFlag{
		{name: "--api-url", key: "apiURL"},
		{name: "--workspace-id", key: "workspaceId"},
	}, flags...)
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--json" {
			input.json = true
			continue
		}
		var spec *apiFlag
		for i := range all {
			if all[i].name == arg {
				spec = &all[i]
				break
			}
		}
		if spec == nil {
			fmt.Fprintf(stderr, "unknown %s flag %q\n", command, arg)
			return input, false
		}
		if spec.boolean {
			input.options[spec.key] = "true"
			continue
		}
		value, ok := nextFlagValue(args, &index)
		if !ok || strings.HasPrefix(value, "--") {
			fmt.Fprintf(stderr, "%s requires a value\n", arg)
			return input, false
		}
		if spec.repeatable {
			input.lists[spec.key] = append(input.lists[spec.key], value)
		} else {
			input.options[spec.key] = value
		}
	}
	if err := resolvePreflightAPIOptions(input.options); err != nil {
		fmt.Fprintf(stderr, "load Preflight CLI config failed: %v\n", err)
		return input, false
	}
	if strings.TrimSpace(input.options["apiURL"]) == "" {
		fmt.Fprintln(stderr, "missing Preflight API URL; pass --api-url, set PREFLIGHT_API_URL or run preflight login")
		return input, false
	}
	return input, true
}

func (input apiCommandInput) workspaceID() string {
	if id := strings.TrimSpace(input.options["workspaceId"]); id != "local" {
		return id
	}
	return ""
}

func (input apiCommandInput) endpoint(path string) string {
	return runnerEndpoint(input.options["apiURL"], path)
}

func appPath(appID string, suffix string) string {
	return "/api/preflight/v1/apps/" + url.PathEscape(appID) + suffix
}

// requestPreflightAPI sends one JSON request to the control plane. Reads and
// idempotent writes retry transient failures; a write that must not repeat
// (queueing a build, sending a push, minting a key) passes retry=false.
func requestPreflightAPI(client *http.Client, input apiCommandInput, method string, path string, body any, retry bool) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode Preflight request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, input.endpoint(path), reader)
	if err != nil {
		return nil, fmt.Errorf("build Preflight request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	addPreflightAuthHeaders(request, input.options["token"], input.workspaceID())
	return sendPreflightRequest(client, request, retry)
}

func sendPreflightRequest(client *http.Client, request *http.Request, retry bool) (json.RawMessage, error) {
	if retry {
		return doPreflightJSON(client, request)
	}
	data, _, err := doPreflightJSONOnce(client, request)
	return data, err
}

// printAPIResult prints the raw envelope data for --json, else calls render.
func printAPIResult(input apiCommandInput, data json.RawMessage, stdout io.Writer, render func() error) error {
	if input.json {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			_, _ = fmt.Fprintln(stdout, string(data))
			return nil
		}
		_, _ = fmt.Fprintln(stdout, pretty.String())
		return nil
	}
	return render()
}

func readJSONFile(path string) (any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	return value, nil
}

func wantsHelp(args []string) bool {
	return len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help"
}

func subcommandHelpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// preflight credentials (signing vault)
// ---------------------------------------------------------------------------

type signingCredentialSummary struct {
	ID        string         `json:"id"`
	AppID     string         `json:"appId"`
	Kind      string         `json:"kind"`
	Scope     string         `json:"scope"`
	Provider  string         `json:"provider"`
	Purpose   string         `json:"purpose"`
	Key       string         `json:"key"`
	LaneScope string         `json:"laneScope"`
	Status    string         `json:"status"`
	Version   int            `json:"version"`
	ExpiresAt string         `json:"expiresAt"`
	Metadata  map[string]any `json:"metadata"`
}

func runSigningCredentialsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	input, ok := parseAPICommand("credentials list", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--include-revoked", key: "includeRevoked", boolean: true},
	}, stderr)
	if !ok {
		return 2
	}
	query := url.Values{}
	if input.options["includeRevoked"] == "true" {
		query.Set("includeRevoked", "true")
	}
	path := "/api/preflight/v1/credentials"
	if appID := input.options["appId"]; appID != "" {
		path = appPath(appID, "/credentials")
	} else {
		if input.workspaceID() == "" {
			fmt.Fprintln(stderr, "missing --app or --workspace-id")
			return 2
		}
		query.Set("workspaceId", input.workspaceID())
	}
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	data, err := requestPreflightAPI(client, input, http.MethodGet, path, nil, true)
	if err != nil {
		fmt.Fprintf(stderr, "credentials list failed: %v\n", err)
		return 1
	}
	var listed struct {
		Credentials []signingCredentialSummary `json:"credentials"`
	}
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode credentials failed: %v\n", err)
		return 1
	}
	_ = printAPIResult(input, data, stdout, func() error {
		if len(listed.Credentials) == 0 {
			fmt.Fprintln(stdout, "no signing credentials")
			return nil
		}
		for _, credential := range listed.Credentials {
			kind := firstNonEmpty(credential.Kind, credential.Purpose)
			fmt.Fprintf(stdout, "%s %s %s %s %s v%d", credential.ID, kind, credential.Scope, credential.LaneScope, credential.Status, credential.Version)
			if credential.ExpiresAt != "" {
				fmt.Fprintf(stdout, " expires=%s", credential.ExpiresAt)
			}
			fmt.Fprintln(stdout)
		}
		return nil
	})
	return 0
}

type easImportEntry struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	BundleID string `json:"bundleId"`
}

type easImportReport struct {
	AppID   string           `json:"appId"`
	Entries []easImportEntry `json:"entries"`
	Summary struct {
		Imported  int `json:"imported"`
		Unchanged int `json:"unchanged"`
		Missing   int `json:"missing"`
		Failed    int `json:"failed"`
	} `json:"summary"`
}

func printEASImportReport(stdout io.Writer, report easImportReport) {
	fmt.Fprintf(stdout, "%s imported=%d unchanged=%d missing=%d failed=%d\n", report.AppID, report.Summary.Imported, report.Summary.Unchanged, report.Summary.Missing, report.Summary.Failed)
	for _, entry := range report.Entries {
		line := fmt.Sprintf("  %s %s %s", entry.Status, entry.Kind, entry.Key)
		if entry.BundleID != "" {
			line += " " + entry.BundleID
		}
		if entry.Reason != "" {
			line += " — " + entry.Reason
		}
		fmt.Fprintln(stdout, line)
	}
}

// runCredentialsImportEAS copies an app's (or every linked app's) signing
// material and build environment from the Expo account into the Preflight
// vault. The control plane reads the workspace's Expo access token from the
// vault (provider expo, purpose api_token); --expo-token-env stores one there
// first, and --expo-token-ref names the stored token to use.
func runCredentialsImportEAS(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	input, ok := parseAPICommand("credentials import-eas", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--all", key: "all", boolean: true},
		{name: "--expo-token-ref", key: "expoTokenRef"},
		{name: "--expo-token-env", key: "expoTokenEnv"},
	}, stderr)
	if !ok {
		return 2
	}
	appID := input.options["appId"]
	all := input.options["all"] == "true"
	if (appID == "") == !all {
		fmt.Fprintln(stderr, "pass exactly one of --app <id> or --all")
		return 2
	}
	if all && input.workspaceID() == "" {
		fmt.Fprintln(stderr, "--all needs --workspace-id (or a saved workspace)")
		return 2
	}
	if envName := input.options["expoTokenEnv"]; envName != "" {
		token := strings.TrimSpace(os.Getenv(envName))
		if token == "" {
			fmt.Fprintf(stderr, "environment variable %s is empty\n", envName)
			return 2
		}
		if input.workspaceID() == "" {
			fmt.Fprintln(stderr, "--expo-token-env needs --workspace-id (or a saved workspace)")
			return 2
		}
		defer registerRedactedSecrets(token)()
		payload := map[string]any{
			"workspaceId": input.workspaceID(),
			"provider":    "expo",
			"purpose":     "api_token",
			// The vault key the control plane documents for the Expo token;
			// the import reads it by provider + purpose.
			"key":       "EXPO_TOKEN",
			"value":     token,
			"laneScope": "all",
		}
		data, err := requestPreflightAPI(client, input, http.MethodPost, "/api/preflight/v1/secret-refs", payload, false)
		if err != nil {
			fmt.Fprintf(stderr, "store Expo access token failed: %v\n", err)
			return 1
		}
		var created credentialsEnvelopeData
		if err := decodeEnvelopeData(data, &created); err == nil && created.SecretReference.ID != "" {
			input.options["expoTokenRef"] = created.SecretReference.ID
			if !input.json {
				fmt.Fprintf(stdout, "stored Expo access token %s\n", created.SecretReference.ID)
			}
		}
	}
	body := map[string]any{}
	if ref := input.options["expoTokenRef"]; ref != "" {
		body["expoTokenSecretReferenceId"] = ref
	}
	path := ""
	if all {
		path = "/api/preflight/v1/credentials/import/eas"
		body["workspaceId"] = input.workspaceID()
	} else {
		path = appPath(appID, "/credentials/import/eas")
	}
	data, err := requestPreflightAPI(client, input, http.MethodPost, path, body, true)
	if err != nil {
		fmt.Fprintf(stderr, "credentials import-eas failed: %v\n", err)
		return 1
	}
	exit := 0
	renderErr := printAPIResult(input, data, stdout, func() error {
		if !all {
			var report easImportReport
			if err := decodeEnvelopeData(data, &report); err != nil {
				return err
			}
			printEASImportReport(stdout, report)
			if report.Summary.Failed > 0 {
				exit = 1
			}
			return nil
		}
		var result struct {
			WorkspaceID string `json:"workspaceId"`
			Apps        []struct {
				AppID  string           `json:"appId"`
				Report *easImportReport `json:"report"`
				Error  *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			} `json:"apps"`
		}
		if err := decodeEnvelopeData(data, &result); err != nil {
			return err
		}
		if len(result.Apps) == 0 {
			fmt.Fprintln(stdout, "no apps in the workspace are linked to an Expo project")
		}
		for _, app := range result.Apps {
			switch {
			case app.Error != nil:
				fmt.Fprintf(stdout, "%s error %s: %s\n", app.AppID, app.Error.Code, app.Error.Message)
				exit = 1
			case app.Report != nil:
				printEASImportReport(stdout, *app.Report)
				if app.Report.Summary.Failed > 0 {
					exit = 1
				}
			}
		}
		return nil
	})
	if renderErr != nil {
		fmt.Fprintf(stderr, "decode import report failed: %v\n", renderErr)
		return 1
	}
	return exit
}

func runCredentialsDoctor(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	input, ok := parseAPICommand("credentials doctor", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--fix", key: "fix", boolean: true},
	}, stderr)
	if !ok {
		return 2
	}
	if missing := requireOptions(input.options, "appId"); missing != "" {
		fmt.Fprintln(stderr, "missing --app")
		return 2
	}
	fix := input.options["fix"] == "true"
	data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(input.options["appId"], "/credentials/doctor"), map[string]any{"fix": fix}, !fix)
	if err != nil {
		fmt.Fprintf(stderr, "credentials doctor failed: %v\n", err)
		return 1
	}
	var report struct {
		AppID    string `json:"appId"`
		Fix      bool   `json:"fix"`
		OK       bool   `json:"ok"`
		Findings []struct {
			Check      string `json:"check"`
			Status     string `json:"status"`
			Message    string `json:"message"`
			TargetName string `json:"targetName"`
			BundleID   string `json:"bundleId"`
			Action     string `json:"action"`
			ResourceID string `json:"resourceId"`
		} `json:"findings"`
	}
	if err := decodeEnvelopeData(data, &report); err != nil {
		fmt.Fprintf(stderr, "decode doctor report failed: %v\n", err)
		return 1
	}
	_ = printAPIResult(input, data, stdout, func() error {
		state := "ready"
		if !report.OK {
			state = "blocked"
		}
		fmt.Fprintf(stdout, "signing %s %s\n", report.AppID, state)
		for _, finding := range report.Findings {
			line := fmt.Sprintf("  %s %s: %s", strings.ToUpper(finding.Status), finding.Check, finding.Message)
			if finding.BundleID != "" {
				line += " [" + finding.BundleID + "]"
			}
			if finding.Action != "" {
				line += " (" + finding.Action
				if finding.ResourceID != "" {
					line += " " + finding.ResourceID
				}
				line += ")"
			}
			fmt.Fprintln(stdout, line)
		}
		if !report.OK && !fix {
			fmt.Fprintln(stdout, "rerun with --fix to create missing App Store Connect resources and vault entries")
		}
		return nil
	})
	if !report.OK {
		return 1
	}
	return 0
}

// signingUploadFileField is the multipart file field each credential kind's
// file travels in (signingUploadFileFields in the control plane).
var signingUploadFileField = map[string]string{
	"asc_api_key":                  "p8",
	"apns_key":                     "p8",
	"ios_distribution_certificate": "p12",
	"ios_development_certificate":  "p12",
	"ios_provisioning_profile":     "profile",
	"play_service_account":         "serviceAccount",
	"fcm_service_account":          "serviceAccount",
	"android_upload_keystore":      "keystore",
}

// signingUploadPasswordField is the payload field --password fills.
var signingUploadPasswordField = map[string]string{
	"ios_distribution_certificate": "p12Password",
	"ios_development_certificate":  "p12Password",
	"android_upload_keystore":      "keystorePassword",
}

// teamScopedSigningKinds may be uploaded without --app (POST /credentials).
var teamScopedSigningKinds = map[string]bool{
	"asc_api_key":                  true,
	"ios_distribution_certificate": true,
	"ios_development_certificate":  true,
	"apns_key":                     true,
	"play_service_account":         true,
}

func runCredentialsUpload(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	input, ok := parseAPICommand("credentials upload", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--kind", key: "kind"},
		{name: "--file", key: "file"},
		{name: "--password", key: "password"},
		{name: "--password-env", key: "passwordEnv"},
		{name: "--team-id", key: "teamId"},
		{name: "--play-developer-id", key: "playDeveloperId"},
		{name: "--lane", key: "laneScope"},
		{name: "--field", key: "fields", repeatable: true},
	}, stderr)
	if !ok {
		return 2
	}
	kind := input.options["kind"]
	fileField, known := signingUploadFileField[kind]
	if !known {
		kinds := make([]string, 0, len(signingUploadFileField))
		for name := range signingUploadFileField {
			kinds = append(kinds, name)
		}
		sort.Strings(kinds)
		fmt.Fprintf(stderr, "--kind must be one of %s\n", strings.Join(kinds, ", "))
		return 2
	}
	if missing := requireOptions(input.options, "file"); missing != "" {
		fmt.Fprintln(stderr, "missing --file")
		return 2
	}
	appID := input.options["appId"]
	if appID == "" {
		if !teamScopedSigningKinds[kind] {
			fmt.Fprintf(stderr, "%s is app-scoped; pass --app <id>\n", kind)
			return 2
		}
		if input.workspaceID() == "" {
			fmt.Fprintln(stderr, "team credentials need --workspace-id (or a saved workspace)")
			return 2
		}
	}
	password := input.options["password"]
	if envName := input.options["passwordEnv"]; envName != "" {
		password = os.Getenv(envName)
		if password == "" {
			fmt.Fprintf(stderr, "environment variable %s is empty\n", envName)
			return 2
		}
	}
	content, err := os.ReadFile(input.options["file"])
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", input.options["file"], err)
		return 2
	}

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	fields := map[string]string{"kind": kind}
	if appID == "" {
		fields["workspaceId"] = input.workspaceID()
	}
	for flagKey, formKey := range map[string]string{"teamId": "teamId", "playDeveloperId": "playDeveloperId", "laneScope": "laneScope"} {
		if value := input.options[flagKey]; value != "" {
			fields[formKey] = value
		}
	}
	if password != "" {
		passwordField, takesPassword := signingUploadPasswordField[kind]
		if !takesPassword {
			fmt.Fprintf(stderr, "%s does not take --password\n", kind)
			return 2
		}
		defer registerRedactedSecrets(password)()
		fields[passwordField] = password
	} else if passwordField, takesPassword := signingUploadPasswordField[kind]; takesPassword && kind != "android_upload_keystore" {
		// An unprotected .p12 still needs the (empty) password field.
		fields[passwordField] = ""
	}
	for _, pair := range input.lists["fields"] {
		key, value, err := parseKeyValue(pair)
		if err != nil {
			fmt.Fprintf(stderr, "--field %q: %v\n", pair, err)
			return 2
		}
		fields[key] = value
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := form.WriteField(name, fields[name]); err != nil {
			fmt.Fprintf(stderr, "encode upload: %v\n", err)
			return 1
		}
	}
	part, err := form.CreateFormFile(fileField, filepath.Base(input.options["file"]))
	if err == nil {
		_, err = part.Write(content)
	}
	if err == nil {
		err = form.Close()
	}
	if err != nil {
		fmt.Fprintf(stderr, "encode upload: %v\n", err)
		return 1
	}

	path := "/api/preflight/v1/credentials"
	if appID != "" {
		path = appPath(appID, "/credentials")
	}
	request, err := http.NewRequest(http.MethodPost, input.endpoint(path), bytes.NewReader(body.Bytes()))
	if err != nil {
		fmt.Fprintf(stderr, "build Preflight request: %v\n", err)
		return 1
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	addPreflightAuthHeaders(request, input.options["token"], input.workspaceID())
	data, err := sendPreflightRequest(client, request, true)
	if err != nil {
		fmt.Fprintf(stderr, "credentials upload failed: %v\n", err)
		return 1
	}
	var result struct {
		Outcome    string                   `json:"outcome"`
		Credential signingCredentialSummary `json:"credential"`
	}
	if err := decodeEnvelopeData(data, &result); err != nil {
		fmt.Fprintf(stderr, "decode upload response failed: %v\n", err)
		return 1
	}
	_ = printAPIResult(input, data, stdout, func() error {
		fmt.Fprintf(stdout, "%s %s %s %s v%d\n", firstNonEmpty(result.Outcome, "stored"), result.Credential.ID, firstNonEmpty(result.Credential.Kind, kind), result.Credential.Scope, result.Credential.Version)
		return nil
	})
	return 0
}

// ---------------------------------------------------------------------------
// preflight signing-targets
// ---------------------------------------------------------------------------

func runSigningTargets(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if wantsHelp(args) {
		printSigningTargetsHelp(stdout)
		return 0
	}
	if subcommandHelpRequested(args[1:]) {
		printSigningTargetsHelp(stdout)
		return 0
	}
	switch args[0] {
	case "get":
		input, ok := parseAPICommand("signing-targets get", args[1:], []apiFlag{{name: "--app", key: "appId"}}, stderr)
		if !ok {
			return 2
		}
		if input.options["appId"] == "" {
			fmt.Fprintln(stderr, "missing --app")
			return 2
		}
		data, err := requestPreflightAPI(client, input, http.MethodGet, appPath(input.options["appId"], "/signing-targets"), nil, true)
		if err != nil {
			fmt.Fprintf(stderr, "signing-targets get failed: %v\n", err)
			return 1
		}
		return renderSigningTargets(input, data, stdout, stderr)
	case "set":
		input, ok := parseAPICommand("signing-targets set", args[1:], []apiFlag{
			{name: "--app", key: "appId"},
			{name: "--file", key: "file"},
			{name: "--clear", key: "clear", boolean: true},
		}, stderr)
		if !ok {
			return 2
		}
		if input.options["appId"] == "" {
			fmt.Fprintln(stderr, "missing --app")
			return 2
		}
		var targets any
		switch {
		case input.options["clear"] == "true":
			targets = nil
		case input.options["file"] != "":
			value, err := readJSONFile(input.options["file"])
			if err != nil {
				fmt.Fprintln(stderr, err.Error())
				return 2
			}
			// Accept either the bare array or {"targets": [...]}.
			if record, isRecord := value.(map[string]any); isRecord {
				value = record["targets"]
			}
			if _, isList := value.([]any); !isList {
				fmt.Fprintln(stderr, "targets file must hold an array of {targetName, bundleId, capabilities}")
				return 2
			}
			targets = value
		default:
			fmt.Fprintln(stderr, "missing --file (or --clear)")
			return 2
		}
		data, err := requestPreflightAPI(client, input, http.MethodPut, appPath(input.options["appId"], "/signing-targets"), map[string]any{"targets": targets}, true)
		if err != nil {
			fmt.Fprintf(stderr, "signing-targets set failed: %v\n", err)
			return 1
		}
		return renderSigningTargets(input, data, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown signing-targets command %q\n", args[0])
		printSigningTargetsHelp(stderr)
		return 2
	}
}

func renderSigningTargets(input apiCommandInput, data json.RawMessage, stdout io.Writer, stderr io.Writer) int {
	var read struct {
		AppID                string `json:"appId"`
		BundleID             string `json:"bundleId"`
		AndroidApplicationID string `json:"androidApplicationId"`
		Targets              []struct {
			TargetName   string   `json:"targetName"`
			BundleID     string   `json:"bundleId"`
			Capabilities []string `json:"capabilities"`
		} `json:"targets"`
	}
	if err := decodeEnvelopeData(data, &read); err != nil {
		fmt.Fprintf(stderr, "decode signing targets failed: %v\n", err)
		return 1
	}
	_ = printAPIResult(input, data, stdout, func() error {
		fmt.Fprintf(stdout, "app %s", read.AppID)
		if read.BundleID != "" {
			fmt.Fprintf(stdout, " ios=%s", read.BundleID)
		}
		if read.AndroidApplicationID != "" {
			fmt.Fprintf(stdout, " android=%s", read.AndroidApplicationID)
		}
		fmt.Fprintln(stdout)
		if len(read.Targets) == 0 {
			fmt.Fprintln(stdout, "  no iOS signing targets (the main bundle id only)")
		}
		for _, target := range read.Targets {
			fmt.Fprintf(stdout, "  %s %s %s\n", target.TargetName, target.BundleID, strings.Join(target.Capabilities, ","))
		}
		return nil
	})
	return 0
}

func printSigningTargetsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight signing-targets <get|set> --app <id> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The iOS targets a store build signs (main app plus extensions) and their capabilities.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  get --app <id>                     show the targets and the Android application id")
	fmt.Fprintln(w, "  set --app <id> --file targets.json replace the targets: [{targetName, bundleId, capabilities}]")
	fmt.Fprintln(w, "  set --app <id> --clear             sign the main bundle id only")
	fmt.Fprintln(w, "  --json                             print the API response")
}

// ---------------------------------------------------------------------------
// preflight build-profiles
// ---------------------------------------------------------------------------

type storeBuildProfile struct {
	Lane                          string            `json:"lane"`
	Environment                   map[string]string `json:"environment"`
	SecretEnvironmentReferenceIDs []string          `json:"secretEnvironmentReferenceIds"`
	IOSScheme                     string            `json:"iosScheme"`
	AndroidGradleTask             string            `json:"androidGradleTask"`
	VersionSource                 string            `json:"versionSource"`
	AppDirectory                  string            `json:"appDirectory"`
	ImportedFromEasProfile        string            `json:"importedFromEasProfile"`
	Stored                        *bool             `json:"stored"`
}

func printBuildProfile(stdout io.Writer, profile storeBuildProfile) {
	origin := ""
	if profile.Stored != nil && !*profile.Stored {
		origin = " (default)"
	}
	fmt.Fprintf(stdout, "%s%s version=%s", profile.Lane, origin, firstNonEmpty(profile.VersionSource, "-"))
	if profile.IOSScheme != "" {
		fmt.Fprintf(stdout, " ios-scheme=%s", profile.IOSScheme)
	}
	if profile.AndroidGradleTask != "" {
		fmt.Fprintf(stdout, " gradle=%s", profile.AndroidGradleTask)
	}
	if profile.AppDirectory != "" {
		fmt.Fprintf(stdout, " dir=%s", profile.AppDirectory)
	}
	fmt.Fprintln(stdout)
	keys := make([]string, 0, len(profile.Environment))
	for key := range profile.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(stdout, "  env %s=%s\n", key, profile.Environment[key])
	}
	for _, id := range profile.SecretEnvironmentReferenceIDs {
		fmt.Fprintf(stdout, "  secret %s\n", id)
	}
}

func runBuildProfiles(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if wantsHelp(args) || subcommandHelpRequested(args[1:]) {
		printBuildProfilesHelp(stdout)
		return 0
	}
	switch args[0] {
	case "get":
		input, ok := parseAPICommand("build-profiles get", args[1:], []apiFlag{{name: "--app", key: "appId"}}, stderr)
		if !ok {
			return 2
		}
		if input.options["appId"] == "" {
			fmt.Fprintln(stderr, "missing --app")
			return 2
		}
		data, err := requestPreflightAPI(client, input, http.MethodGet, appPath(input.options["appId"], "/build-profiles"), nil, true)
		if err != nil {
			fmt.Fprintf(stderr, "build-profiles get failed: %v\n", err)
			return 1
		}
		var read struct {
			Profiles []storeBuildProfile `json:"profiles"`
		}
		if err := decodeEnvelopeData(data, &read); err != nil {
			fmt.Fprintf(stderr, "decode build profiles failed: %v\n", err)
			return 1
		}
		_ = printAPIResult(input, data, stdout, func() error {
			for _, profile := range read.Profiles {
				printBuildProfile(stdout, profile)
			}
			return nil
		})
		return 0
	case "set":
		input, ok := parseAPICommand("build-profiles set", args[1:], []apiFlag{
			{name: "--app", key: "appId"},
			{name: "--file", key: "file"},
		}, stderr)
		if !ok {
			return 2
		}
		if input.options["appId"] == "" || input.options["file"] == "" {
			fmt.Fprintln(stderr, "build-profiles set needs --app and --file")
			return 2
		}
		value, err := readJSONFile(input.options["file"])
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		profiles, err := buildProfilesFromDocument(value)
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		saved := []json.RawMessage{}
		for _, profile := range profiles {
			data, err := requestPreflightAPI(client, input, http.MethodPut, appPath(input.options["appId"], "/build-profiles"), profile, true)
			if err != nil {
				fmt.Fprintf(stderr, "build-profiles set %v failed: %v\n", profile["lane"], err)
				return 1
			}
			saved = append(saved, data)
		}
		if input.json {
			encoded, _ := json.MarshalIndent(saved, "", "  ")
			fmt.Fprintln(stdout, string(encoded))
			return 0
		}
		for _, data := range saved {
			var result struct {
				Profile storeBuildProfile `json:"profile"`
			}
			if err := decodeEnvelopeData(data, &result); err == nil {
				fmt.Fprint(stdout, "saved ")
				printBuildProfile(stdout, result.Profile)
			}
		}
		return 0
	case "import-eas":
		input, ok := parseAPICommand("build-profiles import-eas", args[1:], []apiFlag{
			{name: "--app", key: "appId"},
			{name: "--file", key: "file"},
			{name: "--dry-run", key: "dryRun", boolean: true},
		}, stderr)
		if !ok {
			return 2
		}
		if input.options["appId"] == "" || input.options["file"] == "" {
			fmt.Fprintln(stderr, "build-profiles import-eas needs --app and --file <path to the old build config>")
			return 2
		}
		document, err := readJSONFile(input.options["file"])
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		dryRun := input.options["dryRun"] == "true"
		data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(input.options["appId"], "/build-profiles/import-eas"), map[string]any{"easJson": document, "dryRun": dryRun}, true)
		if err != nil {
			fmt.Fprintf(stderr, "build-profiles import-eas failed: %v\n", err)
			return 1
		}
		var conversion struct {
			Profiles []storeBuildProfile `json:"profiles"`
			Warnings []string            `json:"warnings"`
			Applied  bool                `json:"applied"`
		}
		if err := decodeEnvelopeData(data, &conversion); err != nil {
			fmt.Fprintf(stderr, "decode conversion failed: %v\n", err)
			return 1
		}
		_ = printAPIResult(input, data, stdout, func() error {
			verb := "imported"
			if !conversion.Applied {
				verb = "would import (dry run)"
			}
			fmt.Fprintf(stdout, "%s %d build profile(s)\n", verb, len(conversion.Profiles))
			for _, profile := range conversion.Profiles {
				printBuildProfile(stdout, profile)
			}
			for _, warning := range conversion.Warnings {
				fmt.Fprintf(stdout, "warning: %s\n", warning)
			}
			return nil
		})
		return 0
	default:
		fmt.Fprintf(stderr, "unknown build-profiles command %q\n", args[0])
		printBuildProfilesHelp(stderr)
		return 2
	}
}

// buildProfilesFromDocument accepts one profile ({"lane": …}), an array of
// them, or {"profiles": [...]} (the shape `build-profiles get --json` prints).
func buildProfilesFromDocument(value any) ([]map[string]any, error) {
	if record, isRecord := value.(map[string]any); isRecord {
		if list, hasList := record["profiles"]; hasList {
			value = list
		} else {
			value = []any{record}
		}
	}
	list, isList := value.([]any)
	if !isList || len(list) == 0 {
		return nil, fmt.Errorf("profiles file must hold a profile, an array of profiles or {\"profiles\": [...]}")
	}
	profiles := make([]map[string]any, 0, len(list))
	for index, entry := range list {
		profile, isRecord := entry.(map[string]any)
		lane, _ := profile["lane"].(string)
		if !isRecord || (lane != "internal" && lane != "beta" && lane != "store") {
			return nil, fmt.Errorf("profiles[%d] needs lane internal, beta or store", index)
		}
		// Read-only fields from `get` are not settings.
		delete(profile, "stored")
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func printBuildProfilesHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight build-profiles <get|set|import-eas> --app <id> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Per-lane store build settings (internal, beta, store): environment, secret env")
	fmt.Fprintln(w, "references, iOS scheme, Gradle task, version source and app directory.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  get --app <id>                          every lane, stored or default")
	fmt.Fprintln(w, "  set --app <id> --file profiles.json     replace the lanes in the file")
	fmt.Fprintln(w, "  import-eas --app <id> --file <config> [--dry-run]")
	fmt.Fprintln(w, "                                          convert a legacy hosted-build config into profiles")
	fmt.Fprintln(w, "  --json                                  print the API response")
}

// ---------------------------------------------------------------------------
// preflight build store
// ---------------------------------------------------------------------------

type storeBuildRow struct {
	ID                string `json:"id"`
	Platform          string `json:"platform"`
	Version           string `json:"version"`
	BuildNumber       string `json:"buildNumber"`
	Status            string `json:"status"`
	StoreLane         string `json:"storeLane"`
	StoreDestination  string `json:"storeDestination"`
	StoreUploadStatus string `json:"storeUploadStatus"`
	ASCBuildID        string `json:"ascBuildId"`
	PlayVersionCode   string `json:"playVersionCode"`
	PlayReleaseStatus string `json:"playReleaseStatus"`
	ErrorMessage      string `json:"errorMessage"`
}

func runBuildStore(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if subcommandHelpRequested(args) {
		printBuildStoreHelp(stdout)
		return 0
	}
	input, ok := parseAPICommand("build store", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--platform", key: "platform"},
		{name: "--lane", key: "lane"},
		{name: "--destination", key: "destination"},
		{name: "--git-ref", key: "gitRef"},
		{name: "--version", key: "version"},
		{name: "--build-number", key: "buildNumber"},
		{name: "--build-number-seed", key: "buildNumberSeed"},
		{name: "--release-notes", key: "releaseNotes"},
		{name: "--wait", key: "wait", boolean: true},
		{name: "--poll-interval", key: "pollInterval"},
		{name: "--timeout", key: "timeout"},
	}, stderr)
	if !ok {
		return 2
	}
	options := input.options
	if options["appId"] == "" {
		fmt.Fprintln(stderr, "missing --app")
		return 2
	}
	if options["platform"] != "ios" && options["platform"] != "android" {
		fmt.Fprintln(stderr, "--platform must be ios or android")
		return 2
	}
	switch options["lane"] {
	case "internal", "beta", "store":
	default:
		fmt.Fprintln(stderr, "--lane must be internal, beta or store")
		return 2
	}
	pollInterval, timeout := 15*time.Second, 90*time.Minute
	for key, target := range map[string]*time.Duration{"pollInterval": &pollInterval, "timeout": &timeout} {
		if raw := options[key]; raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed <= 0 {
				fmt.Fprintf(stderr, "--%s must be a positive duration\n", flagName(key))
				return 2
			}
			*target = parsed
		}
	}
	body := map[string]any{"platform": options["platform"], "lane": options["lane"]}
	for _, key := range []string{"destination", "gitRef", "version", "releaseNotes"} {
		if value := strings.TrimSpace(options[key]); value != "" {
			body[key] = value
		}
	}
	for _, key := range []string{"buildNumber", "buildNumberSeed"} {
		if value := strings.TrimSpace(options[key]); value != "" {
			number, err := strconv.Atoi(value)
			if err != nil || number <= 0 {
				fmt.Fprintf(stderr, "--%s must be a positive integer\n", flagName(key))
				return 2
			}
			body[key] = number
		}
	}
	data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(options["appId"], "/store-builds"), body, false)
	if err != nil {
		fmt.Fprintf(stderr, "build store failed: %v\n", err)
		return 1
	}
	var queued struct {
		Build    storeBuildRow `json:"build"`
		Workflow struct {
			ID string `json:"id"`
		} `json:"workflow"`
		RunnerJob struct {
			ID string `json:"id"`
		} `json:"runnerJob"`
	}
	if err := decodeEnvelopeData(data, &queued); err != nil {
		fmt.Fprintf(stderr, "decode store build failed: %v\n", err)
		return 1
	}
	if input.json && options["wait"] != "true" {
		_ = printAPIResult(input, data, stdout, nil)
		return 0
	}
	if !input.json {
		fmt.Fprintf(stdout, "queued store build %s %s %s %s (%s) workflow=%s\n", queued.Build.ID, options["platform"], options["lane"], queued.Build.Version, queued.Build.BuildNumber, queued.Workflow.ID)
	}
	if options["wait"] != "true" {
		return 0
	}
	final, err := waitForStoreBuild(client, input, options["appId"], queued.Build.ID, options["platform"], pollInterval, timeout, stdout)
	if input.json {
		encoded, _ := json.MarshalIndent(final, "", "  ")
		fmt.Fprintln(stdout, string(encoded))
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	if !input.json {
		switch {
		case final.ASCBuildID != "":
			fmt.Fprintf(stdout, "uploaded %s ascBuildId=%s (%s)\n", final.ID, final.ASCBuildID, final.StoreUploadStatus)
		case final.PlayVersionCode != "":
			fmt.Fprintf(stdout, "uploaded %s playVersionCode=%s (%s)\n", final.ID, final.PlayVersionCode, firstNonEmpty(final.PlayReleaseStatus, final.StoreUploadStatus))
		case final.StoreUploadStatus == "" || final.StoreUploadStatus == "not_requested":
			fmt.Fprintf(stdout, "built %s (no store upload requested)\n", final.ID)
		default:
			fmt.Fprintf(stdout, "uploaded %s (%s)\n", final.ID, final.StoreUploadStatus)
		}
	}
	return 0
}

// waitForStoreBuild polls the app's build list until the build is uploaded
// (and, on iOS, App Store Connect has assigned its build id) or fails.
func waitForStoreBuild(client *http.Client, input apiCommandInput, appID string, buildID string, platform string, pollInterval time.Duration, timeout time.Duration, stdout io.Writer) (storeBuildRow, error) {
	deadline := time.Now().Add(timeout)
	last := storeBuildRow{ID: buildID}
	lastState := ""
	for {
		data, err := getPreflightWorkspaceJSON(client, input.endpoint("/api/v1/apps/"+url.PathEscape(appID)+"/builds?limit=50"), input.options["token"], input.workspaceID())
		if err == nil {
			var builds []storeBuildRow
			if decodeErr := json.Unmarshal(data, &builds); decodeErr == nil {
				for _, build := range builds {
					if build.ID == buildID {
						last = build
						break
					}
				}
			}
		}
		state := last.Status + "/" + last.StoreUploadStatus
		if state != lastState && last.Status != "" && !input.json {
			fmt.Fprintf(stdout, "build %s %s upload=%s\n", buildID, last.Status, firstNonEmpty(last.StoreUploadStatus, "-"))
		}
		lastState = state
		if done, failure := storeBuildTerminal(last, platform); done {
			return last, failure
		}
		if !time.Now().Before(deadline) {
			return last, fmt.Errorf("store build %s did not finish within %s (status %s, upload %s)", buildID, timeout, firstNonEmpty(last.Status, "unknown"), firstNonEmpty(last.StoreUploadStatus, "unknown"))
		}
		time.Sleep(pollInterval)
	}
}

func storeBuildTerminal(build storeBuildRow, platform string) (bool, error) {
	switch build.Status {
	case "failed", "cancelled":
		return true, fmt.Errorf("store build %s %s: %s", build.ID, build.Status, firstNonEmpty(build.ErrorMessage, "see the workflow log"))
	}
	switch build.StoreUploadStatus {
	case "failed":
		return true, fmt.Errorf("store upload for %s failed: %s", build.ID, firstNonEmpty(build.ErrorMessage, "see the workflow log"))
	case "processing", "processed":
		return true, nil
	case "uploaded":
		// iOS uploads gain their App Store Connect id once ASC lists the build.
		return platform != "ios" || build.ASCBuildID != "" || build.PlayVersionCode != "", nil
	case "", "not_requested":
		return build.Status == "completed", nil
	}
	return false, nil
}

func printBuildStoreHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight build store --app <id> --platform ios|android --lane internal|beta|store [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Build a signed store binary on the runner fleet (expo prebuild + xcodebuild/gradle)")
	fmt.Fprintln(w, "with the lane's build profile and the vault's signing credentials, then upload it.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  --destination <d>       testflight, play_internal, play_beta, play_production or none")
	fmt.Fprintln(w, "                          (default per lane: iOS testflight; Android play_<lane>)")
	fmt.Fprintln(w, "  --git-ref <ref>         branch or 40-hex commit (default: the app's recorded source)")
	fmt.Fprintln(w, "  --version <v>           marketing version (default: the latest build's)")
	fmt.Fprintln(w, "  --build-number <n>      required when the lane's versionSource is app_config")
	fmt.Fprintln(w, "  --build-number-seed <n> lowest acceptable previous build number")
	fmt.Fprintln(w, "  --release-notes <text>  what's new for testers")
	fmt.Fprintln(w, "  --wait                  poll until uploaded or failed; prints ascBuildId / Play version code")
	fmt.Fprintln(w, "  --poll-interval <d>     default 15s; --timeout <d> default 90m")
	fmt.Fprintln(w, "  --json                  print the API response")
}

// ---------------------------------------------------------------------------
// preflight push
// ---------------------------------------------------------------------------

func runPush(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if wantsHelp(args) || subcommandHelpRequested(args[1:]) {
		printPushHelp(stdout)
		return 0
	}
	switch args[0] {
	case "send":
		input, ok := parseAPICommand("push send", args[1:], []apiFlag{
			{name: "--app", key: "appId"},
			{name: "--file", key: "file"},
			{name: "--dry-run", key: "dryRun", boolean: true},
		}, stderr)
		if !ok {
			return 2
		}
		if input.options["appId"] == "" || input.options["file"] == "" {
			fmt.Fprintln(stderr, "push send needs --app and --file message.json")
			return 2
		}
		message, err := readJSONFile(input.options["file"])
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		body, isRecord := message.(map[string]any)
		if !isRecord {
			fmt.Fprintln(stderr, "message file must be an object: {to, notification, ios?, android?, ttlSeconds?}")
			return 2
		}
		if input.options["dryRun"] == "true" {
			body["dryRun"] = true
		}
		data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(input.options["appId"], "/push/send"), body, false)
		if err != nil {
			fmt.Fprintf(stderr, "push send failed: %v\n", err)
			return 1
		}
		var result struct {
			DryRun      bool `json:"dryRun"`
			Matched     int  `json:"matched"`
			Sent        int  `json:"sent"`
			Failed      int  `json:"failed"`
			Deactivated int  `json:"deactivated"`
		}
		if err := decodeEnvelopeData(data, &result); err != nil {
			fmt.Fprintf(stderr, "decode push result failed: %v\n", err)
			return 1
		}
		_ = printAPIResult(input, data, stdout, func() error {
			if result.DryRun {
				fmt.Fprintf(stdout, "dry run: %d device(s) matched\n", result.Matched)
				return nil
			}
			fmt.Fprintf(stdout, "matched=%d sent=%d failed=%d deactivated=%d\n", result.Matched, result.Sent, result.Failed, result.Deactivated)
			return nil
		})
		if result.Failed > 0 {
			return 1
		}
		return 0
	case "keys":
		if len(args) < 2 || args[1] != "create" {
			fmt.Fprintln(stderr, "usage: preflight push keys create --app <id> --scope send|register")
			return 2
		}
		input, ok := parseAPICommand("push keys create", args[2:], []apiFlag{
			{name: "--app", key: "appId"},
			{name: "--scope", key: "scope"},
			{name: "--name", key: "name"},
		}, stderr)
		if !ok {
			return 2
		}
		scope := ""
		switch input.options["scope"] {
		case "send", "push:send":
			scope = "push:send"
		case "register", "push:register":
			scope = "push:register"
		default:
			fmt.Fprintln(stderr, "--scope must be send or register")
			return 2
		}
		if input.options["appId"] == "" {
			fmt.Fprintln(stderr, "missing --app")
			return 2
		}
		body := map[string]any{"scope": scope}
		if name := strings.TrimSpace(input.options["name"]); name != "" {
			body["name"] = name
		}
		data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(input.options["appId"], "/push/keys"), body, false)
		if err != nil {
			fmt.Fprintf(stderr, "push keys create failed: %v\n", err)
			return 1
		}
		var minted struct {
			ID        string `json:"id"`
			Key       string `json:"key"`
			KeyPrefix string `json:"keyPrefix"`
			Scope     string `json:"scope"`
			Note      string `json:"note"`
		}
		if err := decodeEnvelopeData(data, &minted); err != nil {
			fmt.Fprintf(stderr, "decode push key failed: %v\n", err)
			return 1
		}
		_ = printAPIResult(input, data, stdout, func() error {
			fmt.Fprintf(stdout, "created %s key %s\n", minted.Scope, minted.ID)
			fmt.Fprintln(stdout, minted.Key)
			if minted.Note != "" {
				fmt.Fprintln(stderr, minted.Note)
			}
			return nil
		})
		return 0
	default:
		fmt.Fprintf(stderr, "unknown push command %q\n", args[0])
		printPushHelp(stderr)
		return 2
	}
}

func printPushHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight push <send|keys create> --app <id> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Native push through APNs/FCM with the app's vault credentials.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  send --app <id> --file message.json [--dry-run]")
	fmt.Fprintln(w, "        message: {to: {userRef|userRefs|deviceIds|tokens}, notification: {title, body, data}, ios?, android?}")
	fmt.Fprintln(w, "  keys create --app <id> --scope send|register [--name <label>]")
	fmt.Fprintln(w, "        send: server secret for the app backend; register: public key for the mobile app")
	fmt.Fprintln(w, "  --json  print the API response")
}

// ---------------------------------------------------------------------------
// preflight ota
// ---------------------------------------------------------------------------

func runOTA(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if wantsHelp(args) {
		printOTAHelp(stdout)
		return 0
	}
	switch args[0] {
	case "code-signing":
		if len(args) < 2 || (args[1] != "generate" && args[1] != "get") {
			fmt.Fprintln(stderr, "usage: preflight ota code-signing <generate|get> --app <id> [--out cert.pem] [--rotate]")
			return 2
		}
		return runOTACodeSigning(args[1], args[2:], stdout, stderr, client)
	case "rollback":
		return runOTARollback(args[1:], stdout, stderr, client)
	case "republish":
		return runOTARepublish(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown ota command %q\n", args[0])
		printOTAHelp(stderr)
		return 2
	}
}

func runOTACodeSigning(action string, args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if subcommandHelpRequested(args) {
		printOTAHelp(stdout)
		return 0
	}
	input, ok := parseAPICommand("ota code-signing "+action, args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--out", key: "out"},
		{name: "--rotate", key: "rotate", boolean: true},
	}, stderr)
	if !ok {
		return 2
	}
	if input.options["appId"] == "" {
		fmt.Fprintln(stderr, "missing --app")
		return 2
	}
	path := appPath(input.options["appId"], "/ota/code-signing")
	var (
		data json.RawMessage
		err  error
	)
	if action == "generate" {
		if input.options["rotate"] == "true" {
			path += "?rotate=1"
		}
		data, err = requestPreflightAPI(client, input, http.MethodPost, path, map[string]any{}, false)
	} else {
		data, err = requestPreflightAPI(client, input, http.MethodGet, path, nil, true)
	}
	if err != nil {
		fmt.Fprintf(stderr, "ota code-signing %s failed: %v\n", action, err)
		return 1
	}
	var result struct {
		Configured        *bool  `json:"configured"`
		SecretReferenceID string `json:"secretReferenceId"`
		KeyID             string `json:"keyId"`
		NotAfter          string `json:"notAfter"`
		Rotated           bool   `json:"rotated"`
		Updates           struct {
			CodeSigningCertificate string         `json:"codeSigningCertificate"`
			CodeSigningMetadata    map[string]any `json:"codeSigningMetadata"`
			CertificatePem         string         `json:"certificatePem"`
		} `json:"updates"`
	}
	if err := decodeEnvelopeData(data, &result); err != nil {
		fmt.Fprintf(stderr, "decode code-signing response failed: %v\n", err)
		return 1
	}
	if result.Configured != nil && !*result.Configured {
		fmt.Fprintln(stderr, "no OTA code signing key yet; run preflight ota code-signing generate")
		return 1
	}
	if out := input.options["out"]; out != "" {
		if result.Updates.CertificatePem == "" {
			fmt.Fprintln(stderr, "response did not include a certificate")
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			fmt.Fprintf(stderr, "create %s: %v\n", filepath.Dir(out), err)
			return 1
		}
		if err := os.WriteFile(out, []byte(result.Updates.CertificatePem), 0o644); err != nil {
			fmt.Fprintf(stderr, "write %s: %v\n", out, err)
			return 1
		}
	}
	_ = printAPIResult(input, data, stdout, func() error {
		verb := "code signing key"
		if action == "generate" {
			verb = "generated code signing key"
			if result.Rotated {
				verb = "rotated code signing key (ship a new binary before publishing with it)"
			}
		}
		fmt.Fprintf(stdout, "%s %s keyId=%s", verb, result.SecretReferenceID, result.KeyID)
		if result.NotAfter != "" {
			fmt.Fprintf(stdout, " notAfter=%s", result.NotAfter)
		}
		fmt.Fprintln(stdout)
		if out := input.options["out"]; out != "" {
			fmt.Fprintf(stdout, "wrote certificate to %s\n", out)
		}
		metadata, _ := json.Marshal(result.Updates.CodeSigningMetadata)
		fmt.Fprintln(stdout, "app config updates:")
		fmt.Fprintf(stdout, "  codeSigningCertificate: %q\n", firstNonEmpty(input.options["out"], result.Updates.CodeSigningCertificate))
		fmt.Fprintf(stdout, "  codeSigningMetadata: %s\n", metadata)
		return nil
	})
	return 0
}

func runOTARollback(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if subcommandHelpRequested(args) {
		printOTAHelp(stdout)
		return 0
	}
	input, ok := parseAPICommand("ota rollback", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--channel", key: "channel"},
		{name: "--platform", key: "platform"},
		{name: "--to-embedded", key: "toEmbedded", boolean: true},
		{name: "--to", key: "to"},
		{name: "--previous", key: "previous", boolean: true},
		{name: "--pause", key: "pause", boolean: true},
		{name: "--resume", key: "resume", boolean: true},
		{name: "--message", key: "message"},
	}, stderr)
	if !ok {
		return 2
	}
	options := input.options
	if options["appId"] == "" || options["channel"] == "" {
		fmt.Fprintln(stderr, "ota rollback needs --app and --channel")
		return 2
	}
	platforms := []string{options["platform"]}
	switch options["platform"] {
	case "ios", "android":
	case "", "all":
		platforms = []string{"ios", "android"}
	default:
		fmt.Fprintln(stderr, "--platform must be ios, android or all")
		return 2
	}
	targets := []string{}
	body := map[string]any{"channel": options["channel"]}
	if options["toEmbedded"] == "true" {
		targets = append(targets, "embedded")
	}
	if options["to"] != "" {
		targets = append(targets, "update")
		body["updateId"] = options["to"]
	}
	for _, flag := range []string{"previous", "pause", "resume"} {
		if options[flag] == "true" {
			targets = append(targets, flag)
		}
	}
	if len(targets) > 1 {
		fmt.Fprintln(stderr, "pass one of --to-embedded, --to <updateId>, --previous, --pause or --resume")
		return 2
	}
	if len(targets) == 0 {
		targets = append(targets, "previous")
	}
	body["to"] = targets[0]
	if options["message"] != "" {
		body["message"] = options["message"]
	}
	results := []json.RawMessage{}
	exit := 0
	for _, platform := range platforms {
		body["platform"] = platform
		data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(options["appId"], "/ota/rollback"), body, true)
		if err != nil {
			fmt.Fprintf(stderr, "ota rollback %s %s failed: %v\n", options["channel"], platform, err)
			exit = 1
			continue
		}
		results = append(results, data)
		if input.json {
			continue
		}
		var result struct {
			Directive *string `json:"directive"`
			UpdateID  string  `json:"updateId"`
			ID        string  `json:"id"`
		}
		_ = decodeEnvelopeData(data, &result)
		switch {
		case result.Directive != nil && *result.Directive != "":
			fmt.Fprintf(stdout, "%s %s: %s\n", options["channel"], platform, *result.Directive)
		case targets[0] == "resume":
			fmt.Fprintf(stdout, "%s %s: serving the channel head again\n", options["channel"], platform)
		default:
			fmt.Fprintf(stdout, "%s %s: republished as %s\n", options["channel"], platform, firstNonEmpty(result.UpdateID, result.ID, "a new update"))
		}
	}
	if input.json {
		encoded, _ := json.MarshalIndent(results, "", "  ")
		fmt.Fprintln(stdout, string(encoded))
	}
	return exit
}

func runOTARepublish(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if subcommandHelpRequested(args) {
		printOTAHelp(stdout)
		return 0
	}
	input, ok := parseAPICommand("ota republish", args, []apiFlag{
		{name: "--app", key: "appId"},
		{name: "--update", key: "updateId"},
		{name: "--channel", key: "channel"},
		{name: "--rollout", key: "rollout"},
		{name: "--message", key: "message"},
	}, stderr)
	if !ok {
		return 2
	}
	options := input.options
	if options["appId"] == "" || options["updateId"] == "" {
		fmt.Fprintln(stderr, "ota republish needs --app and --update <updateId>")
		return 2
	}
	body := map[string]any{"updateId": options["updateId"]}
	if options["channel"] != "" {
		body["channel"] = options["channel"]
	}
	if raw := options["rollout"]; raw != "" {
		percent, err := strconv.Atoi(strings.TrimSuffix(raw, "%"))
		if err != nil || percent < 0 || percent > 100 {
			fmt.Fprintln(stderr, "--rollout must be a percentage from 0 to 100")
			return 2
		}
		body["rolloutPercent"] = percent
	}
	if options["message"] != "" {
		body["message"] = options["message"]
	}
	data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(options["appId"], "/ota/republish"), body, false)
	if err != nil {
		fmt.Fprintf(stderr, "ota republish failed: %v\n", err)
		return 1
	}
	var result struct {
		UpdateID string `json:"updateId"`
		ID       string `json:"id"`
		Channel  string `json:"channel"`
		Platform string `json:"platform"`
	}
	_ = decodeEnvelopeData(data, &result)
	_ = printAPIResult(input, data, stdout, func() error {
		fmt.Fprintf(stdout, "republished %s as %s", options["updateId"], firstNonEmpty(result.UpdateID, result.ID, "a new update"))
		if result.Channel != "" {
			fmt.Fprintf(stdout, " on %s", result.Channel)
		}
		if result.Platform != "" {
			fmt.Fprintf(stdout, " (%s)", result.Platform)
		}
		fmt.Fprintln(stdout)
		return nil
	})
	return 0
}

func printOTAHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight ota <command> --app <id> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Preflight-hosted over-the-air updates.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  code-signing generate --app <id> [--out cert.pem] [--rotate]")
	fmt.Fprintln(w, "        create the app's signing key in the vault; writes the public certificate")
	fmt.Fprintln(w, "  code-signing get --app <id> [--out cert.pem]")
	fmt.Fprintln(w, "  rollback --app <id> --channel <c> [--platform ios|android|all]")
	fmt.Fprintln(w, "           [--to-embedded | --to <updateId> | --previous | --pause | --resume]")
	fmt.Fprintln(w, "        default --previous; --platform defaults to both")
	fmt.Fprintln(w, "  republish --app <id> --update <updateId> [--channel <c>] [--rollout <0-100>] [--message <m>]")
	fmt.Fprintln(w, "  --json  print the API response")
}
