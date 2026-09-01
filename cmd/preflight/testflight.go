package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
)

// --- testflight: fleet tester enrollment ---

type cliTestFlightEnrollmentResult struct {
	AppID      string `json:"appId"`
	AppName    string `json:"appName"`
	AscAppID   string `json:"ascAppId"`
	GroupName  string `json:"groupName"`
	Status     string `json:"status"`
	Error      string `json:"error"`
	NextAction string `json:"nextAction"`
}

type cliTestFlightEnrollment struct {
	Email   string                          `json:"email"`
	DryRun  bool                            `json:"dryRun"`
	Results []cliTestFlightEnrollmentResult `json:"results"`
	Summary struct {
		Total           int `json:"total"`
		Enrolled        int `json:"enrolled"`
		AlreadyEnrolled int `json:"alreadyEnrolled"`
		WouldEnroll     int `json:"wouldEnroll"`
		Failed          int `json:"failed"`
		NoInternalGroup int `json:"noInternalGroup"`
	} `json:"summary"`
}

type testFlightEnrollCLIOptions struct {
	apiURL      string
	token       string
	workspaceID string
	email       string
	dryRun      bool
	jsonOut     bool
}

func runTestFlight(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printTestFlightHelp(stdout)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "enroll":
		return runTestFlightEnroll(args[1:], stdout, stderr, client)
	case "groups":
		return runTestFlightGroups(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown testflight subcommand %q\n", args[0])
		printTestFlightHelp(stderr)
		return 2
	}
}

func printTestFlightHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  preflight testflight enroll --email <apple-id> --all-apps [--dry-run] [--workspace-id <id>] [--json]")
	fmt.Fprintln(w, "  preflight testflight groups list <app-id|slug|name> [--json]")
	fmt.Fprintln(w, "  preflight testflight groups create <app-id|slug|name> [--name <group-name>] [--internal] [--json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Enroll an App Store Connect team member in every managed app's internal TestFlight group,")
	fmt.Fprintln(w, "or manage an app's TestFlight beta groups (an internal group is what `enroll` enrolls into).")
}

func runTestFlightEnroll(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	config, _ := loadPreflightCLIConfig()
	options := testFlightEnrollCLIOptions{
		apiURL:      firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL),
		token:       firstNonEmpty(os.Getenv("PREFLIGHT_TOKEN"), config.Token),
		workspaceID: strings.TrimSpace(os.Getenv("PREFLIGHT_WORKSPACE_ID")),
	}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--email":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--email requires a value")
				return 2
			}
			options.email = strings.TrimSpace(value)
		case "--workspace-id":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--workspace-id requires a value")
				return 2
			}
			options.workspaceID = strings.TrimSpace(value)
		case "--api-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return 2
			}
			options.apiURL = value
		case "--all-apps":
			// Fleet enrollment is the only supported scope in v1.
		case "--dry-run":
			options.dryRun = true
		case "--json":
			options.jsonOut = true
		case "--help", "-h":
			printTestFlightHelp(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "unknown testflight enroll flag %q\n", args[index])
			return 2
		}
	}
	if options.email == "" {
		fmt.Fprintln(stderr, "--email is required")
		return 2
	}
	if options.token == "" {
		fmt.Fprintln(stderr, "not signed in; run `preflight login` or set PREFLIGHT_TOKEN")
		return 2
	}

	payload := map[string]any{
		"email":  options.email,
		"dryRun": options.dryRun,
	}
	if options.workspaceID != "" {
		payload["workspaceId"] = options.workspaceID
	}
	endpoint := strings.TrimRight(options.apiURL, "/") + "/api/preflight/v1/testflight/enroll"
	data, err := postPreflightJSON(client, endpoint, options.token, payload)
	if err != nil {
		fmt.Fprintf(stderr, "TestFlight enrollment failed: %v\n", err)
		return 1
	}
	var response struct {
		Enrollment cliTestFlightEnrollment `json:"enrollment"`
	}
	if err := decodeEnvelopeData(data, &response); err != nil {
		fmt.Fprintf(stderr, "decode TestFlight enrollment response failed: %v\n", err)
		return 1
	}
	enrollment := response.Enrollment
	if options.jsonOut {
		content, err := json.MarshalIndent(enrollment, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode TestFlight enrollment failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
	} else {
		writer := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "APP\tGROUP\tSTATUS\tERROR")
		for _, result := range enrollment.Results {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n",
				result.AppName,
				emptyDash(result.GroupName),
				result.Status,
				emptyDash(result.Error),
			)
		}
		writer.Flush()
		mode := "enrollment"
		if enrollment.DryRun {
			mode = "dry run"
		}
		fmt.Fprintf(stdout, "TestFlight %s for %s: %d %s; %d enrolled, %d already enrolled, %d would enroll, %d failed, %d without an internal group.\n",
			mode,
			enrollment.Email,
			enrollment.Summary.Total,
			pluralize(enrollment.Summary.Total, "app", "apps"),
			enrollment.Summary.Enrolled,
			enrollment.Summary.AlreadyEnrolled,
			enrollment.Summary.WouldEnroll,
			enrollment.Summary.Failed,
			enrollment.Summary.NoInternalGroup,
		)
		if enrollment.Summary.NoInternalGroup > 0 {
			fmt.Fprintln(stdout, "Create the missing internal groups, then re-run enroll:")
			for _, result := range enrollment.Results {
				if result.Status != "no_internal_group" {
					continue
				}
				action := result.NextAction
				if action == "" {
					action = fmt.Sprintf("preflight testflight groups create %s --internal", result.AppID)
				}
				fmt.Fprintf(stdout, "  %s\n", action)
			}
		}
	}
	if enrollment.Summary.Failed > 0 || enrollment.Summary.NoInternalGroup > 0 {
		return 1
	}
	return 0
}

func pluralize(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// --- testflight groups: beta-group management ---

type cliTestFlightGroup struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	IsInternal        bool   `json:"isInternal"`
	PublicLinkEnabled bool   `json:"publicLinkEnabled"`
	PublicLink        string `json:"publicLink"`
}

func runTestFlightGroups(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printTestFlightHelp(stdout)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "list":
		return runTestFlightGroupsList(args[1:], stdout, stderr, client)
	case "create":
		return runTestFlightGroupsCreate(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown testflight groups subcommand %q\n", args[0])
		printTestFlightHelp(stderr)
		return 2
	}
}

func testFlightGroupsEndpoint(apiURL string, appID string) string {
	return strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/testflight/groups"
}

// resolveTestFlightAppID resolves an app reference via the fleet endpoint, but
// lets an explicit registry id (pfapp_…) through even when the app is not on
// the release-status fleet — some registered apps (no release program row) are
// enrollable yet invisible there, and the server 404s on an unknown id anyway.
func resolveTestFlightAppID(client *http.Client, options releaseStatusCLIOptions, ref string) (string, error) {
	appID, err := resolveReleaseAppID(client, options, ref)
	if err != nil && strings.HasPrefix(strings.TrimSpace(ref), "pfapp") {
		return strings.TrimSpace(ref), nil
	}
	return appID, err
}

func runTestFlightGroupsList(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options, ok := parseReleaseStatusCLIOptions(args, stderr)
	if !ok {
		return 2
	}
	if len(options.rest) != 1 {
		fmt.Fprintln(stderr, "Usage: preflight testflight groups list <app-id|slug|name> [--json]")
		return 2
	}
	appID, err := resolveTestFlightAppID(client, options, options.rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve app failed: %v\n", err)
		return 1
	}
	data, err := getPreflightJSON(client, testFlightGroupsEndpoint(options.apiURL, appID), options.token)
	if err != nil {
		fmt.Fprintf(stderr, "list TestFlight groups failed: %v\n", err)
		return 1
	}
	var payload struct {
		Configured bool                 `json:"configured"`
		AscLinked  bool                 `json:"ascLinked"`
		Groups     []cliTestFlightGroup `json:"groups"`
	}
	if err := decodeEnvelopeData(data, &payload); err != nil {
		fmt.Fprintf(stderr, "decode TestFlight groups failed: %v\n", err)
		return 1
	}
	if options.jsonOut {
		content, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode TestFlight groups failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
		return 0
	}
	if !payload.Configured {
		fmt.Fprintln(stderr, "App Store Connect credentials are not configured on the server.")
		return 1
	}
	if !payload.AscLinked {
		fmt.Fprintln(stderr, "The app has no linked App Store Connect record.")
		return 1
	}
	writer := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "GROUP\tID\tKIND\tPUBLIC LINK")
	for _, group := range payload.Groups {
		kind := "external"
		if group.IsInternal {
			kind = "internal"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n",
			group.Name,
			group.ID,
			kind,
			emptyDash(group.PublicLink),
		)
	}
	writer.Flush()
	if len(payload.Groups) == 0 {
		fmt.Fprintln(stdout, "No beta groups. Create an internal one with `preflight testflight groups create <app> --internal`.")
	}
	return 0
}

func runTestFlightGroupsCreate(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	config, _ := loadPreflightCLIConfig()
	options := releaseStatusCLIOptions{
		apiURL:   firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL),
		token:    firstNonEmpty(os.Getenv("PREFLIGHT_TOKEN"), config.Token),
		platform: "ios",
	}
	name := ""
	internal := false
	jsonOut := false
	appRef := ""
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--name":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--name requires a value")
				return 2
			}
			name = strings.TrimSpace(value)
		case "--internal":
			internal = true
		case "--api-url":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return 2
			}
			options.apiURL = value
		case "--json":
			jsonOut = true
		case "--help", "-h":
			printTestFlightHelp(stdout)
			return 0
		default:
			if strings.HasPrefix(args[index], "-") {
				fmt.Fprintf(stderr, "unknown testflight groups create flag %q\n", args[index])
				return 2
			}
			if appRef != "" {
				fmt.Fprintln(stderr, "testflight groups create takes a single app reference")
				return 2
			}
			appRef = args[index]
		}
	}
	if appRef == "" {
		fmt.Fprintln(stderr, "Usage: preflight testflight groups create <app-id|slug|name> [--name <group-name>] [--internal] [--json]")
		return 2
	}
	if name == "" {
		if !internal {
			fmt.Fprintln(stderr, "--name is required for an external group")
			return 2
		}
		name = "Internal Testers"
	}
	if options.token == "" {
		fmt.Fprintln(stderr, "not signed in; run `preflight login` or set PREFLIGHT_TOKEN")
		return 2
	}
	appID, err := resolveTestFlightAppID(client, options, appRef)
	if err != nil {
		fmt.Fprintf(stderr, "resolve app failed: %v\n", err)
		return 1
	}
	payload := map[string]any{"name": name, "internal": internal}
	data, err := postPreflightJSON(client, testFlightGroupsEndpoint(options.apiURL, appID), options.token, payload)
	if err != nil {
		fmt.Fprintf(stderr, "create TestFlight group failed: %v\n", err)
		return 1
	}
	var response struct {
		Group *cliTestFlightGroup `json:"group"`
	}
	if err := decodeEnvelopeData(data, &response); err != nil {
		fmt.Fprintf(stderr, "decode TestFlight group failed: %v\n", err)
		return 1
	}
	if response.Group == nil {
		fmt.Fprintln(stderr, "App Store Connect did not return the created group")
		return 1
	}
	if jsonOut {
		content, err := json.MarshalIndent(response.Group, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode TestFlight group failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
		return 0
	}
	kind := "external"
	if response.Group.IsInternal {
		kind = "internal"
	}
	fmt.Fprintf(stdout, "created %s TestFlight group %q (%s) for %s\n", kind, response.Group.Name, response.Group.ID, appID)
	if internal && !response.Group.IsInternal {
		fmt.Fprintln(stderr, "warning: the server created the group but it did not come back marked internal — check App Store Connect")
		return 1
	}
	return 0
}
