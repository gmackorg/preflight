package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
)

// --- testflight: fleet tester enrollment ---

type cliTestFlightEnrollmentResult struct {
	AppID     string `json:"appId"`
	AppName   string `json:"appName"`
	AscAppID  string `json:"ascAppId"`
	GroupName string `json:"groupName"`
	Status    string `json:"status"`
	Error     string `json:"error"`
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
	if args[0] != "enroll" {
		fmt.Fprintf(stderr, "unknown testflight subcommand %q\n", args[0])
		printTestFlightHelp(stderr)
		return 2
	}
	return runTestFlightEnroll(args[1:], stdout, stderr, client)
}

func printTestFlightHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  preflight testflight enroll --email <apple-id> --all-apps [--dry-run] [--workspace-id <id>] [--json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Enroll an App Store Connect team member in every managed app's internal TestFlight group.")
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
