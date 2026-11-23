package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// `preflight apps demo-accounts <app>` lists an app's App Review demo
// accounts; `--reveal <label>` fetches one account's stored secret through
// the owner-only reveal endpoint, so an agent can sign in as it.
//
// The secret reaches plaintext only when --reveal is given, and then goes to
// exactly one sink: --output-file (mode 0600, nothing echoed), --json, or a
// bare value on stdout.

type cliDemoAccount struct {
	ID            string `json:"id"`
	AppID         string `json:"appId"`
	Label         string `json:"label"`
	Flavor        string `json:"flavor"`
	Identifier    string `json:"identifier"`
	ProbeURL      string `json:"probeUrl,omitempty"`
	LastProbeAt   string `json:"lastProbeAt,omitempty"`
	LastProbeOk   *bool  `json:"lastProbeOk,omitempty"`
	LastProbeNote string `json:"lastProbeNote,omitempty"`
	Notes         string `json:"notes,omitempty"`
	HasSecret     bool   `json:"hasSecret"`
}

type cliDemoAccountReveal struct {
	Account    cliDemoAccount `json:"account"`
	Secret     string         `json:"secret"`
	RevealedAt string         `json:"revealedAt"`
}

const demoAccountsUsage = "Usage: preflight apps demo-accounts <app-id|slug|name> [--json] [--reveal <label> [--output-file <path>]]"

func runAppsDemoAccounts(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	var revealLabel, outputFile string
	revealSet := false
	filtered := make([]string, 0, len(args))
	for index := 0; index < len(args); index += 1 {
		switch args[index] {
		case "--help", "-h":
			printDemoAccountsHelp(stdout)
			return 0
		case "--reveal":
			value, ok := nextFlagValue(args, &index)
			if !ok || strings.HasPrefix(value, "--") {
				fmt.Fprintln(stderr, "--reveal requires a demo account label (see `preflight apps demo-accounts <app>`)")
				return 2
			}
			revealLabel, revealSet = value, true
		case "--output-file":
			value, ok := nextFlagValue(args, &index)
			if !ok {
				fmt.Fprintln(stderr, "--output-file requires a path")
				return 2
			}
			outputFile = value
		case "--workspace-id":
			// Accepted for parity with other commands; the app's own
			// workspace scopes the request server-side.
			if _, ok := nextFlagValue(args, &index); !ok {
				fmt.Fprintln(stderr, "--workspace-id requires a value")
				return 2
			}
		default:
			filtered = append(filtered, args[index])
		}
	}
	if outputFile != "" && !revealSet {
		fmt.Fprintln(stderr, "--output-file only applies with --reveal <label>")
		return 2
	}
	options, ok := parseReleaseStatusCLIOptions(filtered, stderr)
	if !ok {
		return 2
	}
	if len(options.rest) != 1 {
		fmt.Fprintln(stderr, demoAccountsUsage)
		return 2
	}
	appID, err := resolveReleaseAppID(client, options, options.rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve app failed: %v\n", err)
		return 1
	}
	base := strings.TrimRight(options.apiURL, "/") + "/api/preflight/v1/apps/" + url.PathEscape(appID) + "/demo-accounts"
	if !revealSet {
		return listDemoAccounts(client, options, base, appID, stdout, stderr)
	}
	return revealDemoAccount(client, options, base, revealLabel, outputFile, stdout, stderr)
}

func listDemoAccounts(client *http.Client, options releaseStatusCLIOptions, base string, appID string, stdout io.Writer, stderr io.Writer) int {
	data, err := getPreflightJSON(client, base, options.token)
	if err != nil {
		fmt.Fprintf(stderr, "list demo accounts failed: %v\n", err)
		return 1
	}
	var listed struct {
		Accounts []cliDemoAccount `json:"accounts"`
	}
	if err := decodeEnvelopeData(data, &listed); err != nil {
		fmt.Fprintf(stderr, "decode demo accounts failed: %v\n", err)
		return 1
	}
	if options.jsonOut {
		content, err := json.MarshalIndent(listed.Accounts, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode demo accounts failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(content))
		return 0
	}
	if len(listed.Accounts) == 0 {
		fmt.Fprintf(stdout, "%s has no demo accounts\n", appID)
		return 0
	}
	writer := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "LABEL\tIDENTIFIER\tFLAVOR\tSECRET\tPROBE")
	for _, account := range listed.Accounts {
		secret := "none"
		if account.HasSecret {
			secret = "stored"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", account.Label, account.Identifier, account.Flavor, secret, demoAccountProbeSummary(account))
	}
	writer.Flush()
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Reveal one: preflight apps demo-accounts %s --reveal <label> --output-file <path>\n", appID)
	return 0
}

func demoAccountProbeSummary(account cliDemoAccount) string {
	if account.LastProbeOk == nil {
		return "-"
	}
	if *account.LastProbeOk {
		return "ok"
	}
	return truncateForTable("failed: "+account.LastProbeNote, 48)
}

func revealDemoAccount(client *http.Client, options releaseStatusCLIOptions, base string, label string, outputFile string, stdout io.Writer, stderr io.Writer) int {
	data, err := postPreflightJSON(client, base+"/"+url.PathEscape(label)+"/reveal", options.token, map[string]any{})
	if err != nil {
		fmt.Fprintf(stderr, "reveal demo account %q failed: %v\n", label, err)
		return 1
	}
	var revealed cliDemoAccountReveal
	if err := decodeEnvelopeData(data, &revealed); err != nil {
		fmt.Fprintf(stderr, "decode demo account reveal failed: %v\n", err)
		return 1
	}
	if revealed.Secret == "" {
		fmt.Fprintf(stderr, "demo account %q returned no secret\n", label)
		return 1
	}
	if outputFile != "" {
		if err := writeSecretFile(outputFile, revealed.Secret); err != nil {
			fmt.Fprintf(stderr, "write %s failed: %v\n", outputFile, err)
			return 1
		}
		if options.jsonOut {
			content, _ := json.MarshalIndent(map[string]any{
				"label":      revealed.Account.Label,
				"identifier": revealed.Account.Identifier,
				"flavor":     revealed.Account.Flavor,
				"secretFile": outputFile,
				"revealedAt": revealed.RevealedAt,
			}, "", "  ")
			fmt.Fprintln(stdout, string(content))
			return 0
		}
		fmt.Fprintf(stdout, "wrote %s (%s) secret to %s (mode 0600)\n", revealed.Account.Label, revealed.Account.Identifier, outputFile)
		return 0
	}
	if options.jsonOut {
		content, _ := json.MarshalIndent(map[string]any{
			"label":      revealed.Account.Label,
			"identifier": revealed.Account.Identifier,
			"flavor":     revealed.Account.Flavor,
			"secret":     revealed.Secret,
			"revealedAt": revealed.RevealedAt,
		}, "", "  ")
		fmt.Fprintln(stdout, string(content))
		return 0
	}
	fmt.Fprintln(stdout, revealed.Secret)
	return 0
}

// writeSecretFile writes value to path with mode 0600, atomically: a temp
// file in the same directory, chmod, then rename — so no reader ever sees a
// partially written or wider-permission file, and an existing file at path is
// replaced rather than reused with its old mode.
func writeSecretFile(path string, value string) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".preflight-secret-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	cleanup := func() { _ = os.Remove(tempName) }
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		cleanup()
		return err
	}
	if _, err := temp.WriteString(value); err != nil {
		temp.Close()
		cleanup()
		return err
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func printDemoAccountsHelp(w io.Writer) {
	fmt.Fprintln(w, demoAccountsUsage)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Lists the app's App Review demo accounts (label, login, whether a secret is stored, last probe).")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  --reveal <label>       fetch that account's stored secret (workspace owner/admin only; audited)")
	fmt.Fprintln(w, "  --output-file <path>   write the secret to <path> with mode 0600 instead of printing it")
	fmt.Fprintln(w, "  --json                 machine-readable output (with --reveal and no --output-file, includes the secret)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Without --output-file or --json, --reveal prints the bare secret on stdout.")
}
