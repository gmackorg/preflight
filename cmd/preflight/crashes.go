package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

// `preflight crashes analyze` generates AI root-cause narratives for crash
// issues. It runs OFF the worker: fetches the analysis queue (issues + stack +
// deterministic signals) from preflight, shells out to a local agent CLI
// (`claude -p` / `codex exec`) to write a narrative, and posts it back. The
// worker can't run an LLM; the runner (same box as the sentry-sync cron) can.

const defaultAnalyzeAgent = "claude -p"
const defaultAnalyzeLimit = 10

type analysisQueueItem struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	Message          string   `json:"message"`
	Level            string   `json:"level"`
	Runtime          string   `json:"runtime"`
	Platform         string   `json:"platform"`
	Culprit          string   `json:"culprit"`
	EventCount       int      `json:"eventCount"`
	AffectedReleases []string `json:"affectedReleases"`
	Stack            []struct {
		Function string `json:"function"`
		Filename string `json:"filename"`
		Module   string `json:"module"`
		Lineno   int    `json:"lineno"`
		InApp    bool   `json:"inApp"`
	} `json:"stack"`
	Breadcrumbs []struct {
		Category string `json:"category"`
		Message  string `json:"message"`
		Level    string `json:"level"`
	} `json:"breadcrumbs"`
	RootCause *struct {
		Summary    string `json:"summary"`
		Confidence string `json:"confidence"`
	} `json:"rootCause"`
}

type aiAnalysisResult struct {
	Summary      string `json:"summary"`
	LikelyCause  string `json:"likelyCause"`
	SuggestedFix string `json:"suggestedFix"`
	Confidence   string `json:"confidence"`
	Agent        string `json:"agent,omitempty"`
}

// buildAnalysisPrompt renders an issue + its signals into an agent prompt that
// asks for a strict-JSON root-cause narrative.
func buildAnalysisPrompt(item analysisQueueItem) string {
	var b strings.Builder
	b.WriteString("You are a senior engineer doing root-cause analysis on a production crash/error.\n\n")
	b.WriteString("Issue:\n")
	fmt.Fprintf(&b, "- Type: %s\n- Message: %s\n", firstNonEmpty(item.Type, "(unknown)"), item.Message)
	fmt.Fprintf(&b, "- Runtime/Platform: %s/%s\n", firstNonEmpty(item.Runtime, "?"), firstNonEmpty(item.Platform, "?"))
	fmt.Fprintf(&b, "- Occurrences: %d; releases: %s\n", item.EventCount, strings.Join(item.AffectedReleases, ", "))
	if item.Culprit != "" {
		fmt.Fprintf(&b, "- Culprit: %s\n", item.Culprit)
	}
	if len(item.Stack) > 0 {
		b.WriteString("\nStack (most recent first):\n")
		for i, f := range item.Stack {
			if i >= 15 {
				break
			}
			loc := firstNonEmpty(f.Filename, f.Module)
			marker := ""
			if f.InApp {
				marker = " [in-app]"
			}
			fmt.Fprintf(&b, "  %s (%s:%d)%s\n", firstNonEmpty(f.Function, "?"), loc, f.Lineno, marker)
		}
	}
	if len(item.Breadcrumbs) > 0 {
		b.WriteString("\nRecent breadcrumbs:\n")
		for i, c := range item.Breadcrumbs {
			if i >= 15 {
				break
			}
			fmt.Fprintf(&b, "  [%s] %s\n", firstNonEmpty(c.Category, "-"), c.Message)
		}
	}
	if item.RootCause != nil && item.RootCause.Summary != "" {
		fmt.Fprintf(&b, "\nDeterministic correlation preflight computed (%s confidence):\n  %s\n",
			item.RootCause.Confidence, item.RootCause.Summary)
	}
	b.WriteString("\nAnalyze the most likely root cause. Respond with ONLY a JSON object, no prose, no markdown:\n")
	b.WriteString(`{"likelyCause":"1-2 sentences on the most likely cause","suggestedFix":"the concrete next step or code area to check","confidence":"high|medium|low","summary":"one concise line"}`)
	b.WriteString("\n")
	return b.String()
}

// runAgent pipes the prompt to the configured agent CLI and returns stdout.
func runAgent(agentCmd, prompt string) (string, error) {
	parts := strings.Fields(agentCmd)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty agent command")
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = strings.NewReader(prompt)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parseAgentJSON extracts the first {...} JSON object from agent output
// (tolerating markdown fences / surrounding prose) and decodes it.
func parseAgentJSON(output string) (aiAnalysisResult, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start < 0 || end <= start {
		return aiAnalysisResult{}, fmt.Errorf("no JSON object in agent output")
	}
	var res aiAnalysisResult
	if err := json.Unmarshal([]byte(output[start:end+1]), &res); err != nil {
		return aiAnalysisResult{}, err
	}
	if res.Summary == "" && res.LikelyCause == "" {
		return aiAnalysisResult{}, fmt.Errorf("agent JSON missing summary/likelyCause")
	}
	if res.Confidence == "" {
		res.Confidence = "low"
	}
	return res, nil
}

func runCrashes(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printCrashesHelp(stdout)
		return 0
	}
	switch args[0] {
	case "analyze":
		return runCrashesAnalyze(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown crashes subcommand %q\n", args[0])
		printCrashesHelp(stderr)
		return 2
	}
}

func printCrashesHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight crashes analyze --app <id> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Generate AI root-cause narratives for crash issues via a local agent CLI")
	fmt.Fprintln(w, "(claude -p / codex) and post them back to preflight.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --app <id>       Preflight app id (or use --all)")
	fmt.Fprintln(w, "  --all            Analyze every fleet app's queue")
	fmt.Fprintln(w, "  --agent <cmd>    Agent CLI to pipe the prompt to (default \"claude -p\")")
	fmt.Fprintln(w, "  --limit <N>      Max issues to analyze (default 10)")
	fmt.Fprintln(w, "  --reanalyze      Include issues that already have an analysis")
	fmt.Fprintln(w, "  --dry-run        Print prompts + agent output, don't post back")
}

func runCrashesAnalyze(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	appID := ""
	agent := defaultAnalyzeAgent
	limit := defaultAnalyzeLimit
	reanalyze := false
	dryRun := false
	all := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			printCrashesHelp(stdout)
			return 0
		case "--app":
			if !nextInto(args, &i, &appID, stderr, "--app") {
				return 2
			}
		case "--agent":
			if !nextInto(args, &i, &agent, stderr, "--agent") {
				return 2
			}
		case "--limit":
			var raw string
			if !nextInto(args, &i, &raw, stderr, "--limit") {
				return 2
			}
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		case "--reanalyze":
			reanalyze = true
		case "--dry-run":
			dryRun = true
		case "--all":
			all = true
		default:
			fmt.Fprintf(stderr, "unknown flag %q\n", args[i])
			return 2
		}
	}
	if !all && strings.TrimSpace(appID) == "" {
		fmt.Fprintln(stderr, "--app <id> or --all is required")
		return 2
	}
	apiURL, token := preflightAPIConfig()
	if apiURL == "" || token == "" {
		fmt.Fprintln(stderr, "needs a Preflight API url/token (run `preflight config`)")
		return 2
	}

	// Resolve the app set: one app, or every distinct fleet app id.
	var appIDs []string
	if all {
		rows, err := fetchFleetReleaseRows(client, releaseStatusCLIOptions{
			apiURL: apiURL, token: token, platform: "ios",
		})
		if err != nil {
			fmt.Fprintf(stderr, "fetch fleet failed: %v\n", err)
			return 1
		}
		seen := map[string]bool{}
		for _, r := range rows {
			if r.AppID != "" && !seen[r.AppID] {
				seen[r.AppID] = true
				appIDs = append(appIDs, r.AppID)
			}
		}
	} else {
		appIDs = []string{appID}
	}

	opts := analyzeOptions{agent: agent, limit: limit, reanalyze: reanalyze, dryRun: dryRun}
	totalAnalyzed, totalFailed := 0, 0
	for _, id := range appIDs {
		a, f := analyzeApp(client, apiURL, token, id, opts, stdout, stderr)
		totalAnalyzed += a
		totalFailed += f
	}
	fmt.Fprintf(stdout, "\nanalyzed %d issue(s) across %d app(s); %d failed\n",
		totalAnalyzed, len(appIDs), totalFailed)
	return 0
}

type analyzeOptions struct {
	agent     string
	limit     int
	reanalyze bool
	dryRun    bool
}

// analyzeApp fetches one app's analysis queue and runs the agent over each item,
// posting the narrative back. Returns (analyzed, failed).
func analyzeApp(
	client *http.Client,
	apiURL, token, appID string,
	opts analyzeOptions,
	stdout, stderr io.Writer,
) (int, int) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(opts.limit))
	if opts.reanalyze {
		q.Set("reanalyze", "1")
	}
	endpoint := strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/errors/analysis-queue?" + q.Encode()
	raw, err := getPreflightJSON(client, endpoint, token)
	if err != nil {
		fmt.Fprintf(stderr, "  %s: fetch queue failed: %v\n", appID, err)
		return 0, 1
	}
	var payload struct {
		Queue []analysisQueueItem `json:"queue"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		fmt.Fprintf(stderr, "  %s: decode queue failed: %v\n", appID, err)
		return 0, 1
	}
	if len(payload.Queue) == 0 {
		return 0, 0
	}
	fmt.Fprintf(stdout, "%s: %d issue(s) to analyze\n", appID, len(payload.Queue))

	analyzed, failed := 0, 0
	for _, item := range payload.Queue {
		prompt := buildAnalysisPrompt(item)
		if opts.dryRun {
			fmt.Fprintf(stdout, "\n=== %s (%s) ===\n%s\n", item.ID, item.Type, prompt)
		}
		out, err := runAgent(opts.agent, prompt)
		if err != nil {
			fmt.Fprintf(stderr, "  %s: agent failed: %v\n", item.ID, err)
			failed++
			continue
		}
		res, err := parseAgentJSON(out)
		if err != nil {
			fmt.Fprintf(stderr, "  %s: parse failed: %v\n", item.ID, err)
			failed++
			continue
		}
		res.Agent = strings.Fields(opts.agent)[0]
		if opts.dryRun {
			fmt.Fprintf(stdout, "  → %s [%s]\n", res.LikelyCause, res.Confidence)
			analyzed++
			continue
		}
		post := strings.TrimRight(apiURL, "/") +
			"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/errors/" +
			url.PathEscape(item.ID) + "/analysis"
		if _, err := postPreflightJSON(client, post, token, res); err != nil {
			fmt.Fprintf(stderr, "  %s: post failed: %v\n", item.ID, err)
			failed++
			continue
		}
		fmt.Fprintf(stdout, "  %s → %s [%s]\n", item.ID, truncate(res.LikelyCause, 70), res.Confidence)
		analyzed++
	}
	return analyzed, failed
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
