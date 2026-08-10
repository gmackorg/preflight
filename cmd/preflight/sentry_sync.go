package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// `preflight sentry sync` relays raw Sentry issues into preflight's crash/error
// backbone (POST /apps/[id]/errors). We lean on Sentry for capture and pull the
// fingerprinted issues into preflight so they can be correlated with builds +
// dependency drift — the things Sentry can't see. Sentry project → preflight app
// is auto-matched by slug/name (same fleet resolver the deps sweep uses).

const defaultSentryStatsPeriod = "14d"
const defaultSentryIssueQuery = "is:unresolved"
const defaultSentryIssueLimit = 50

// Sentry's default rate limit is ~5 requests/second. Keep a hair under 4/s and
// back off on 429 so a full-fleet sweep doesn't get throttled mid-run.
const sentryMinInterval = 260 * time.Millisecond

// Project-slug suffixes that name a variant of the same app (the mobile Sentry
// project is where RN crash data lives). Stripped as a fallback match so
// `crucible-mobile` still resolves to the `crucible` preflight app.
var sentryProjectSuffixes = []string{"-mobile", "-app", "-native", "-ios", "-android", "-expo"}

// Built-in aliases for fleet apps whose Sentry project slug doesn't line up with
// their preflight slug/name (auto-match can't bridge these). Keyed by the base
// Sentry project slug (after suffix stripping). Overridable via --alias.
var defaultSentryAliases = map[string]string{
	"classcheck":      "pfapp_seed_classcheck_app",
	"habitplay":       "pfapp_seed_habit_play",
	"latchflow":       "pfapp_seed_escape_puzzles",
	"controlsfoundry": "pfapp_seed_edgeops_mobile",
	"appealkey":       "pfapp_seed_truecomps_app",
}

// --- Sentry API response shapes (only the fields we consume) ---

type sentryProject struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

type sentryIssue struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Culprit   string `json:"culprit"`
	Level     string `json:"level"`
	Permalink string `json:"permalink"`
	Count     string `json:"count"`
	UserCount int    `json:"userCount"`
	LastSeen  string `json:"lastSeen"`
	FirstSeen string `json:"firstSeen"`
	Platform  string `json:"platform"`
	Metadata  struct {
		Type     string `json:"type"`
		Value    string `json:"value"`
		Filename string `json:"filename"`
	} `json:"metadata"`
}

type sentryEvent struct {
	EventID     string `json:"eventID"`
	ID          string `json:"id"`
	Platform    string `json:"platform"`
	Release     string `json:"release"`
	DateCreated string `json:"dateCreated"`
	Tags        []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
	Entries []struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	} `json:"entries"`
	// Structured contexts (app/os/device/runtime/…). Values are heterogeneous
	// so we decode the ones we care about individually.
	Contexts map[string]json.RawMessage `json:"contexts"`
}

// Sentry breadcrumb entry payload (entries[].type == "breadcrumbs").
type sentryBreadcrumbData struct {
	Values []struct {
		Timestamp any                    `json:"timestamp"`
		Category  string                 `json:"category"`
		Level     string                 `json:"level"`
		Message   string                 `json:"message"`
		Type      string                 `json:"type"`
		Data      map[string]interface{} `json:"data"`
	} `json:"values"`
}

// Only the context fields we lift onto the error payload.
type sentryContexts struct {
	release     string
	appVersion  string
	osName      string
	osVersion   string
	deviceModel string
	runtimeName string
}

type sentryBreadcrumb struct {
	Timestamp string                 `json:"timestamp,omitempty"`
	Category  string                 `json:"category,omitempty"`
	Level     string                 `json:"level,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// The exception entry payload (entries[].type == "exception").
type sentryExceptionData struct {
	Values []struct {
		Type       string `json:"type"`
		Value      string `json:"value"`
		Stacktrace struct {
			Frames []sentryAPIFrame `json:"frames"`
		} `json:"stacktrace"`
	} `json:"values"`
}

type sentryAPIFrame struct {
	Function string `json:"function"`
	Module   string `json:"module"`
	Filename string `json:"filename"`
	AbsPath  string `json:"absPath"`
	LineNo   int    `json:"lineNo"`
	ColNo    int    `json:"colNo"`
	InApp    bool   `json:"inApp"`
}

// --- preflight /errors payload (matches the route's normalizeEventInput) ---

type sentryStackFrame struct {
	Function string `json:"function,omitempty"`
	Module   string `json:"module,omitempty"`
	Filename string `json:"filename,omitempty"`
	Lineno   int    `json:"lineno,omitempty"`
	Colno    int    `json:"colno,omitempty"`
	InApp    bool   `json:"inApp"`
}

type sentryErrorPayload struct {
	Provider        string             `json:"provider"`
	ProviderEventID string             `json:"providerEventId,omitempty"`
	ProviderIssueID string             `json:"providerIssueId,omitempty"`
	Level           string             `json:"level,omitempty"`
	Runtime         string             `json:"runtime,omitempty"`
	Platform        string             `json:"platform,omitempty"`
	Type            string             `json:"type,omitempty"`
	Message         string             `json:"message,omitempty"`
	Culprit         string             `json:"culprit,omitempty"`
	Stack           []sentryStackFrame `json:"stack,omitempty"`
	IsFatal         bool               `json:"isFatal,omitempty"`
	Release         string             `json:"release,omitempty"`
	AppVersion      string             `json:"appVersion,omitempty"`
	OsName          string             `json:"osName,omitempty"`
	OsVersion       string             `json:"osVersion,omitempty"`
	DeviceModel     string             `json:"deviceModel,omitempty"`
	Breadcrumbs     []sentryBreadcrumb `json:"breadcrumbs,omitempty"`
	IssueURL        string             `json:"issueUrl,omitempty"`
	OccurredAt      string             `json:"occurredAt,omitempty"`
	Context         map[string]any     `json:"context,omitempty"`
}

// extractSentryContexts lifts app/os/device/runtime details from an event's
// structured contexts. Mobile events carry app+os+device; server/worker events
// carry runtime. Everything is best-effort.
func extractSentryContexts(event *sentryEvent) sentryContexts {
	out := sentryContexts{}
	if event == nil || event.Contexts == nil {
		return out
	}
	if raw, ok := event.Contexts["app"]; ok {
		var app struct {
			AppVersion string `json:"app_version"`
			AppBuild   string `json:"app_build"`
		}
		if json.Unmarshal(raw, &app) == nil {
			out.appVersion = app.AppVersion
			if app.AppVersion != "" && app.AppBuild != "" {
				out.release = fmt.Sprintf("%s (%s)", app.AppVersion, app.AppBuild)
			} else {
				out.release = firstNonEmpty(app.AppVersion, app.AppBuild)
			}
		}
	}
	if raw, ok := event.Contexts["os"]; ok {
		var os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &os) == nil {
			out.osName = os.Name
			out.osVersion = os.Version
		}
	}
	if raw, ok := event.Contexts["device"]; ok {
		var dev struct {
			Model  string `json:"model"`
			Family string `json:"family"`
		}
		if json.Unmarshal(raw, &dev) == nil {
			out.deviceModel = firstNonEmpty(dev.Model, dev.Family)
		}
	}
	if raw, ok := event.Contexts["runtime"]; ok {
		var rt struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &rt) == nil {
			out.runtimeName = rt.Name
		}
	}
	return out
}

// sentryEventEnvironment pulls the environment tag (development/production/…).
func sentryEventEnvironment(event *sentryEvent) string {
	if event == nil {
		return ""
	}
	for _, tag := range event.Tags {
		if tag.Key == "environment" {
			return tag.Value
		}
	}
	return ""
}

// extractSentryBreadcrumbs converts an event's breadcrumb trail (oldest→newest
// in Sentry) into preflight breadcrumbs, capped to the most recent 30.
func extractSentryBreadcrumbs(event *sentryEvent) []sentryBreadcrumb {
	if event == nil {
		return nil
	}
	for _, entry := range event.Entries {
		if entry.Type != "breadcrumbs" {
			continue
		}
		var data sentryBreadcrumbData
		if json.Unmarshal(entry.Data, &data) != nil {
			return nil
		}
		crumbs := make([]sentryBreadcrumb, 0, len(data.Values))
		for _, v := range data.Values {
			ts := ""
			switch t := v.Timestamp.(type) {
			case string:
				ts = t
			case float64:
				ts = strconv.FormatFloat(t, 'f', -1, 64)
			}
			crumbs = append(crumbs, sentryBreadcrumb{
				Timestamp: ts,
				Category:  firstNonEmpty(v.Category, v.Type),
				Level:     v.Level,
				Message:   v.Message,
				Data:      v.Data,
			})
		}
		if len(crumbs) > 30 {
			crumbs = crumbs[len(crumbs)-30:]
		}
		return crumbs
	}
	return nil
}

// mapSentryLevel collapses Sentry levels onto preflight's error levels.
func mapSentryLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "fatal":
		return "fatal"
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "info", "debug", "sample":
		return "info"
	default:
		return "error"
	}
}

// sentryRuntime maps a Sentry platform tag to a preflight runtime. Tuned for the
// fleet: JS/RN/native-mobile → expo, C#/Unity → unity, node → node.
func sentryRuntime(platform string) string {
	p := strings.ToLower(platform)
	switch {
	case strings.Contains(p, "unity"), strings.Contains(p, "csharp"), strings.Contains(p, "dotnet"):
		return "unity"
	case strings.Contains(p, "node"), strings.Contains(p, "cloudflare"),
		strings.Contains(p, "deno"), strings.Contains(p, "worker"):
		return "node"
	case strings.Contains(p, "react-native"), strings.Contains(p, "javascript"),
		strings.Contains(p, "cocoa"), p == "apple-ios", strings.Contains(p, "android"),
		strings.Contains(p, "java"):
		return "expo"
	default:
		return ""
	}
}

// sentryPlatform derives ios/android when the Sentry platform tag makes it
// unambiguous; otherwise empty (the route treats non-ios/android as null).
func sentryPlatform(platform string) string {
	p := strings.ToLower(platform)
	switch {
	case strings.Contains(p, "cocoa"), strings.Contains(p, "ios"), strings.Contains(p, "apple"):
		return "ios"
	case strings.Contains(p, "android"):
		return "android"
	default:
		return ""
	}
}

// sentryFramesToStack converts Sentry frames (bottom-to-top) into preflight
// frames ordered most-recent-first, matching how the client SDK would report.
func sentryFramesToStack(frames []sentryAPIFrame) []sentryStackFrame {
	out := make([]sentryStackFrame, 0, len(frames))
	for i := len(frames) - 1; i >= 0; i-- {
		f := frames[i]
		filename := f.Filename
		if filename == "" {
			filename = f.AbsPath
		}
		out = append(out, sentryStackFrame{
			Function: f.Function,
			Module:   f.Module,
			Filename: filename,
			Lineno:   f.LineNo,
			Colno:    f.ColNo,
			InApp:    f.InApp,
		})
	}
	return out
}

// extractSentryException pulls the type/value/frames out of an event's exception
// entry (if present).
func extractSentryException(event *sentryEvent) (excType string, excValue string, stack []sentryStackFrame) {
	if event == nil {
		return "", "", nil
	}
	for _, entry := range event.Entries {
		if entry.Type != "exception" {
			continue
		}
		var data sentryExceptionData
		if err := json.Unmarshal(entry.Data, &data); err != nil {
			continue
		}
		if len(data.Values) == 0 {
			continue
		}
		// The last value is the outermost thrown exception.
		v := data.Values[len(data.Values)-1]
		return v.Type, v.Value, sentryFramesToStack(v.Stacktrace.Frames)
	}
	return "", "", nil
}

// normalizeSentryIssue maps a Sentry issue (+ its latest event, when fetched)
// into the preflight /errors payload. Grouping is by provider:issueId (the store
// derives the fingerprint), so Sentry's own grouping is preserved 1:1.
func normalizeSentryIssue(issue sentryIssue, latest *sentryEvent) sentryErrorPayload {
	level := mapSentryLevel(issue.Level)
	excType, excValue, stack := extractSentryException(latest)
	if excType == "" {
		excType = issue.Metadata.Type
	}
	message := firstNonEmpty(excValue, issue.Metadata.Value, issue.Title, issue.Culprit)

	platformTag := issue.Platform
	release := ""
	eventID := ""
	if latest != nil {
		if latest.Platform != "" {
			platformTag = latest.Platform
		}
		release = latest.Release
		eventID = firstNonEmpty(latest.EventID, latest.ID)
		if release == "" {
			for _, tag := range latest.Tags {
				if tag.Key == "release" {
					release = tag.Value
					break
				}
			}
		}
	}

	// Enrich from the event's structured contexts + breadcrumbs.
	cx := extractSentryContexts(latest)
	if release == "" {
		release = cx.release
	}
	environment := sentryEventEnvironment(latest)
	breadcrumbs := extractSentryBreadcrumbs(latest)

	// Runtime: prefer the event runtime context (cloudflare/node/deno →
	// server), fall back to the platform-tag heuristic.
	runtime := sentryRuntime(platformTag)
	if cx.runtimeName != "" {
		if rt := sentryRuntime(cx.runtimeName); rt != "" {
			runtime = rt
		}
	}

	ctx := map[string]any{}
	if issue.Count != "" {
		if n, err := strconv.Atoi(issue.Count); err == nil {
			ctx["sentryEventCount"] = n
		}
	}
	if issue.UserCount > 0 {
		ctx["sentryUserCount"] = issue.UserCount
	}
	if issue.FirstSeen != "" {
		ctx["sentryFirstSeen"] = issue.FirstSeen
	}
	if environment != "" {
		ctx["environment"] = environment
	}
	if cx.runtimeName != "" {
		ctx["sentryRuntime"] = cx.runtimeName
	}
	if len(ctx) == 0 {
		ctx = nil
	}

	return sentryErrorPayload{
		Provider:        "sentry",
		ProviderEventID: eventID,
		ProviderIssueID: issue.ID,
		Level:           level,
		Runtime:         runtime,
		Platform:        sentryPlatform(platformTag),
		Type:            excType,
		Message:         message,
		Culprit:         issue.Culprit,
		Stack:           stack,
		IsFatal:         level == "fatal",
		Release:         release,
		AppVersion:      cx.appVersion,
		OsName:          cx.osName,
		OsVersion:       cx.osVersion,
		DeviceModel:     cx.deviceModel,
		Breadcrumbs:     breadcrumbs,
		IssueURL:        issue.Permalink,
		OccurredAt:      issue.LastSeen,
		Context:         ctx,
	}
}

// matchSentryProject resolves a Sentry project to a preflight app id: explicit
// alias first, then auto-match by slug/name (case-insensitive), then the same
// with a variant suffix stripped (e.g. `crucible-mobile` → `crucible`, or the
// aliased `classcheck-mobile` → `classcheck`). Returns "" when nothing matches.
func matchSentryProject(project sentryProject, aliases, bySlug, byName map[string]string) string {
	slug := strings.ToLower(project.Slug)
	base := slug
	for _, suffix := range sentryProjectSuffixes {
		if strings.HasSuffix(slug, suffix) {
			base = strings.TrimSuffix(slug, suffix)
			break
		}
	}
	if id := firstNonEmpty(aliases[slug], aliases[base]); id != "" {
		return id
	}
	if id := bySlug[slug]; id != "" {
		return id
	}
	if id := byName[strings.ToLower(project.Name)]; id != "" {
		return id
	}
	if id := byName[slug]; id != "" {
		return id
	}
	if base != slug {
		if id := firstNonEmpty(bySlug[base], byName[base]); id != "" {
			return id
		}
	}
	return ""
}

// --- HTTP command ---

type sentrySyncOptions struct {
	apiURL       string
	org          string
	authToken    string
	project      string
	forcedAppID  string
	statsPeriod  string
	query        string
	limit        int
	json         bool
	dryRun       bool
	alert        bool
	aliases      map[string]string
	preflightURL string
	preflightTok string
}

func runSentry(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printSentryHelp(stdout)
		return 0
	}
	switch args[0] {
	case "sync":
		return runSentrySync(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown sentry subcommand %q\n", args[0])
		printSentryHelp(stderr)
		return 2
	}
}

func printSentryHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight sentry sync --org <slug> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Relay raw Sentry issues into preflight crash/error tracking. Sentry projects")
	fmt.Fprintln(w, "are auto-matched to preflight apps by slug/name.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --org <slug>            Sentry organization slug (required)")
	fmt.Fprintln(w, "  --auth-token-env <NAME> Env var holding the Sentry auth token (default SENTRY_AUTH_TOKEN)")
	fmt.Fprintln(w, "  --sentry-api-url <url>  Sentry API base (default https://sentry.io)")
	fmt.Fprintln(w, "  --project <slug>        Sync only this project (else every project in the org)")
	fmt.Fprintln(w, "  --app <id>              Force target preflight app id (with --project)")
	fmt.Fprintln(w, "  --stats-period <p>      Sentry stats period (default 14d)")
	fmt.Fprintln(w, "  --query <q>             Issue search query (default \"is:unresolved\")")
	fmt.Fprintln(w, "  --limit <N>             Max issues per project (default 50)")
	fmt.Fprintln(w, "  --alias <slug=appId>    Map a Sentry project slug to a preflight app id (repeatable)")
	fmt.Fprintln(w, "  --dry-run               Fetch + normalize but don't POST to preflight")
	fmt.Fprintln(w, "  --alert                 After syncing, evaluate crash alert rules + notify")
	fmt.Fprintln(w, "  --json                  Emit a JSON summary")
}

func runSentrySync(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	opts := sentrySyncOptions{
		apiURL:      defaultSentryAPIURL,
		statsPeriod: defaultSentryStatsPeriod,
		query:       defaultSentryIssueQuery,
		limit:       defaultSentryIssueLimit,
		aliases:     map[string]string{},
	}
	for k, v := range defaultSentryAliases {
		opts.aliases[k] = v
	}
	authTokenEnv := "SENTRY_AUTH_TOKEN"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			printSentryHelp(stdout)
			return 0
		case "--org":
			if !nextInto(args, &i, &opts.org, stderr, "--org") {
				return 2
			}
		case "--auth-token-env":
			if !nextInto(args, &i, &authTokenEnv, stderr, "--auth-token-env") {
				return 2
			}
		case "--sentry-api-url":
			if !nextInto(args, &i, &opts.apiURL, stderr, "--sentry-api-url") {
				return 2
			}
		case "--project":
			if !nextInto(args, &i, &opts.project, stderr, "--project") {
				return 2
			}
		case "--app":
			if !nextInto(args, &i, &opts.forcedAppID, stderr, "--app") {
				return 2
			}
		case "--stats-period":
			if !nextInto(args, &i, &opts.statsPeriod, stderr, "--stats-period") {
				return 2
			}
		case "--query":
			if !nextInto(args, &i, &opts.query, stderr, "--query") {
				return 2
			}
		case "--limit":
			var raw string
			if !nextInto(args, &i, &raw, stderr, "--limit") {
				return 2
			}
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				opts.limit = n
			}
		case "--alias":
			var pair string
			if !nextInto(args, &i, &pair, stderr, "--alias") {
				return 2
			}
			if k, v, ok := strings.Cut(pair, "="); ok {
				opts.aliases[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			} else {
				fmt.Fprintf(stderr, "--alias expects slug=appId, got %q\n", pair)
				return 2
			}
		case "--dry-run":
			opts.dryRun = true
		case "--alert":
			opts.alert = true
		case "--json":
			opts.json = true
		default:
			fmt.Fprintf(stderr, "unknown flag %q\n", args[i])
			return 2
		}
	}

	if strings.TrimSpace(opts.org) == "" {
		fmt.Fprintln(stderr, "--org <slug> is required")
		return 2
	}
	opts.authToken = strings.TrimSpace(os.Getenv(authTokenEnv))
	if opts.authToken == "" {
		fmt.Fprintf(stderr, "environment variable %s is empty (Sentry auth token)\n", authTokenEnv)
		return 2
	}
	opts.preflightURL, opts.preflightTok = preflightAPIConfig()
	if !opts.dryRun && (opts.preflightURL == "" || opts.preflightTok == "") {
		fmt.Fprintln(stderr, "posting needs a Preflight API url/token (run `preflight config`)")
		return 2
	}

	// Build the fleet slug/name → appId maps for auto-matching.
	bySlug, byName := map[string]string{}, map[string]string{}
	if opts.forcedAppID == "" || opts.project == "" {
		rows, err := fetchFleetReleaseRows(client, releaseStatusCLIOptions{
			apiURL: opts.preflightURL, token: opts.preflightTok, platform: "ios",
		})
		if err != nil {
			fmt.Fprintf(stderr, "fetch fleet failed: %v\n", err)
			return 1
		}
		for _, r := range rows {
			if r.Slug != "" {
				bySlug[strings.ToLower(r.Slug)] = r.AppID
			}
			if r.Name != "" {
				byName[strings.ToLower(r.Name)] = r.AppID
			}
		}
	}

	// Resolve the project list.
	var projects []sentryProject
	if opts.project != "" {
		projects = []sentryProject{{Slug: opts.project, Name: opts.project}}
	} else {
		list, err := listSentryProjects(client, opts)
		if err != nil {
			fmt.Fprintf(stderr, "list Sentry projects failed: %v\n", err)
			return 1
		}
		projects = list
	}

	type appReport struct {
		appID    string
		project  string
		issues   int
		posted   int
		deduped  int
		newGroup int
	}
	var reports []appReport
	var unmatched []string
	totalIssues, totalPosted := 0, 0

	for _, project := range projects {
		appID := opts.forcedAppID
		if appID == "" {
			appID = matchSentryProject(project, opts.aliases, bySlug, byName)
		}
		if appID == "" {
			unmatched = append(unmatched, project.Slug)
			continue
		}
		issues, err := listSentryIssues(client, opts, project.Slug)
		if err != nil {
			fmt.Fprintf(stderr, "  %-30s issues fetch failed: %v\n", project.Slug, err)
			continue
		}
		payloads := make([]sentryErrorPayload, 0, len(issues))
		for _, issue := range issues {
			latest, _ := fetchSentryLatestEvent(client, opts, issue.ID)
			payloads = append(payloads, normalizeSentryIssue(issue, latest))
		}
		totalIssues += len(payloads)
		rep := appReport{appID: appID, project: project.Slug, issues: len(payloads)}
		if opts.dryRun {
			fmt.Fprintf(stdout, "  [dry-run] %-30s → %s : %d issues\n", project.Slug, appID, len(payloads))
			reports = append(reports, rep)
			continue
		}
		if len(payloads) > 0 {
			res, err := postSentryErrors(client, opts, appID, payloads)
			if err != nil {
				fmt.Fprintf(stderr, "  %-30s post failed: %v\n", project.Slug, err)
				reports = append(reports, rep)
				continue
			}
			rep.posted = res.Ingested
			rep.deduped = res.Deduped
			rep.newGroup = res.NewGroups
			totalPosted += res.Ingested
		}
		fmt.Fprintf(stdout, "  %-30s → %-24s %d issues (%d new, %d dup)\n",
			project.Slug, appID, rep.issues, rep.newGroup, rep.deduped)
		reports = append(reports, rep)
	}

	// After syncing, evaluate crash alert rules so a fresh regression raises a
	// notification on the board (opt-in via --alert).
	if opts.alert && !opts.dryRun {
		if raised, err := evaluateCrashAlerts(client, opts); err != nil {
			fmt.Fprintf(stderr, "alert evaluation failed: %v\n", err)
		} else if raised > 0 {
			fmt.Fprintf(stdout, "raised %d crash alert(s)\n", raised)
		}
	}

	if opts.json {
		summary := map[string]any{
			"org": opts.org, "projects": len(projects), "matched": len(reports),
			"unmatched": unmatched, "totalIssues": totalIssues, "totalPosted": totalPosted,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	} else {
		fmt.Fprintf(stdout, "\nsynced %d issues across %d apps (%d posted); %d unmatched projects\n",
			totalIssues, len(reports), totalPosted, len(unmatched))
		if len(unmatched) > 0 {
			fmt.Fprintf(stdout, "unmatched (no fleet app by slug/name): %s\n", strings.Join(unmatched, ", "))
		}
	}
	return 0
}

// nextInto reads the next arg into dst, erroring if absent.
func nextInto(args []string, i *int, dst *string, stderr io.Writer, flag string) bool {
	if *i+1 >= len(args) {
		fmt.Fprintf(stderr, "%s requires a value\n", flag)
		return false
	}
	*i++
	*dst = args[*i]
	return true
}

func sentryGet(client *http.Client, opts sentrySyncOptions, endpoint string, out any) error {
	// Throttle + retry on 429 to stay under Sentry's ~5 req/s limit.
	for attempt := 0; ; attempt++ {
		time.Sleep(sentryMinInterval)
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+opts.authToken)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		retryAfter := resp.Header.Get("Retry-After")
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 4 {
			wait := 1500 * time.Millisecond
			if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
			time.Sleep(wait)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := strings.TrimSpace(string(body))
			if len(msg) > 200 {
				msg = msg[:200]
			}
			return fmt.Errorf("Sentry HTTP %d: %s", resp.StatusCode, msg)
		}
		return json.Unmarshal(body, out)
	}
}

func listSentryProjects(client *http.Client, opts sentrySyncOptions) ([]sentryProject, error) {
	base := strings.TrimRight(opts.apiURL, "/")
	endpoint := base + "/api/0/organizations/" + url.PathEscape(opts.org) + "/projects/"
	var projects []sentryProject
	if err := sentryGet(client, opts, endpoint, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func listSentryIssues(client *http.Client, opts sentrySyncOptions, projectSlug string) ([]sentryIssue, error) {
	base := strings.TrimRight(opts.apiURL, "/")
	q := url.Values{}
	q.Set("query", opts.query)
	q.Set("statsPeriod", opts.statsPeriod)
	q.Set("limit", strconv.Itoa(opts.limit))
	endpoint := base + "/api/0/projects/" + url.PathEscape(opts.org) + "/" +
		url.PathEscape(projectSlug) + "/issues/?" + q.Encode()
	var issues []sentryIssue
	if err := sentryGet(client, opts, endpoint, &issues); err != nil {
		return nil, err
	}
	if len(issues) > opts.limit {
		issues = issues[:opts.limit]
	}
	return issues, nil
}

func fetchSentryLatestEvent(client *http.Client, opts sentrySyncOptions, issueID string) (*sentryEvent, error) {
	base := strings.TrimRight(opts.apiURL, "/")
	endpoint := base + "/api/0/issues/" + url.PathEscape(issueID) + "/events/latest/"
	var event sentryEvent
	if err := sentryGet(client, opts, endpoint, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

type sentryPostResult struct {
	Ingested  int `json:"ingested"`
	Deduped   int `json:"deduped"`
	NewGroups int `json:"newGroups"`
	Groups    int `json:"groups"`
}

func postSentryErrors(client *http.Client, opts sentrySyncOptions, appID string, payloads []sentryErrorPayload) (sentryPostResult, error) {
	endpoint := strings.TrimRight(opts.preflightURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/errors"
	body := map[string]any{"events": payloads}
	raw, err := postPreflightJSON(client, endpoint, opts.preflightTok, body)
	if err != nil {
		return sentryPostResult{}, err
	}
	// postPreflightJSON already unwraps the envelope's `data`, so `raw` is the
	// route's result object directly.
	var result sentryPostResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return sentryPostResult{}, fmt.Errorf("decode errors response: %w", err)
	}
	return result, nil
}

// evaluateCrashAlerts asks the server to evaluate crash.* alert rules across the
// caller's workspaces + write notifications. Returns the number raised.
func evaluateCrashAlerts(client *http.Client, opts sentrySyncOptions) (int, error) {
	endpoint := strings.TrimRight(opts.preflightURL, "/") +
		"/api/preflight/v1/crashes/alerts/evaluate"
	raw, err := postPreflightJSON(client, endpoint, opts.preflightTok, map[string]any{})
	if err != nil {
		return 0, err
	}
	var result struct {
		Raised int `json:"raised"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, nil
	}
	return result.Raised, nil
}
