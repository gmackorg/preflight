package main

// Build-farm operations: trigger work, watch the queue, and see the hosts.
//
// The control plane already exposes all of this (work orders carry the
// provider decision + dispatch planning; runners report capacity and
// heartbeats), but none of it was reachable from the CLI — so the only way to
// answer "why is nothing building?" was to open a psql session against
// production. These four commands close that gap:
//
//	preflight build         trigger a work order
//	preflight queue         what is queued/running/blocked, and why
//	preflight nodes         which runners exist, which are stale, what they hold
//	preflight integrations  is the API + its upstreams actually reachable
//
// The recurring failure this is built to expose is a deep queue with zero live
// runners: both halves look fine in isolation, so `queue` and `nodes` each
// report the other's number.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

type buildOpsContext struct {
	apiURL      string
	token       string
	workspaceID string
}

func newBuildOpsContext() buildOpsContext {
	config, _ := loadPreflightCLIConfig()
	return buildOpsContext{
		apiURL:      firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL),
		token:       firstNonEmpty(os.Getenv("PREFLIGHT_TOKEN"), config.Token),
		workspaceID: firstNonEmpty(os.Getenv("PREFLIGHT_WORKSPACE_ID"), config.WorkspaceID),
	}
}

func (c buildOpsContext) endpoint(path string, query url.Values) string {
	base := strings.TrimRight(c.apiURL, "/") + "/api/preflight/v1" + path
	if len(query) == 0 {
		return base
	}
	return base + "?" + query.Encode()
}

// requireWorkspace fails early rather than letting the API answer with an
// opaque 401 — an unset workspace is the most common first-run mistake.
func (c buildOpsContext) requireWorkspace(stderr io.Writer) bool {
	if strings.TrimSpace(c.workspaceID) == "" {
		fmt.Fprintln(stderr, "no workspace id — run `preflight login` or set PREFLIGHT_WORKSPACE_ID")
		return false
	}
	return true
}

// relativeAge renders a second count the way an operator reads it.
func relativeAge(seconds *int) string {
	if seconds == nil {
		return "never"
	}
	s := *seconds
	switch {
	case s < 90:
		return fmt.Sprintf("%ds", s)
	case s < 5400:
		return fmt.Sprintf("%dm", s/60)
	default:
		return fmt.Sprintf("%dh", s/3600)
	}
}

func writeJSON(stdout io.Writer, payload any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// preflight build
// ---------------------------------------------------------------------------

var workOrderKinds = []string{
	"build", "simulator_test", "device_test", "e2e_suite",
	"submission_verify", "submit", "release_candidate",
	"build_matrix", "post_release_monitor",
}

type workOrder struct {
	ID            string `json:"id"`
	AppID         string `json:"appId"`
	Kind          string `json:"kind"`
	Platform      string `json:"platform"`
	Status        string `json:"status"`
	PriorityClass string `json:"priorityClass"`
	BuildProvider string `json:"buildProvider"`
	BlockedReason string `json:"blockedReason"`
	RequestedBy   string `json:"requestedBy"`
	CreatedAt     string `json:"createdAt"`
}

func runBuild(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printBuildHelp(stdout)
		return 0
	}
	ctx := newBuildOpsContext()
	appID, platform, runtime := "", "ios", "expo"
	kind, priorityClass, idempotencyKey := "build", "normal", ""
	wait, jsonOut := false, false
	preference := ""
	appDir := "."
	ciBuild := false

	for i := 0; i < len(args); i++ {
		next := func(dst *string) {
			if value, ok := nextFlagValue(args, &i); ok {
				*dst = value
			}
		}
		switch args[i] {
		case "--app":
			next(&appID)
		case "--platform":
			next(&platform)
		case "--runtime":
			next(&runtime)
		case "--kind":
			next(&kind)
		case "--priority-class":
			next(&priorityClass)
		case "--provider":
			next(&preference)
		case "--idempotency-key":
			next(&idempotencyKey)
		case "--app-dir":
			next(&appDir)
		case "--ci":
			ciBuild = true
		case "--wait":
			wait = true
		case "--json":
			jsonOut = true
		}
	}

	if strings.TrimSpace(appID) == "" {
		fmt.Fprintln(stderr, "--app is required")
		printBuildHelp(stderr)
		return 2
	}
	if !contains(workOrderKinds, kind) {
		fmt.Fprintf(stderr, "unknown --kind %q; expected one of: %s\n", kind, strings.Join(workOrderKinds, ", "))
		return 2
	}
	if platform != "ios" && platform != "android" {
		fmt.Fprintf(stderr, "--platform must be ios or android, got %q\n", platform)
		return 2
	}
	if !ctx.requireWorkspace(stderr) {
		return 2
	}

	// The API rejects a work order without sourceBinding.workspaceRoot, and the
	// runner routes jobs by matching that root against the checkouts it owns —
	// so an approximate binding would queue an order no runner can claim.
	// Derived with the same discoverSourceBinding() prove-app uses, rather than
	// a second implementation that could drift from it.
	binding, bindingErr := discoverSourceBinding(proveAppOptions{
		appDir:   appDir,
		platform: platform,
		lane:     "simulator",
	})
	if bindingErr != nil {
		fmt.Fprintf(stderr, "cannot describe the app source: %v\n", bindingErr)
		fmt.Fprintf(stderr, "run this from the app package, or pass --app-dir <path-to-expo-app>\n")
		return 2
	}

	// A binding taken from a developer working tree can only be satisfied by a
	// runner sharing that exact tree. Any other runner claims the job, compares
	// the binding against its own checkout, rejects it with
	// source_binding_mismatch, and releases — then the next runner does the
	// same. Observed on 2026-08-14: seven claim/release cycles in seven minutes
	// for one order, churning the farm and never building anything.
	//
	// A dirty tree guarantees that outcome, since the runner cannot reproduce
	// uncommitted work. Refuse up front rather than queue an order that can only
	// thrash. CI-owned checkouts under .preflight-ci/ are exempt: the runner
	// syncs those to the requested commit itself.
	// --ci retargets the binding at a Preflight-owned checkout. The runner
	// clones the remote there and hard-resets to the requested commit, so the
	// build no longer depends on the caller's working tree existing (or being
	// clean) on the machine that claims the job. This is the only way a farm
	// build works from a developer machine: a developer-tree binding can only
	// ever be satisfied by that same machine.
	//
	// The commit must be pushed — the runner fetches it from the remote.
	if ciBuild {
		if strings.TrimSpace(binding.GitRemoteURL) == "" {
			fmt.Fprintln(stderr, "--ci needs a git remote; this checkout has none")
			return 2
		}
		if strings.TrimSpace(binding.GitCommitSHA) == "" {
			fmt.Fprintln(stderr, "--ci needs a commit sha to sync to")
			return 2
		}
		// The runner fetches from the remote and hard-resets to this sha, so a
		// local-only commit fails there, not here:
		//   fatal: Could not parse object '<sha>'
		// and the job then thrashes claim/mismatch/release. Checking that the
		// remote actually has it turns that into an error the caller can act on.
		if !commitIsOnRemote(binding.GitCommitSHA) {
			fmt.Fprintf(stderr, "commit %s is not on the remote\n", binding.GitCommitSHA[:min(12, len(binding.GitCommitSHA))])
			fmt.Fprintln(stderr, "the runner fetches from the remote and cannot check out a local-only commit")
			fmt.Fprintln(stderr, "push the branch (or cherry-pick it to the tracked branch) and re-run")
			return 2
		}
		repo := filepath.Base(strings.TrimSuffix(binding.WorkspaceRoot, "/"))
		binding.WorkspaceRoot = filepath.Join(
			filepath.Dir(binding.WorkspaceRoot), ciCheckoutRootSegment, repo)
		// The runner hard-resets this checkout, so whatever was uncommitted
		// locally is irrelevant to what actually gets built.
		binding.DirtyWorkspace = false
		binding.ChangedSetupFiles = nil
		fmt.Fprintf(stdout, "ci build: %s @ %s\n", binding.WorkspaceRoot, binding.GitCommitSHA[:min(12, len(binding.GitCommitSHA))])
	}

	if binding.DirtyWorkspace && !strings.Contains(binding.WorkspaceRoot, ciCheckoutRootSegment) {
		fmt.Fprintf(stderr, "refusing to queue: %s has uncommitted changes\n", binding.WorkspaceRoot)
		fmt.Fprintf(stderr, "the runner validates the binding against its own checkout and will reject it\n")
		fmt.Fprintf(stderr, "commit and push, then re-run — or build from a .preflight-ci checkout\n")
		return 2
	}

	// A work order whose workspaceRoot no active runner can reach is accepted,
	// queued, and then sits forever: nothing rejects it and nothing reports it.
	// Observed on 2026-08-14 — a probe job rooted at /Users/mackieg/playtrek-build
	// sat queued for 47 minutes because every runner serves only /Volumes/dev,
	// while the board showed it as ordinary pending work.
	//
	// prove-app already refuses this; `build` did not. Same probe, same message.
	if err := verifyPreflightRunnerCapacity(client, proveAppOptions{
		apiURL:      ctx.apiURL,
		token:       ctx.token,
		workspaceID: ctx.workspaceID,
		platform:    platform,
		lane:        "simulator",
	}, binding); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}

	payload := map[string]any{
		"workspaceId":   ctx.workspaceID,
		"appId":         appID,
		"runtime":       runtime,
		"platform":      platform,
		"kind":          kind,
		"priorityClass": priorityClass,
		"requestedBy":   "cli",
		"sourceBinding": binding,
	}
	if preference != "" {
		payload["buildProviderPreference"] = preference
	}
	if idempotencyKey != "" {
		payload["idempotencyKey"] = idempotencyKey
	}

	raw, err := postPreflightJSON(client, ctx.endpoint("/work-orders", nil), ctx.token, payload)
	if err != nil {
		fmt.Fprintf(stderr, "create work order failed: %v\n", err)
		return 1
	}
	var response struct {
		WorkOrder  workOrder `json:"workOrder"`
		Idempotent bool      `json:"idempotent"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		fmt.Fprintf(stderr, "decode response: %v\n", err)
		return 1
	}
	if jsonOut {
		return writeJSON(stdout, response)
	}

	order := response.WorkOrder
	if response.Idempotent {
		fmt.Fprintf(stdout, "Reused existing work order %s (idempotency key matched).\n", order.ID)
	} else {
		fmt.Fprintf(stdout, "Queued %s %s for %s → %s\n", order.Kind, order.Platform, order.AppID, order.ID)
	}
	if order.BuildProvider != "" {
		fmt.Fprintf(stdout, "  provider: %s\n", order.BuildProvider)
	}
	// A blocked order is accepted by the API but will never run; say so here
	// rather than letting it sit in the queue looking pending.
	if order.Status == "blocked" {
		fmt.Fprintf(stdout, "  BLOCKED: %s\n", firstNonEmpty(order.BlockedReason, "no reason reported"))
		return 1
	}
	if !wait {
		fmt.Fprintf(stdout, "  watch with: preflight queue --app %s --watch\n", order.AppID)
		return 0
	}
	return waitForWorkOrder(ctx, client, order.ID, stdout, stderr)
}

// waitForWorkOrder polls until the order reaches a terminal state. Terminal
// failures exit non-zero so this is usable in a script.
func waitForWorkOrder(ctx buildOpsContext, client *http.Client, id string, stdout, stderr io.Writer) int {
	last := ""
	for {
		raw, err := getPreflightJSON(client, ctx.endpoint("/work-orders/"+url.PathEscape(id), nil), ctx.token)
		if err != nil {
			fmt.Fprintf(stderr, "poll work order: %v\n", err)
			return 1
		}
		var response struct {
			WorkOrder workOrder `json:"workOrder"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			fmt.Fprintf(stderr, "decode work order: %v\n", err)
			return 1
		}
		status := response.WorkOrder.Status
		if status != last {
			fmt.Fprintf(stdout, "  %s\n", status)
			last = status
		}
		switch status {
		case "succeeded":
			return 0
		case "failed", "cancelled":
			return 1
		case "blocked":
			fmt.Fprintf(stdout, "  BLOCKED: %s\n", firstNonEmpty(response.WorkOrder.BlockedReason, "no reason reported"))
			return 1
		}
		time.Sleep(5 * time.Second)
	}
}

func printBuildHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight build --app <appId> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Queue a work order on the build farm.")
	fmt.Fprintln(w, "  --app <id>             app to build (required)")
	fmt.Fprintln(w, "  --platform ios|android default ios")
	fmt.Fprintln(w, "  --runtime <name>       app runtime, default expo")
	fmt.Fprintln(w, "  --kind <kind>          default build; one of:")
	fmt.Fprintf(w, "                         %s\n", strings.Join(workOrderKinds, ", "))
	fmt.Fprintln(w, "  --priority-class <c>   background|normal|… default normal")
	fmt.Fprintln(w, "  --provider <p>         build provider preference (local/cloud)")
	fmt.Fprintln(w, "  --idempotency-key <k>  reuse an existing order instead of duplicating")
	fmt.Fprintln(w, "  --app-dir <dir>        the Expo app package (default \".\"); its workspace")
	fmt.Fprintln(w, "                         root is what the runner matches jobs against")
	fmt.Fprintln(w, "  --ci                   build a Preflight-owned checkout of the pushed commit")
	fmt.Fprintln(w, "                         instead of your working tree (required for farm builds)")
	fmt.Fprintln(w, "  --wait                 poll until the order reaches a terminal state")
	fmt.Fprintln(w, "  --json                 machine-readable output")
}

// ---------------------------------------------------------------------------
// preflight queue
// ---------------------------------------------------------------------------

func runQueue(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight queue [--status <s>] [--app <id>] [--all] [--watch] [--json]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Show what the build farm is working on. Finished and cancelled")
		fmt.Fprintln(stdout, "orders are hidden unless you ask for them.")
		fmt.Fprintln(stdout, "  --status <s>  filter: queued|planning|waiting_for_resource|running|blocked|succeeded|failed|cancelled")
		fmt.Fprintln(stdout, "  --app <id>    filter to one app")
		fmt.Fprintln(stdout, "  --all         include finished, failed and cancelled orders")
		fmt.Fprintln(stdout, "  --watch       refresh every 5s until interrupted")
		fmt.Fprintln(stdout, "  --json        machine-readable output")
		return 0
	}
	ctx := newBuildOpsContext()
	status, appID := "", ""
	watch, jsonOut, showAll := false, false, false
	for i := 0; i < len(args); i++ {
		next := func(dst *string) {
			if value, ok := nextFlagValue(args, &i); ok {
				*dst = value
			}
		}
		switch args[i] {
		case "--status":
			next(&status)
		case "--app":
			next(&appID)
		case "--watch":
			watch = true
		case "--json":
			jsonOut = true
		case "--all":
			showAll = true
		}
	}
	if !ctx.requireWorkspace(stderr) {
		return 2
	}
	for {
		code := printQueueOnce(ctx, client, status, appID, showAll, jsonOut, stdout, stderr)
		if !watch || jsonOut || code != 0 {
			return code
		}
		time.Sleep(5 * time.Second)
		fmt.Fprintln(stdout)
	}
}

func printQueueOnce(ctx buildOpsContext, client *http.Client, status, appID string, showAll, jsonOut bool, stdout, stderr io.Writer) int {
	query := url.Values{}
	query.Set("workspaceId", ctx.workspaceID)
	if status != "" {
		query.Set("status", status)
	}
	if appID != "" {
		query.Set("appId", appID)
	}
	raw, err := getPreflightJSON(client, ctx.endpoint("/work-orders", query), ctx.token)
	if err != nil {
		fmt.Fprintf(stderr, "list work orders failed: %v\n", err)
		return 1
	}
	var response struct {
		WorkOrders []workOrder `json:"workOrders"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		fmt.Fprintf(stderr, "decode work orders: %v\n", err)
		return 1
	}
	// A work order that finished is history, not queue. Showing them by default
	// buried the handful of live rows under pages of `cancelled` — after the
	// fleet-hygiene reaper terminalised a backlog, the first screen of this
	// command was entirely corpses.
	orders := response.WorkOrders
	hidden := 0
	if !showAll && status == "" {
		live := make([]workOrder, 0, len(orders))
		for _, order := range orders {
			if workOrderIsTerminal(order.Status) {
				hidden++
				continue
			}
			live = append(live, order)
		}
		orders = live
	}

	if jsonOut {
		return writeJSON(stdout, struct {
			WorkOrders []workOrder `json:"workOrders"`
		}{WorkOrders: orders})
	}
	if len(orders) == 0 {
		fmt.Fprintln(stdout, "Nothing queued or running.")
		if hidden > 0 {
			fmt.Fprintf(stdout, "%d finished order(s) hidden — `preflight queue --all` to see them.\n", hidden)
		}
		return 0
	}

	// Oldest first: the thing that has been waiting longest is the thing worth
	// looking at, and age is the signal the board was missing entirely while a
	// 42-day-old build sat in the queue unnoticed.
	sort.SliceStable(orders, func(left, right int) bool {
		return orders[left].CreatedAt < orders[right].CreatedAt
	})

	byStatus := map[string]int{}
	for _, order := range orders {
		byStatus[order.Status]++
	}
	fmt.Fprintf(stdout, "%-26s %-18s %-9s %-22s %-18s %s\n", "WORK ORDER", "APP", "PLATFORM", "STATUS", "KIND", "AGE")
	for _, order := range orders {
		statusCell := order.Status
		// Blocked orders never run; surface the reason inline so the queue
		// explains itself instead of prompting a second lookup.
		if order.Status == "blocked" && order.BlockedReason != "" {
			statusCell = "blocked: " + truncate(order.BlockedReason, 40)
		}
		fmt.Fprintf(stdout, "%-26s %-18s %-9s %-22s %-18s %s\n",
			truncate(order.ID, 26), truncate(order.AppID, 18),
			order.Platform, truncate(statusCell, 22), truncate(order.Kind, 18),
			workOrderAge(order.CreatedAt))
	}
	fmt.Fprintf(stdout, "\n%d work order(s): %s\n", len(orders), summarizeCounts(byStatus))
	if hidden > 0 {
		fmt.Fprintf(stdout, "%d finished order(s) hidden — `preflight queue --all` to see them.\n", hidden)
	}

	// The queue alone cannot tell you a build is stuck for lack of a host, so
	// pull runner state whenever anything is actually waiting.
	waiting := byStatus["queued"] + byStatus["waiting_for_resource"]
	if waiting > 0 {
		if online, total, ok := nodeHeadcount(ctx, client); ok && online == 0 {
			fmt.Fprintf(stdout, "WARNING: %d work order(s) waiting and 0 of %d node(s) online — run `preflight nodes`.\n", waiting, total)
		}
	}
	return 0
}

// workOrderIsTerminal reports whether an order has finished, one way or another.
func workOrderIsTerminal(status string) bool {
	switch status {
	case "succeeded", "failed", "cancelled":
		return true
	}
	return false
}

// workOrderAge renders how long an order has existed, compactly. Returns "-"
// for a timestamp the server did not send or that will not parse, rather than
// inventing an age.
func workOrderAge(createdAt string) string {
	if strings.TrimSpace(createdAt) == "" {
		return "-"
	}
	created, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return "-"
	}
	elapsed := time.Since(created)
	switch {
	case elapsed < time.Minute:
		return "just now"
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm", int(elapsed.Minutes()))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%.1fh", elapsed.Hours())
	default:
		return fmt.Sprintf("%.1fd", elapsed.Hours()/24)
	}
}

func summarizeCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// preflight nodes
// ---------------------------------------------------------------------------

type farmNode struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	MachineID         string   `json:"machineId"`
	Status            string   `json:"status"`
	Engines           []string `json:"engines"`
	Platforms         []string `json:"platforms"`
	AgentCount        int      `json:"agentCount"`
	LiveAgentCount    int      `json:"liveAgentCount"`
	FreeDiskGb        *int     `json:"freeDiskGb"`
	DiskPressure      string   `json:"diskPressure"`
	LastSeenAgeSecond *int     `json:"lastSeenAgeSeconds"`
	Jobs              *struct {
		Running     int `json:"running"`
		Queued      int `json:"queued"`
		Succeeded24 int `json:"succeeded24h"`
		Failed24    int `json:"failed24h"`
	} `json:"jobs"`
}

type nodeSummary struct {
	Total             int      `json:"total"`
	Online            int      `json:"online"`
	Stale             int      `json:"stale"`
	Retired           int      `json:"retired"`
	LiveAgents        int      `json:"liveAgents"`
	DiskCritical      int      `json:"diskCritical"`
	DiskCriticalNodes []string `json:"diskCriticalNodes"`
	QueuedJobs        int      `json:"queuedJobs"`
	RunningJobs       int      `json:"runningJobs"`
}

func fetchNodes(ctx buildOpsContext, client *http.Client) ([]farmNode, nodeSummary, error) {
	query := url.Values{}
	query.Set("workspaceId", ctx.workspaceID)
	raw, err := getPreflightJSON(client, ctx.endpoint("/nodes", query), ctx.token)
	if err != nil {
		return nil, nodeSummary{}, err
	}
	var response struct {
		Nodes   []farmNode  `json:"nodes"`
		Summary nodeSummary `json:"summary"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		// An HTML body here means the route 404'd, which reads as a confusing
		// JSON parse error ("invalid character '<'") unless we say so.
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "<") {
			return nil, nodeSummary{}, fmt.Errorf(
				"/nodes returned HTML, not JSON — the endpoint is missing on this deployment")
		}
		return nil, nodeSummary{}, err
	}
	return response.Nodes, response.Summary, nil
}

// nodeHeadcount is the cheap form used to annotate the queue. Failures are
// silent: an unavailable node list must not break `queue`.
func nodeHeadcount(ctx buildOpsContext, client *http.Client) (online int, total int, ok bool) {
	_, summary, err := fetchNodes(ctx, client)
	if err != nil {
		return 0, 0, false
	}
	return summary.Online, summary.Total, true
}

func runNodes(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight nodes [--watch] [--json] [--retire <node>]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Show build-farm nodes: engines, free disk, agents, and live job counts.")
		fmt.Fprintln(stdout, "  --watch          refresh every 5s until interrupted")
		fmt.Fprintln(stdout, "  --json           machine-readable output")
		fmt.Fprintln(stdout, "  --retire <node>  revoke a node's agents and take it out of the fleet")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Retiring is for a host that is gone for good (decommissioned, reimaged).")
		fmt.Fprintln(stdout, "A host that is merely offline stays listed as stale on purpose — hiding it")
		fmt.Fprintln(stdout, "is how an outage goes unnoticed. The agents re-register if it comes back.")
		return 0
	}
	ctx := newBuildOpsContext()
	watch, jsonOut := false, false
	retire := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--watch":
			watch = true
		case "--json":
			jsonOut = true
		case "--retire":
			if value, ok := nextFlagValue(args, &i); ok {
				retire = value
			}
		}
	}
	if !ctx.requireWorkspace(stderr) {
		return 2
	}
	if retire != "" {
		return retireNode(ctx, client, retire, stdout, stderr)
	}
	for {
		code := printNodesOnce(ctx, client, jsonOut, stdout, stderr)
		if !watch || jsonOut || code != 0 {
			return code
		}
		time.Sleep(5 * time.Second)
		fmt.Fprintln(stdout)
	}
}

func printNodesOnce(ctx buildOpsContext, client *http.Client, jsonOut bool, stdout, stderr io.Writer) int {
	nodes, summary, err := fetchNodes(ctx, client)
	if err != nil {
		fmt.Fprintf(stderr, "list nodes failed: %v\n", err)
		return 1
	}
	if jsonOut {
		return writeJSON(stdout, map[string]any{"nodes": nodes, "summary": summary})
	}
	if len(nodes) == 0 {
		fmt.Fprintln(stdout, "No nodes registered for this workspace.")
		return 0
	}
	fmt.Fprintf(stdout, "%-16s %-8s %-7s %-16s %-9s %s\n",
		"NODE", "STATE", "AGENTS", "ENGINES", "DISK", "JOBS(run/queued)")
	for _, node := range nodes {
		disk := "unknown"
		if node.FreeDiskGb != nil {
			disk = fmt.Sprintf("%dGB", *node.FreeDiskGb)
			// A host under the floor silently stops claiming, so flag it here
			// rather than leaving it looking merely idle.
			if node.DiskPressure == "critical" {
				disk += "!"
			}
		}
		jobs := "0/0"
		if node.Jobs != nil {
			jobs = fmt.Sprintf("%d/%d", node.Jobs.Running, node.Jobs.Queued)
		}
		fmt.Fprintf(stdout, "%-16s %-8s %-7s %-16s %-9s %s\n",
			truncate(node.Name, 16), node.Status,
			fmt.Sprintf("%d/%d", node.LiveAgentCount, node.AgentCount),
			truncate(strings.Join(node.Engines, ","), 16), disk, jobs)
	}
	fmt.Fprintf(stdout, "\n%d node(s): %d online, %d stale, %d retired. %d live agent(s). %d queued / %d running.\n",
		summary.Total, summary.Online, summary.Stale, summary.Retired,
		summary.LiveAgents, summary.QueuedJobs, summary.RunningJobs)
	exit := 0
	if summary.DiskCritical > 0 {
		fmt.Fprintf(stdout, "WARNING: disk critical on %s — these hosts decline work below the free-space floor.\n",
			strings.Join(summary.DiskCriticalNodes, ", "))
		exit = 1
	}
	if summary.Online == 0 && summary.QueuedJobs > 0 {
		fmt.Fprintln(stdout, "WARNING: work is queued but no node is online — nothing will be claimed.")
		exit = 1
	}
	return exit
}

// ---------------------------------------------------------------------------
// preflight integrations
// ---------------------------------------------------------------------------

func runIntegrations(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight integrations [--json]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Probe the Preflight API and the upstreams it depends on.")
		return 0
	}
	ctx := newBuildOpsContext()
	jsonOut := false
	for _, arg := range args {
		if arg == "--json" {
			jsonOut = true
		}
	}

	type probe struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	probes := []probe{}
	add := func(name string, err error, detail string) {
		if err != nil {
			probes = append(probes, probe{Name: name, Status: "fail", Detail: err.Error()})
			return
		}
		probes = append(probes, probe{Name: name, Status: "ok", Detail: detail})
	}

	start := time.Now()
	_, err := getPreflightJSON(client, ctx.endpoint("/health", nil), ctx.token)
	add("preflight api", err, fmt.Sprintf("%s (%dms)", ctx.apiURL, time.Since(start).Milliseconds()))

	// Capabilities is the contract surface: it reports which integrations the
	// server believes are configured, which is the thing that silently drifts.
	raw, err := getPreflightJSON(client, ctx.endpoint("/capabilities", nil), ctx.token)
	if err != nil {
		add("capabilities", err, "")
	} else {
		var caps map[string]any
		if err := json.Unmarshal(raw, &caps); err != nil {
			add("capabilities", err, "")
		} else {
			add("capabilities", nil, fmt.Sprintf("%d field(s)", len(caps)))
		}
	}

	if ctx.workspaceID != "" {
		_, summary, err := fetchNodes(ctx, client)
		if err != nil {
			add("build farm", err, "")
		} else {
			detail := fmt.Sprintf("%d node(s), %d online, %d job(s) queued",
				summary.Total, summary.Online, summary.QueuedJobs)
			if summary.Online == 0 && summary.Total > 0 {
				probes = append(probes, probe{Name: "build farm", Status: "warn", Detail: detail + " — no node online"})
			} else {
				add("build farm", nil, detail)
			}
		}
	}

	if jsonOut {
		return writeJSON(stdout, map[string]any{"probes": probes})
	}
	failed := 0
	for _, p := range probes {
		marker := "ok  "
		if p.Status == "fail" {
			marker = "FAIL"
			failed++
		} else if p.Status == "warn" {
			marker = "warn"
		}
		fmt.Fprintf(stdout, "[%s] %-16s %s\n", marker, p.Name, p.Detail)
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

// retireNode revokes every agent on a machine, which takes the node out of the
// fleet: reconcile ignores revoked agents, so the node stops counting as
// capacity and is marked retired.
//
// Deliberately explicit rather than automatic on "offline". A machine that is
// merely unreachable should stay visible as stale — that is how an outage gets
// noticed — and its agents come back on their own. Retiring is for a host that
// is not coming back.
func retireNode(ctx buildOpsContext, client *http.Client, name string, stdout, stderr io.Writer) int {
	nodes, _, err := fetchNodes(ctx, client)
	if err != nil {
		fmt.Fprintf(stderr, "list nodes failed: %v\n", err)
		return 1
	}
	var target *farmNode
	for i := range nodes {
		if nodes[i].Name == name || nodes[i].MachineID == name || nodes[i].ID == name {
			target = &nodes[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(stderr, "no node named %q in this workspace\n", name)
		return 1
	}
	if target.LiveAgentCount > 0 {
		// Refusing here is the point: retiring a live host silently removes
		// working capacity, and the agents would re-register anyway.
		fmt.Fprintf(stderr, "%s still has %d live agent(s) — it is not offline. Stop its agents first, or revoke them individually.\n",
			target.Name, target.LiveAgentCount)
		return 1
	}

	raw, err := postPreflightJSON(client,
		ctx.endpoint("/nodes/"+url.PathEscape(target.ID)+"/retire", nil),
		ctx.token,
		map[string]any{"workspaceId": ctx.workspaceID})
	if err != nil {
		fmt.Fprintf(stderr, "retire %s failed: %v\n", target.Name, err)
		return 1
	}
	var response struct {
		Revoked int `json:"revokedAgents"`
	}
	_ = json.Unmarshal(raw, &response)
	fmt.Fprintf(stdout, "Retired %s — revoked %d agent(s). It will drop out of the fleet on the next reconcile.\n",
		target.Name, response.Revoked)
	fmt.Fprintln(stdout, "If the machine comes back, its agents re-register and the node returns.")
	return 0
}

// commitIsOnRemote reports whether a remote-tracking ref contains the commit —
// i.e. whether a runner fetching from the remote could check it out.
func commitIsOnRemote(sha string) bool {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return false
	}
	out, err := exec.Command("git", "branch", "-r", "--contains", sha).Output()
	if err != nil {
		// Unknown rather than absent (detached objects, shallow clones): do not
		// block the build on a check that could not run.
		return true
	}
	return strings.TrimSpace(string(out)) != ""
}
