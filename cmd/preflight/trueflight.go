package main

// TrueFlight review workflows. A review workflow is a normal Maestro flow with
// `# tf:` annotations that carry the reviewer-facing prose, capture points, and
// account binding. One annotated flow compiles to two things:
//
//   - an executable Maestro flow with takeScreenshot / recording injected at
//     each capture point (run by the runner to produce the evidence bundle);
//   - a Markdown section for the App Review guide — the same steps in plain
//     language with the captured screenshots/videos linked.
//
// Keeping the prose and the automation in one file means the reviewer docs can
// never drift from the test. This file is the pure compiler (parse → emit); it
// has no I/O so the whole thing is unit-tested. Authoring conventions ship as a
// Preflight skill.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type reviewCapture string

const (
	captureNone       reviewCapture = "none"
	captureScreenshot reviewCapture = "screenshot"
	captureVideo      reviewCapture = "video"
)

type reviewStep struct {
	Describe string        // reviewer-facing sentence (→ Markdown)
	Capture  reviewCapture // screenshot | video | none
	Maestro  []string      // the raw Maestro command lines this step drives
}

// A test account the reviewer (and the run) uses. Credentials never live in the
// flow — `SecretRef` points at the secret store; the real password is injected
// only at run time and only into the private reviewer guide.
type reviewAccount struct {
	Role        string
	Email       string
	SecretRef   string
	Permissions []string
	Notes       string
}

type reviewWorkflow struct {
	ID       string
	Title    string
	Account  string // test-account role this journey runs as
	AppID    string // Maestro appId header, passed through
	Preamble []string // non-annotated header lines before the first `---`
	Accounts []reviewAccount
	Steps    []reviewStep
	Verify   []string // expected outcomes
}

var tfAnnotationRe = regexp.MustCompile(`^\s*#\s*tf:(\w+)\s*(.*)$`)

// leadingQuoted pulls a leading "double-quoted" string off a directive's args,
// returning it plus the remainder (the key=value tail).
func leadingQuoted(s string) (string, string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return "", s
	}
	if end := strings.IndexByte(s[1:], '"'); end >= 0 {
		return s[1 : end+1], strings.TrimSpace(s[end+2:])
	}
	return "", s
}

// kvPairs parses `key=value` and `key="quoted value"` tokens from a tail.
func kvPairs(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[i : i+eq])
		rest := s[i+eq+1:]
		var val string
		if strings.HasPrefix(rest, `"`) {
			if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
				val = rest[1 : end+1]
				i = i + eq + 1 + end + 2
			} else {
				val = rest[1:]
				i = len(s)
			}
		} else {
			sp := strings.IndexByte(rest, ' ')
			if sp < 0 {
				val = rest
				i = len(s)
			} else {
				val = rest[:sp]
				i = i + eq + 1 + sp
			}
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// parseReviewFlow reads an annotated Maestro flow into a structured workflow.
// Maestro commands that follow a `# tf:step` annotation belong to that step;
// the appId header + anything before the first `---` is preserved as preamble.
func parseReviewFlow(content string) (reviewWorkflow, error) {
	var wf reviewWorkflow
	lines := strings.Split(content, "\n")
	inBody := false
	var cur *reviewStep
	sawStep := false

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)

		if m := tfAnnotationRe.FindStringSubmatch(line); m != nil {
			directive, args := m[1], m[2]
			switch directive {
			case "workflow":
				_, tail := leadingQuoted(args)
				kv := kvPairs(tail)
				wf.ID = kv["id"]
				wf.Title = kv["title"]
				wf.Account = kv["account"]
			case "step":
				desc, tail := leadingQuoted(args)
				kv := kvPairs(tail)
				capture := captureNone
				switch kv["capture"] {
				case "screenshot":
					capture = captureScreenshot
				case "video":
					capture = captureVideo
				}
				wf.Steps = append(wf.Steps, reviewStep{Describe: desc, Capture: capture})
				cur = &wf.Steps[len(wf.Steps)-1]
				sawStep = true
			case "verify":
				if v, _ := leadingQuoted(args); v != "" {
					wf.Verify = append(wf.Verify, v)
				}
			case "account":
				kv := kvPairs(args)
				acct := reviewAccount{
					Role:      kv["role"],
					Email:     kv["email"],
					SecretRef: kv["secretRef"],
					Notes:     kv["notes"],
				}
				if p := kv["permissions"]; p != "" {
					acct.Permissions = strings.Split(p, ",")
				}
				if acct.Role != "" {
					wf.Accounts = append(wf.Accounts, acct)
				}
			}
			continue
		}

		if trimmed == "---" {
			inBody = true
			wf.Preamble = append(wf.Preamble, line)
			continue
		}
		if !inBody {
			if strings.HasPrefix(trimmed, "appId:") {
				wf.AppID = strings.TrimSpace(strings.TrimPrefix(trimmed, "appId:"))
			}
			wf.Preamble = append(wf.Preamble, line)
			continue
		}
		// Body: attach Maestro command lines to the current step.
		if trimmed == "" {
			continue
		}
		if cur == nil {
			// Commands before any tf:step — keep them in an implicit lead step
			// so nothing is silently dropped.
			wf.Steps = append(wf.Steps, reviewStep{Describe: "", Capture: captureNone})
			cur = &wf.Steps[len(wf.Steps)-1]
		}
		cur.Maestro = append(cur.Maestro, line)
	}

	if wf.ID == "" {
		return wf, fmt.Errorf("missing `# tf:workflow id=...` annotation")
	}
	if !sawStep {
		return wf, fmt.Errorf("workflow %q has no `# tf:step` annotations", wf.ID)
	}
	return wf, nil
}

// compileExecutableFlow re-emits the flow with capture commands injected after
// each annotated step — takeScreenshot for a screenshot point, start/stop
// recording around a video point. The result is a runnable Maestro flow.
func compileExecutableFlow(wf reviewWorkflow) string {
	var b strings.Builder
	for _, p := range wf.Preamble {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	for i, step := range wf.Steps {
		if step.Capture == captureVideo {
			fmt.Fprintf(&b, "- startRecording: %s\n", stepArtifactName(wf, i))
		}
		for _, m := range step.Maestro {
			b.WriteString(m)
			b.WriteByte('\n')
		}
		switch step.Capture {
		case captureScreenshot:
			fmt.Fprintf(&b, "- takeScreenshot: %s\n", stepArtifactName(wf, i))
		case captureVideo:
			b.WriteString("- stopRecording\n")
		}
	}
	return b.String()
}

// stepArtifactName is the stable evidence filename stem for a step (no ext).
func stepArtifactName(wf reviewWorkflow, index int) string {
	return fmt.Sprintf("%s-%02d", wf.ID, index+1)
}

// renderReviewMarkdown emits the reviewer-guide section for one workflow: the
// numbered steps in plain language, each linking its captured evidence, then
// the expected outcomes.
func renderReviewMarkdown(wf reviewWorkflow) string {
	var b strings.Builder
	title := wf.Title
	if title == "" {
		title = wf.ID
	}
	fmt.Fprintf(&b, "## %s\n\n", title)
	if wf.Account != "" {
		fmt.Fprintf(&b, "_Sign in as the **%s** test account (see the accounts table)._\n\n", wf.Account)
	}
	n := 0
	for i, step := range wf.Steps {
		if step.Describe == "" {
			continue
		}
		n++
		fmt.Fprintf(&b, "%d. %s", n, step.Describe)
		switch step.Capture {
		case captureScreenshot:
			fmt.Fprintf(&b, "  \n   ![%s](evidence/%s.png)", stepArtifactName(wf, i), stepArtifactName(wf, i))
		case captureVideo:
			fmt.Fprintf(&b, "  \n   [▶ recording](evidence/%s.mp4)", stepArtifactName(wf, i))
		}
		b.WriteByte('\n')
	}
	if len(wf.Verify) > 0 {
		b.WriteString("\n**Expected result:**\n")
		for _, v := range wf.Verify {
			fmt.Fprintf(&b, "- %s\n", v)
		}
	}
	return b.String()
}

// renderAccountsTable renders the reviewer guide's test-account table. `creds`
// maps a secretRef to its resolved password; when present the real password is
// shown (the guide is private — it goes into the ASC review-notes field),
// otherwise the secretRef is shown as a placeholder so nothing sensitive leaks
// from a plain `compile`.
func renderAccountsTable(accounts []reviewAccount, creds map[string]string) string {
	if len(accounts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Test accounts\n\n")
	b.WriteString("| Role | Email | Password | Permissions | Notes |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, a := range accounts {
		pw := a.SecretRef
		if real, ok := creds[a.SecretRef]; ok && real != "" {
			pw = real
		}
		if pw == "" {
			pw = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			a.Role, a.Email, pw, strings.Join(a.Permissions, ", "), a.Notes)
	}
	b.WriteByte('\n')
	return b.String()
}

// accountForRole returns the registered account matching a workflow's role.
func accountForRole(accounts []reviewAccount, role string) (reviewAccount, bool) {
	for _, a := range accounts {
		if a.Role == role {
			return a, true
		}
	}
	return reviewAccount{}, false
}

// renderReviewerNotesText builds the concise plain-text note for ASC's "App
// Review Information → Notes" (≈4000 char cap) from the workflows — the demo
// account goes in the structured fields, this is the how-to-test summary.
func renderReviewerNotesText(workflows []reviewWorkflow) string {
	var b strings.Builder
	b.WriteString("Thanks for reviewing. Sign in with the demo account in App Review Information. Key flows to try:\n\n")
	for i, wf := range workflows {
		fmt.Fprintf(&b, "%d. %s", i+1, firstNonEmptyStr(wf.Title, wf.ID))
		if wf.Account != "" {
			fmt.Fprintf(&b, " (as the %s account)", wf.Account)
		}
		b.WriteByte('\n')
		for _, v := range wf.Verify {
			fmt.Fprintf(&b, "   - Expect: %s\n", v)
		}
	}
	s := b.String()
	if len(s) > 3900 {
		s = s[:3900] + "…"
	}
	return s
}

// runAppsReview dispatches the review-workflow commands.
func runAppsReview(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage:")
		fmt.Fprintln(stdout, "  preflight apps review compile <flow.review.yaml> [--out-dir <dir>]   → executable flow + REVIEW.md")
		fmt.Fprintln(stdout, "  preflight apps review run --flow <f> --scheme <s> --sim <udid>       → run + evidence bundle + guide")
		fmt.Fprintln(stdout, "  preflight apps review notes --app <id> --review-dir <dir>            → push notes+demo account to ASC (R6)")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "compile":
		return runReviewCompile(args[1:], stdout, stderr)
	case "run":
		return runReviewRun(args[1:], stdout, stderr)
	case "notes":
		return runReviewNotes(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown review subcommand %q\n", args[0])
		return 2
	}
}

// runReviewNotes reads an app's review flows, builds the reviewer note + demo
// account, and pushes them into ASC "App Review Information" via the gated
// route (which also ticks the R6 reviewer_notes gate).
func runReviewNotes(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	config, _ := loadPreflightCLIConfig()
	apiURL := firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL)
	token := firstNonEmpty(os.Getenv("PREFLIGHT_TOKEN"), config.Token)
	appID, reviewDir, demoRole, contactEmail := "", "", "", ""
	dryRun := false
	secrets := map[string]string{}
	for i := 0; i < len(args); i++ {
		next := func(dst *string) {
			if i+1 < len(args) {
				*dst = args[i+1]
				i++
			}
		}
		switch args[i] {
		case "--app":
			next(&appID)
		case "--review-dir":
			next(&reviewDir)
		case "--demo-role":
			next(&demoRole)
		case "--contact-email":
			next(&contactEmail)
		case "--secret":
			var kv string
			next(&kv)
			if eq := strings.IndexByte(kv, '='); eq > 0 {
				secrets[kv[:eq]] = kv[eq+1:]
			}
		case "--dry-run":
			dryRun = true
		}
	}
	if appID == "" || reviewDir == "" {
		fmt.Fprintln(stderr, "Usage: preflight apps review notes --app <id> --review-dir <dir> [--demo-role <role>] [--secret ref=pw] [--dry-run]")
		return 2
	}

	entries, err := os.ReadDir(reviewDir)
	if err != nil {
		fmt.Fprintf(stderr, "read review dir: %v\n", err)
		return 1
	}
	var workflows []reviewWorkflow
	var accounts []reviewAccount
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".review.yaml") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(reviewDir, e.Name()))
		if err != nil {
			continue
		}
		wf, err := parseReviewFlow(string(content))
		if err != nil {
			fmt.Fprintf(stderr, "skip %s: %v\n", e.Name(), err)
			continue
		}
		workflows = append(workflows, wf)
		accounts = append(accounts, wf.Accounts...)
	}
	if len(workflows) == 0 {
		fmt.Fprintf(stderr, "no *.review.yaml flows in %s\n", reviewDir)
		return 1
	}

	// Pick the demo account: the named role, else the first account found.
	var demo reviewAccount
	if demoRole != "" {
		if a, ok := accountForRole(accounts, demoRole); ok {
			demo = a
		}
	} else if len(accounts) > 0 {
		demo = accounts[0]
	}
	notes := renderReviewerNotesText(workflows)

	// A flow's email is a Maestro template ("${TF_ACCOUNT_EMAIL}") that the
	// runner substitutes at run time from the registered demo account. It is
	// NOT a literal address: sending it as demoAccountName ships
	// "${TF_ACCOUNT_EMAIL}" to App Review. Drop it and let the server resolve
	// the app's registered demo account instead (it already prefers one whose
	// last probe passed, and reveals the password server-side).
	demoUsable := demo.Email != "" && !hasUnresolvedTemplate(demo.Email)

	if dryRun {
		fmt.Fprintf(stdout, "Reviewer notes for %s (%d workflows):\n\n%s\n", appID, len(workflows), notes)
		if demoUsable {
			fmt.Fprintf(stdout, "Demo account: %s (%s)\n", demo.Email, demo.Role)
		} else if demo.Email != "" {
			fmt.Fprintf(stdout, "Demo account: resolved server-side from the registered demo account (flow declares the template %s for role %q)\n", demo.Email, demo.Role)
		}
		return 0
	}

	payload := map[string]any{"notes": notes}
	if demoUsable {
		payload["demoAccountName"] = demo.Email
		if pw := secrets[demo.SecretRef]; pw != "" {
			payload["demoAccountPassword"] = pw
		}
	}
	if contactEmail != "" {
		payload["contactEmail"] = contactEmail
	}
	endpoint := strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + appID + "/review-notes"
	if _, err := postPreflightJSON(client, endpoint, token, payload); err != nil {
		fmt.Fprintf(stderr, "set review notes failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Set ASC review notes for %s (%d workflows) + ticked reviewer_notes.\n", appID, len(workflows))
	return 0
}

// runReviewRun compiles a review flow, runs it on a simulator (reusing the
// screenshot-harness executor for build/boot/install/launch), injects the
// selected account's credentials into the Maestro run, collects the evidence
// bundle (screenshots + videos), and writes the resolved REVIEW.md.
func runReviewRun(args []string, stdout io.Writer, stderr io.Writer) int {
	in := screenshotPlanInput{StatusBarTime: "9:41", XcrunPath: "xcrun", MaestroPath: "maestro"}
	flowPath, outDir, appPathOverride := "", "", ""
	workspaceRoot, packagePath := "", ""
	dryRun := false
	secrets := map[string]string{} // secretRef → password

	for i := 0; i < len(args); i++ {
		next := func(dst *string) bool {
			if i+1 < len(args) {
				*dst = args[i+1]
				i++
				return true
			}
			return false
		}
		switch args[i] {
		case "--flow":
			next(&flowPath)
		case "--workspace-root":
			next(&workspaceRoot)
		case "--package-path":
			next(&packagePath)
		case "--scheme":
			next(&in.Scheme)
		case "--sim":
			next(&in.SimUDID)
		case "--bundle-id":
			next(&in.BundleID)
		case "--derived-data":
			next(&in.DerivedData)
		case "--app-path":
			next(&appPathOverride)
		case "--maestro-path":
			next(&in.MaestroPath)
		case "--out-dir":
			next(&outDir)
		case "--secret":
			var kv string
			if next(&kv) {
				if eq := strings.IndexByte(kv, '='); eq > 0 {
					secrets[kv[:eq]] = kv[eq+1:]
				}
			}
		case "--skip-build":
			in.SkipBuild = true
		case "--dry-run":
			dryRun = true
		}
	}
	if flowPath == "" || in.Scheme == "" || in.SimUDID == "" {
		fmt.Fprintln(stderr, "Usage: preflight apps review run --flow <f.review.yaml> --scheme <s> --sim <udid> [--bundle-id ...] [--secret ref=pw] [--skip-build] [--dry-run]")
		return 2
	}

	content, err := os.ReadFile(flowPath)
	if err != nil {
		fmt.Fprintf(stderr, "read flow: %v\n", err)
		return 1
	}
	wf, err := parseReviewFlow(string(content))
	if err != nil {
		fmt.Fprintf(stderr, "parse %s: %v\n", flowPath, err)
		return 1
	}

	if workspaceRoot == "" {
		workspaceRoot, _ = os.Getwd()
	}
	appDir := workspaceRoot
	if packagePath != "" {
		appDir = filepath.Join(workspaceRoot, packagePath)
	}
	workspace, err := resolveIOSWorkspace(appDir, in.Scheme)
	if err != nil {
		fmt.Fprintf(stderr, "resolve ios workspace: %v\n", err)
		return 1
	}
	in.Workspace = workspace
	if in.DerivedData == "" {
		in.DerivedData = filepath.Join(appDir, ".preflight", "dd-screenshots")
	}
	if appPathOverride != "" {
		in.AppPath = appPathOverride
	} else {
		in.AppPath = filepath.Join(in.DerivedData, "Build", "Products",
			"Release-iphonesimulator", in.Scheme+".app")
	}
	if in.BundleID == "" {
		in.BundleID = wf.AppID
	}

	reviewRoot := outDir
	if reviewRoot == "" {
		reviewRoot = filepath.Join(appDir, ".preflight", "review", wf.ID)
	}
	evidenceDir := filepath.Join(reviewRoot, "evidence")
	in.ScreenshotDir = evidenceDir
	in.FlowPath = "" // no per-app flow — we append our own compiled step below

	compiledPath := filepath.Join(reviewRoot, wf.ID+".maestro.yaml")

	plan, err := buildScreenshotCapturePlan(in)
	if err != nil {
		fmt.Fprintf(stderr, "build plan: %v\n", err)
		return 1
	}
	// Append the review step: run the compiled flow with the account's creds.
	acct, _ := accountForRole(wf.Accounts, wf.Account)
	maestroArgs := []string{"--device", in.SimUDID, "test", compiledPath}
	if acct.Email != "" {
		maestroArgs = append(maestroArgs, "-e", "TF_ACCOUNT_EMAIL="+acct.Email)
	}
	if pw := secrets[acct.SecretRef]; pw != "" {
		maestroArgs = append(maestroArgs, "-e", "TF_ACCOUNT_PASSWORD="+pw)
	}
	plan = append(plan, screenshotStep{
		label: "review", dir: evidenceDir,
		name: firstNonEmptyStr(in.MaestroPath, "maestro"), args: maestroArgs,
	})

	if dryRun {
		fmt.Fprintf(stdout, "Review run plan for %q (account: %s):\n\n", wf.ID, wf.Account)
		for i, s := range plan {
			fmt.Fprintf(stdout, "  %d. %-11s %s %s\n", i+1, s.label, s.name, strings.Join(s.args, " "))
		}
		fmt.Fprintf(stdout, "\ncompiled flow → %s\nevidence      → %s\n", compiledPath, evidenceDir)
		return 0
	}

	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir evidence: %v\n", err)
		return 1
	}
	if err := os.WriteFile(compiledPath, []byte(compileExecutableFlow(wf)), 0o644); err != nil {
		fmt.Fprintf(stderr, "write compiled flow: %v\n", err)
		return 1
	}
	for _, s := range plan {
		fmt.Fprintf(stdout, "[%s] %s %s\n", s.label, s.name, strings.Join(s.args, " "))
		if err := runScreenshotStep(s, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "step %q failed: %v\n", s.label, err)
			return 1
		}
	}

	evidence := findFilesWithExtensions(evidenceDir, ".png", ".mp4", ".mov")
	md := "# " + firstNonEmptyStr(wf.Title, wf.ID) + " — App Review Guide\n\n" +
		renderAccountsTable(wf.Accounts, secrets) + renderReviewMarkdown(wf)
	guidePath := filepath.Join(reviewRoot, "REVIEW.md")
	if err := os.WriteFile(guidePath, []byte(md), 0o644); err != nil {
		fmt.Fprintf(stderr, "write guide: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "\nReview %q: %d evidence file(s)\n  evidence: %s\n  guide:    %s\n",
		wf.ID, len(evidence), evidenceDir, guidePath)
	return 0
}

func runReviewCompile(args []string, stdout io.Writer, stderr io.Writer) int {
	flowPath, outDir := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out-dir":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") && flowPath == "" {
				flowPath = args[i]
			}
		}
	}
	if flowPath == "" {
		fmt.Fprintln(stderr, "Usage: preflight apps review compile <flow.review.yaml> [--out-dir <dir>]")
		return 2
	}
	content, err := os.ReadFile(flowPath)
	if err != nil {
		fmt.Fprintf(stderr, "read flow: %v\n", err)
		return 1
	}
	wf, err := parseReviewFlow(string(content))
	if err != nil {
		fmt.Fprintf(stderr, "parse %s: %v\n", flowPath, err)
		return 1
	}
	if outDir == "" {
		outDir = filepath.Dir(flowPath)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir out: %v\n", err)
		return 1
	}
	flowOut := filepath.Join(outDir, wf.ID+".maestro.yaml")
	mdOut := filepath.Join(outDir, wf.ID+".review.md")
	if err := os.WriteFile(flowOut, []byte(compileExecutableFlow(wf)), 0o644); err != nil {
		fmt.Fprintf(stderr, "write flow: %v\n", err)
		return 1
	}
	md := "# " + firstNonEmptyStr(wf.Title, wf.ID) + " — App Review Guide\n\n" +
		renderAccountsTable(wf.Accounts, nil) + renderReviewMarkdown(wf)
	if err := os.WriteFile(mdOut, []byte(md), 0o644); err != nil {
		fmt.Fprintf(stderr, "write markdown: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Compiled %q (%d steps):\n  flow:   %s\n  guide:  %s\n",
		wf.ID, len(wf.Steps), flowOut, mdOut)
	return 0
}

// hasUnresolvedTemplate reports whether a value still carries a "${VAR}"
// placeholder. Review flows declare account emails as Maestro templates the
// runner substitutes at run time, so an unsubstituted one must never be
// forwarded to App Store Connect as a real address.
func hasUnresolvedTemplate(value string) bool {
	i := strings.Index(value, "${")
	return i >= 0 && strings.Contains(value[i:], "}")
}
