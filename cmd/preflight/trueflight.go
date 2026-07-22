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

type reviewWorkflow struct {
	ID       string
	Title    string
	Account  string // test-account role this journey runs as
	AppID    string // Maestro appId header, passed through
	Preamble []string // non-annotated header lines before the first `---`
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

// runAppsReview dispatches the review-workflow commands. Slice 1 ships `compile`:
// annotated flow → executable Maestro flow + Markdown reviewer guide (no device
// run yet — that's slice 2).
func runAppsReview(args []string, stdout io.Writer, stderr io.Writer, _ *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: preflight apps review compile <flow.review.yaml> [--out-dir <dir>]")
		fmt.Fprintln(stdout, "  compile   annotated Maestro flow → executable flow + REVIEW.md (no device run)")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "compile":
		return runReviewCompile(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown review subcommand %q\n", args[0])
		return 2
	}
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
	md := "# " + firstNonEmptyStr(wf.Title, wf.ID) + " — App Review Guide\n\n" + renderReviewMarkdown(wf)
	if err := os.WriteFile(mdOut, []byte(md), 0o644); err != nil {
		fmt.Fprintf(stderr, "write markdown: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Compiled %q (%d steps):\n  flow:   %s\n  guide:  %s\n",
		wf.ID, len(wf.Steps), flowOut, mdOut)
	return 0
}
