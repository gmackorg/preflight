package main

import (
	"strings"
	"testing"
)

const sampleReviewFlow = `# tf:workflow id=sign-in title="Sign in and start a fast" account=premium
# tf:account role=free email="reviewer+free@crucible.app" secretRef=crucible/free_pw permissions=basic notes="Free tier"
# tf:account role=premium email="reviewer+premium@crucible.app" secretRef=crucible/prem_pw permissions=basic,health_read notes="Premium tier"
# tf:verify "The active-fast timer is counting down."
appId: com.gmacko.crucible
---
# tf:step "Launch the app — you land on the welcome screen." capture=screenshot
- launchApp
# tf:step "Tap Sign In, enter the demo account." capture=screenshot
- tapOn: "Sign In"
- inputText: "${TF_ACCOUNT_EMAIL}"
# tf:step "Grant HealthKit, then start a 16:8 fast." capture=video
- tapOn: "Allow"
- tapOn: "Start Fast"
`

func TestParseReviewFlow(t *testing.T) {
	wf, err := parseReviewFlow(sampleReviewFlow)
	if err != nil {
		t.Fatal(err)
	}
	if wf.ID != "sign-in" || wf.Title != "Sign in and start a fast" || wf.Account != "premium" {
		t.Errorf("header parsed wrong: %+v", wf)
	}
	if wf.AppID != "com.gmacko.crucible" {
		t.Errorf("appId = %q", wf.AppID)
	}
	if len(wf.Steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(wf.Steps))
	}
	if wf.Steps[0].Capture != captureScreenshot || len(wf.Steps[0].Maestro) != 1 {
		t.Errorf("step 0 = %+v", wf.Steps[0])
	}
	if wf.Steps[2].Capture != captureVideo || len(wf.Steps[2].Maestro) != 2 {
		t.Errorf("step 2 = %+v", wf.Steps[2])
	}
	if len(wf.Verify) != 1 || !strings.Contains(wf.Verify[0], "timer") {
		t.Errorf("verify = %v", wf.Verify)
	}
}

func TestCompileExecutableFlow_InjectsCaptures(t *testing.T) {
	wf, _ := parseReviewFlow(sampleReviewFlow)
	out := compileExecutableFlow(wf)

	// appId header preserved.
	if !strings.Contains(out, "appId: com.gmacko.crucible") {
		t.Error("missing appId header")
	}
	// screenshot injected right after the launch step.
	if !strings.Contains(out, "- launchApp\n- takeScreenshot: sign-in-01") {
		t.Errorf("screenshot not injected after launch:\n%s", out)
	}
	// video wrapped with start/stop recording around the last step.
	if !strings.Contains(out, "- startRecording: sign-in-03\n- tapOn: \"Allow\"") {
		t.Errorf("startRecording not before video step:\n%s", out)
	}
	if !strings.Contains(out, "- tapOn: \"Start Fast\"\n- stopRecording") {
		t.Errorf("stopRecording not after video step:\n%s", out)
	}
	// The original commands survive.
	if !strings.Contains(out, `- inputText: "${TF_ACCOUNT_EMAIL}"`) {
		t.Error("original command dropped")
	}
}

func TestRenderReviewMarkdown(t *testing.T) {
	wf, _ := parseReviewFlow(sampleReviewFlow)
	md := renderReviewMarkdown(wf)

	for _, want := range []string{
		"## Sign in and start a fast",
		"**premium**",
		"1. Launch the app",
		"![sign-in-01](evidence/sign-in-01.png)",
		"[▶ recording](evidence/sign-in-03.mp4)",
		"**Expected result:**",
		"- The active-fast timer is counting down.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q in:\n%s", want, md)
		}
	}
}

func TestParseReviewFlow_RejectsMissingHeader(t *testing.T) {
	if _, err := parseReviewFlow("appId: x\n---\n- launchApp\n"); err == nil {
		t.Error("expected error for a flow with no tf:workflow annotation")
	}
}

func TestReviewAccounts_ParseAndTable(t *testing.T) {
	wf, err := parseReviewFlow(sampleReviewFlow)
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Accounts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(wf.Accounts))
	}
	prem, ok := accountForRole(wf.Accounts, "premium")
	if !ok || prem.Email != "reviewer+premium@crucible.app" {
		t.Errorf("premium account = %+v", prem)
	}
	if len(prem.Permissions) != 2 || prem.Permissions[1] != "health_read" {
		t.Errorf("premium permissions = %v", prem.Permissions)
	}

	// Without resolved creds the secretRef shows (no password leak from compile).
	table := renderAccountsTable(wf.Accounts, nil)
	if !strings.Contains(table, "crucible/prem_pw") {
		t.Errorf("expected secretRef placeholder in:\n%s", table)
	}
	// With resolved creds the real password shows (private guide).
	resolved := renderAccountsTable(wf.Accounts, map[string]string{"crucible/prem_pw": "s3cret"})
	if !strings.Contains(resolved, "s3cret") || strings.Contains(resolved, "crucible/prem_pw") {
		t.Errorf("expected resolved password, got:\n%s", resolved)
	}
}

func TestRenderReviewerNotesText(t *testing.T) {
	wf, _ := parseReviewFlow(sampleReviewFlow)
	notes := renderReviewerNotesText([]reviewWorkflow{wf})
	for _, want := range []string{
		"demo account",
		"1. Sign in and start a fast (as the premium account)",
		"Expect: The active-fast timer is counting down.",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes missing %q in:\n%s", want, notes)
		}
	}
	if len(notes) > 4000 {
		t.Errorf("notes %d chars exceeds ASC ~4000 cap", len(notes))
	}
}

func TestHasUnresolvedTemplate(t *testing.T) {
	// Review flows declare account emails as Maestro templates the runner
	// substitutes at run time. Forwarding an unsubstituted one to App Store
	// Connect ships a literal "${TF_ACCOUNT_EMAIL}" to the reviewer.
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"${TF_ACCOUNT_EMAIL}", true},
		{"prefix-${VAR}-suffix", true},
		{"reviewer@demo.preflight.app", false},
		{"", false},
		{"costs $5", false},
		{"${unterminated", false},
	} {
		if got := hasUnresolvedTemplate(tc.value); got != tc.want {
			t.Errorf("hasUnresolvedTemplate(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
