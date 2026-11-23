package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWorkOrderIsTerminal(t *testing.T) {
	// Terminal orders are history, not queue. Getting this wrong is what buried
	// two live builds under seventy cancelled ones.
	for _, status := range []string{"succeeded", "failed", "cancelled"} {
		if !workOrderIsTerminal(status) {
			t.Fatalf("%q should be terminal", status)
		}
	}
	for _, status := range []string{"queued", "planning", "waiting_for_resource", "running", "blocked"} {
		if workOrderIsTerminal(status) {
			t.Fatalf("%q should still be live", status)
		}
	}
}

func TestWorkOrderAgeRefusesToInventOne(t *testing.T) {
	// A missing or unparseable timestamp reads as unknown. Showing "just now"
	// for an order of unknown age is worse than showing nothing.
	for _, value := range []string{"", "   ", "not-a-date", "1788483941126"} {
		if got := workOrderAge(value); got != "-" {
			t.Fatalf("workOrderAge(%q) = %q, want %q", value, got, "-")
		}
	}
}

func TestWorkOrderAgeScalesWithElapsedTime(t *testing.T) {
	at := func(d time.Duration) string {
		return time.Now().Add(-d).UTC().Format(time.RFC3339)
	}
	for _, tc := range []struct {
		elapsed time.Duration
		want    string
	}{
		{elapsed: 10 * time.Second, want: "just now"},
		{elapsed: 30 * time.Minute, want: "30m"},
		{elapsed: 5 * time.Hour, want: "5.0h"},
		{elapsed: 42 * 24 * time.Hour, want: "42.0d"},
	} {
		if got := workOrderAge(at(tc.elapsed)); got != tc.want {
			t.Fatalf("workOrderAge(%v) = %q, want %q", tc.elapsed, got, tc.want)
		}
	}
}

func TestCICheckoutRootUsesRunnerServedRoot(t *testing.T) {
	if got := ciCheckoutRoot("/Users/me/work/app/feature", "", "app"); got != "/Users/me/work/app/.preflight-ci/app" {
		t.Fatalf("default root = %q", got)
	}
	if got := ciCheckoutRoot("/Users/me/work/app/feature", "/Volumes/dev", "app"); got != "/Volumes/dev/.preflight-ci/app" {
		t.Fatalf("explicit root = %q", got)
	}
}

func TestNormalizeBuildProviderPreferenceMapsLocalNames(t *testing.T) {
	for input, want := range map[string]string{
		"":            "",
		"local":       "local_first",
		"local_first": "local_first",
		"local_only":  "local_only",
		" local ":     "local_first",
	} {
		got, refusal := normalizeBuildProviderPreference(input)
		if refusal != "" {
			t.Fatalf("normalizeBuildProviderPreference(%q) refused: %s", input, refusal)
		}
		if got != want {
			t.Fatalf("normalizeBuildProviderPreference(%q) = %q, want %q", input, got, want)
		}
	}
}

// The server used to turn "cloud" (and any typo) into local_first, so the
// order silently built locally. Cloud is refused outright now that the runner
// has no EAS job kinds.
func TestNormalizeBuildProviderPreferenceRefusesCloudAndUnknown(t *testing.T) {
	for input, want := range map[string]string{
		"cloud":      "no cloud build provider",
		"cloud_only": "no cloud build provider",
		"eas":        "not a provider",
		"eas_cloud":  "not a provider",
		"remote":     "not a provider",
		"LOCAL":      "not a provider",
	} {
		got, refusal := normalizeBuildProviderPreference(input)
		if refusal == "" || got != "" {
			t.Fatalf("normalizeBuildProviderPreference(%q) = %q, should be refused", input, got)
		}
		if !strings.Contains(refusal, want) {
			t.Fatalf("normalizeBuildProviderPreference(%q) message %q lacks %q", input, refusal, want)
		}
	}
}

func TestBuildRefusesCloudProviderBeforeAnyRequest(t *testing.T) {
	for _, provider := range []string{"cloud", "cloud_only", "bogus"} {
		var stdout, stderr bytes.Buffer
		// http.DefaultClient would fail loudly only if a request were made; the
		// refusal must come first, with exit 2.
		code := runBuild([]string{"--app", "pfapp_x", "--provider", provider}, &stdout, &stderr, http.DefaultClient)
		if code != 2 {
			t.Errorf("--provider %s: exit %d, want 2", provider, code)
		}
		if !strings.Contains(stderr.String(), "--provider") {
			t.Errorf("--provider %s: stderr %q does not explain the refusal", provider, stderr.String())
		}
	}
}
