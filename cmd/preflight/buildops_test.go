package main

import (
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

func TestNormalizeBuildProviderPreferenceMapsShortNames(t *testing.T) {
	// `--provider cloud` used to reach the API verbatim, where
	// decideBuildProvider recognised only local_first/cloud_only/local_only and
	// defaulted everything else to local_first. The order came back
	// buildProvider=local_runner, reason=local_runner_ready — a cloud build that
	// silently was not one. Observed 2026-09-04 on a store build for bob.
	for input, want := range map[string]string{
		"":            "",
		"local":       "local_first",
		"cloud":       "cloud_only",
		"local_first": "local_first",
		"cloud_only":  "cloud_only",
		"local_only":  "local_only",
	} {
		got, ok := normalizeBuildProviderPreference(input)
		if !ok {
			t.Fatalf("normalizeBuildProviderPreference(%q) rejected a valid value", input)
		}
		if got != want {
			t.Fatalf("normalizeBuildProviderPreference(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeBuildProviderPreferenceRejectsUnknownNames(t *testing.T) {
	// Refusing beats defaulting: a typo that silently builds locally costs a
	// full build cycle before anyone notices the provider was wrong.
	for _, input := range []string{"cloud-only", "eas", "eas_cloud", "remote", "CLOUD"} {
		if _, ok := normalizeBuildProviderPreference(input); ok {
			t.Fatalf("normalizeBuildProviderPreference(%q) should have been rejected", input)
		}
	}
}
