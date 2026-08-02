package main

import (
	"strings"
	"testing"
	"time"
)

func TestSeedStalenessWarning(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

	t.Run("silent without a seed policy", func(t *testing.T) {
		if got := seedStalenessWarning(&screenshotRecipe{}, now); got != "" {
			t.Fatalf("expected no warning, got %q", got)
		}
	})

	t.Run("warns when never seeded", func(t *testing.T) {
		got := seedStalenessWarning(&screenshotRecipe{SeedStaleAfterMinutes: 600}, now)
		if !strings.Contains(got, "never been seeded") {
			t.Fatalf("expected never-seeded warning, got %q", got)
		}
	})

	t.Run("silent while fresh", func(t *testing.T) {
		r := &screenshotRecipe{
			SeedStaleAfterMinutes: 600,
			SeedLastRunAt:         now.Add(-2 * time.Hour).Format(time.RFC3339),
		}
		if got := seedStalenessWarning(r, now); got != "" {
			t.Fatalf("expected no warning for fresh seed, got %q", got)
		}
	})

	// The crucible case: a 16h fast seeded five days earlier rendered
	// "125:06:12 / 100% complete" and shipped as a screenshot.
	t.Run("warns once past the window", func(t *testing.T) {
		r := &screenshotRecipe{
			SeedStaleAfterMinutes: 600,
			SeedLastRunAt:         now.Add(-5 * 24 * time.Hour).Format(time.RFC3339),
		}
		got := seedStalenessWarning(r, now)
		if !strings.Contains(got, "stale") {
			t.Fatalf("expected staleness warning, got %q", got)
		}
	})

	t.Run("tolerates an unparseable timestamp", func(t *testing.T) {
		r := &screenshotRecipe{SeedStaleAfterMinutes: 600, SeedLastRunAt: "not-a-time"}
		if got := seedStalenessWarning(r, now); got != "" {
			t.Fatalf("expected silence on bad timestamp, got %q", got)
		}
	})
}
