package main

import "testing"

func TestFleetNextGroups_DedupsAndPartitionsByOwner(t *testing.T) {
	rows := []cliFleetReleaseRow{
		// Duplicate app records for the same slug — keep the furthest-along.
		{AppID: "a1", Slug: "habit-play", Name: "@habit/expo", CurrentStage: "identity", NextStage: "compliance", NextOwner: "user"},
		{AppID: "a2", Slug: "habit-play", Name: "@habitplay/expo", CurrentStage: "metadata", NextStage: "submitted", NextOwner: "preflight"},
		// A user-owned action.
		{AppID: "b", Slug: "calzone", Name: "Calzone", CurrentStage: "identity", NextStage: "compliance", NextOwner: "user"},
		// Automatable.
		{AppID: "c", Slug: "bob", Name: "Bob", CurrentStage: "testflight", NextStage: "metadata", NextOwner: "preflight"},
		// Released.
		{AppID: "d", Slug: "ship", Name: "Ship", CurrentStage: "released", NextStage: "", NextOwner: ""},
	}
	you, pf, done := fleetNextGroups(rows)

	// habit-play collapses to one row (the metadata one, furthest along) → pf.
	if len(you) != 1 || you[0].Slug != "calzone" {
		t.Errorf("you = %+v, want just calzone", names(you))
	}
	if len(pf) != 2 {
		t.Fatalf("pf = %v, want 2 (bob + collapsed habit-play)", names(pf))
	}
	// Sorted by the rung being cleared: bob→metadata(R5) before habit→submitted(R6).
	if pf[0].Slug != "bob" || pf[1].Slug != "habit-play" {
		t.Errorf("pf order = %v, want [bob habit-play]", names(pf))
	}
	if len(done) != 1 || done[0].Slug != "ship" {
		t.Errorf("done = %v, want [ship]", names(done))
	}
}

func TestStageLabel(t *testing.T) {
	cases := map[string]string{
		"":           "R0 identity",
		"metadata":   "R5 metadata",
		"released":   "R7 released",
		"weird_thing": "weird_thing",
	}
	for in, want := range cases {
		if got := stageLabel(in); got != want {
			t.Errorf("stageLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func names(rows []cliFleetReleaseRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Slug
	}
	return out
}
