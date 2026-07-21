package main

// `preflight fleet next` — the fleet cockpit. One glance at where every app sits
// on the release ladder and the single next action + who owns it (you, in
// ASC/portal, vs preflight, automatable). Derived entirely from the release-status
// envelope each app already reports.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

var releaseStageRank = map[string]int{
	"identity":    0,
	"compliance":  1,
	"asc_record":  2,
	"store_build": 3,
	"testflight":  4,
	"metadata":    5,
	"submitted":   6,
	"released":    7,
}

// stageLabel renders a stage key as "R<n> <name>" for the cockpit.
func stageLabel(stage string) string {
	if stage == "" {
		return "R0 identity"
	}
	if r, ok := releaseStageRank[stage]; ok {
		return fmt.Sprintf("R%d %s", r, stage)
	}
	return stage
}

func runFleet(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: preflight fleet next [--platform ios|android] [--json]")
		fmt.Fprintln(stdout, "  next   per-app next action + owner across the release ladder")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "next":
		return runFleetNext(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown fleet subcommand %q\n", args[0])
		return 2
	}
}

func runFleetNext(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	options, ok := parseReleaseStatusCLIOptions(args, stderr)
	if !ok {
		return 2
	}
	rows, err := fetchFleetReleaseRows(client, options)
	if err != nil {
		fmt.Fprintf(stderr, "fetch fleet failed: %v\n", err)
		return 1
	}
	you, pf, done := fleetNextGroups(rows)

	if options.jsonOut {
		out, _ := json.MarshalIndent(
			map[string][]cliFleetReleaseRow{"you": you, "preflight": pf, "done": done},
			"", "  ")
		fmt.Fprintln(stdout, string(out))
		return 0
	}

	name := func(r cliFleetReleaseRow) string {
		return firstNonEmpty(r.Name, r.Slug, r.AppID)
	}
	printGroup := func(title string, list []cliFleetReleaseRow) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(stdout, "\n%s (%d):\n", title, len(list))
		for _, r := range list {
			action := r.BlockerReason
			if action == "" {
				action = "—"
			}
			fmt.Fprintf(stdout, "  %-26s %-15s %s\n",
				name(r), stageLabel(firstNonEmpty(r.NextStage, r.CurrentStage)), action)
		}
	}

	fmt.Fprintf(stdout, "Fleet next actions — %d apps (%s)\n",
		len(you)+len(pf)+len(done), options.platform)
	printGroup("YOU — action in App Store Connect / portal", you)
	printGroup("PREFLIGHT — automatable next step", pf)
	printGroup("DONE — released", done)
	return 0
}

// fleetNextGroups dedups duplicate app records (same slug — the fleet carries
// multiple rows per EAS project) keeping the furthest-along, then partitions by
// who acts next: you (portal/ASC), preflight (automatable), or done (released).
// Each group is sorted by the rung it's trying to clear. Pure — unit-testable.
func fleetNextGroups(rows []cliFleetReleaseRow) (you, pf, done []cliFleetReleaseRow) {
	best := map[string]cliFleetReleaseRow{}
	var order []string
	for _, r := range rows {
		key := strings.ToLower(firstNonEmpty(r.Slug, r.Name, r.AppID))
		if existing, seen := best[key]; !seen ||
			releaseStageRank[r.CurrentStage] > releaseStageRank[existing.CurrentStage] {
			if !seen {
				order = append(order, key)
			}
			best[key] = r
		}
	}
	for _, k := range order {
		r := best[k]
		switch {
		case r.NextStage == "" && r.CurrentStage == "released":
			done = append(done, r)
		case r.NextOwner == "user":
			you = append(you, r)
		default:
			pf = append(pf, r)
		}
	}
	byRank := func(list []cliFleetReleaseRow) {
		sort.SliceStable(list, func(i, j int) bool {
			return releaseStageRank[list[i].NextStage] < releaseStageRank[list[j].NextStage]
		})
	}
	byRank(you)
	byRank(pf)
	return you, pf, done
}
