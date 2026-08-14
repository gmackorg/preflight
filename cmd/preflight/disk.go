package main

// `preflight disk` — the missing half of build-farm disk safety.
//
// The pieces already existed but never met: cleanupBuildStorageUnderPressure
// sweeps managed caches, runnerMinFreeDiskBytes defines a floor, and the
// runners report freeDiskGb upward every heartbeat. What was missing is a way
// to *look*. The floor only gates job claims, so a host that drops under it
// stops taking work and looks idle rather than sick, and every interactive
// build (`preflight apps screenshots`, a local xcodebuild) bypasses the gate
// entirely — which is how /Volumes/dev reached 226 MiB free twice.
//
//	preflight disk            local volumes, reclaimable caches, fleet nodes
//	preflight disk --reclaim  sweep the regenerable caches under a root
//
// Deliberately reports the fleet alongside the local machine: "am I full" and
// "is a build host full" are the same question asked from two places, and
// keeping them in one command is what makes the answer get looked at.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Roots swept by --reclaim. Each is a workspace root whose managed cache dirs
// (DerivedData, ModuleCache.noindex, XCBuildData, …) are regenerable.
func defaultReclaimRoots() []string {
	roots := []string{}
	if extra := strings.TrimSpace(os.Getenv("PREFLIGHT_WORKSPACE_ROOTS")); extra != "" {
		for _, part := range strings.Split(extra, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				roots = append(roots, trimmed)
			}
		}
		return roots
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"))
	}
	return roots
}

func runDisk(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: preflight disk [--reclaim] [--root <dir>] [--max-age 24h] [--dry-run] [--json]")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Show free space here and across the build farm, and what can be reclaimed.")
		fmt.Fprintln(stdout, "  --reclaim        prune stale regenerable caches (DerivedData, ModuleCache, XCBuildData)")
		fmt.Fprintln(stdout, "  --root <dir>     root to sweep (repeatable; defaults to Xcode DerivedData)")
		fmt.Fprintln(stdout, "  --max-age <dur>  only prune entries older than this (default 24h)")
		fmt.Fprintln(stdout, "  --dry-run        with --reclaim, report without deleting")
		fmt.Fprintln(stdout, "  --json           machine-readable output")
		return 0
	}

	reclaim, dryRun, jsonOut := false, false, false
	maxAge := 24 * time.Hour
	roots := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--reclaim":
			reclaim = true
		case "--dry-run":
			dryRun = true
		case "--json":
			jsonOut = true
		case "--root":
			if value, ok := nextFlagValue(args, &i); ok {
				roots = append(roots, value)
			}
		case "--max-age":
			if value, ok := nextFlagValue(args, &i); ok {
				if parsed, err := time.ParseDuration(value); err == nil {
					maxAge = parsed
				}
			}
		}
	}
	if len(roots) == 0 {
		roots = defaultReclaimRoots()
	}

	type volumeReport struct {
		Path      string `json:"path"`
		FreeGb    uint64 `json:"freeGb"`
		BelowFlo  bool   `json:"belowFloor"`
		FloorGb   uint64 `json:"floorGb"`
		Reachable bool   `json:"reachable"`
	}

	floor := runnerMinFreeDiskBytes()
	// The floor is opt-in (0 = disabled); report against the same 15 GiB the
	// runner plists use so the number means something even when unset here.
	floorGb := floor / bytesPerGiB
	if floorGb == 0 {
		floorGb = 15
	}

	// Report mount points, not arbitrary paths: a reclaim root that has been
	// swept away is not a volume, and the volume that actually fills here
	// (/Volumes/dev) is not a reclaim root. Include "/" plus everything
	// mounted under /Volumes, then any roots that live somewhere else.
	candidates := []string{"/"}
	if entries, err := os.ReadDir("/Volumes"); err == nil {
		for _, entry := range entries {
			candidates = append(candidates, filepath.Join("/Volumes", entry.Name()))
		}
	}
	for _, root := range roots {
		if _, err := os.Stat(root); err == nil {
			candidates = append(candidates, root)
		}
	}

	volumes := []volumeReport{}
	seen := map[string]bool{}
	for _, path := range candidates {
		clean := filepath.Clean(path)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		free, err := freeBytesForPath(clean)
		if err != nil {
			continue
		}
		freeGb := free / bytesPerGiB
		volumes = append(volumes, volumeReport{
			Path:      clean,
			FreeGb:    freeGb,
			BelowFlo:  freeGb < floorGb,
			FloorGb:   floorGb,
			Reachable: true,
		})
	}

	reclaimed := 0
	if reclaim {
		for _, root := range roots {
			if _, err := os.Stat(root); err != nil {
				continue
			}
			n, err := cleanupBuilds(root, maxAge, dryRun, false, stdout)
			if err != nil {
				fmt.Fprintf(stderr, "sweep %s: %v\n", root, err)
				continue
			}
			reclaimed += n
		}

		// DerivedData alone is not where the space goes. On labtop the managed
		// sweep found ZERO reclaimable entries while the disk sat at 9GB — the
		// actual consumers were a 19GB pnpm store and 10GB of CocoaPods. The
		// launchd sweep on both Macs has therefore been running for days and
		// reclaiming almost nothing, which is why they keep falling under the
		// floor and declining iOS work.
		//
		// The store is content-addressable and fully regenerable, so pruning it
		// is safe; pnpm refetches on the next install. Only run it under
		// pressure, since a warm store is worth a lot to build times.
		if free, err := freeBytesForPath("/"); err == nil && free/bytesPerGiB < pnpmStorePruneFloorGb() {
			if pruned := prunePnpmStore(dryRun, stdout, stderr); pruned {
				reclaimed++
			}
		}
	}

	// Fleet view. Best-effort: no workspace/auth must not break the local report.
	ctx := newBuildOpsContext()
	var nodes []farmNode
	var summary nodeSummary
	if ctx.workspaceID != "" {
		if fetched, s, err := fetchNodes(ctx, client); err == nil {
			nodes, summary = fetched, s
		}
	}

	if jsonOut {
		return writeJSON(stdout, map[string]any{
			"volumes":        volumes,
			"reclaimedItems": reclaimed,
			"nodes":          nodes,
			"summary":        summary,
		})
	}

	fmt.Fprintf(stdout, "%-44s %-10s %s\n", "VOLUME", "FREE", "STATE")
	exit := 0
	for _, volume := range volumes {
		if !volume.Reachable {
			fmt.Fprintf(stdout, "%-44s %-10s %s\n", truncate(volume.Path, 44), "-", "unreadable")
			continue
		}
		state := "ok"
		if volume.BelowFlo {
			// Below the floor the runner declines claims silently, so this is
			// the difference between "idle" and "unable to build".
			state = fmt.Sprintf("BELOW FLOOR (%dGB)", volume.FloorGb)
			exit = 1
		}
		fmt.Fprintf(stdout, "%-44s %-10s %s\n",
			truncate(volume.Path, 44), fmt.Sprintf("%dGB", volume.FreeGb), state)
	}

	if reclaim {
		verb := "reclaimed"
		if dryRun {
			verb = "would reclaim"
		}
		fmt.Fprintf(stdout, "\n%s %d cache entry(ies) older than %s.\n", verb, reclaimed, maxAge)
	} else {
		fmt.Fprintln(stdout, "\nRun `preflight disk --reclaim` to prune stale regenerable caches.")
	}

	if len(nodes) > 0 {
		fmt.Fprintf(stdout, "\n%-18s %-10s %s\n", "NODE", "FREE", "STATE")
		for _, node := range nodes {
			free := "unknown"
			if node.FreeDiskGb != nil {
				free = fmt.Sprintf("%dGB", *node.FreeDiskGb)
			}
			state := node.DiskPressure
			if state == "critical" {
				exit = 1
			}
			fmt.Fprintf(stdout, "%-18s %-10s %s\n", truncate(node.Name, 18), free, state)
		}
		if summary.DiskCritical > 0 {
			fmt.Fprintf(stdout, "\nWARNING: %d node(s) below the floor: %s\n",
				summary.DiskCritical, strings.Join(summary.DiskCriticalNodes, ", "))
		}
	}
	return exit
}

// Below this many GB free, `--reclaim` also prunes the pnpm store. Kept under
// the runner's 15GB claim floor so a host prunes before it starts declining
// work, not after.
const defaultPnpmStorePruneFloorGb = 25

// Overridable so a host with different headroom can tune it, and so the path is
// exercisable without having to fill a disk to test it.
func pnpmStorePruneFloorGb() uint64 {
	if raw := strings.TrimSpace(os.Getenv("PREFLIGHT_STORE_PRUNE_FLOOR_GB")); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultPnpmStorePruneFloorGb
}

// prunePnpmStore drops unreferenced packages from the shared pnpm store.
// Reported 12.8GB reclaimed on labtop, versus 0 from the DerivedData sweep.
func prunePnpmStore(dryRun bool, stdout io.Writer, stderr io.Writer) bool {
	if _, err := exec.LookPath("pnpm"); err != nil {
		return false
	}
	if dryRun {
		fmt.Fprintln(stdout, "would prune the pnpm store (unreferenced packages)")
		return false
	}
	fmt.Fprintln(stdout, "pruning the pnpm store…")
	cmd := exec.Command("pnpm", "store", "prune")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(stderr, "pnpm store prune: %v\n", err)
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) != "" {
			fmt.Fprintf(stdout, "  %s\n", line)
		}
	}
	return true
}
