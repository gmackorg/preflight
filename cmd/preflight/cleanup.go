package main

// P6 — runner self-maintenance. `preflight cleanup builds` prunes stale
// regenerable build caches under a root; cleanupBuildStorageUnderPressure is
// the same sweep gated on free disk, for the runner loop to call before
// claiming work. The build volume filling to 100% (twice in one fleet-capture
// day) presents as mid-build lipo/codegen failures, not as a disk error —
// prune proactively instead. Contract defined by cleanup_test.go.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const bytesPerGiB uint64 = 1 << 30

// Managed cache directories: entries directly inside these (relative to the
// cleanup root) are regenerable build state and safe to remove when stale.
// Artifacts and anything else are never touched.
var managedCacheDirs = []string{
	"DerivedData",
	"tmp",
	"CocoaPods",
	"ModuleCache.noindex",
	"XCBuildData",
}

var diskImageExts = map[string]bool{
	".sparseimage": true, ".dmg": true, ".sparsebundle": true,
}

type cleanupEntry struct {
	path    string
	modTime time.Time
	isImage bool
}

func collectCleanupEntries(root string, includeDiskImages bool) []cleanupEntry {
	var entries []cleanupEntry
	for _, dir := range managedCacheDirs {
		base := filepath.Join(root, dir)
		items, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, item := range items {
			info, err := item.Info()
			if err != nil {
				continue
			}
			entries = append(entries, cleanupEntry{
				path:    filepath.Join(base, item.Name()),
				modTime: info.ModTime(),
			})
		}
	}
	if includeDiskImages {
		items, err := os.ReadDir(root)
		if err == nil {
			for _, item := range items {
				if item.IsDir() || !diskImageExts[filepath.Ext(item.Name())] {
					continue
				}
				info, err := item.Info()
				if err != nil {
					continue
				}
				entries = append(entries, cleanupEntry{
					path:    filepath.Join(root, item.Name()),
					modTime: info.ModTime(),
					isImage: true,
				})
			}
		}
	}
	return entries
}

func cleanupBuilds(root string, maxAge time.Duration, dryRun, includeDiskImages bool, stdout io.Writer) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for _, entry := range collectCleanupEntries(root, includeDiskImages) {
		if entry.modTime.After(cutoff) {
			continue
		}
		if dryRun {
			fmt.Fprintf(stdout, "would remove %s (age %s)\n",
				entry.path, time.Since(entry.modTime).Round(time.Hour))
			continue
		}
		if err := os.RemoveAll(entry.path); err != nil {
			return removed, fmt.Errorf("remove %s: %w", entry.path, err)
		}
		removed++
	}
	if !dryRun {
		noun := "entries"
		if removed == 1 {
			noun = "entry"
		}
		fmt.Fprintf(stdout, "removed %d stale build cache %s\n", removed, noun)
	}
	return removed, nil
}

type cleanupPressureResult struct {
	Removed            int
	SkippedForHeadroom bool
	FreeBytes          uint64
}

// freeBytesForPath reports free space on the volume holding path.
func freeBytesForPath(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// buildVolumePaths lists the locations a native build actually consumes space
// in. The workspace root is only half the story on macOS: DerivedData, the
// simulator runtimes and every toolchain cache live under the home directory,
// which is routinely a different volume from the checkout.
//
// This matters because the heartbeat's freeDiskGb is what the fleet board
// alarms on. A host reported 572 GB free — its workspace sits on an external
// SSD — while the internal volume every xcodebuild wrote to was down to 7 GB,
// and the board called the node healthy straight through the resulting outage.
func buildVolumePaths(workspaceRoot string) []string {
	paths := make([]string, 0, 2)
	if workspaceRoot != "" {
		paths = append(paths, workspaceRoot)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, home)
	}
	return paths
}

// tightestFreeBytes reports the smallest free space across the given paths; a
// host is constrained by whichever of its volumes fills first. Paths that
// cannot be stat'd are skipped rather than treated as empty, so a bad path
// cannot fake an alarm. freeFn is injectable for tests; pass nil for the real
// statfs probe.
func tightestFreeBytes(paths []string, freeFn func(string) (uint64, error)) (uint64, bool) {
	if freeFn == nil {
		freeFn = freeBytesForPath
	}
	var tightest uint64
	found := false
	for _, path := range paths {
		free, err := freeFn(path)
		if err != nil {
			continue
		}
		if !found || free < tightest {
			tightest = free
			found = true
		}
	}
	return tightest, found
}

// cleanupBuildStorageUnderPressure sweeps stale managed caches only when free
// space on the root's volume is at or below minFreeBytes. freeFn is injectable
// for tests; pass nil for the real statfs probe.
func cleanupBuildStorageUnderPressure(
	root string,
	maxAge time.Duration,
	minFreeBytes uint64,
	freeFn func(string) (uint64, error),
) (cleanupPressureResult, error) {
	if freeFn == nil {
		freeFn = freeBytesForPath
	}
	free, err := freeFn(root)
	if err != nil {
		return cleanupPressureResult{}, err
	}
	if free > minFreeBytes {
		return cleanupPressureResult{SkippedForHeadroom: true, FreeBytes: free}, nil
	}
	removed, err := cleanupBuilds(root, maxAge, false, false, io.Discard)
	if err != nil {
		return cleanupPressureResult{Removed: removed, FreeBytes: free}, err
	}

	// The workspace root is not where the space usually is. On 2026-08-13 all
	// five labtop runners logged
	//
	//   low disk: 10.4 GiB free (< 15 GiB) after sweeping 0 cache entries
	//
	// and then stopped: the sweep was scoped to managed cache dirs under the
	// workspace root, which were already clean, while ~6.8 GiB sat in
	// simulator data and several more in Xcode's own DerivedData. A sweep that
	// can only ever report 0 is worse than none — it makes the host look
	// unrecoverable when it is one directory away from healthy.
	//
	// Xcode keeps DerivedData under ~/Library/Developer/Xcode, and DerivedData
	// is already a managed cache dir, so the same collector handles it.
	for _, hostRoot := range hostCacheRoots() {
		hostRemoved, hostErr := cleanupBuilds(hostRoot, maxAge, false, false, io.Discard)
		removed += hostRemoved
		if hostErr != nil {
			return cleanupPressureResult{Removed: removed, FreeBytes: free}, hostErr
		}
	}
	return cleanupPressureResult{Removed: removed, FreeBytes: free}, nil
}

// hostCacheRoots are machine-level roots holding regenerable build caches that
// no workspace owns. Kept deliberately narrow: only caches a build is expected
// to recreate, never anything a user would miss.
func hostCacheRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, "Library", "Developer", "Xcode")}
}

func runCleanup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: preflight cleanup builds --root <dir> [--max-age 24h] [--dry-run] [--include-disk-images]")
		fmt.Fprintln(stdout, "Prune stale regenerable build caches (DerivedData, tmp, CocoaPods, module caches).")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "builds" {
		fmt.Fprintf(stderr, "unknown cleanup subcommand %q\n", args[0])
		return 2
	}
	fs := flag.NewFlagSet("cleanup builds", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "directory whose managed caches to prune")
	maxAgeStr := fs.String("max-age", "24h", "entries older than this are stale")
	dryRun := fs.Bool("dry-run", false, "print what would be removed")
	includeImages := fs.Bool("include-disk-images", false,
		"also prune stale .sparseimage/.dmg files directly under root")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if strings.TrimSpace(*root) == "" {
		fmt.Fprintln(stderr, "--root is required")
		return 2
	}
	maxAge, err := time.ParseDuration(*maxAgeStr)
	if err != nil {
		fmt.Fprintf(stderr, "bad --max-age: %v\n", err)
		return 2
	}
	if _, err := cleanupBuilds(*root, maxAge, *dryRun, *includeImages, stdout); err != nil {
		fmt.Fprintf(stderr, "cleanup: %v\n", err)
		return 1
	}
	return 0
}

// runnerMinFreeDiskBytes: claims are declined (and post-job sweeps run) below
// this free-space floor. Opt-in via PREFLIGHT_MIN_FREE_DISK_GB — 0 (unset)
// disables the gate, so tests and ad-hoc CLI runs on low-disk machines are
// unaffected; runner launchd definitions set it (15 is a good floor: a
// Release sim build peaks ~6 GiB of DerivedData).
func runnerMinFreeDiskBytes() uint64 {
	if raw := os.Getenv("PREFLIGHT_MIN_FREE_DISK_GB"); raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			return uint64(n) * bytesPerGiB
		}
	}
	return 0
}
