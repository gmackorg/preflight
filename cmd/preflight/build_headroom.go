package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Automatic checks only probe the build and home volumes. Cache age cannot
// establish ownership or whether a preserved native product is still needed.
func ensureBuildDiskHeadroom(buildDir string, stdout io.Writer) error {
	return ensureBuildDiskHeadroomWithProbe(buildDir, stdout, freeBytesForPath)
}

func ensureBuildDiskHeadroomWithProbe(buildDir string, stdout io.Writer, freeFn func(string) (uint64, error)) error {
	floor, err := buildDiskHeadroomFloor(os.Getenv("PREFLIGHT_MIN_FREE_DISK_GB"))
	if err != nil {
		return err
	}
	if floor == 0 {
		return nil
	}
	paths := buildVolumePaths(buildDir)
	if len(paths) == 0 {
		return fmt.Errorf("build disk headroom: no build volume configured")
	}
	for _, path := range paths {
		free, err := probeBuildDiskFreeBytes(path, freeFn, 2*time.Second)
		if err != nil {
			return fmt.Errorf("build disk headroom: cannot verify free space for %s: %w", path, err)
		}
		if free < floor {
			return fmt.Errorf("build disk headroom: %s has %.1f GiB free, below configured %.0f GiB floor; preserve products and reclaim explicitly before retry", path, float64(free)/float64(bytesPerGiB), float64(floor)/float64(bytesPerGiB))
		}
	}
	fmt.Fprintf(stdout, "build disk headroom meets configured %.0f GiB floor; caches preserved\n", float64(floor)/float64(bytesPerGiB))
	return nil
}

func buildDiskHeadroomFloor(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	gib, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || gib > ^uint64(0)/bytesPerGiB {
		return 0, fmt.Errorf("PREFLIGHT_MIN_FREE_DISK_GB must be a non-negative whole number of GiB")
	}
	return gib * bytesPerGiB, nil
}

var buildDiskProbeSlot = make(chan struct{}, 1)

// A mounted volume can stop responding to statfs. Do not let it hold a runner
// indefinitely; the buffered result lets a late probe finish after refusal.
func probeBuildDiskFreeBytes(path string, freeFn func(string) (uint64, error), timeout time.Duration) (uint64, error) {
	type result struct {
		free uint64
		err  error
	}
	completed := make(chan result, 1)
	select {
	case buildDiskProbeSlot <- struct{}{}:
	default:
		return 0, fmt.Errorf("previous free-space probe is still running; retry when the volume responds")
	}
	go func() {
		value := func() result {
			defer func() { <-buildDiskProbeSlot }()
			free, err := freeFn(path)
			return result{free, err}
		}()
		completed <- value
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-completed:
		return value.free, value.err
	case <-timer.C:
		return 0, fmt.Errorf("free-space probe timed out after %s", timeout)
	}
}
