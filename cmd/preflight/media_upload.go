package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Keep aligned with the control plane's per-artifact limit. Originals stay on
// the runner; only a validated derivative is registered and streamed.
const runnerMediaMaxBytes int64 = 25 * 1024 * 1024

type mediaCommand func(name string, args ...string) error

func runMediaCommand(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %.2048s", name, err, output)
	}
	return nil
}

func prepareVideoUpload(original string, run mediaCommand) (string, error) {
	info, err := os.Stat(original)
	if err != nil {
		return "", fmt.Errorf("stat recording: %w", err)
	}
	if info.Size() <= runnerMediaMaxBytes {
		return original, nil
	}
	// A private temporary path prevents a failed encode from being reused. Never
	// overwrite the source or discard a recording to make its upload fit.
	temp, err := os.CreateTemp(filepath.Dir(original), ".preflight-upload-*.mp4")
	if err != nil {
		return "", err
	}
	path := temp.Name()
	if err := temp.Close(); err != nil {
		return "", err
	}
	defer os.Remove(path)
	for _, crf := range []int{28, 34, 40} {
		err := run("ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", original,
			"-map", "0:v:0", "-an", "-vf", "scale=w='min(720,iw)':h=-2,fps=15", "-c:v", "libx264", "-preset", "veryfast",
			"-crf", strconv.Itoa(crf), "-pix_fmt", "yuv420p", "-movflags", "+faststart", path)
		if err != nil {
			return "", fmt.Errorf("recording compression failed; original retained at %s: %w", original, err)
		}
		encoded, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if encoded.Size() > 0 && encoded.Size() <= runnerMediaMaxBytes {
			destination := original + ".preflight-upload.mp4"
			if err := os.Rename(path, destination); err != nil {
				return "", err
			}
			return destination, nil
		}
	}
	return "", fmt.Errorf("recording still exceeds %d bytes after bounded compression; original retained at %s", runnerMediaMaxBytes, original)
}

// Retry the same registered artifact, never the smoke or native build. PUT is
// idempotent, so a lost response can safely retry these retained bytes.
func retryMediaPublication(publish func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = publish(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("media publication failed after 3 attempts: %w", err)
}
