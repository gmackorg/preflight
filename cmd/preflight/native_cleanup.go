package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Only the queued native builders use these paths under the checkout mutex.
// Products and diagnostic logs are deliberately outside the reclaimable set.
var nativeBuildCacheDirs = [][]string{
	{"Build", "Intermediates.noindex"},
	{"ModuleCache.noindex"},
	{"Index.noindex"},
	{"SDKStatCaches.noindex"},
}

func cleanupNativeBuildCaches(root string, cutoff time.Time, dryRun bool, stdout io.Writer) (int, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("resolve native cleanup root: %w", err)
	}
	preflightDir := filepath.Join(resolved, ".preflight")
	if exists, err := nativeCleanupDirectory(preflightDir); err != nil || !exists {
		return 0, err
	}
	flags := syscall.O_RDWR | syscall.O_CREAT | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if dryRun {
		// A preview may read a pre-existing mutex but must not create one.
		flags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	}
	fd, err := syscall.Open(filepath.Join(preflightDir, "checkout.lock"), flags, 0o644)
	if err != nil && !(dryRun && errors.Is(err, os.ErrNotExist)) {
		return 0, fmt.Errorf("establish native cleanup ownership: %w", err)
	}
	if err == nil {
		lock := os.NewFile(uintptr(fd), "checkout.lock")
		defer lock.Close()
		info, err := lock.Stat()
		if err != nil {
			return 0, fmt.Errorf("inspect native cleanup mutex: %w", err)
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("native cleanup mutex must be a regular file")
		}
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				fmt.Fprintf(stdout, "skipped active native build caches in %s\n", root)
				return 0, nil
			}
			return 0, fmt.Errorf("lock native cleanup checkout: %w", err)
		}
		defer syscall.Flock(fd, syscall.LOCK_UN)
	}

	removed := 0
	for _, lane := range []string{"ios-sim-deriveddata", "ios-device-deriveddata"} {
		for _, relative := range nativeBuildCacheDirs {
			path := preflightDir
			missing := false
			for _, component := range append([]string{lane}, relative...) {
				path = filepath.Join(path, component)
				exists, err := nativeCleanupDirectory(path)
				if err != nil {
					return removed, err
				}
				if !exists {
					missing = true
					break
				}
			}
			if missing {
				continue
			}
			stale, err := nativeCacheIsStale(path, cutoff)
			if err != nil {
				return removed, fmt.Errorf("inspect native cache %s: %w", path, err)
			}
			if !stale {
				continue
			}
			if dryRun {
				fmt.Fprintf(stdout, "would remove native build cache %s\n", path)
			} else if err := os.RemoveAll(path); err != nil {
				return removed, fmt.Errorf("remove native build cache %s: %w", path, err)
			}
			removed++
		}
	}
	return removed, nil
}

func nativeCleanupDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect native cleanup directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("native cleanup directory must not be linked or non-directory: %s", path)
	}
	return true, nil
}

func nativeCacheIsStale(path string, cutoff time.Time) (bool, error) {
	fresh := false
	err := filepath.WalkDir(path, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(cutoff) {
			fresh = true
			return fs.SkipAll
		}
		return nil
	})
	return !fresh, err
}
