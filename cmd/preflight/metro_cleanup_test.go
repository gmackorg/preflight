package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestMetroCleanupProcess(t *testing.T) {
	if os.Getenv("PREFLIGHT_TEST_METRO_CLEANUP_PROCESS") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("PREFLIGHT_TEST_METRO_READY_FILE"), []byte("ready"), 0o600); err != nil {
		os.Exit(2)
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestMetroCleanupPreservesOtherWorkspaceSession(t *testing.T) {
	for _, currentPath := range []string{"worktrees/driftport", ".preflight-ci/current-app"} {
		t.Run(currentPath, func(t *testing.T) {
			root := t.TempDir()
			current := filepath.Join(root, currentPath)
			other := filepath.Join(root, ".preflight-ci/simulator-evidence/apps/mobile")
			ready := filepath.Join(root, "ready")
			command := exec.Command(os.Args[0], "-test.run=^TestMetroCleanupProcess$", "--", filepath.Join(other, "expo"), "start", "--dev-client")
			command.Env = append(os.Environ(), "PREFLIGHT_TEST_METRO_CLEANUP_PROCESS=1", "PREFLIGHT_TEST_METRO_READY_FILE="+ready)
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			t.Cleanup(func() {
				_ = command.Process.Kill()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
			})
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("session helper did not become ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			pidPath := filepath.Join(other, ".preflight/expo-dev-session.pid")
			if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pidPath, []byte(strconv.Itoa(command.Process.Pid)), 0o600); err != nil {
				t.Fatal(err)
			}
			// Confine any regression that reintroduces a process scan to the
			// disposable helper; shared build hosts must never enter this test's
			// process inventory.
			tools := filepath.Join(root, "tools")
			if err := os.Mkdir(tools, 0o700); err != nil {
				t.Fatal(err)
			}
			inventory := fmt.Sprintf("%d %s start --dev-client", command.Process.Pid, filepath.Join(other, "expo"))
			shim := "#!/bin/sh\nprintf '%s\\n' \"$PREFLIGHT_TEST_METRO_INVENTORY\"\n"
			if err := os.WriteFile(filepath.Join(tools, "ps"), []byte(shim), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PREFLIGHT_TEST_METRO_INVENTORY", inventory)
			t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
			var output bytes.Buffer
			cleanupStalePreflightDevServers(current, &output)
			select {
			case err := <-done:
				t.Fatalf("starting another app stopped an existing session: %v; %s", err, output.String())
			case <-time.After(150 * time.Millisecond):
			}
			if _, err := os.Stat(pidPath); err != nil {
				t.Fatalf("another workspace's session handle changed: %v", err)
			}
		})
	}
}

func TestMetroCleanupOnlyRemovesDeadCurrentWorkspaceHandle(t *testing.T) {
	appDir := t.TempDir()
	tools := filepath.Join(appDir, "tools")
	if err := os.Mkdir(tools, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "ps"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	pidPath := filepath.Join(appDir, ".preflight/expo-dev-session.pid")
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{strconv.Itoa(os.Getpid()), "invalid"} {
		if err := os.WriteFile(pidPath, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		cleanupStalePreflightDevServers(appDir, &bytes.Buffer{})
		content, err := os.ReadFile(pidPath)
		if err != nil || string(content) != value {
			t.Fatalf("live or unverified handle changed: value=%q content=%q err=%v", value, content, err)
		}
	}
	const absentPID = 999999999
	if !errors.Is(syscall.Kill(absentPID, 0), syscall.ESRCH) {
		t.Fatal("dead-process fixture is not absent")
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(absentPID)), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanupStalePreflightDevServers(appDir, &bytes.Buffer{})
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("dead current-app handle was retained: %v", err)
	}
}
