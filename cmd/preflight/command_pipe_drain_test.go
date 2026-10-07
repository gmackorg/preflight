package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type delayedCommandOutputWriter struct {
	destination io.Writer
}

func (writer delayedCommandOutputWriter) Write(chunk []byte) (int, error) {
	time.Sleep(600 * time.Millisecond)
	return writer.destination.Write(chunk)
}

func TestCommandDrainAllowsRedactingWriterToFinishAfterSuccessfulExit(t *testing.T) {
	for _, grace := range []string{"250ms", "2s"} {
		t.Run(grace, func(t *testing.T) {
			t.Setenv("PREFLIGHT_COMMAND_OUTPUT_DRAIN_TIMEOUT", grace)
			command := exec.Command("/bin/sh", "-c", "printf 'completed build output\\n'")
			var output strings.Builder
			flush := attachRedactedCommandLog(command, delayedCommandOutputWriter{destination: &output})
			err := runCommandWithTimeout(command, 3*time.Second)
			flush()
			if grace == "250ms" {
				if !errors.Is(err, exec.ErrWaitDelay) {
					t.Fatalf("expected original short drain failure, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("successful output drain rejected: %v", err)
			}
			if output.String() != "completed build output\n" {
				t.Fatalf("redacted output lost: %q", output.String())
			}
		})
	}
}

func TestSimulatorBuildDrainsSuccessfulTrailingOutputBeforeInstall(t *testing.T) {
	appDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(appDir, "ios", "Review.xcworkspace"), 0o755); err != nil {
		t.Fatal(err)
	}
	products := filepath.Join(appDir, ".preflight", "ios-sim-deriveddata", "Build", "Products", "Debug-iphonesimulator")
	if err := os.MkdirAll(filepath.Join(products, "Review.app"), 0o755); err != nil {
		t.Fatal(err)
	}
	xcodebuild := writeFakeExecutable(t, "xcodebuild", "#!/bin/sh\nprintf 'BUILD SUCCEEDED\\n'\n(sleep 0.6; printf 'trailing build output\\n') &\nexit 0\n")
	t.Setenv("PATH", filepath.Dir(xcodebuild)+string(os.PathListSeparator)+os.Getenv("PATH"))
	xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\nprintf 'install executed\\n'\n")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "build.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	if err := buildAndInstallIOSSimulatorApp(logFile, runnerOnceOptions{xcrunPath: xcrun}, appDir, "review-simulator", apiRunnerJob{}, nil); err != nil {
		t.Fatalf("successful build rejected before installation: %v", err)
	}
	data, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	trailing := strings.Index(text, "trailing build output")
	install := strings.Index(text, "install executed")
	if trailing < 0 || install <= trailing {
		t.Fatalf("installation preceded full redacted output drain: %q", text)
	}
}

func TestCommandDrainPreservesExplicitBoundAndFailure(t *testing.T) {
	for _, exitCode := range []string{"0", "7"} {
		t.Run("exit-"+exitCode, func(t *testing.T) {
			command := exec.Command("/bin/sh", "-c", "(sleep 2) & exit "+exitCode)
			command.WaitDelay = 50 * time.Millisecond
			logFile, err := os.Create(filepath.Join(t.TempDir(), "command.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			flush := attachRedactedCommandLog(command, logFile)
			err = runCommandWithTimeout(command, 3*time.Second)
			flush()
			terminateCommandProcess(command.Process.Pid)
			if exitCode == "0" {
				if !errors.Is(err, exec.ErrWaitDelay) || !command.ProcessState.Success() {
					t.Fatalf("expected retained drain failure after successful exit, got %v", err)
				}
			} else {
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) || exitError.ExitCode() != 7 {
					t.Fatalf("nonzero command became successful: %v", err)
				}
			}
		})
	}
}

func TestSimulatorBuildFailureNeverInstallsExistingArtifact(t *testing.T) {
	appDir := t.TempDir()
	for _, dir := range []string{"ios/Review.xcworkspace", ".preflight/ios-sim-deriveddata/Build/Products/Debug-iphonesimulator/Old.app"} {
		if err := os.MkdirAll(filepath.Join(appDir, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	xcodebuild := writeFakeExecutable(t, "xcodebuild", "#!/bin/sh\nprintf 'failed build\\n'\n(sleep 0.6; printf 'trailing failure output\\n') &\nexit 7\n")
	t.Setenv("PATH", filepath.Dir(xcodebuild)+string(os.PathListSeparator)+os.Getenv("PATH"))
	installMarker := filepath.Join(t.TempDir(), "installed")
	t.Setenv("PIPE_DRAIN_INSTALL_MARKER", installMarker)
	xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\ntouch \"$PIPE_DRAIN_INSTALL_MARKER\"\n")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "failed.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	err = buildAndInstallIOSSimulatorApp(logFile, runnerOnceOptions{xcrunPath: xcrun}, appDir, "review-simulator", apiRunnerJob{}, nil)
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 7 {
		t.Fatalf("build error not retained: %v", err)
	}
	if _, err := os.Stat(installMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installed stale artifact after build failure: %v", err)
	}
}
