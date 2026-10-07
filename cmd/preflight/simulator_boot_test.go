package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestBootIOSSimulatorBoundsHungCommands(t *testing.T) {
	for _, stage := range []string{"boot", "bootstatus"} {
		t.Run(stage, func(t *testing.T) {
			t.Setenv("PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT", "3s")
			xcrun := filepath.Join(t.TempDir(), "xcrun")
			pidFile := filepath.Join(t.TempDir(), "pid")
			t.Setenv("BOOT_PID_FILE", pidFile)
			script := "#!/bin/sh\nif [ \"$2\" = \"" + stage + "\" ]; then\n echo $$ > \"$BOOT_PID_FILE\"\n echo stalled-" + stage + " >&2\n exec sleep 10\nfi\n"
			if err := os.WriteFile(xcrun, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err := bootIOSSimulator(runnerOnceOptions{xcrunPath: xcrun}, "fleet-simulator", nil)
			if !errors.Is(err, errCommandTimedOut) || !strings.Contains(err.Error(), "stalled-"+stage) {
				t.Fatalf("expected bounded %s failure with command output, got %v", stage, err)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("boot waited %s for stalled %s", elapsed, stage)
			}
			assertBootProcessStopped(t, pidFile)
		})
	}
}

func assertBootProcessStopped(t *testing.T, pidFile string) {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("boot subprocess %d survived completion: %v", pid, err)
	}
}

func TestBootIOSSimulatorSharesDeadlineAcrossBothStages(t *testing.T) {
	t.Setenv("PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT", "4s")
	xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\nsleep 2.5\n")
	err := bootIOSSimulator(runnerOnceOptions{xcrunPath: xcrun}, "fleet-simulator", nil)
	if !errors.Is(err, errCommandTimedOut) || !strings.Contains(err.Error(), "bootstatus") {
		t.Fatalf("each stage received a fresh deadline: %v", err)
	}
}

func TestBootDeadlineSurvivesPendingCancellationLookup(t *testing.T) {
	t.Setenv("PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT", "300ms")
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "10ms")
	xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\nexec sleep 10\n")
	lookupFinished := make(chan struct{})
	releaseLookup := make(chan struct{})
	defer close(releaseLookup)
	var calls atomic.Int32
	started := time.Now()
	err := bootIOSSimulator(runnerOnceOptions{xcrunPath: xcrun}, "fleet-simulator", func() (bool, error) {
		calls.Add(1)
		<-releaseLookup
		close(lookupFinished)
		return false, nil
	})
	if !errors.Is(err, errCommandTimedOut) {
		t.Fatalf("expected timeout, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("deadline blocked by cancellation lookup: %s", elapsed)
	}
	if calls.Load() != 1 {
		t.Fatalf("overlapping cancellation lookups: %d", calls.Load())
	}
}

func TestCommandTimeoutStopsDescendantsHoldingOutputPipes(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "(trap '' TERM; sleep 5) & wait")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	started := time.Now()
	err := runCommandWithTimeoutAndCancellation(command, 300*time.Millisecond, nil, 0)
	if !errors.Is(err, errCommandTimedOut) {
		t.Fatalf("expected timeout, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("deadline blocked by inherited pipe: %s", elapsed)
	}
}

func TestBootIOSSimulatorCancelsAndStopsOnPollingError(t *testing.T) {
	for _, stage := range []string{"boot", "bootstatus"} {
		for _, pollingFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pollingError=%t", stage, pollingFails), func(t *testing.T) {
				t.Setenv("PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT", "2s")
				t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")
				pidFile := filepath.Join(t.TempDir(), "pid")
				t.Setenv("BOOT_PID_FILE", pidFile)
				xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\nif [ \"$2\" = \""+stage+"\" ]; then\n echo $$ > \"$BOOT_PID_FILE\"\n exec sleep 10\nfi\n")
				pollingError := errors.New("job lookup failed")
				check := func() (bool, error) {
					if _, err := os.Stat(pidFile); err != nil {
						return false, nil
					}
					if pollingFails {
						return false, pollingError
					}
					return true, nil
				}
				want := errCommandCancelled
				if pollingFails {
					want = pollingError
				}
				err := bootIOSSimulator(runnerOnceOptions{xcrunPath: xcrun}, "fleet-simulator", check)
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want %v", err, want)
				}
				assertBootProcessStopped(t, pidFile)
			})
		}
	}
}

func TestBootIOSSimulatorRequiresReadinessAfterAlreadyBootedExit(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprintf("ready=%t", ready), func(t *testing.T) {
			statusExit := "1"
			if ready {
				statusExit = "0"
			}
			xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\nif [ \"$2\" = boot ]; then\n echo already-booted >&2\n exit 149\nfi\necho readiness-result >&2\nexit "+statusExit+"\n")
			err := bootIOSSimulator(runnerOnceOptions{xcrunPath: xcrun}, "fleet-simulator", nil)
			if ready && err != nil {
				t.Fatalf("already booted simulator rejected: %v", err)
			}
			if !ready && (err == nil || !strings.Contains(err.Error(), "readiness-result")) {
				t.Fatalf("unready simulator accepted or diagnostics lost: %v", err)
			}
		})
	}
}

func TestRunnerCompletesUnreadySimulatorWithoutStartingApp(t *testing.T) {
	for _, kind := range []string{"dev_session.start", "simulator.open"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancelled=%t", kind, cancelled), func(t *testing.T) {
				t.Setenv("PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT", "3s")
				t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "20ms")
				t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "0")
				pidFile := filepath.Join(t.TempDir(), "boot-pid")
				t.Setenv("BOOT_PID_FILE", pidFile)
				xcrun := writeFakeExecutable(t, "xcrun", "#!/bin/sh\nif [ \"$2\" = bootstatus ]; then\n echo $$ > \"$BOOT_PID_FILE\"\n echo waiting-on-backboard >&2\n exec sleep 10\nfi\n")
				appStart := filepath.Join(t.TempDir(), "app-start")
				t.Setenv("APP_START_FILE", appStart)
				npx := writeFakeExecutable(t, "npx", "#!/bin/sh\ntouch \"$APP_START_FILE\"\nexit 1\n")
				t.Setenv("PATH", filepath.Dir(npx)+string(os.PathListSeparator)+os.Getenv("PATH"))
				var completion struct {
					Result struct {
						Status  string `json:"status"`
						Failure struct {
							Message string `json:"message"`
						} `json:"failure"`
						DevSession struct {
							Status string `json:"status"`
						} `json:"devSession"`
					} `json:"result"`
				}
				unexpected := make(chan string, 5)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pfjob_boot"):
						status := "running"
						if _, err := os.Stat(pidFile); err == nil && cancelled {
							status = "cancelled"
						}
						fmt.Fprintf(w, `{"data":{"job":{"id":"pfjob_boot","status":%q,"runnerId":"pfrun_boot"}},"meta":{"apiVersion":"v1"}}`, status)
					case strings.HasSuffix(r.URL.Path, "/heartbeat"):
						fmt.Fprint(w, `{"data":{"job":{"id":"pfjob_boot","status":"running"}},"meta":{"apiVersion":"v1"}}`)
					case strings.HasSuffix(r.URL.Path, "/complete"):
						if err := json.NewDecoder(r.Body).Decode(&completion); err != nil {
							unexpected <- err.Error()
						}
						fmt.Fprint(w, `{"data":{"job":{"id":"pfjob_boot","status":"failed"}},"meta":{"apiVersion":"v1"}}`)
					default:
						unexpected <- r.Method + " " + r.URL.Path
						http.Error(w, "unexpected request", 500)
					}
				}))
				defer server.Close()
				options := runnerOnceOptions{apiURL: server.URL, workspaceRoot: t.TempDir(), xcrunPath: xcrun, metroStatusURL: server.URL + "/unused", hostMode: "localhost"}
				registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_boot", Capabilities: map[string]any{"runnerJobHeartbeat": false}}, Token: "test_token"}
				job := apiRunnerJob{ID: "pfjob_boot", Kind: kind, TargetID: "fleet-simulator", Payload: runnerJobPayload{Lane: "simulator", ProviderIdentity: "fleet-simulator"}}
				var output bytes.Buffer
				var err error
				if kind == "dev_session.start" {
					_, err = handleDevSessionStartJob(server.Client(), options, registration, job, &output)
				} else {
					err = handleSimulatorOpenJob(server.Client(), options, registration, job, &output)
				}
				if err != nil {
					t.Fatal(err)
				}
				want := "failed"
				if cancelled {
					want = "cancelled"
				}
				if completion.Result.Status != want {
					t.Fatalf("completion = %+v, want %s", completion, want)
				}
				if kind == "dev_session.start" && completion.Result.DevSession.Status != want {
					t.Fatalf("dev-session status = %s, want %s", completion.Result.DevSession.Status, want)
				}
				if !cancelled && !strings.Contains(completion.Result.Failure.Message, "waiting-on-backboard") {
					t.Fatalf("boot diagnostic lost: %+v", completion)
				}
				if _, err := os.Stat(appStart); !os.IsNotExist(err) {
					t.Fatalf("started app after failed boot: %v", err)
				}
				select {
				case request := <-unexpected:
					t.Fatalf("unexpected follow-on operation: %s", request)
				default:
				}
				assertBootProcessStopped(t, pidFile)
			})
		}
	}
}
