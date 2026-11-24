package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestSimlockChecksJobOwnershipDuringCIFetch(t *testing.T) {
	for _, outcome := range []string{"renewed", "revoked"} {
		t.Run(outcome, func(t *testing.T) {
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("PREFLIGHT_RUNNER_JOB_HEARTBEAT_INTERVAL", "20ms")
			fetchStarted := make(chan struct{})
			checked := make(chan struct{})
			var startOnce, checkOnce sync.Once
			var timedOut, completed atomic.Bool
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startOnce.Do(func() { close(fetchStarted) })
				var proceed <-chan struct{}
				if outcome == "renewed" {
					proceed = checked
				}
				select {
				case <-proceed:
				case <-r.Context().Done():
					return
				case <-time.After(3 * time.Second):
					timedOut.Store(true)
				}
				http.NotFound(w, r)
			}))
			defer remote.Close()

			root := t.TempDir()
			checkout := filepath.Join(root, ".preflight-ci", "app")
			runGit(t, root, "init", checkout)
			origin := remote.URL + "/app.git"
			runGit(t, checkout, "remote", "add", "origin", origin)
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/heartbeat"):
					select {
					case <-fetchStarted:
						checkOnce.Do(func() { close(checked) })
						if outcome == "revoked" {
							w.WriteHeader(http.StatusForbidden)
							io.WriteString(w, `{"error":{"code":"runner_job_lease_denied","message":"claim revoked"}}`)
							return
						}
					default:
					}
					io.WriteString(w, `{"data":{"job":{"id":"job","runnerId":"runner_scope","status":"running"}}}`)
				case strings.HasSuffix(r.URL.Path, "/complete"):
					completed.Store(true)
					io.WriteString(w, `{"data":{}}`)
				default:
					t.Errorf("unexpected control-plane request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer control.Close()
			job := apiRunnerJob{ID: "job", WorkflowID: "workflow", Kind: "device.discover", Payload: runnerJobPayload{
				Platform: "android", Lane: "simulator", TargetClass: "simulator",
				SourceBinding: runnerJobSourceBinding{WorkspaceRoot: checkout, GitRemoteURL: origin, GitBranch: "main"},
			}}
			options := runnerOnceOptions{apiURL: control.URL, workspaceRoot: root}
			err := runWithSimlockRunnerLease(control.Client(), options, scopedRegistration(t), job, io.Discard, func(runnerOnceOptions) error {
				t.Error("simulator ran after checkout failed")
				return nil
			})
			select {
			case <-checked:
			default:
				t.Fatal("job lease was never checked while Git was fetching the CI checkout")
			}
			if timedOut.Load() {
				t.Fatal("Git remained blocked after the job lease check")
			}
			if outcome == "revoked" {
				if !jobLeaseLost(err) || completed.Load() {
					t.Fatalf("revoked job attempted completion or lost its ownership error: completed=%v, err=%v", completed.Load(), err)
				}
			} else if err != nil || !completed.Load() {
				t.Fatalf("expected the owned job to report the fixture's missing repository: completed=%v, err=%v", completed.Load(), err)
			}
		})
	}
}

func TestCancelledCIResetAllowsRetry(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	for name, content := range map[string]string{".gitattributes": "app.txt filter=slow\n", "app.txt": "pinned source\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
	started := filepath.Join(t.TempDir(), "smudge-started")
	runGit(t, root, "config", "filter.slow.smudge", "touch "+simlockShellQuote(started)+" && exec sleep 60")
	if err := os.Remove(filepath.Join(root, "app.txt")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := runCICommand(ctx, root, "git", "reset", "--hard", "HEAD")
		result <- err
	}()
	for !fileExists(started) {
		select {
		case err := <-result:
			t.Fatalf("reset exited before reaching the filter: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancelled reset, got %v", err)
	}
	runGit(t, root, "config", "--unset", "filter.slow.smudge")
	runGit(t, root, "reset", "--hard", "HEAD")
}

func TestSimlockChecksFinishedCheckoutBeforeActing(t *testing.T) {
	t.Setenv("PREFLIGHT_RUNNER_JOB_HEARTBEAT_INTERVAL", "1h")
	root := t.TempDir()
	remote := filepath.Join(root, "source")
	checkout := filepath.Join(root, ".preflight-ci", "work")
	runGit(t, root, "init", "-b", "main", remote)
	runGit(t, remote, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "fixture")
	runGit(t, root, "clone", remote, checkout)
	sha := runGitOutput(t, checkout, "rev-parse", "HEAD")
	if err := os.MkdirAll(filepath.Join(checkout, ".preflight"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, ".preflight", "ci-deps.sha"), []byte(sha), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	fakeSimlockCLI(t, bin, simlockWorkflowGrantJSON(t, "android", "ours"), false)
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			io.WriteString(w, `{"data":{"job":{"id":"job","runnerId":"runner_scope","status":"cancelled"}}}`)
			return
		}
		t.Errorf("unexpected request after cancellation: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer control.Close()
	job := apiRunnerJob{ID: "job", WorkflowID: "ours", Kind: "device.discover", Payload: runnerJobPayload{
		Platform: "android", Lane: "simulator", TargetClass: "simulator",
		SourceBinding: runnerJobSourceBinding{WorkspaceRoot: checkout, GitRemoteURL: remote, GitCommitSHA: sha},
	}}
	for _, tc := range []struct{ name, revision string }{
		{"warm", sha},
		{"missing revision", strings.Repeat("0", 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job.Payload.SourceBinding.GitCommitSHA = tc.revision
			err := runWithSimlockRunnerLease(control.Client(), runnerOnceOptions{apiURL: control.URL, workspaceRoot: root}, scopedRegistration(t), job, io.Discard, func(runnerOnceOptions) error {
				t.Error("ran a simulator for a cancelled job")
				return io.EOF
			})
			if !errors.Is(err, errCommandCancelled) || simlockCallCount(t, bin, "--local lease --platform") != 0 {
				t.Fatalf("cancelled job reached SimLock or lost its cancellation: %v", err)
			}
		})
	}
}

func TestCICommandCancelsDescendantsAfterLeaderExits(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runCICommand(ctx, root, "sh", "-c", `sleep 60 & echo "$$ $!" > pids`)
		done <- err
	}()
	var leader, child int
	for {
		data, _ := os.ReadFile(filepath.Join(root, "pids"))
		if _, err := fmt.Sscan(string(data), &leader, &child); err == nil && errors.Is(syscall.Kill(leader, 0), syscall.ESRCH) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture leader did not exit")
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer func() {
		if group, err := syscall.Getpgid(child); err == nil && group == leader {
			_ = syscall.Kill(-group, syscall.SIGKILL)
		}
	}()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	state, _ := exec.Command("ps", "-o", "stat=", "-p", fmt.Sprint(child)).Output()
	if status := strings.TrimSpace(string(state)); status != "" && !strings.HasPrefix(status, "Z") {
		t.Fatalf("checkout descendant survived cancellation after its leader exited: %s", status)
	}
}
