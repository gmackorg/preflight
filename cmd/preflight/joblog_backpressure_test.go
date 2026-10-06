package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCommandLogDrainsWhileUploadIsBlocked(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	rec := &recorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Chunk string `json:"chunk"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode log: %v", err)
		}
		enterOnce.Do(func() { close(entered) })
		<-release
		_ = rec.post(payload.Chunk)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer server.Close()
	stop := startJobLogShipping(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}, Token: "test-token"}, apiRunnerJob{ID: "job"})
	defer stop()
	defer releaseOnce.Do(func() { close(release) })

	command := exec.Command("sh", "-c", "i=0; while [ $i -lt 32 ]; do printf '%s\\n' \"$1\"; i=$((i+1)); done", "command-log-fixture", strings.Repeat("compile object abcdefghijklmnopqrstuvwxyz", 64))
	var local bytes.Buffer
	flush := attachRedactedCommandLog(command, &local)
	done := make(chan error, 1)
	go func() { err := command.Run(); flush(); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upload never reached HTTP server")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("command failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(release) })
		<-done
		t.Fatal("native command output drain blocked behind delayed HTTP log POST")
	}
	releaseOnce.Do(func() { close(release) })
	stop()
	if got := strings.Count(local.String(), "\n"); got != 32 {
		t.Fatalf("local lines=%d", got)
	}
	if rec.all() != local.String() {
		t.Fatal("uploaded logs differ from complete local logs")
	}
}

func TestJobLogStopCancelsStalledHTTPUpload(t *testing.T) {
	// A timed-out native process must not then wait indefinitely for log upload.
	t.Setenv("PREFLIGHT_JOB_LOG_STOP_TIMEOUT", "50ms")
	entered := make(chan struct{})
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	stop := startJobLogShipping(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, apiRunnerJob{ID: "job"})
	// Below threshold: stopping itself must flush the final buffered line.
	writeActiveJobLog("final build failure\n")
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("terminal flush never started")
	}
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		server.CloseClientConnections()
		server.Close()
		<-done
		t.Fatal("terminal flush blocked on stalled HTTP")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upload request was not canceled")
	}
	stop()
}

func TestCommandLogsRemainBoundToTheirJobAndShipRedactedTail(t *testing.T) {
	var mu sync.Mutex
	logs := make(map[string]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Chunk string `json:"chunk"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		mu.Lock()
		logs[r.URL.Path] += payload.Chunk
		mu.Unlock()
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer server.Close()
	registration := runnerRegistrationData{Runner: apiRunner{ID: "runner"}}
	firstStop := startJobLogShipping(server.Client(), runnerOnceOptions{apiURL: server.URL}, registration, apiRunnerJob{ID: "first"})
	defer firstStop()
	firstCommand := exec.Command("sh")
	var firstLocal bytes.Buffer
	firstFlush := attachRedactedCommandLog(firstCommand, &firstLocal)
	secondStop := startJobLogShipping(server.Client(), runnerOnceOptions{apiURL: server.URL}, registration, apiRunnerJob{ID: "second"})
	defer secondStop()
	secondCommand := exec.Command("sh")
	var secondLocal bytes.Buffer
	secondFlush := attachRedactedCommandLog(secondCommand, &secondLocal)
	_, _ = io.WriteString(firstCommand.Stdout, "first output\n")
	firstFlush()
	firstStop()
	// Stopping an older job cannot detach the current one, and a stopped
	// writer cannot ship lingering output into the new job's upload stream.
	_, _ = io.WriteString(firstCommand.Stdout, "lingering old output\n")
	_, _ = io.WriteString(secondCommand.Stderr, "EXPO_TOKEN=example-secret-no-newline")
	secondFlush()
	secondStop()
	mu.Lock()
	defer mu.Unlock()
	if logs["/api/preflight/v1/runners/runner/jobs/first/logs"] != "first output\n" {
		t.Fatal("first job output lost/misattributed")
	}
	second := logs["/api/preflight/v1/runners/runner/jobs/second/logs"]
	if second != secondLocal.String() || strings.Contains(second, "example-secret") || strings.Contains(second, "lingering") || !strings.Contains(second, "REDACTED") {
		t.Fatalf("tail redaction or job isolation failed: %q", second)
	}
	if !strings.Contains(firstLocal.String(), "lingering old output") {
		t.Fatal("local output was lost after upload stopped")
	}
}

func TestJobLogUploadTimeoutDoesNotRetryOrStopSubsequentChunks(t *testing.T) {
	t.Setenv("PREFLIGHT_JOB_LOG_UPLOAD_TIMEOUT", "30ms")
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		requests++
		number := requests
		mu.Unlock()
		if number == 1 {
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer server.Close()
	stop := startJobLogShipping(server.Client(), runnerOnceOptions{apiURL: server.URL}, runnerRegistrationData{Runner: apiRunner{ID: "runner"}}, apiRunnerJob{ID: "job"})
	defer stop()
	writeActiveJobLog(strings.Repeat("x", jobLogFlushBytes*2))
	stop()
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 {
		t.Fatalf("timed-out chunk retried or following chunk lost: requests=%d", requests)
	}
}
