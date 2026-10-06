package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This subprocess has its own cwd and listener, like an actual Expo process.
// Keeping the two apps in separate processes prevents an in-process HTTP fake
// from accidentally making both listeners belong to the same recorded PID.
func TestMetroOwnerHelperProcess(t *testing.T) {
	if os.Getenv("PREFLIGHT_TEST_METRO_PROCESS") != "1" {
		return
	}
	if os.Getenv("PREFLIGHT_TEST_METRO_PARENT") == "1" {
		command := exec.Command(os.Args[0], os.Args[1:]...)
		command.Env = append(os.Environ(), "PREFLIGHT_TEST_METRO_PARENT=0")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			panic(err)
		}
		return
	}
	port := "0"
	address := "127.0.0.1"
	for i, arg := range os.Args {
		if arg == "--port" && i+1 < len(os.Args) {
			port = os.Args[i+1]
		}
		if arg == "--test-host-address" && i+1 < len(os.Args) {
			address = os.Args[i+1]
		}
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address, port))
	if err != nil {
		panic(err)
	}
	fmt.Println("Metro waiting on http://" + listener.Addr().String())
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("packager-status:running"))
	})}
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}

type testMetroProcess struct {
	URL string
	PID int
}

func startTestMetroProcess(t *testing.T, appDir string) testMetroProcess {
	return startTestMetroProcessTree(t, appDir, false)
}

func startTestMetroProcessTree(t *testing.T, appDir string, parent bool) testMetroProcess {
	return startTestMetroProcessAt(t, appDir, parent, "127.0.0.1", "0")
}

func startTestMetroProcessAt(t *testing.T, appDir string, parent bool, address, port string) testMetroProcess {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestMetroOwnerHelperProcess$", "--", "--port", port, "--test-host-address", address)
	command.Dir = appDir
	command.Env = append(os.Environ(), "PREFLIGHT_TEST_METRO_PROCESS=1")
	if parent {
		command.Env = append(command.Env, "PREFLIGHT_TEST_METRO_PARENT=1")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { terminateCommandProcess(command.Process.Pid); _ = command.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		if scanner.Scan() {
			ready <- strings.TrimPrefix(scanner.Text(), "Metro waiting on ")
		}
	}()
	select {
	case address := <-ready:
		return testMetroProcess{URL: address, PID: command.Process.Pid}
	case <-time.After(5 * time.Second):
		t.Fatal("Metro helper did not report readiness")
		return testMetroProcess{}
	}
}

func TestPreflightOwnedMetroRejectsForeignIPv6ListenerOnSamePort(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	_ = probe.Close()
	appDir := t.TempDir()
	own := startTestMetroProcess(t, appDir)
	parsed, err := url.Parse(own.URL)
	if err != nil {
		t.Fatal(err)
	}
	foreign := startTestMetroProcessAt(t, t.TempDir(), false, "::1", parsed.Port())
	writeTestMetroPID(t, appDir, own.PID)
	if preflightOwnedMetroReady(http.DefaultClient, appDir, foreign.URL+"/status") {
		t.Fatal("an owned IPv4 listener must not authorize another app's IPv6 listener on the same port")
	}
	if !metroStatusReady(http.DefaultClient, own.URL+"/status") || !metroStatusReady(http.DefaultClient, foreign.URL+"/status") {
		t.Fatal("address ownership rejection must leave both listeners running")
	}
}

func TestPreflightOwnedMetroAcceptsDescendantListener(t *testing.T) {
	appDir := t.TempDir()
	process := startTestMetroProcessTree(t, appDir, true)
	writeTestMetroPID(t, appDir, process.PID)
	if !preflightOwnedMetroReady(http.DefaultClient, appDir, process.URL+"/status") {
		t.Fatal("the recorded npx process may delegate its listener to a descendant")
	}
}

func writeTestMetroPID(t *testing.T, appDir string, pid int) {
	t.Helper()
	dir := filepath.Join(appDir, ".preflight")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expo-dev-session.pid"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightOwnedMetroRejectsOtherAppsHealthyPort(t *testing.T) {
	appDir := t.TempDir()
	own := startTestMetroProcess(t, appDir)
	foreignDir := t.TempDir()
	foreign := startTestMetroProcess(t, foreignDir)
	writeTestMetroPID(t, appDir, own.PID)
	if !preflightOwnedMetroReady(http.DefaultClient, appDir, own.URL+"/status") {
		t.Fatal("expected the recorded process's own listener to be reusable")
	}
	if preflightOwnedMetroReady(http.DefaultClient, appDir, foreign.URL+"/status") {
		t.Fatal("an app's live PID on one port must not authorize another app's healthy port")
	}
	if !metroStatusReady(http.DefaultClient, foreign.URL+"/status") {
		t.Fatal("ownership rejection must leave the foreign listener running")
	}
	writeTestMetroPID(t, appDir, foreign.PID)
	if preflightOwnedMetroReady(http.DefaultClient, appDir, foreign.URL+"/status") {
		t.Fatal("a listener from another app directory must not be reusable")
	}
}

func TestDevSessionStartAllocatesNewMetroInsteadOfReusingOtherApp(t *testing.T) {
	appDir := writeExpoFixture(t)
	own := startTestMetroProcess(t, appDir)
	foreign := startTestMetroProcess(t, t.TempDir())
	writeTestMetroPID(t, appDir, own.PID)
	parsed, err := url.Parse(foreign.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	// exec replaces the shell with the real helper listener, so the pid handle
	// and cwd are observed through the same production ownership check.
	script := "#!/bin/sh\nexport PREFLIGHT_TEST_METRO_PROCESS=1\nexec '" + strings.ReplaceAll(binary, "'", "'\\''") + "' -test.run='^TestMetroOwnerHelperProcess$' -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "npx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_RUNNER_POLL_INTERVAL", "10ms")
	var completed struct {
		Result struct {
			DevSession struct {
				Status    string `json:"status"`
				Port      int    `json:"port"`
				StatusURL string `json:"statusUrl"`
			} `json:"devSession"`
		} `json:"result"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/complete") {
			if err := json.NewDecoder(r.Body).Decode(&completed); err != nil {
				t.Error(err)
			}
		}
		_, _ = w.Write([]byte(`{"data":{"job":{"id":"pfjob_owner","kind":"dev_session.start","status":"running","runnerId":"pfrun_owner"}},"meta":{"apiVersion":"v1"}}`))
	}))
	t.Cleanup(server.Close)
	options := runnerOnceOptions{apiURL: server.URL, workspaceRoot: appDir, hostMode: "localhost", metroPort: port}
	registration := runnerRegistrationData{Runner: apiRunner{ID: "pfrun_owner"}, Token: "test_token"}
	job := apiRunnerJob{ID: "pfjob_owner", Kind: "dev_session.start", Payload: runnerJobPayload{
		Platform: "ios", Lane: "development", SourceBinding: runnerJobSourceBinding{WorkspaceRoot: appDir, PackagePath: ".", AppScheme: "forgegraph"},
	}}
	var stdout bytes.Buffer
	continued, err := handleDevSessionStartJob(server.Client(), options, registration, job, &stdout)
	pidPath := filepath.Join(appDir, ".preflight", "expo-dev-session.pid")
	t.Cleanup(func() {
		content, readErr := os.ReadFile(pidPath)
		if readErr != nil {
			return
		}
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(content)))
		if parseErr == nil && pid != own.PID && pid != foreign.PID {
			_, _ = stopPreflightOwnedDevSession(appDir, pid)
		}
	})
	if err != nil || !continued {
		t.Fatalf("expected a new dev session, continued=%v err=%v stdout=%s", continued, err, stdout.String())
	}
	result := completed.Result.DevSession
	if result.Status != "started" || result.Port == port || result.Port == 0 {
		t.Fatalf("expected a newly started server on a distinct port, got %+v", result)
	}
	if !preflightOwnedMetroReady(http.DefaultClient, appDir, result.StatusURL) {
		t.Fatal("newly recorded listener must belong to the requested app")
	}
	if !metroStatusReady(http.DefaultClient, own.URL+"/status") || !metroStatusReady(http.DefaultClient, foreign.URL+"/status") {
		t.Fatal("both pre-existing servers must remain running")
	}
}
