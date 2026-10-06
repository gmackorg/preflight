package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLocalhostMetroHealthRejectsIPv6OnlyListener(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "packager-status:running") }))
	server.Listener = listener
	server.Start()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	client := &http.Client{Timeout: 200 * time.Millisecond}
	if !metroStatusReady(client, server.URL+"/status") {
		t.Fatal("IPv6-only fixture not healthy")
	}
	if metroStatusReady(client, runnerLocalDevServerURL(runnerOnceOptions{hostMode: "localhost", metroPort: port})+"/status") {
		t.Fatal("localhost health accepted unreachable advertised IPv4 asset endpoint")
	}
}

func TestLocalhostExpoProcessBindsAdvertisedIPv4WithExistingNodeOptions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for real localhost binding regression")
	}
	if err := exec.Command(node, "--dns-result-order=ipv6first", "-e", "").Run(); err != nil {
		t.Skip("Node must support ipv6first for this real Node 24 binding regression")
	}
	appDir := t.TempDir()
	bin := t.TempDir()
	script := filepath.Join(bin, "metro.cjs")
	source := `const http=require('node:http');
 const server=http.createServer((req,res)=>res.end('packager-status:running'));
 server.listen(0,'localhost',()=>require('node:fs').writeFileSync(process.env.PREFLIGHT_TEST_METRO_ADDRESS,JSON.stringify(server.address())));
 `
	if err := os.WriteFile(script, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "npx"), []byte("#!/bin/sh\nexec \"$PREFLIGHT_TEST_NODE\" \"$PREFLIGHT_TEST_METRO_SCRIPT\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	address := filepath.Join(bin, "address.json")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_TEST_NODE", node)
	t.Setenv("PREFLIGHT_TEST_METRO_SCRIPT", script)
	t.Setenv("PREFLIGHT_TEST_METRO_ADDRESS", address)
	t.Setenv("NODE_OPTIONS", "--max-old-space-size=128 --dns-result-order=ipv6first")
	process, err := startExpoDevServer(runnerOnceOptions{hostMode: "localhost", metroPort: 19000}, appDir, apiRunnerJob{Payload: runnerJobPayload{Lane: "simulator"}})
	if err != nil {
		t.Fatal(err)
	}
	defer terminateExpoDevServer(process)
	deadline := time.Now().Add(3 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(address)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("Node fixture failed to start")
	}
	// The real listener address is the regression signal, not a NODE_OPTIONS string assertion.
	if !strings.Contains(string(data), `"address":"127.0.0.1"`) {
		t.Fatalf("Metro bound wrong interface: %s", data)
	}
	var binding struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(data, &binding); err != nil {
		t.Fatal(err)
	}
	port := binding.Port
	if !metroStatusReady(&http.Client{Timeout: time.Second}, "http://127.0.0.1:"+strconv.Itoa(port)+"/status") {
		t.Fatal("advertised IPv4 asset endpoint unreachable")
	}
}

func TestExpoLocalhostDNSOverridePreservesModesAndExistingOptions(t *testing.T) {
	for _, mode := range []string{"localhost", "lan", "tunnel", "tailscale"} {
		t.Run(mode, func(t *testing.T) {
			existing := `--max-old-space-size=256 --require="/tmp/a quoted path.cjs" --dns-result-order ipv6first`
			t.Setenv("NODE_OPTIONS", existing)
			job := apiRunnerJob{Payload: runnerJobPayload{Lane: "simulator"}}
			env := expoDevServerEnv(runnerOnceOptions{hostMode: mode}, job)
			found := ""
			for _, entry := range env {
				if value, ok := strings.CutPrefix(entry, "NODE_OPTIONS="); ok {
					found = value
				}
			}
			expected := existing
			if mode == "localhost" {
				expected += " --dns-result-order=ipv4first"
			}
			if found != expected {
				t.Fatalf("existing Node options changed: %q", found)
			}
			if !strings.Contains(strings.Join(env, "\n"), "APP_VARIANT=development") {
				t.Fatal("source/profile variant handling lost")
			}
		})
	}
	t.Setenv("NODE_OPTIONS", "")
	job := apiRunnerJob{}
	job.Payload.NetworkPolicy.TunnelRequired = true
	for _, entry := range expoDevServerEnv(runnerOnceOptions{hostMode: "localhost"}, job) {
		if entry == "NODE_OPTIONS=--dns-result-order=ipv4first" {
			t.Fatal("tunnel-required job changed DNS")
		}
	}
}
