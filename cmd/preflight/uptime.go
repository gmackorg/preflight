package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// `preflight uptime check` probes the configured uptime monitors (URLs) and
// posts up/down + latency results back to preflight. Runs off the worker on a
// cron, same pattern as sentry sync / crashes analyze.

type uptimeMonitor struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Method          string `json:"method"`
	ExpectedStatus  int    `json:"expectedStatus"`
	BodyMatch       string `json:"bodyMatch"`
	BodyMatchAbsent bool   `json:"bodyMatchAbsent"`
}

func runUptime(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: preflight uptime check")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Probe configured uptime monitors and post up/down results.")
		return 0
	}
	switch args[0] {
	case "check":
		return runUptimeCheck(args[1:], stdout, stderr, client)
	default:
		fmt.Fprintf(stderr, "unknown uptime subcommand %q\n", args[0])
		return 2
	}
}

// probeMonitor performs one HTTP probe and returns a result map. Never errors —
// a failed request is a "down" result.
func probeMonitor(client *http.Client, m uptimeMonitor) map[string]any {
	method := m.Method
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequest(method, m.URL, nil)
	if err != nil {
		return map[string]any{"status": "down", "error": err.Error()}
	}
	req.Header.Set("User-Agent", "preflight-uptime/1.0")
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]any{
			"status":    "down",
			"latencyMs": latency,
			"error":     err.Error(),
		}
	}
	defer resp.Body.Close()
	// Read enough body to run the assertion (bounded).
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	expected := m.ExpectedStatus
	if expected == 0 {
		expected = 200
	}
	statusOK := resp.StatusCode == expected ||
		(expected == 200 && resp.StatusCode >= 200 && resp.StatusCode < 400)

	up := statusOK
	failReason := ""
	if !statusOK {
		failReason = fmt.Sprintf("HTTP %d (expected %d)", resp.StatusCode, expected)
	} else if m.BodyMatch != "" {
		// Body assertion only runs when the status is OK.
		present := strings.Contains(string(bodyBytes), m.BodyMatch)
		if m.BodyMatchAbsent && present {
			up = false
			failReason = fmt.Sprintf("body contains %q (should be absent)", m.BodyMatch)
		} else if !m.BodyMatchAbsent && !present {
			up = false
			failReason = fmt.Sprintf("body missing %q", m.BodyMatch)
		}
	}

	status := "down"
	if up {
		status = "up"
	}
	out := map[string]any{
		"status":     status,
		"statusCode": resp.StatusCode,
		"latencyMs":  latency,
	}
	if !up {
		out["error"] = failReason
	}
	return out
}

func runUptimeCheck(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Fprintln(stdout, "Usage: preflight uptime check")
			return 0
		}
	}
	apiURL, token := preflightAPIConfig()
	if apiURL == "" || token == "" {
		fmt.Fprintln(stderr, "needs a Preflight API url/token (run `preflight config`)")
		return 2
	}

	raw, err := getPreflightJSON(client, strings.TrimRight(apiURL, "/")+
		"/api/preflight/v1/uptime/check-queue", token)
	if err != nil {
		fmt.Fprintf(stderr, "fetch monitors failed: %v\n", err)
		return 1
	}
	var payload struct {
		Monitors []uptimeMonitor `json:"monitors"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		fmt.Fprintf(stderr, "decode monitors failed: %v\n", err)
		return 1
	}
	if len(payload.Monitors) == 0 {
		fmt.Fprintln(stdout, "no active uptime monitors")
		return 0
	}

	// Probe client with a tight per-request timeout, separate from the API one.
	probeClient := &http.Client{Timeout: 15 * time.Second}
	up, down := 0, 0
	for _, m := range payload.Monitors {
		result := probeMonitor(probeClient, m)
		post := strings.TrimRight(apiURL, "/") +
			"/api/preflight/v1/uptime/" + url.PathEscape(m.ID) + "/result"
		if _, err := postPreflightJSON(client, post, token, result); err != nil {
			fmt.Fprintf(stderr, "  %s: post failed: %v\n", m.Name, err)
			continue
		}
		if result["status"] == "up" {
			up++
			fmt.Fprintf(stdout, "  ✓ %-30s %v (%vms)\n", m.Name, result["statusCode"], result["latencyMs"])
		} else {
			down++
			fmt.Fprintf(stdout, "  ✗ %-30s DOWN: %v\n", m.Name, result["error"])
		}
	}
	fmt.Fprintf(stdout, "\n%d up, %d down (%d monitors)\n", up, down, len(payload.Monitors))
	return 0
}
