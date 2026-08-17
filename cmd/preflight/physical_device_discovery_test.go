package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportDiscoveryTargetsUsesDevicectlForPhysicalIOSJob(t *testing.T) {
	xcrunPath := filepath.Join(t.TempDir(), "xcrun")
	if err := os.WriteFile(xcrunPath, []byte(`#!/bin/sh
case "$1" in
  devicectl)
    printf '%s\n' '{"result":{"devices":[{"deviceProperties":{"name":"OODA iPad"},"hardwareProperties":{"udid":"IPAD-UDID","platform":"iOS"},"connectionProperties":{"tunnelState":"connected","pairingState":"paired"}}]}}'
    ;;
  simctl)
    printf '%s\n' '{"devices":{}}'
    ;;
  *)
    exit 64
    ;;
esac
`), 0o755); err != nil {
		t.Fatalf("write xcrun fixture: %v", err)
	}

	var sawIOSDevices bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/preflight/v1/runners/pfrun_ipad/targets/ios-devices" {
			http.Error(w, "unexpected discovery endpoint "+r.URL.Path, http.StatusConflict)
			return
		}
		sawIOSDevices = true
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if !strings.Contains(fmt.Sprint(body["devicectlOutput"]), "OODA iPad") {
			http.Error(w, "missing devicectl inventory", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"pftgt_ipad","displayName":"OODA iPad","providerIdentity":"IPAD-UDID","availability":"available"}]}}`))
	}))
	t.Cleanup(server.Close)

	targets, err := reportDiscoveryTargets(
		server.Client(),
		runnerOnceOptions{apiURL: server.URL, xcrunPath: xcrunPath},
		runnerRegistrationData{Runner: apiRunner{ID: "pfrun_ipad"}, Token: "runner-token"},
		apiRunnerJob{Payload: runnerJobPayload{
			Platform:    "ios",
			Lane:        "development",
			TargetClass: "device",
		}},
	)
	if err != nil {
		t.Fatalf("report physical iOS targets: %v", err)
	}
	if !sawIOSDevices {
		t.Fatal("expected physical iOS inventory endpoint")
	}
	if len(targets.Targets) != 1 || targets.Targets[0].ID != "pftgt_ipad" {
		t.Fatalf("unexpected physical iOS targets: %#v", targets.Targets)
	}
}

func TestPhysicalIOSDiscoveryWaitsForExplicitTargetSelection(t *testing.T) {
	job := apiRunnerJob{Payload: runnerJobPayload{
		Platform:    "ios",
		Lane:        "development",
		TargetClass: "device",
	}}
	targets := []apiTarget{
		{ID: "pftgt_iphone", DisplayName: "iPhone-gm", Availability: "available"},
		{ID: "pftgt_ipad", DisplayName: "OODA iPad", Availability: "available"},
	}

	if target := automaticDiscoveryTarget(runnerOnceOptions{}, job, targets); target != nil {
		t.Fatalf("physical iOS discovery must wait for explicit selection, got %#v", target)
	}
}
