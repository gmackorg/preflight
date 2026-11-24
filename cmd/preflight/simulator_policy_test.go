package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The policy as the control plane serves it (preflight-app simulator-policy.ts).
const testSimulatorPolicyJSON = `{
  "id": "ios-27.2/iphone-17+ipad-pro-13-m5",
  "platform": "ios",
  "xcode": {"minimumVersion": "27.2"},
  "runtime": {"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-2", "version": "27.2"},
  "devices": {
    "iphone": {"simlockClass": "phone", "name": "iPhone 17", "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17"},
    "ipad": {"simlockClass": "tablet", "name": "iPad Pro 13-inch (M5)", "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"}
  },
  "defaultDevice": "iphone"
}`

func testSimulatorPolicy(t *testing.T) *simulatorPolicy {
	t.Helper()
	var policy simulatorPolicy
	if err := json.Unmarshal([]byte(testSimulatorPolicyJSON), &policy); err != nil {
		t.Fatal(err)
	}
	return &policy
}

func testIPadTarget() *simulatorTarget {
	return &simulatorTarget{
		PolicyID:             "ios-27.2/iphone-17+ipad-pro-13-m5",
		Device:               "ipad",
		Name:                 "iPad Pro 13-inch (M5)",
		DeviceTypeIdentifier: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB",
		SimlockClass:         "tablet",
		RuntimeIdentifier:    "com.apple.CoreSimulator.SimRuntime.iOS-27-2",
		OSVersion:            "27.2",
	}
}

func simlockPolicyGrantJSON(t *testing.T, workflowID, model, osVersion string) string {
	t.Helper()
	grant := simlockTestGrant(t, "ios")
	grant.Lease.ID = "pfwl_" + simlockWorkflowKey(workflowID, "ios") + "_000000000001"
	grant.Device.Spec.Model = model
	grant.Device.Spec.OSVersion = osVersion
	data, _ := json.Marshal(grant)
	return string(data)
}

func simlockLeaseCall(t *testing.T, dir string) string {
	t.Helper()
	for _, line := range strings.Split(string(mustRead(t, filepath.Join(dir, "calls"))), "\n") {
		if strings.HasPrefix(line, "--local lease ") {
			return line
		}
	}
	t.Fatal("no SimLock lease request recorded")
	return ""
}

func TestSimlockLeaseNamesThePolicyDeviceAndOS(t *testing.T) {
	t.Run("job target from the claim", func(t *testing.T) {
		dir := t.TempDir()
		fakeSimlockCLI(t, dir, simlockPolicyGrantJSON(t, "wf-ipad", "iPad Pro 13-inch (M5)", "27.2"), false)
		job := apiRunnerJob{WorkflowID: "wf-ipad", Kind: "device.discover", Payload: runnerJobPayload{Platform: "ios", TargetClass: "simulator", SimulatorTarget: testIPadTarget()}}
		lease, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "test"}, job, io.Discard, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { lease.finish(); lease.close() }()
		call := simlockLeaseCall(t, dir)
		if !strings.Contains(call, "--device iPad Pro 13-inch (M5) --os 27.2") {
			t.Fatalf("lease does not name the policy iPad and OS: %s", call)
		}
		if strings.Contains(call, "--class") {
			t.Fatalf("lease still asks for a device class: %s", call)
		}
		if !strings.Contains(call, "--meta preflight.simulatorPolicy=ios-27.2/iphone-17+ipad-pro-13-m5") {
			t.Fatalf("lease does not record the policy: %s", call)
		}
	})

	t.Run("registration policy default when the job carries none", func(t *testing.T) {
		dir := t.TempDir()
		fakeSimlockCLI(t, dir, simlockPolicyGrantJSON(t, "wf-default", "iPhone 17", "27.2"), false)
		job := apiRunnerJob{WorkflowID: "wf-default", Kind: "device.discover", Payload: runnerJobPayload{Platform: "ios", TargetClass: "simulator"}}
		options := runnerOnceOptions{hostIdentity: "test", simulatorPolicy: testSimulatorPolicy(t)}
		lease, err := acquireSimlockRunnerLease(options, job, io.Discard, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { lease.finish(); lease.close() }()
		if call := simlockLeaseCall(t, dir); !strings.Contains(call, "--device iPhone 17 --os 27.2") {
			t.Fatalf("lease does not name the policy iPhone: %s", call)
		}
	})

	t.Run("android keeps the phone class", func(t *testing.T) {
		args := simlockLeaseDeviceArgs(jobSimulatorTarget(runnerOnceOptions{simulatorPolicy: testSimulatorPolicy(t)}, apiRunnerJob{Payload: runnerJobPayload{Platform: "android", TargetClass: "emulator"}}))
		if !reflect.DeepEqual(args, []string{"--class", "phone"}) {
			t.Fatalf("android lease args = %v", args)
		}
	})
}

func TestSimlockRefusesAGrantOutsideThePolicy(t *testing.T) {
	dir := t.TempDir()
	fakeSimlockCLI(t, dir, simlockPolicyGrantJSON(t, "wf-old", "iPhone 17", "26.5"), false)
	job := apiRunnerJob{WorkflowID: "wf-old", Kind: "device.discover", Payload: runnerJobPayload{Platform: "ios", TargetClass: "simulator", SimulatorTarget: testSimulatorPolicy(t).defaultTarget()}}
	if _, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "test"}, job, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "fleet simulator policy") {
		t.Fatalf("accepted an iOS 26.5 grant under the 27.2 policy: %v", err)
	}
	if !simlockReleased(dir) {
		t.Fatal("refused grant was not released")
	}
}

func TestJobSimulatorTargetSkipsPhysicalAndAndroidWork(t *testing.T) {
	options := runnerOnceOptions{simulatorPolicy: testSimulatorPolicy(t)}
	for _, job := range []apiRunnerJob{
		{Payload: runnerJobPayload{Platform: "android", TargetClass: "emulator"}},
		{Payload: runnerJobPayload{Platform: "ios", Lane: "development", TargetClass: "device"}},
	} {
		if target := jobSimulatorTarget(options, job); target != nil {
			t.Fatalf("%+v got a simulator target", job.Payload)
		}
	}
	if target := jobSimulatorTarget(runnerOnceOptions{}, apiRunnerJob{Payload: runnerJobPayload{Platform: "ios", TargetClass: "simulator"}}); target != nil {
		t.Fatal("invented a target without a served policy")
	}
}

func fakeCommandOutput(outputs map[string]string, failures map[string]bool) commandOutput {
	return func(name string, args ...string) ([]byte, error) {
		key := strings.Join(args, " ")
		if failures[key] {
			return nil, errors.New("exit status 1")
		}
		return []byte(outputs[key]), nil
	}
}

const testRuntimesJSON = `{"runtimes":[
 {"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-27-2","version":"27.2","isAvailable":true},
 {"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-26-4","version":"26.4","isAvailable":true}]}`

const testDeviceTypesJSON = `{"devicetypes":[
 {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-17"},
 {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"},
 {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-16"}]}`

func TestSimulatorToolchainProbeAndDrift(t *testing.T) {
	policy := testSimulatorPolicy(t)
	compliant := probeIOSSimulatorToolchain("xcrun", fakeCommandOutput(map[string]string{
		"xcodebuild -version":        "Xcode 27.2\nBuild version 27C5032e\n",
		"simctl list runtimes -j":    testRuntimesJSON,
		"simctl list devicetypes -j": testDeviceTypesJSON,
	}, nil))
	if compliant.XcodeVersion != "27.2" || len(compliant.Runtimes) != 2 || len(compliant.DeviceTypes) != 3 || compliant.ProbeError != "" {
		t.Fatalf("probe = %+v", compliant)
	}
	if drift := simulatorPolicyDrift(policy, compliant); len(drift) != 0 {
		t.Fatalf("compliant host reported drift: %v", drift)
	}

	// gmacko-mini before its upgrade: Xcode 26.6, no iOS 27.2 runtime.
	drifted := probeIOSSimulatorToolchain("xcrun", fakeCommandOutput(map[string]string{
		"xcodebuild -version":        "Xcode 26.6\nBuild version 26F100\n",
		"simctl list runtimes -j":    `{"runtimes":[{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-26-4","version":"26.4","isAvailable":true}]}`,
		"simctl list devicetypes -j": `{"devicetypes":[{"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-16"}]}`,
	}, nil))
	drift := strings.Join(simulatorPolicyDrift(policy, drifted), "; ")
	for _, want := range []string{"Xcode 26.6 < 27.2", "SimRuntime.iOS-27-2 not installed", "SimDeviceType.iPhone-17 not available", "iPad-Pro-13-inch-M5-12GB not available"} {
		if !strings.Contains(drift, want) {
			t.Fatalf("drift %q missing %q", drift, want)
		}
	}

	failed := probeIOSSimulatorToolchain("xcrun", fakeCommandOutput(nil, map[string]bool{"simctl list runtimes -j": true}))
	if failed.ProbeError == "" || len(simulatorPolicyDrift(policy, failed)) == 0 {
		t.Fatalf("a failed probe must read as drift: %+v", failed)
	}
}

// Drift is reported in the heartbeat — raw toolchain facts the control plane
// judges at claim, plus the runner's own verdict — and only takes the host off
// iOS simulator work: platforms and adapters for everything else stay.
func TestDriftIsReportedInHeartbeatWithoutDroppingOtherWork(t *testing.T) {
	policy := testSimulatorPolicy(t)
	toolchain := iosSimulatorToolchain{XcodeVersion: "26.6", Runtimes: []iosSimulatorRuntime{}, DeviceTypes: []string{}}
	capabilities := map[string]any{
		"platforms":             []string{"ios", "android"},
		"adapters":              []string{"android.emulator", "ios.simulator", "xcodebuild"},
		"iosSimulatorToolchain": toolchain.capability(),
	}
	var log bytes.Buffer
	applySimulatorPolicyToCapabilities(capabilities, policy, &toolchain, &log)
	if !strings.Contains(log.String(), "will not claim iOS simulator work") {
		t.Fatalf("drift not logged: %q", log.String())
	}

	var heartbeat map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&heartbeat)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	}))
	defer server.Close()
	registration := runnerRegistrationData{Runner: apiRunner{ID: "runner"}, Token: "token"}
	if err := heartbeatRunner(server.Client(), runnerOnceOptions{apiURL: server.URL, workspaceRoot: t.TempDir()}, registration, capabilities); err != nil {
		t.Fatal(err)
	}
	reported, _ := heartbeat["capabilities"].(map[string]any)
	verdict, _ := reported["iosSimulatorPolicy"].(map[string]any)
	if verdict["status"] != "drift" || verdict["policyId"] != policy.ID {
		t.Fatalf("heartbeat verdict = %#v", verdict)
	}
	if _, ok := reported["iosSimulatorToolchain"].(map[string]any); !ok {
		t.Fatalf("heartbeat lacks the toolchain facts: %#v", reported)
	}
	if !reflect.DeepEqual(reported["platforms"], []any{"ios", "android"}) || !reflect.DeepEqual(reported["adapters"], []any{"android.emulator", "ios.simulator", "xcodebuild"}) {
		t.Fatalf("drift removed other capabilities: %#v", reported)
	}
}

func TestPolicySimctlInventoryKeepsOnlyThePolicyDevice(t *testing.T) {
	target := testSimulatorPolicy(t).defaultTarget()
	inventory := `{"devices":{
	 "com.apple.CoreSimulator.SimRuntime.iOS-27-2":[
	  {"udid":"AAAA","name":"iPhone 17","deviceTypeIdentifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-17","isAvailable":true},
	  {"udid":"BBBB","name":"iPhone 16 Pro","deviceTypeIdentifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro","isAvailable":true}],
	 "com.apple.CoreSimulator.SimRuntime.iOS-26-4":[
	  {"udid":"CCCC","name":"iPhone 17","deviceTypeIdentifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-17","isAvailable":true,"state":"Booted"}]}}`
	fixture := filepath.Join(t.TempDir(), "simctl.json")
	if err := os.WriteFile(fixture, []byte(inventory), 0600); err != nil {
		t.Fatal(err)
	}
	options := runnerOnceOptions{simctlJSON: fixture, simulatorPolicy: testSimulatorPolicy(t)}
	filtered, err := loadPolicySimctlInventory(options, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(filtered), "AAAA") || strings.Contains(string(filtered), "BBBB") || strings.Contains(string(filtered), "CCCC") {
		t.Fatalf("inventory not limited to the policy device: %s", filtered)
	}

	// The booted iOS 26.4 iPhone and the iPhone 16 Pro are never selected.
	job := apiRunnerJob{Payload: runnerJobPayload{Platform: "ios", TargetClass: "simulator", SimulatorTarget: target}}
	targets := []apiTarget{
		{ID: "old-os", DisplayName: "iPhone 17", ProviderIdentity: "CCCC", Availability: "available"},
		{ID: "other-model", DisplayName: "iPhone 16 Pro", ProviderIdentity: "BBBB", Availability: "available"},
		{ID: "policy", DisplayName: "iPhone 17", ProviderIdentity: "AAAA", Availability: "available"},
	}
	selected := automaticDiscoveryTarget(options, job, targets)
	if selected == nil || selected.ID != "policy" {
		t.Fatalf("selected %+v, want the policy simulator", selected)
	}
	if selected := automaticDiscoveryTarget(options, job, targets[:2]); selected != nil {
		t.Fatalf("fell back to a non-policy simulator: %+v", selected)
	}
}

func TestPolicySimulatorIsCreatedWhenMissing(t *testing.T) {
	target := testIPadTarget()
	var created []string
	run := func(name string, args ...string) ([]byte, error) {
		created = append(created, strings.Join(args, "|"))
		return []byte("NEW-UDID\n"), nil
	}
	if err := createPolicySimulator("xcrun", target, run); err != nil {
		t.Fatal(err)
	}
	want := "simctl|create|iPad Pro 13-inch (M5)|com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB|com.apple.CoreSimulator.SimRuntime.iOS-27-2"
	if len(created) != 1 || created[0] != want {
		t.Fatalf("created %v", created)
	}
}

func TestSimulatorPolicyCommandPrintsThePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/preflight/v1/simulator-policy" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"simulatorPolicy":`+testSimulatorPolicyJSON+`}}`)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"simulator-policy", "--api-url", server.URL}, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{"iOS 27.2", "iPhone 17", "iPad Pro 13-inch (M5)", "(default)"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("output %q missing %q", stdout.String(), want)
		}
	}
	stdout.Reset()
	if code := run([]string{"simulator-policy", "--json", "--api-url", server.URL}, &stdout, &stderr, server.Client()); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var policy simulatorPolicy
	if err := json.Unmarshal(stdout.Bytes(), &policy); err != nil || policy.Runtime.Identifier != "com.apple.CoreSimulator.SimRuntime.iOS-27-2" {
		t.Fatalf("json output %q: %v", stdout.String(), err)
	}
}

func TestCompareDottedVersions(t *testing.T) {
	for _, test := range []struct {
		left, right string
		want        int
	}{{"27.10", "27.2", 1}, {"27.2", "27.2.0", 0}, {"26.6", "27.2", -1}} {
		if got := compareDottedVersions(test.left, test.right); got != test.want {
			t.Fatalf("compare(%s, %s) = %d", test.left, test.right, got)
		}
	}
}
