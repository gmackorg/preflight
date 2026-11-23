package main

// Fleet simulator policy (PREFLT-73).
//
// Every Preflight simulator lease, build and run uses one iPhone image and one
// iPad image on one iOS runtime. The control plane owns that policy: runners
// receive it in their registration response (`simulatorPolicy`) and the
// control plane stamps the concrete target onto every iOS simulator job it
// hands out (`payload.simulatorTarget`). Nothing here hard-codes a model or an
// iOS version, so moving the fleet to the next Xcode is a control-plane change.
//
// The runner's part:
//   - lease from SimLock by the policy model and OS, not by device class;
//   - pick (or create) only a simulator of the policy device type on the
//     policy runtime when SimLock is not in use;
//   - report its Xcode, runtimes and device types so the control plane can
//     refuse it iOS simulator work while it drifts from the policy.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

type simulatorPolicyDevice struct {
	SimlockClass         string `json:"simlockClass"`
	Name                 string `json:"name"`
	DeviceTypeIdentifier string `json:"deviceTypeIdentifier"`
}

type simulatorPolicy struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	Xcode    struct {
		MinimumVersion string `json:"minimumVersion"`
	} `json:"xcode"`
	Runtime struct {
		Identifier string `json:"identifier"`
		Version    string `json:"version"`
	} `json:"runtime"`
	Devices       map[string]simulatorPolicyDevice `json:"devices"`
	DefaultDevice string                           `json:"defaultDevice"`
}

// simulatorTarget is the concrete simulator for one job, as the control plane
// resolved it at claim time.
type simulatorTarget struct {
	PolicyID             string `json:"policyId"`
	Device               string `json:"device"`
	Name                 string `json:"name"`
	DeviceTypeIdentifier string `json:"deviceTypeIdentifier"`
	SimlockClass         string `json:"simlockClass"`
	RuntimeIdentifier    string `json:"runtimeIdentifier"`
	OSVersion            string `json:"osVersion"`
}

func (target *simulatorTarget) valid() bool {
	return target != nil && target.Name != "" && target.DeviceTypeIdentifier != "" &&
		target.RuntimeIdentifier != "" && target.OSVersion != ""
}

// defaultTarget is what a job gets when the control plane predates per-job
// targets but served the policy at registration.
func (policy *simulatorPolicy) defaultTarget() *simulatorTarget {
	if policy == nil {
		return nil
	}
	device, ok := policy.Devices[policy.DefaultDevice]
	if !ok {
		return nil
	}
	target := &simulatorTarget{
		PolicyID:             policy.ID,
		Device:               policy.DefaultDevice,
		Name:                 device.Name,
		DeviceTypeIdentifier: device.DeviceTypeIdentifier,
		SimlockClass:         device.SimlockClass,
		RuntimeIdentifier:    policy.Runtime.Identifier,
		OSVersion:            policy.Runtime.Version,
	}
	if !target.valid() {
		return nil
	}
	return target
}

// jobSimulatorTarget is the policy simulator an iOS simulator job must use,
// or nil for Android, physical-device work, or a control plane that serves no
// policy (which keeps the pre-policy behaviour rather than inventing one).
func jobSimulatorTarget(options runnerOnceOptions, job apiRunnerJob) *simulatorTarget {
	if jobPlatform(job) != "ios" || isPhysicalIOSDeviceDiscovery(job) || job.Payload.TargetClass == "device" {
		return nil
	}
	if target := job.Payload.SimulatorTarget; target.valid() {
		return target
	}
	return options.simulatorPolicy.defaultTarget()
}

// simlockLeaseDeviceArgs names what to lease. SimLock takes --device or
// --class, not both; the policy names the model and OS.
func simlockLeaseDeviceArgs(target *simulatorTarget) []string {
	if !target.valid() {
		return []string{"--class", "phone"}
	}
	return []string{"--device", target.Name, "--os", target.OSVersion}
}

// grantMatchesSimulatorTarget refuses a SimLock grant for any other model or
// OS: every lease in the fleet reports the policy device.
func grantMatchesSimulatorTarget(grant simlockGrant, target *simulatorTarget) error {
	if !target.valid() {
		return nil
	}
	if grant.Device.Spec.Model != target.Name || compareDottedVersions(grant.Device.Spec.OSVersion, target.OSVersion) != 0 {
		return fmt.Errorf("SimLock granted %s on iOS %s; the fleet simulator policy requires %s on iOS %s",
			grant.Device.Spec.Model, grant.Device.Spec.OSVersion, target.Name, target.OSVersion)
	}
	return nil
}

// ---------------------------------------------------------------------------
// toolchain probe and drift
// ---------------------------------------------------------------------------

type iosSimulatorRuntime struct {
	Identifier  string `json:"identifier"`
	Version     string `json:"version,omitempty"`
	IsAvailable *bool  `json:"isAvailable,omitempty"`
}

// iosSimulatorToolchain is reported as capabilities.iosSimulatorToolchain.
type iosSimulatorToolchain struct {
	XcodeVersion string                `json:"xcodeVersion,omitempty"`
	Runtimes     []iosSimulatorRuntime `json:"runtimes"`
	DeviceTypes  []string              `json:"deviceTypes"`
	ProbeError   string                `json:"probeError,omitempty"`
}

// commandOutput runs a tool and returns stdout; replaced by tests.
type commandOutput func(name string, args ...string) ([]byte, error)

func execCommandOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func probeIOSSimulatorToolchain(xcrunPath string, run commandOutput) iosSimulatorToolchain {
	if xcrunPath == "" {
		xcrunPath = "xcrun"
	}
	toolchain := iosSimulatorToolchain{Runtimes: []iosSimulatorRuntime{}, DeviceTypes: []string{}}
	problems := []string{}

	if output, err := run(xcrunPath, "xcodebuild", "-version"); err != nil {
		problems = append(problems, "xcodebuild -version: "+err.Error())
	} else {
		toolchain.XcodeVersion = parseXcodeVersion(string(output))
	}

	if output, err := run(xcrunPath, "simctl", "list", "runtimes", "-j"); err != nil {
		problems = append(problems, "simctl list runtimes: "+err.Error())
	} else {
		var parsed struct {
			Runtimes []struct {
				Identifier  string `json:"identifier"`
				Version     string `json:"version"`
				IsAvailable *bool  `json:"isAvailable"`
			} `json:"runtimes"`
		}
		if err := json.Unmarshal(output, &parsed); err != nil {
			problems = append(problems, "simctl list runtimes: "+err.Error())
		}
		for _, runtime := range parsed.Runtimes {
			if runtime.Identifier == "" {
				continue
			}
			toolchain.Runtimes = append(toolchain.Runtimes, iosSimulatorRuntime{Identifier: runtime.Identifier, Version: runtime.Version, IsAvailable: runtime.IsAvailable})
		}
	}

	if output, err := run(xcrunPath, "simctl", "list", "devicetypes", "-j"); err != nil {
		problems = append(problems, "simctl list devicetypes: "+err.Error())
	} else {
		var parsed struct {
			DeviceTypes []struct {
				Identifier string `json:"identifier"`
			} `json:"devicetypes"`
		}
		if err := json.Unmarshal(output, &parsed); err != nil {
			problems = append(problems, "simctl list devicetypes: "+err.Error())
		}
		for _, deviceType := range parsed.DeviceTypes {
			if deviceType.Identifier != "" {
				toolchain.DeviceTypes = append(toolchain.DeviceTypes, deviceType.Identifier)
			}
		}
	}

	if len(problems) > 0 {
		toolchain.ProbeError = strings.Join(problems, "; ")
	}
	return toolchain
}

// parseXcodeVersion reads "Xcode 27.2\nBuild version 27C5032e".
func parseXcodeVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if version, ok := strings.CutPrefix(strings.TrimSpace(line), "Xcode "); ok {
			return strings.TrimSpace(version)
		}
	}
	return ""
}

func (toolchain iosSimulatorToolchain) capability() map[string]any {
	runtimes := make([]any, 0, len(toolchain.Runtimes))
	for _, runtime := range toolchain.Runtimes {
		entry := map[string]any{"identifier": runtime.Identifier}
		if runtime.Version != "" {
			entry["version"] = runtime.Version
		}
		if runtime.IsAvailable != nil {
			entry["isAvailable"] = *runtime.IsAvailable
		}
		runtimes = append(runtimes, entry)
	}
	deviceTypes := make([]any, 0, len(toolchain.DeviceTypes))
	for _, deviceType := range toolchain.DeviceTypes {
		deviceTypes = append(deviceTypes, deviceType)
	}
	out := map[string]any{"runtimes": runtimes, "deviceTypes": deviceTypes}
	if toolchain.XcodeVersion != "" {
		out["xcodeVersion"] = toolchain.XcodeVersion
	}
	if toolchain.ProbeError != "" {
		out["probeError"] = toolchain.ProbeError
	}
	return out
}

// simulatorPolicyDrift lists how a host's toolchain falls short of the policy;
// empty means it can run the policy simulators. The control plane makes the
// same judgement from the reported toolchain and enforces it at claim; this
// copy is for the runner's own log and its heartbeat.
func simulatorPolicyDrift(policy *simulatorPolicy, toolchain iosSimulatorToolchain) []string {
	if policy == nil {
		return nil
	}
	drift := []string{}
	if toolchain.ProbeError != "" {
		drift = append(drift, "toolchain probe failed: "+toolchain.ProbeError)
	}
	if toolchain.XcodeVersion == "" {
		drift = append(drift, fmt.Sprintf("Xcode version unknown; %s+ required", policy.Xcode.MinimumVersion))
	} else if compareDottedVersions(toolchain.XcodeVersion, policy.Xcode.MinimumVersion) < 0 {
		drift = append(drift, fmt.Sprintf("Xcode %s < %s", toolchain.XcodeVersion, policy.Xcode.MinimumVersion))
	}
	runtimeFound := false
	for _, runtime := range toolchain.Runtimes {
		if runtime.Identifier != policy.Runtime.Identifier {
			continue
		}
		runtimeFound = true
		if runtime.IsAvailable != nil && !*runtime.IsAvailable {
			drift = append(drift, policy.Runtime.Identifier+" installed but unavailable")
		}
	}
	if !runtimeFound {
		drift = append(drift, policy.Runtime.Identifier+" not installed")
	}
	deviceTypes := map[string]bool{}
	for _, deviceType := range toolchain.DeviceTypes {
		deviceTypes[deviceType] = true
	}
	for _, key := range []string{"iphone", "ipad"} {
		device, ok := policy.Devices[key]
		if ok && !deviceTypes[device.DeviceTypeIdentifier] {
			drift = append(drift, device.DeviceTypeIdentifier+" not available")
		}
	}
	return drift
}

func simulatorPolicyCapability(policy *simulatorPolicy, drift []string) map[string]any {
	status := "compliant"
	reasons := make([]any, 0, len(drift))
	for _, reason := range drift {
		reasons = append(reasons, reason)
	}
	if len(drift) > 0 {
		status = "drift"
	}
	return map[string]any{"policyId": policy.ID, "status": status, "drift": reasons}
}

// applySimulatorPolicyToCapabilities records the host's verdict against the
// policy served at registration, and says so when it drifts.
func applySimulatorPolicyToCapabilities(capabilities map[string]any, policy *simulatorPolicy, toolchain *iosSimulatorToolchain, stdout io.Writer) {
	if policy == nil || toolchain == nil {
		return
	}
	drift := simulatorPolicyDrift(policy, *toolchain)
	capabilities["iosSimulatorPolicy"] = simulatorPolicyCapability(policy, drift)
	if len(drift) > 0 {
		fmt.Fprintf(stdout, "simulator policy %s drift: %s; this host will not claim iOS simulator work\n", policy.ID, strings.Join(drift, "; "))
	}
}

// compareDottedVersions compares "27.10" > "27.2" numerically; "27.2" = "27.2.0".
func compareDottedVersions(left, right string) int {
	parse := func(value string) []int {
		parts := strings.Split(strings.TrimSpace(value), ".")
		out := make([]int, len(parts))
		for index, part := range parts {
			out[index], _ = strconv.Atoi(part)
		}
		return out
	}
	a, b := parse(left), parse(right)
	for index := 0; index < len(a) || index < len(b); index++ {
		var x, y int
		if index < len(a) {
			x = a[index]
		}
		if index < len(b) {
			y = b[index]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// non-SimLock simulator selection
// ---------------------------------------------------------------------------

// filterSimctlInventoryToTarget keeps only simulators of the policy device
// type on the policy runtime, so the control plane never learns of (and the
// runner never picks) an ad-hoc model or iOS version.
func filterSimctlInventoryToTarget(content []byte, target *simulatorTarget) (json.RawMessage, int, error) {
	var parsed struct {
		Devices map[string][]map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil {
		return nil, 0, err
	}
	out := map[string][]map[string]any{}
	count := 0
	for runtime, devices := range parsed.Devices {
		if runtime != target.RuntimeIdentifier {
			continue
		}
		for _, device := range devices {
			if deviceType, _ := device["deviceTypeIdentifier"].(string); deviceType == target.DeviceTypeIdentifier {
				out[runtime] = append(out[runtime], device)
				count++
			}
		}
	}
	marshaled, err := json.Marshal(map[string]any{"devices": out})
	if err != nil {
		return nil, 0, err
	}
	return json.RawMessage(marshaled), count, nil
}

// createPolicySimulator creates the policy device on this host when none
// exists yet. It needs the policy runtime installed; a host without it is
// already drifting and the control plane does not route it this job.
func createPolicySimulator(xcrunPath string, target *simulatorTarget, run commandOutput) error {
	if xcrunPath == "" {
		xcrunPath = "xcrun"
	}
	if _, err := run(xcrunPath, "simctl", "create", target.Name, target.DeviceTypeIdentifier, target.RuntimeIdentifier); err != nil {
		return fmt.Errorf("create %s (%s) on %s: %w", target.Name, target.DeviceTypeIdentifier, target.RuntimeIdentifier, err)
	}
	return nil
}

// loadPolicySimctlInventory returns the host's simulators of the policy
// device and runtime, creating one first if there are none.
func loadPolicySimctlInventory(options runnerOnceOptions, target *simulatorTarget, run commandOutput) (json.RawMessage, error) {
	content, err := loadSimctlInventory(options)
	if err != nil {
		return nil, err
	}
	filtered, count, err := filterSimctlInventoryToTarget(content, target)
	if err != nil {
		return nil, fmt.Errorf("filter simctl inventory to the simulator policy: %w", err)
	}
	if count > 0 {
		return filtered, nil
	}
	if strings.TrimSpace(options.simulatorUDID) != "" {
		return nil, fmt.Errorf("pinned simulator %s is not a %s on %s, which the fleet simulator policy requires", options.simulatorUDID, target.Name, target.RuntimeIdentifier)
	}
	if options.simctlJSON != "" {
		return nil, fmt.Errorf("simctl inventory has no %s on %s", target.Name, target.RuntimeIdentifier)
	}
	if err := createPolicySimulator(options.xcrunPath, target, run); err != nil {
		return nil, err
	}
	content, err = loadSimctlInventory(options)
	if err != nil {
		return nil, err
	}
	filtered, count, err = filterSimctlInventoryToTarget(content, target)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, fmt.Errorf("created %s but simctl does not list it on %s", target.Name, target.RuntimeIdentifier)
	}
	return filtered, nil
}

// policySimulatorTargets keeps the reported targets whose simulator is the
// policy device on the policy runtime, judged from this host's simctl
// inventory (the control plane's target list may still hold older devices).
func policySimulatorTargets(options runnerOnceOptions, target *simulatorTarget, targets []apiTarget) []apiTarget {
	content, err := loadSimctlInventory(options)
	if err != nil {
		return nil
	}
	filtered, _, err := filterSimctlInventoryToTarget(content, target)
	if err != nil {
		return nil
	}
	var parsed struct {
		Devices map[string][]struct {
			UDID string `json:"udid"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(filtered, &parsed); err != nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, devices := range parsed.Devices {
		for _, device := range devices {
			allowed[strings.ToLower(device.UDID)] = true
		}
	}
	out := []apiTarget{}
	for _, candidate := range targets {
		if allowed[strings.ToLower(strings.TrimSpace(candidate.ProviderIdentity))] {
			out = append(out, candidate)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// preflight simulator-policy
// ---------------------------------------------------------------------------

func runSimulatorPolicy(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	jsonOut := false
	ctx := newBuildOpsContext()
	apiURL := ctx.apiURL
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--help", "-h":
			fmt.Fprintln(stdout, "Usage: preflight simulator-policy [--json] [--api-url <url>]")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Print the fleet-wide iOS simulator target every Preflight build and run uses.")
			return 0
		case "--json":
			jsonOut = true
		case "--api-url":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "--api-url requires a value")
				return 2
			}
			apiURL = args[index+1]
			index++
		default:
			fmt.Fprintf(stderr, "unknown simulator-policy flag %q\n", args[index])
			return 2
		}
	}
	data, err := getPreflightJSON(client, runnerEndpoint(apiURL, "/api/preflight/v1/simulator-policy"), "")
	if err != nil {
		fmt.Fprintf(stderr, "read simulator policy: %v\n", err)
		return 1
	}
	var body struct {
		SimulatorPolicy *simulatorPolicy `json:"simulatorPolicy"`
	}
	if err := decodeEnvelopeData(data, &body); err != nil || body.SimulatorPolicy == nil {
		fmt.Fprintf(stderr, "Preflight did not return a simulator policy (%v)\n", err)
		return 1
	}
	policy := body.SimulatorPolicy
	if jsonOut {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(policy); err != nil {
			fmt.Fprintf(stderr, "write simulator policy: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "policy   %s\n", policy.ID)
	fmt.Fprintf(stdout, "xcode    %s+\n", policy.Xcode.MinimumVersion)
	fmt.Fprintf(stdout, "runtime  iOS %s (%s)\n", policy.Runtime.Version, policy.Runtime.Identifier)
	for _, key := range []string{"iphone", "ipad"} {
		device, ok := policy.Devices[key]
		if !ok {
			continue
		}
		marker := ""
		if key == policy.DefaultDevice {
			marker = " (default)"
		}
		fmt.Fprintf(stdout, "%-8s %s (%s)%s\n", key, device.Name, device.DeviceTypeIdentifier, marker)
	}
	return 0
}

// probeLocalSimulatorToolchain is the capability probe for this host; nil on
// a host without the iOS platform. A variable so tests do not run Xcode.
var probeLocalSimulatorToolchain = func(options runnerOnceOptions, platforms []string) *iosSimulatorToolchain {
	for _, platform := range platforms {
		if platform == "ios" {
			toolchain := probeIOSSimulatorToolchain(options.xcrunPath, execCommandOutput)
			return &toolchain
		}
	}
	return nil
}
