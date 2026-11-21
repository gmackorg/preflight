package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A grant is parsed once at the CLI boundary. Only documented environment
// fields are accepted; a daemon response cannot replace PATH or credentials.
type simlockGrant struct {
	Lease struct {
		ID       string `json:"id"`
		Deadline int64  `json:"ttlDeadline"`
	} `json:"lease"`
	Device struct {
		Address  string `json:"address"`
		Physical bool   `json:"physical"`
		Spec     struct {
			Platform  string `json:"platform"`
			Model     string `json:"model"`
			OSVersion string `json:"osVersion"`
		} `json:"spec"`
	} `json:"device"`
	Environment struct {
		IOSDeviceSet string `json:"SIMLOCK_IOS_DEVICE_SET"`
		ADBPort      string `json:"ANDROID_ADB_SERVER_PORT"`
	} `json:"environment"`
}

type simlockRunnerLease struct {
	grant      simlockGrant
	workflowID string
	command    *exec.Cmd
	done       chan struct{}
	closeOnce  sync.Once
	shimDir    string
}

func simlockDeviceJob(job apiRunnerJob) bool {
	if job.Payload.TargetClass == "device" || job.Payload.DeviceProvider == "cloud" || isPhysicalIOSDeviceDiscovery(job) {
		return false
	}
	switch job.Kind {
	case "device.discover", "simulator.open", "simulator.install", "dev_session.open", "maestro.run":
		return true
	default:
		return false
	}
}

func parseSimlockGrant(data []byte, platform string) (simlockGrant, error) {
	var grant simlockGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return grant, fmt.Errorf("decode SimLock grant: %w", err)
	}
	if grant.Lease.ID == "" || grant.Device.Address == "" || grant.Device.Spec.Platform != platform || grant.Device.Physical || grant.Lease.Deadline <= time.Now().UnixMilli() {
		return grant, fmt.Errorf("SimLock returned an invalid, expired, or incompatible grant")
	}
	if grant.Environment.IOSDeviceSet != "" && !filepath.IsAbs(grant.Environment.IOSDeviceSet) {
		return grant, fmt.Errorf("SimLock device set must be absolute")
	}
	if platform == "android" {
		port, err := strconv.Atoi(grant.Environment.ADBPort)
		if err != nil || port < 1 || port > 65535 {
			return grant, fmt.Errorf("SimLock grant is missing a valid isolated ADB server port")
		}
		if _, err := simlockAndroidMaestroArgs(grant.Device.Address); err != nil {
			return grant, err
		}
	}
	return grant, nil
}

// The holder renews for as long as this process lives. --local deliberately
// avoids a gateway lease: native builds and Metro need a device on this host.
// Gateway/T3 leases are charged against the same worker capacity.
func acquireSimlockRunnerLease(options runnerOnceOptions, job apiRunnerJob, output io.Writer, cancelled func() (bool, error)) (*simlockRunnerLease, error) {
	binary, err := exec.LookPath("simlock")
	if err != nil {
		return nil, fmt.Errorf("--simlock requires the installed SimLock CLI: %w", err)
	}
	args := []string{"--local", "lease", "--platform", jobPlatform(job), "--class", "phone", "--mode", "full", "--timeout", "4m", "--bind-pid", strconv.Itoa(os.Getpid()), "--meta", "preflight.workflowId=" + job.WorkflowID}
	command := exec.Command(binary, args...)
	// A service gets its own identity, independent of any agent invoking it.
	command.Env = append(os.Environ(), "SIMLOCK_AGENT_ID=preflight:"+options.hostIdentity+":"+strconv.Itoa(os.Getpid())+":"+job.WorkflowID)
	command.Stderr = output
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	lease := &simlockRunnerLease{command: command, workflowID: job.WorkflowID, done: make(chan struct{})}
	type grantRead struct {
		data []byte
		err  error
	}
	read := make(chan grantRead, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		if scanner.Scan() {
			read <- grantRead{data: append([]byte(nil), scanner.Bytes()...)}
		} else {
			scanErr := scanner.Err()
			if scanErr == nil {
				scanErr = fmt.Errorf("SimLock exited before granting a device")
			}
			read <- grantRead{err: scanErr}
		}
		_, _ = io.Copy(io.Discard, pipe)
		_ = command.Wait()
		close(lease.done)
	}()
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case result := <-read:
			if result.err != nil {
				lease.close()
				return nil, result.err
			}
			grant, err := parseSimlockGrant(result.data, jobPlatform(job))
			if err != nil {
				lease.close()
				return nil, err
			}
			lease.grant = grant
			fmt.Fprintf(output, "SimLock leased %s %s for workflow %s\n", grant.Lease.ID, grant.Device.Address, job.WorkflowID)
			return lease, nil
		case <-ticker.C:
			if cancelled != nil {
				stop, err := cancelled()
				if stop || err != nil {
					lease.close()
					if err != nil {
						return nil, err
					}
					return nil, errCommandCancelled
				}
			}
		case <-timer.C:
			lease.close()
			return nil, fmt.Errorf("timed out acquiring a SimLock device")
		}
	}
}

func (lease *simlockRunnerLease) close() {
	lease.closeOnce.Do(func() {
		_ = lease.command.Process.Signal(syscall.SIGTERM)
		select {
		case <-lease.done:
		case <-time.After(10 * time.Second):
			_ = lease.command.Process.Kill()
			<-lease.done
		}
		if lease.shimDir != "" {
			_ = os.RemoveAll(lease.shimDir)
		}
	})
}

func (lease *simlockRunnerLease) alive() error {
	select {
	case <-lease.done:
		return fmt.Errorf("SimLock lease holder exited; device work stopped")
	default:
		return nil
	}
}

func (lease *simlockRunnerLease) validateJob(job apiRunnerJob) error {
	if err := lease.alive(); err != nil {
		return err
	}
	if job.WorkflowID != lease.workflowID || jobPlatform(job) != lease.grant.Device.Spec.Platform {
		return fmt.Errorf("job is outside the held SimLock workflow/platform")
	}
	if job.Kind != "device.discover" && job.Payload.ProviderIdentity != lease.grant.Device.Address {
		return fmt.Errorf("job device does not match the held SimLock lease; rediscover before resuming")
	}
	return nil
}

func simlockShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (lease *simlockRunnerLease) configure(options *runnerOnceOptions) (func(), error) {
	binary, err := exec.LookPath("simlock")
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "preflight-simlock-")
	if err != nil {
		return nil, err
	}
	lease.shimDir = dir
	if err := os.MkdirAll(filepath.Join(dir, "android", "avd"), 0700); err != nil {
		return nil, err
	}
	identity := "preflight:" + options.hostIdentity + ":" + strconv.Itoa(os.Getpid()) + ":" + lease.workflowID
	prefix := "#!/bin/sh\nexport PATH=" + simlockShellQuote(os.Getenv("PATH")) + "\nexport SIMLOCK_AGENT_ID=" + simlockShellQuote(identity) + "\nexec " + simlockShellQuote(binary) + " --local "
	scripts := map[string]string{
		"adb": prefix + "adb --lease " + simlockShellQuote(lease.grant.Lease.ID) + " \"$@\"\n",
	}
	if lease.grant.Device.Spec.Platform == "ios" {
		realXcrun, err := exec.LookPath(options.xcrunPath)
		if err != nil {
			return nil, err
		}
		scripts["xcrun"] = "#!/bin/sh\nif [ \"${1:-}\" = simctl ]; then\nshift\nexport PATH=" + simlockShellQuote(os.Getenv("PATH")) + "\nexport SIMLOCK_AGENT_ID=" + simlockShellQuote(identity) + "\nexec " + simlockShellQuote(binary) + " --local simctl --lease " + simlockShellQuote(lease.grant.Lease.ID) + " \"$@\"\nfi\nexec " + simlockShellQuote(realXcrun) + " \"$@\"\n"
		if lease.grant.Environment.IOSDeviceSet != "" {
			realBuild, err := exec.LookPath("xcodebuild")
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			version, err := exec.CommandContext(ctx, realBuild, "-version").Output()
			var major int
			if err != nil {
				return nil, fmt.Errorf("read Xcode version: %w", err)
			}
			if _, err := fmt.Sscanf(string(version), "Xcode %d", &major); err != nil || major < 27 {
				return nil, fmt.Errorf("SimLock isolated iOS validation requires Xcode 27 or newer")
			}
			scripts["xcodebuild"] = "#!/bin/sh\nexec " + simlockShellQuote(realBuild) + " " + simlockShellQuote("-DVTSimulatorSetLocation="+lease.grant.Environment.IOSDeviceSet) + " \"$@\"\n"
		}
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			return nil, err
		}
	}
	values := map[string]string{"PATH": dir + string(os.PathListSeparator) + os.Getenv("PATH")}
	if port := lease.grant.Environment.ADBPort; port != "" {
		values["ANDROID_ADB_SERVER_PORT"] = port
		values["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:" + port
	}
	undo := make([]func(), 0, len(values))
	restore := func() {
		for _, f := range undo {
			f()
		}
	}
	for key, value := range values {
		old, present := os.LookupEnv(key)
		undo = append(undo, func() {
			if present {
				_ = os.Setenv(key, old)
			} else {
				_ = os.Unsetenv(key)
			}
		})
		if err := os.Setenv(key, value); err != nil {
			restore()
			return nil, err
		}
	}
	options.simulatorUDID = lease.grant.Device.Address
	if lease.grant.Device.Spec.Platform == "ios" {
		options.xcrunPath = filepath.Join(dir, "xcrun")
	} else {
		options.adbPath = filepath.Join(dir, "adb")
	}
	return restore, nil
}

// Maestro 2.6's device discovery uses ADB port 5037 even when the environment
// selects another server. Its direct-device route (--host/--port) avoids that
// global discovery. An emulator's ADB endpoint is its console serial port + 1.
func simlockAndroidMaestroArgs(address string) ([]string, error) {
	if !strings.HasPrefix(address, "emulator-") {
		return nil, fmt.Errorf("SimLock Android grant must name a local emulator")
	}
	port, err := strconv.Atoi(strings.TrimPrefix(address, "emulator-"))
	if err != nil || port < 1 || port >= 65535 {
		return nil, fmt.Errorf("invalid SimLock emulator console port")
	}
	return []string{"--platform", "android", "--host", "127.0.0.1", "--port", strconv.Itoa(port + 1)}, nil
}

func reportSimlockDiscoveryTargets(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData) (runnerTargetsData, error) {
	lease := options.simlockLease
	if err := lease.alive(); err != nil {
		return runnerTargetsData{}, err
	}
	grant := lease.grant
	var payload map[string]any
	var endpoint string
	if grant.Device.Spec.Platform == "android" {
		endpoint = "android-emulators"
		payload = map[string]any{"adbDevicesOutput": "List of devices attached\n" + grant.Device.Address + " device model:" + strings.ReplaceAll(grant.Device.Spec.Model, " ", "_") + "\n"}
	} else {
		endpoint = "ios-simulators"
		runtime := "com.apple.CoreSimulator.SimRuntime.iOS-" + strings.ReplaceAll(grant.Device.Spec.OSVersion, ".", "-")
		payload = map[string]any{"simctlInventory": map[string]any{"devices": map[string]any{runtime: []map[string]any{{"udid": grant.Device.Address, "name": grant.Device.Spec.Model, "state": "Booted", "isAvailable": true}}}}}
	}
	data, err := postPreflightJSON(client, runnerEndpoint(options.apiURL, "/api/preflight/v1/runners/"+registration.Runner.ID+"/targets/"+endpoint), registration.Token, payload)
	if err != nil {
		return runnerTargetsData{}, err
	}
	var targets runnerTargetsData
	if err := decodeEnvelopeData(data, &targets); err != nil {
		return targets, err
	}
	// A response containing stale/foreign inventory never becomes selectable.
	var owned []apiTarget
	for _, target := range targets.Targets {
		if target.ProviderIdentity == grant.Device.Address {
			owned = append(owned, target)
		}
	}
	targets.Targets = owned
	return targets, nil
}

// An ephemeral lease is no longer a ready fleet target after this sequence.
func clearSimlockDiscoveryTargets(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, output io.Writer) {
	endpoint := "ios-simulators"
	payload := map[string]any{"simctlInventory": map[string]any{"devices": map[string]any{}}}
	if options.simlockLease.grant.Device.Spec.Platform == "android" {
		endpoint = "android-emulators"
		payload = map[string]any{"adbDevicesOutput": "List of devices attached\n"}
	}
	_, err := postPreflightJSON(client, runnerEndpoint(options.apiURL, "/api/preflight/v1/runners/"+registration.Runner.ID+"/targets/"+endpoint), registration.Token, payload)
	if err != nil {
		fmt.Fprintf(output, "warning: failed to retire SimLock target inventory: %v\n", err)
	}
}

func completeSimlockFailure(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, failure error) error {
	status := "failed"
	if failure == errCommandCancelled {
		status = "cancelled"
	}
	return completeRunnerJob(client, options, registration, job, map[string]any{"status": status, "failure": map[string]any{"code": "simlock_lease_unavailable", "message": failure.Error()}})
}

// Maestro enumerates Android ports even for an explicit iOS --device. Prevent
// that process from connecting to any emulator's ADB/console endpoint. The
// Xcode/iOS driver ports stay available. This is applied only to Maestro.
func isolateSimlockIOSMaestro(command *exec.Cmd) error {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		return fmt.Errorf("SimLock iOS validation requires sandbox-exec to isolate Android discovery: %w", err)
	}
	var profile strings.Builder
	profile.WriteString("(version 1)(allow default)(deny network-outbound")
	profile.WriteString(` (remote tcp "*:5037") (remote tcp "*:5038")`)
	for port := 5554; port <= 5683; port++ {
		fmt.Fprintf(&profile, ` (remote tcp "*:%d")`, port)
	}
	profile.WriteString(")")
	args := []string{"/usr/bin/sandbox-exec", "-p", profile.String(), command.Path}
	command.Args = append(args, command.Args[1:]...)
	command.Path = "/usr/bin/sandbox-exec"
	return nil
}

// runner once executes one chain in a dedicated process. Hold the environment
// and lease around that complete recursive chain, including development-lane
// handlers that dispatch their next job directly instead of handleRunnerClaim.
func runWithSimlockRunnerLease(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, output io.Writer, run func(runnerOnceOptions) error) error {
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, output, err)
	}
	options.workflowID = job.WorkflowID
	if options.workflowID == "" {
		return completeSimlockFailure(client, options, registration, job, fmt.Errorf("SimLock requires a workflow ID"))
	}
	if err := requireRunnerWorkflowClaimScope(options, registration); err != nil {
		return completeSimlockFailure(client, options, registration, job, err)
	}
	stopHeartbeat := startJobHeartbeat(client, options, registration, job)
	lease, err := acquireSimlockRunnerLease(options, job, output, runnerJobCancellationCheck(client, options, registration, job))
	stopHeartbeat()
	if err != nil {
		return completeSimlockFailure(client, options, registration, job, err)
	}
	defer lease.close()
	options.simlockLease = lease
	if err := lease.validateJob(job); err != nil {
		return completeSimlockFailure(client, options, registration, job, err)
	}
	undo, err := lease.configure(&options)
	if err != nil {
		return completeSimlockFailure(client, options, registration, job, err)
	}
	defer undo()
	defer clearSimlockDiscoveryTargets(client, options, registration, output)
	return run(options)
}

// Maestro analytics reads every .android/avd entry even with analytics off.
// A broken foreign AVD symlink must not prevent a leased-device run starting.
func simlockMaestroEnv(base []string, lease *simlockRunnerLease) []string {
	env := maestroCommandEnv(base)
	if lease == nil {
		return env
	}
	return upsertEnvValues(env, map[string]string{"ANDROID_USER_HOME": filepath.Join(lease.shimDir, "android"), "ANDROID_AVD_HOME": filepath.Join(lease.shimDir, "android", "avd")})
}
