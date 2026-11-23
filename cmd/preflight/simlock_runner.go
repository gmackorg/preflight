package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	key        string
	grant      simlockGrant
	workflowID string
	binary     string
	agentID    string
	ttl        time.Duration
	statePath  string
	done       chan struct{}
	stopRenew  chan struct{}
	lostOnce   sync.Once
	closeOnce  sync.Once
	finished   bool
	shimDir    string
}

func simlockDeviceJob(job apiRunnerJob) bool {
	if job.Payload.TargetClass == "device" || job.Payload.DeviceProvider == "cloud" || isPhysicalIOSDeviceDiscovery(job) {
		return false
	}
	switch job.Kind {
	case "device.discover", "dev_session.start", "simulator.open", "simulator.install", "dev_session.open", "maestro.run":
		return true
	default:
		return false
	}
}

// simlockWorkflowTerminalJob reports whether a job ends a workflow's use of its
// simulator. Work-order sequences end with maestro.run; a stopped dev session
// gives its device back too.
func simlockWorkflowTerminalJob(job apiRunnerJob) bool {
	return job.Kind == "maestro.run" || job.Kind == "dev_session.stop"
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

const defaultSimlockWorkflowTTL = 20 * time.Minute

// simlockWorkflowKey names a workflow's simulator on this host. Each `runner
// once` process handles part of a workflow; the device must outlive any one of
// them, so every process looks the workflow's lease up under this key and
// adopts it instead of provisioning a new simulator whose UDID the control
// plane has never seen. SimLock daemons are per host, so the key needs no host
// component.
func simlockWorkflowKey(workflowID, platform string) string {
	sum := sha256.Sum256([]byte("preflight-simlock\x00" + workflowID + "\x00" + platform))
	return hex.EncodeToString(sum[:16])
}

// simlockWorkflowLeaseID names one lease for a workflow. SimLock never reuses
// an ended lease's ID, so each new lease (a retry, or one after the TTL ran
// out) gets a fresh suffix.
func simlockWorkflowLeaseID(workflowID, platform string) string {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		suffix = []byte(strconv.FormatInt(time.Now().UnixNano(), 36))
	}
	return "pfwl_" + simlockWorkflowKey(workflowID, platform) + "_" + hex.EncodeToString(suffix)
}

func simlockWorkflowTTL() time.Duration {
	ttl := durationFromEnv("PREFLIGHT_SIMLOCK_WORKFLOW_TTL", defaultSimlockWorkflowTTL)
	if ttl < 2*time.Minute {
		return 2 * time.Minute
	}
	return ttl
}

func simlockLeaseStateDir() string {
	if dir := os.Getenv("PREFLIGHT_SIMLOCK_STATE_DIR"); dir != "" {
		return dir
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "preflight", "simlock-leases")
}

func simlockTTLArg(ttl time.Duration) string {
	return strconv.FormatInt(int64(ttl/time.Second), 10) + "s"
}

// runSimlock runs a short SimLock CLI command and returns its stdout.
func (lease *simlockRunnerLease) runSimlock(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, lease.binary, args...)
	command.Env = append(os.Environ(), "SIMLOCK_AGENT_ID="+lease.agentID)
	command.WaitDelay = time.Second
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		detail := strings.TrimSpace(stdout.String() + " " + stderr.String())
		return []byte(stdout.String()), fmt.Errorf("simlock %s: %w: %s", strings.Join(args, " "), err, detail)
	}
	return []byte(stdout.String()), nil
}

// simlockLeaseGone reports whether a SimLock error says the lease no longer
// exists, as opposed to a transient daemon or connection failure.
func simlockLeaseGone(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "LEASE_NOT_FOUND") || strings.Contains(text, "NOT_FOUND") || strings.Contains(text, "LEASE_EXPIRED") || strings.Contains(text, "not found")
}

func (lease *simlockRunnerLease) renew() error {
	_, err := lease.runSimlock(30*time.Second, "lease", "renew", lease.grant.Lease.ID, "--ttl", simlockTTLArg(lease.ttl))
	return err
}

func (lease *simlockRunnerLease) markLost() {
	lease.lostOnce.Do(func() { close(lease.done) })
}

// keepRenewed renews the workflow lease while this process works on it. A
// lease SimLock no longer knows stops device work; transient failures are
// retried until the lease's own deadline.
func (lease *simlockRunnerLease) keepRenewed() {
	interval := lease.ttl / 4
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-lease.stopRenew:
			return
		case <-lease.done:
			return
		case <-ticker.C:
			if err := lease.renew(); err != nil && simlockLeaseGone(err) {
				lease.markLost()
				return
			}
		}
	}
}

func (lease *simlockRunnerLease) saveState() error {
	if err := os.MkdirAll(filepath.Dir(lease.statePath), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(lease.grant)
	if err != nil {
		return err
	}
	temporary := lease.statePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, lease.statePath)
}

// adopt resumes a workflow lease an earlier runner process left held.
func (lease *simlockRunnerLease) adopt(platform string) (bool, error) {
	data, err := os.ReadFile(lease.statePath)
	if err != nil {
		return false, nil
	}
	grant, err := parseSimlockGrantState(data, platform)
	if err != nil || !strings.HasPrefix(grant.Lease.ID, "pfwl_"+lease.key+"_") {
		_ = os.Remove(lease.statePath)
		return false, nil
	}
	lease.grant = grant
	if err := lease.renew(); err != nil {
		if simlockLeaseGone(err) {
			_ = os.Remove(lease.statePath)
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// A workflow's lease is held across `runner once` processes: it is requested
// detached under a workflow-derived ID, renewed while a process works on the
// workflow, and released when the workflow's device work ends. Between
// processes the TTL keeps the simulator (and the UDID the control plane
// recorded at discovery) alive. --local deliberately avoids a gateway lease:
// native builds and Metro need a device on this host. Gateway/T3 leases are
// charged against the same worker capacity.
func acquireSimlockRunnerLease(options runnerOnceOptions, job apiRunnerJob, output io.Writer, cancelled func() (bool, error)) (*simlockRunnerLease, error) {
	binary, err := exec.LookPath("simlock")
	if err != nil {
		return nil, fmt.Errorf("--simlock requires the installed SimLock CLI: %w", err)
	}
	platform := jobPlatform(job)
	key := simlockWorkflowKey(job.WorkflowID, platform)
	lease := &simlockRunnerLease{
		key:        key,
		workflowID: job.WorkflowID,
		binary:     binary,
		// A service gets its own identity, independent of any agent invoking it.
		agentID:   "preflight:" + options.hostIdentity + ":" + job.WorkflowID,
		ttl:       simlockWorkflowTTL(),
		statePath: filepath.Join(simlockLeaseStateDir(), key+".json"),
		done:      make(chan struct{}),
		stopRenew: make(chan struct{}),
	}
	adopted, err := lease.adopt(platform)
	if err != nil {
		return nil, err
	}
	if adopted {
		fmt.Fprintf(output, "SimLock resumed %s %s for workflow %s\n", lease.grant.Lease.ID, lease.grant.Device.Address, job.WorkflowID)
		go lease.keepRenewed()
		return lease, nil
	}
	lease.grant = simlockGrant{}
	lease.grant.Lease.ID = simlockWorkflowLeaseID(job.WorkflowID, platform)
	grant, err := lease.requestDetached(platform, output, cancelled)
	if err != nil {
		return nil, err
	}
	lease.grant = grant
	if err := lease.saveState(); err != nil {
		lease.finished = true
		lease.close()
		return nil, fmt.Errorf("record SimLock workflow lease: %w", err)
	}
	fmt.Fprintf(output, "SimLock leased %s %s for workflow %s\n", grant.Lease.ID, grant.Device.Address, job.WorkflowID)
	go lease.keepRenewed()
	return lease, nil
}

func (lease *simlockRunnerLease) requestDetached(platform string, output io.Writer, cancelled func() (bool, error)) (simlockGrant, error) {
	args := []string{"--local", "lease", "--platform", platform, "--class", "phone", "--mode", "full", "--timeout", "4m", "--detach", "--ttl", simlockTTLArg(lease.ttl), "--lease-id", lease.grant.Lease.ID, "--meta", "preflight.workflowId=" + lease.workflowID}
	command := exec.Command(lease.binary, args...)
	command.Env = append(os.Environ(), "SIMLOCK_AGENT_ID="+lease.agentID)
	refusals := &simlockRefusalWriter{next: output}
	command.Stderr = refusals
	pipe, err := command.StdoutPipe()
	if err != nil {
		return simlockGrant{}, err
	}
	if err := command.Start(); err != nil {
		return simlockGrant{}, err
	}
	type grantRead struct {
		data []byte
		err  error
	}
	read := make(chan grantRead, 1)
	exited := make(chan struct{})
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
		close(exited)
	}()
	stop := func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			<-exited
		}
	}
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case result := <-read:
			if result.err != nil {
				stop()
				if refusal := refusals.refusal(); refusal != "" {
					return simlockGrant{}, fmt.Errorf("SimLock refused the lease: %s", refusal)
				}
				return simlockGrant{}, result.err
			}
			var refusal struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(result.data, &refusal) == nil && refusal.Error.Code != "" {
				stop()
				return simlockGrant{}, fmt.Errorf("SimLock %s: %s", refusal.Error.Code, refusal.Error.Message)
			}
			grant, err := parseSimlockGrant(result.data, platform)
			if err != nil {
				stop()
				// A detached grant is held even if this side rejects it.
				_, _ = lease.runSimlock(30*time.Second, "release", lease.grant.Lease.ID)
				return simlockGrant{}, err
			}
			// --detach exits once the grant is printed; the lease stays held.
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				_ = command.Process.Kill()
				<-exited
			}
			return grant, nil
		case <-ticker.C:
			if cancelled != nil {
				halt, err := cancelled()
				if halt || err != nil {
					stop()
					_, _ = lease.runSimlock(30*time.Second, "release", lease.grant.Lease.ID)
					if err != nil {
						return simlockGrant{}, err
					}
					return simlockGrant{}, errCommandCancelled
				}
			}
		case <-timer.C:
			stop()
			_, _ = lease.runSimlock(30*time.Second, "release", lease.grant.Lease.ID)
			return simlockGrant{}, fmt.Errorf("timed out acquiring a SimLock device")
		}
	}
}

// parseSimlockGrantState reads a grant saved for adoption. Its deadline is
// the one recorded at grant time; adoption renews before trusting it.
func parseSimlockGrantState(data []byte, platform string) (simlockGrant, error) {
	var grant simlockGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return grant, err
	}
	grant.Lease.Deadline = time.Now().Add(time.Minute).UnixMilli()
	return parseSimlockGrant(mustMarshalGrant(grant), platform)
}

func mustMarshalGrant(grant simlockGrant) []byte {
	data, _ := json.Marshal(grant)
	return data
}

// simlockRefusalWriter passes SimLock's stderr through and keeps the last
// structured error line, which is how the CLI reports a refused lease.
type simlockRefusalWriter struct {
	next io.Writer
	mu   sync.Mutex
	last string
}

func (w *simlockRefusalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	for _, line := range strings.Split(string(p), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), `{"error"`) {
			w.last = strings.TrimSpace(line)
		}
	}
	w.mu.Unlock()
	return w.next.Write(p)
}

func (w *simlockRefusalWriter) refusal() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

// finish marks the workflow's device work as over: close releases the lease
// instead of leaving it held for the workflow's next job.
func (lease *simlockRunnerLease) finish() {
	if lease != nil {
		lease.finished = true
	}
}

// close stops renewing. A finished workflow releases its lease and forgets
// it; otherwise the lease stays held, for its TTL, for the next process.
func (lease *simlockRunnerLease) close() {
	lease.closeOnce.Do(func() {
		close(lease.stopRenew)
		if lease.finished {
			if lease.binary != "" && lease.grant.Lease.ID != "" {
				if _, err := lease.runSimlock(30*time.Second, "release", lease.grant.Lease.ID); err == nil || simlockLeaseGone(err) {
					_ = os.Remove(lease.statePath)
				}
			}
			lease.markLost()
		}
		if lease.shimDir != "" {
			_ = os.RemoveAll(lease.shimDir)
		}
	})
}

func (lease *simlockRunnerLease) alive() error {
	select {
	case <-lease.done:
		return fmt.Errorf("SimLock lease ended; device work stopped")
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
	options.simlockLease.finish()
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
		lease.finish()
		return completeSimlockFailure(client, options, registration, job, err)
	}
	undo, err := lease.configure(&options)
	if err != nil {
		lease.finish()
		return completeSimlockFailure(client, options, registration, job, err)
	}
	defer undo()
	// The target stays advertised while the workflow holds its simulator, and
	// is retired only once the lease is given back.
	defer func() {
		if lease.finished {
			clearSimlockDiscoveryTargets(client, options, registration, output)
		}
	}()
	err = run(options)
	if err != nil {
		lease.finish()
	}
	return err
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
