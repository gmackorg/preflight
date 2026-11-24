package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func simlockTestGrant(t *testing.T, platform string) simlockGrant {
	t.Helper()
	data := `{"lease":{"id":"our-lease","ttlDeadline":4102444800000},"device":{"address":"device-udid","physical":false,"spec":{"platform":"ios","model":"iPhone 17","osVersion":"26.5"}},"environment":{}}`
	grant, err := parseSimlockGrant([]byte(data), "ios")
	if err != nil {
		t.Fatal(err)
	}
	if platform == "android" {
		grant.Device.Spec.Platform = "android"
		grant.Device.Address = "emulator-5580"
		grant.Device.Spec.Model = "Pixel 9"
		grant.Environment.ADBPort = "5038"
	}
	return grant
}

// fakeSimlockCLI installs a fake `simlock` that answers a detached lease with
// grantLine (nothing for "waiting"), records each invocation in dir/calls, and
// touches dir/released on `release`. A renew fails once dir/gone exists.
func fakeSimlockCLI(t *testing.T, dir string, grantLine string, waiting bool) {
	t.Helper()
	calls := filepath.Join(dir, "calls")
	released := filepath.Join(dir, "released")
	gone := filepath.Join(dir, "gone")
	leaseBody := "echo " + simlockShellQuote(grantLine) + "\nexit 0\n"
	if waiting {
		leaseBody = "while :; do sleep 0.1; done\n"
	}
	body := "#!/bin/sh\necho \"$*\" >> " + simlockShellQuote(calls) + "\n" +
		"if [ \"$1\" = --local ]; then shift; fi\n" +
		"case \"$1 $2\" in\n" +
		"'lease renew') if [ -e " + simlockShellQuote(gone) + " ]; then echo '{\"error\":{\"code\":\"LEASE_NOT_FOUND\"}}'; exit 1; fi; exit 0;;\n" +
		"esac\n" +
		"case \"$1\" in\n" +
		"release) touch " + simlockShellQuote(released) + "; exit 0;;\n" +
		"lease) " + leaseBody + ";;\n" +
		"esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "simlock"), []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_SIMLOCK_STATE_DIR", filepath.Join(dir, "state"))
}

func simlockCallCount(t *testing.T, dir, prefix string) int {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(dir, "calls"))
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}

func simlockReleased(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "released"))
	return err == nil
}

func simlockWorkflowGrantJSON(t *testing.T, platform, workflowID string) string {
	t.Helper()
	grant := simlockTestGrant(t, platform)
	grant.Lease.ID = "pfwl_" + simlockWorkflowKey(workflowID, platform) + "_000000000001"
	data, _ := json.Marshal(grant)
	return string(data)
}

func TestSimlockGrantBoundary(t *testing.T) {
	grant := simlockTestGrant(t, "ios")
	for _, change := range []func(*simlockGrant){
		func(g *simlockGrant) { g.Lease.ID = "" },
		func(g *simlockGrant) { g.Lease.Deadline = 1 },
		func(g *simlockGrant) { g.Device.Address = "" },
		func(g *simlockGrant) { g.Device.Physical = true },
		func(g *simlockGrant) { g.Device.Spec.Platform = "android" },
		func(g *simlockGrant) { g.Environment.IOSDeviceSet = "relative" },
	} {
		invalid := grant
		change(&invalid)
		data, _ := json.Marshal(invalid)
		if _, err := parseSimlockGrant(data, "ios"); err == nil {
			t.Fatalf("accepted invalid grant %s", data)
		}
	}
	for _, port := range []string{"", "0", "65536", "5038; touch /tmp/unsafe"} {
		invalid := simlockTestGrant(t, "android")
		invalid.Environment.ADBPort = port
		data, _ := json.Marshal(invalid)
		if _, err := parseSimlockGrant(data, "android"); err == nil {
			t.Fatalf("accepted invalid adb port %q", port)
		}
	}
}

func TestSimlockRejectsForeignJobsAndLostLease(t *testing.T) {
	lease := &simlockRunnerLease{grant: simlockTestGrant(t, "ios"), workflowID: "ours", done: make(chan struct{})}
	job := apiRunnerJob{WorkflowID: "ours", Kind: "simulator.open", Payload: runnerJobPayload{Platform: "ios", ProviderIdentity: "device-udid"}}
	if err := lease.validateJob(job); err != nil {
		t.Fatal(err)
	}
	job.Payload.ProviderIdentity = "foreign"
	if err := lease.validateJob(job); err == nil {
		t.Fatal("accepted foreign device")
	}
	job.Kind = "device.discover"
	job.WorkflowID = "foreign"
	if err := lease.validateJob(job); err == nil {
		t.Fatal("accepted foreign workflow")
	}
	job.WorkflowID = "ours"
	close(lease.done)
	if err := lease.validateJob(job); err == nil {
		t.Fatal("accepted lost lease")
	}
}

func TestSimlockDiscoveryOnlyPublishesAndSelectsGrantedTarget(t *testing.T) {
	for _, platform := range []string{"ios", "android"} {
		t.Run(platform, func(t *testing.T) {
			lease := &simlockRunnerLease{grant: simlockTestGrant(t, platform), done: make(chan struct{})}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Header.Get("Authorization") != "Bearer runner-token" {
					t.Error("missing runner auth")
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if requests == 1 && !strings.Contains(string(data), lease.grant.Device.Address) {
					t.Errorf("grant absent from discovery: %s", data)
				}
				if requests == 2 && strings.Contains(string(data), lease.grant.Device.Address) {
					t.Error("released target remains advertised")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"targets": []map[string]string{{"id": "ours", "providerIdentity": lease.grant.Device.Address}, {"id": "foreign", "providerIdentity": "foreign"}}}})
			}))
			defer server.Close()
			options := runnerOnceOptions{apiURL: server.URL, simlockLease: lease}
			registration := runnerRegistrationData{Runner: apiRunner{ID: "runner"}, Token: "runner-token"}
			targets, err := reportDiscoveryTargets(server.Client(), options, registration, apiRunnerJob{})
			if err != nil {
				t.Fatal(err)
			}
			if len(targets.Targets) != 1 || targets.Targets[0].ID != "ours" {
				t.Fatalf("selected foreign inventory: %#v", targets)
			}
			clearSimlockDiscoveryTargets(server.Client(), options, registration, io.Discard)
			if requests != 2 {
				t.Fatalf("expected registration and retirement, got %d", requests)
			}
		})
	}
}

func TestSimlockAndroidMaestroNeverUsesDefaultADBDiscovery(t *testing.T) {
	args, err := simlockAndroidMaestroArgs("emulator-5580")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []string{"--platform", "android", "--host", "127.0.0.1", "--port", "5581"}) {
		t.Fatalf("unexpected direct device args: %v", args)
	}
	for _, address := range []string{"physical", "emulator-0", "emulator-65535", "emulator-123;echo"} {
		if _, err := simlockAndroidMaestroArgs(address); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}

func TestSimlockDetachedLeaseReleasesOnCancellationAndInvalidGrant(t *testing.T) {
	for _, mode := range []string{"invalid", "waiting", "valid"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			grantLine := simlockWorkflowGrantJSON(t, "ios", "workflow")
			if mode == "invalid" {
				grantLine = `{"bad":true}`
			}
			fakeSimlockCLI(t, dir, grantLine, mode == "waiting")
			job := apiRunnerJob{WorkflowID: "workflow", Payload: runnerJobPayload{Platform: "ios"}}
			lease, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "test"}, job, io.Discard, func() (bool, error) { return true, nil })
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid/cancelled lease accepted")
				}
				if !simlockReleased(dir) {
					t.Fatal("detached lease was not released after refusal")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(mustRead(t, filepath.Join(dir, "calls"))), "--detach") {
				t.Fatal("workflow lease was not requested detached")
			}
			lease.finish()
			lease.close()
			lease.close()
			if !simlockReleased(dir) {
				t.Fatal("finished workflow did not release its lease")
			}
			if lease.alive() == nil {
				t.Fatal("released lease still reads as alive")
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The regression behind "Invalid device" boots: a workflow's simulator must
// survive the end of the runner process that discovered it, and the next
// process must reuse it instead of provisioning a different UDID.
func TestSimlockWorkflowLeaseOutlivesProcessAndIsAdopted(t *testing.T) {
	dir := t.TempDir()
	fakeSimlockCLI(t, dir, simlockWorkflowGrantJSON(t, "ios", "wf"), false)
	job := apiRunnerJob{WorkflowID: "wf", Kind: "device.discover", Payload: runnerJobPayload{Platform: "ios"}}
	first, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "agent-1"}, job, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.close() // process ends between jobs, workflow not finished
	if simlockReleased(dir) {
		t.Fatal("lease released between a workflow's jobs")
	}
	job.Kind = "dev_session.start"
	job.Payload.ProviderIdentity = first.grant.Device.Address
	second, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "agent-2"}, job, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := simlockCallCount(t, dir, "--local lease"); got != 1 {
		t.Fatalf("next process provisioned a new device (%d lease requests)", got)
	}
	if second.grant.Device.Address != first.grant.Device.Address || second.validateJob(job) != nil {
		t.Fatal("next process did not adopt the workflow's simulator")
	}
	second.finish()
	second.close()
	if !simlockReleased(dir) {
		t.Fatal("finished workflow kept its lease")
	}
	if _, err := os.Stat(second.statePath); !os.IsNotExist(err) {
		t.Fatal("released lease left adoption state behind")
	}
}

func TestSimlockExpiredWorkflowLeaseIsReprovisioned(t *testing.T) {
	dir := t.TempDir()
	fakeSimlockCLI(t, dir, simlockWorkflowGrantJSON(t, "ios", "wf"), false)
	job := apiRunnerJob{WorkflowID: "wf", Kind: "device.discover", Payload: runnerJobPayload{Platform: "ios"}}
	first, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "test"}, job, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.close()
	if err := os.WriteFile(filepath.Join(dir, "gone"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "test"}, job, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if got := simlockCallCount(t, dir, "--local lease"); got != 2 {
		t.Fatalf("expired lease was not re-requested (%d lease requests)", got)
	}
}

func TestSimlockWorkflowLeaseIDsAreFreshAndValid(t *testing.T) {
	workflow := "pfw_8eee75a6-042b-43d2-adc5-48182ff3dea6"
	if simlockWorkflowKey(workflow, "ios") != simlockWorkflowKey(workflow, "ios") || simlockWorkflowKey(workflow, "ios") == simlockWorkflowKey(workflow, "android") {
		t.Fatal("workflow key is not a stable function of workflow and platform")
	}
	first, second := simlockWorkflowLeaseID(workflow, "ios"), simlockWorkflowLeaseID(workflow, "ios")
	// SimLock refuses an ended lease's ID (LEASE_ENDED), so a retry needs a new one.
	if first == second {
		t.Fatal("lease ID reused across requests")
	}
	pattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	if !pattern.MatchString(first) {
		t.Fatalf("lease ID %q breaks SimLock's ID pattern", first)
	}
}

func TestSimlockDevSessionStartRunsUnderTheWorkflowLease(t *testing.T) {
	job := apiRunnerJob{Kind: "dev_session.start", Payload: runnerJobPayload{Platform: "ios", Lane: "simulator", TargetClass: "simulator"}}
	if !simlockDeviceJob(job) {
		t.Fatal("dev_session.start boots the workflow simulator outside SimLock's device set")
	}
}

func TestSimlockToolShimsQuoteArgumentsAndRestoreEnvironment(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "simlock")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+simlockShellQuote(log)+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ADB_SERVER_SOCKET", "original")
	before := os.Getenv("PATH")
	lease := &simlockRunnerLease{grant: simlockTestGrant(t, "android"), workflowID: "quoted ' workflow", done: make(chan struct{})}
	defer func() { _ = os.RemoveAll(lease.shimDir) }()
	options := runnerOnceOptions{hostIdentity: "test"}
	undo, err := lease.configure(&options)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ADB_SERVER_SOCKET") != "tcp:127.0.0.1:5038" {
		t.Fatal("ADB server was not isolated")
	}
	cmd := exec.Command(options.adbPath, "-s", "emulator-5580", "install", "a file's.apk")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shim failed: %v %s", err, output)
	}
	content, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "--local\nadb\n--lease\nour-lease\n-s\nemulator-5580\ninstall\na file's.apk\n" {
		t.Fatalf("arguments lost quoting: %s", content)
	}
	undo()
	if os.Getenv("PATH") != before || os.Getenv("ADB_SERVER_SOCKET") != "original" {
		t.Fatal("environment was not restored")
	}
}

func TestSimlockCancellationStopsBeforeControlPlaneCall(t *testing.T) {
	done := make(chan struct{})
	close(done)
	check := runnerJobCancellationCheck(nil, runnerOnceOptions{simlockLease: &simlockRunnerLease{done: done}}, runnerRegistrationData{}, apiRunnerJob{})
	if _, err := check(); err == nil || !strings.Contains(err.Error(), "SimLock") {
		t.Fatal("lease loss did not stop work", err)
	}
}

func TestSimlockOnlyAllocatesForSimulatorDeviceJobs(t *testing.T) {
	for _, kind := range []string{"device.discover", "simulator.open", "maestro.run"} {
		job := apiRunnerJob{Kind: kind, Payload: runnerJobPayload{Platform: "ios", Lane: "simulator", TargetClass: "simulator"}}
		if !simlockDeviceJob(job) {
			t.Fatalf("simulator job ignored: %s", kind)
		}
		job.Payload.TargetClass = "device"
		job.Payload.Lane = "development"
		if simlockDeviceJob(job) {
			t.Fatalf("physical job allocated: %s", kind)
		}
	}
}

// Explicitly opted in on a configured worker. This exercises the actual CLI
// holder, isolated tooling and Maestro driver, without requiring an app build.
func TestSimlockLive(t *testing.T) {
	platform := os.Getenv("PREFLIGHT_SIMLOCK_LIVE")
	if platform == "" {
		t.Skip("set PREFLIGHT_SIMLOCK_LIVE=ios or android on a configured worker")
	}
	if platform != "ios" && platform != "android" {
		t.Fatal("invalid live platform")
	}
	root := t.TempDir()
	if keep := os.Getenv("PREFLIGHT_SIMLOCK_LIVE_ROOT"); keep != "" {
		// Keep Maestro's logs and artifacts for diagnosis.
		root = keep
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	job := apiRunnerJob{ID: "simlock-live", WorkflowID: "PREFLT-65-live", Kind: "device.discover", Payload: runnerJobPayload{Platform: platform, Lane: "simulator", TargetClass: "simulator"}}
	options := runnerOnceOptions{hostIdentity: "preflight-live-check", workspaceRoot: root, xcrunPath: "xcrun", adbPath: "adb"}
	t.Setenv("PREFLIGHT_SIMLOCK_STATE_DIR", filepath.Join(root, "simlock-state"))
	discovered, err := acquireSimlockRunnerLease(options, job, os.Stdout, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The discovering process ends; the next one must get the same simulator.
	discovered.close()
	lease, err := acquireSimlockRunnerLease(options, job, os.Stdout, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		lease.finish()
		lease.close()
	}()
	if lease.grant.Device.Address != discovered.grant.Device.Address {
		t.Fatalf("workflow simulator changed between processes: %s then %s", discovered.grant.Device.Address, lease.grant.Device.Address)
	}
	options.simlockLease = lease
	undo, err := lease.configure(&options)
	if err != nil {
		t.Fatal(err)
	}
	defer undo()
	if platform == "ios" {
		// The boot path dev_session.start takes, through the lease's xcrun shim.
		if err := bootIOSSimulator(options, lease.grant.Device.Address, nil); err != nil {
			t.Fatalf("boot leased simulator: %v", err)
		}
	}
	appID := "com.android.settings"
	if platform == "ios" {
		appID = "com.apple.Preferences"
		job.Payload.SourceBinding.IOSBundleID = appID
	} else {
		job.Payload.SourceBinding.AndroidPackage = appID
	}
	flow := filepath.Join(root, "settings.yaml")
	if err := os.WriteFile(flow, []byte("appId: "+appID+"\n---\n- launchApp\n- assertVisible: Settings\n"), 0600); err != nil {
		t.Fatal(err)
	}
	job.Kind = "maestro.run"
	job.Payload.ProviderIdentity = lease.grant.Device.Address
	job.Payload.SourceBinding.WorkspaceRoot = root
	artifacts, err := runMaestroSmoke(options, job, lease.grant.Device.Address, flow, func() (bool, error) { return false, lease.alive() })
	if err != nil {
		data, _ := os.ReadFile(artifacts.LogPath)
		t.Fatalf("Maestro on leased device: %v\n%s", err, data)
	}
	t.Logf("SimLock %s %s Maestro report: %s", lease.grant.Lease.ID, lease.grant.Device.Address, artifacts.ReportPath)
}

func TestSimlockIOSMaestroCannotProbeAndroidPorts(t *testing.T) {
	command := exec.Command("maestro", "--platform", "ios", "--device", "ours", "test", "flow.yaml")
	if err := isolateSimlockIOSMaestro(command); err != nil {
		t.Skip(err)
	}
	if command.Path != "/usr/bin/sandbox-exec" || !strings.Contains(command.Args[2], `(remote tcp "*:5037")`) || !strings.Contains(command.Args[2], `(remote tcp "*:5683")`) {
		t.Fatalf("Android discovery was not blocked: %v", command.Args)
	}
	if command.Args[len(command.Args)-1] != "flow.yaml" {
		t.Fatal("Maestro arguments changed")
	}
}

func TestSimlockWorkflowRetainsLeaseScopeAndReleasesOnRunError(t *testing.T) {
	dir := t.TempDir()
	fakeSimlockCLI(t, dir, simlockWorkflowGrantJSON(t, "android", "ours"), false)
	released := filepath.Join(dir, "released")
	retired := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/claim") {
			var body struct {
				WorkflowID string `json:"workflowId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.WorkflowID != "ours" {
				t.Error("next job not workflow scoped")
			}
			_, _ = w.Write([]byte(`{"data":{"job":{"id":"next","workflowId":"ours","kind":"maestro.run","payload":{"platform":"android","lane":"simulator","providerIdentity":"emulator-5580"}}}}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/targets/android-emulators") {
			retired = true
			_, _ = w.Write([]byte(`{"data":{"targets":[]}}`))
			return
		}
		t.Errorf("unexpected request %s", r.URL.Path)
	}))
	defer server.Close()
	job := apiRunnerJob{ID: "discover", WorkflowID: "ours", Kind: "device.discover", Payload: runnerJobPayload{Platform: "android", Lane: "simulator", TargetClass: "simulator", SourceBinding: runnerJobSourceBinding{WorkspaceRoot: dir}}}
	options := runnerOnceOptions{apiURL: server.URL, workspaceRoot: dir, hostIdentity: "test"}
	err := runWithSimlockRunnerLease(server.Client(), options, scopedRegistration(t), job, io.Discard, func(scoped runnerOnceOptions) error {
		if scoped.simlockLease == nil || scoped.simulatorUDID != "emulator-5580" {
			t.Error("lease did not span workflow")
		}
		if _, err := claimRunnerJob(server.Client(), scoped, scopedRegistration(t)); err != nil {
			t.Fatal(err)
		}
		return io.EOF
	})
	if err != io.EOF {
		t.Fatal("run error was not preserved", err)
	}
	if !retired {
		t.Error("terminal path did not retire target inventory")
	}
	if _, err := os.Stat(released); err != nil {
		t.Error("terminal path did not release lease", err)
	}
}

func TestSimlockMaestroDoesNotReadForeignAVDMetadata(t *testing.T) {
	lease := &simlockRunnerLease{shimDir: t.TempDir()}
	env := simlockMaestroEnv([]string{"ANDROID_USER_HOME=/broken-foreign", "ANDROID_AVD_HOME=/another-foreign", "KEEP=present"}, lease)
	values := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	if values["ANDROID_USER_HOME"] != filepath.Join(lease.shimDir, "android") || values["ANDROID_AVD_HOME"] != filepath.Join(lease.shimDir, "android", "avd") || values["KEEP"] != "present" {
		t.Fatalf("Maestro inherited foreign AVD state: %v", env)
	}
	untouched := simlockMaestroEnv([]string{"ANDROID_USER_HOME=/physical"}, nil)
	if !strings.Contains(strings.Join(untouched, "\n"), "ANDROID_USER_HOME=/physical") {
		t.Fatal("non-SimLock environment was changed")
	}
}

func TestSimlockDiscoveryLeaseSpansNextClaim(t *testing.T) {
	// The development-lane dispatcher went away with eas.build.dev (PREFLT-66);
	// discovery continues through the generic claim handler only.
	dir := t.TempDir()
	fakeSimlockCLI(t, dir, simlockWorkflowGrantJSON(t, "android", "ours"), false)
	claimed := false
	retired := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/targets/android-emulators"):
			var body struct {
				ADB string `json:"adbDevicesOutput"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !strings.Contains(body.ADB, "emulator-5580") {
				retired = true
			}
			_, _ = w.Write([]byte(`{"data":{"targets":[{"id":"ours","providerIdentity":"emulator-5580","kind":"android_emulator","platform":"android","availability":"available"}]}}`))
		case strings.HasSuffix(r.URL.Path, "/targets/ours/lock"):
			_, _ = w.Write([]byte(`{"data":{"target":{"id":"ours","displayName":"Pixel 9"}}}`))
		case strings.HasSuffix(r.URL.Path, "/claim"):
			claimed = true
			if simlockReleased(dir) {
				t.Error("discovery released SimLock before the next job claim")
			}
			var body struct {
				WorkflowID string `json:"workflowId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.WorkflowID != "ours" {
				t.Error("continuation lost SimLock workflow scope")
			}
			_, _ = w.Write([]byte(`{"data":null}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	job := apiRunnerJob{ID: "discover", WorkflowID: "ours", Kind: "device.discover", Payload: runnerJobPayload{Platform: "android", Lane: "simulator", TargetClass: "simulator", SourceBinding: runnerJobSourceBinding{WorkspaceRoot: dir}}}
	options := runnerOnceOptions{simlock: true, apiURL: server.URL, workspaceRoot: dir, hostIdentity: "test"}
	if err := handleRunnerClaim(server.Client(), options, scopedRegistration(t), job, io.Discard, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Error("discovery did not continue")
	}
	// No next job yet (not queued, or this host declined it): the workflow's
	// simulator and its advertised target must survive for whoever claims it.
	if simlockReleased(dir) {
		t.Error("lease released while the workflow still needs its simulator")
	}
	if retired {
		t.Error("target retired while the workflow still holds its simulator")
	}
}

func TestSimlockLeaseEndsOnFailedOrFinalJobOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	for _, tc := range []struct {
		kind, status string
		finished     bool
	}{
		{"device.discover", "succeeded", false},
		{"dev_session.start", "succeeded", false},
		{"simulator.open", "succeeded", false},
		{"dev_session.start", "failed", true},
		{"simulator.open", "cancelled", true},
		{"maestro.run", "succeeded", true},
		{"maestro.run", "failed", true},
	} {
		lease := &simlockRunnerLease{workflowID: "wf", done: make(chan struct{}), stopRenew: make(chan struct{})}
		options := runnerOnceOptions{apiURL: server.URL, simlockLease: lease}
		job := apiRunnerJob{ID: "job", WorkflowID: "wf", Kind: tc.kind}
		if err := completeRunnerJob(server.Client(), options, scopedRegistration(t), job, map[string]any{"status": tc.status}); err != nil {
			t.Fatal(err)
		}
		if lease.finished != tc.finished {
			t.Errorf("%s %s: finished=%v, want %v", tc.kind, tc.status, lease.finished, tc.finished)
		}
	}
}

// A host below its disk floor must still finish a workflow whose simulator it
// holds; otherwise the lease expires under a half-run workflow (seen on
// gmacko-mini, pfw_58f4439b: dev session started, simulator.open never claimed).
func TestSimlockHeldWorkflowContinuesBelowDiskFloor(t *testing.T) {
	t.Setenv("PREFLIGHT_MIN_FREE_DISK_GB", "1000000")
	// Below the floor admission would otherwise prune this machine's pnpm store.
	t.Setenv("PREFLIGHT_AUTO_PRUNE_PNPM_STORE", "0")
	claims := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/claim") {
			t.Errorf("unexpected request %s", r.URL.Path)
			return
		}
		var body struct {
			WorkflowID string `json:"workflowId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		claims = append(claims, body.WorkflowID)
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	options := runnerOnceOptions{simlock: true, apiURL: server.URL, workspaceRoot: dir, workflowID: "held"}

	// Within a held chain: the next step is still claimed, scoped to the workflow.
	options.simlockLease = &simlockRunnerLease{workflowID: "held", done: make(chan struct{}), stopRenew: make(chan struct{})}
	if err := claimAndHandleNextRunnerJob(server.Client(), options, scopedRegistration(t), io.Discard, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0] != "held" {
		t.Fatalf("held workflow did not continue below the floor: %v", claims)
	}

	// Without a held workflow, the floor still refuses every claim.
	options.simlockLease = nil
	options.workflowID = ""
	if err := claimAndHandleNextRunnerJob(server.Client(), options, scopedRegistration(t), io.Discard, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 {
		t.Fatalf("floor admitted unscoped work: %v", claims)
	}

	// A fresh process finds held workflows from their adoption state and
	// claims only within them.
	state := filepath.Join(dir, "state")
	t.Setenv("PREFLIGHT_SIMLOCK_STATE_DIR", state)
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	lease := &simlockRunnerLease{workflowID: "resumed", statePath: filepath.Join(state, simlockWorkflowKey("resumed", "ios")+".json")}
	lease.grant = simlockTestGrant(t, "ios")
	if err := lease.saveState(); err != nil {
		t.Fatal(err)
	}
	if got := heldSimlockWorkflows(); len(got) != 1 || got[0] != "resumed" {
		t.Fatalf("held workflows not found from state: %v", got)
	}
	if _, err := claimHeldSimlockWorkflowJob(server.Client(), options, scopedRegistration(t), io.Discard); err != nil {
		t.Fatal(err)
	}
	if claims[len(claims)-1] != "resumed" {
		t.Fatalf("held workflow claim was not scoped: %v", claims)
	}
	options.simlock = false
	before := len(claims)
	if _, err := claimHeldSimlockWorkflowJob(server.Client(), options, scopedRegistration(t), io.Discard); err != nil || len(claims) != before {
		t.Fatal("claimed held workflows without SimLock enabled")
	}
}
