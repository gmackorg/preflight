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

func TestSimlockHolderReleasesOnCancellationAndInvalidGrant(t *testing.T) {
	for _, mode := range []string{"invalid", "waiting", "valid"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			released := filepath.Join(dir, "released")
			grant := simlockTestGrant(t, "ios")
			data, _ := json.Marshal(grant)
			body := "#!/bin/sh\ntrap 'echo released > " + simlockShellQuote(released) + "; exit 0' TERM\n"
			switch mode {
			case "valid":
				body += "echo " + simlockShellQuote(string(data)) + "\n"
			case "invalid":
				body += "echo '{\"bad\":true}'\n"
			}
			body += "while :; do sleep 0.1; done\n"
			if err := os.WriteFile(filepath.Join(dir, "simlock"), []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			job := apiRunnerJob{WorkflowID: "workflow", Payload: runnerJobPayload{Platform: "ios"}}
			lease, err := acquireSimlockRunnerLease(runnerOnceOptions{hostIdentity: "test"}, job, io.Discard, func() (bool, error) { return true, nil })
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				lease.close()
				lease.close()
			} else if err == nil {
				t.Fatal("invalid/cancelled lease accepted")
			}
			if _, err := os.Stat(released); err != nil {
				t.Fatal("holder was not gracefully released", err)
			}
		})
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
	job := apiRunnerJob{ID: "simlock-live", WorkflowID: "PREFLT-65-live", Kind: "device.discover", Payload: runnerJobPayload{Platform: platform, Lane: "simulator", TargetClass: "simulator"}}
	options := runnerOnceOptions{hostIdentity: "preflight-live-check", workspaceRoot: root, xcrunPath: "xcrun", adbPath: "adb"}
	lease, err := acquireSimlockRunnerLease(options, job, os.Stdout, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.close()
	options.simlockLease = lease
	undo, err := lease.configure(&options)
	if err != nil {
		t.Fatal(err)
	}
	defer undo()
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
	released := filepath.Join(dir, "released")
	grant := simlockTestGrant(t, "android")
	data, _ := json.Marshal(grant)
	fake := "#!/bin/sh\ntrap 'touch " + simlockShellQuote(released) + "; exit 0' TERM\necho " + simlockShellQuote(string(data)) + "\nwhile :; do sleep 0.1; done\n"
	if err := os.WriteFile(filepath.Join(dir, "simlock"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
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
