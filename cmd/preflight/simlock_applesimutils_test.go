package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAppleSimutilsPrivacyChanges(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        []simctlPrivacyChange
		ok          bool
	}{
		{"photos", "YES", []simctlPrivacyChange{{"grant", "photos"}}, true},
		{"photos", "limited", []simctlPrivacyChange{{"grant", "photos-add"}}, true},
		{"contacts", "limited", []simctlPrivacyChange{{"grant", "contacts-limited"}}, true},
		{"medialibrary", "NO", []simctlPrivacyChange{{"revoke", "media-library"}}, true},
		{"microphone", "unset", []simctlPrivacyChange{{"reset", "microphone"}}, true},
		{"location", "always", []simctlPrivacyChange{{"grant", "location-always"}}, true},
		{"location", "inuse", []simctlPrivacyChange{{"grant", "location"}}, true},
		{"location", "never", []simctlPrivacyChange{{"revoke", "location-always"}, {"revoke", "location"}}, true},
		{"notifications", "YES", nil, false},
		{"camera", "YES", nil, false},
		{"photos", "sometimes", nil, false},
	} {
		got, ok := appleSimutilsPrivacyChanges(tc.name, tc.value)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s=%s: got %v %v, want %v %v", tc.name, tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

// Maestro's launchApp failed on every SimLock simulator because applesimutils
// cannot see SimLock's device set. The translator must grant inside the lease.
func TestSimlockAppleSimutilsGrantsThroughLease(t *testing.T) {
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	fake := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + simlockShellQuote(calls) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "simlock"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stderr bytes.Buffer
	code := runSimlockAppleSimutils([]string{"--lease", "lse_1", "--device", "UDID-1", "--", "--byId", "UDID-1", "--bundle", "com.example.app", "--setPermissions", "photos=YES, notifications=YES, location=inuse"}, &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, _ := os.ReadFile(calls)
	want := "--local simctl --lease lse_1 privacy UDID-1 grant photos com.example.app\n--local simctl --lease lse_1 privacy UDID-1 grant location com.example.app\n"
	if string(data) != want {
		t.Fatalf("simctl privacy calls:\n%s\nwant:\n%s", data, want)
	}
	if !strings.Contains(stderr.String(), "skipped notifications=YES") {
		t.Fatalf("unsupported permission not reported: %s", stderr.String())
	}
	// Another simulator is never touched, and unsupported verbs are refused.
	if code := runSimlockAppleSimutils([]string{"--lease", "lse_1", "--device", "UDID-1", "--", "--byId", "OTHER", "--bundle", "b", "--setPermissions", "photos=YES"}, &bytes.Buffer{}, &bytes.Buffer{}); code == 0 {
		t.Fatal("translated permissions for a device outside the lease")
	}
	if code := runSimlockAppleSimutils([]string{"--lease", "lse_1", "--device", "UDID-1", "--", "--booted", "--setLocation", "[1,2]"}, &bytes.Buffer{}, &bytes.Buffer{}); code == 0 {
		t.Fatal("accepted an unsupported applesimutils command")
	}
}

func TestSimlockIOSLeaseShimsApplesimutils(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "simlock"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := exec.LookPath("xcrun"); err != nil {
		t.Skip("xcrun unavailable")
	}
	lease := &simlockRunnerLease{grant: simlockTestGrant(t, "ios"), workflowID: "wf", done: make(chan struct{})}
	defer func() { _ = os.RemoveAll(lease.shimDir) }()
	options := runnerOnceOptions{hostIdentity: "test", xcrunPath: "xcrun"}
	undo, err := lease.configure(&options)
	if err != nil {
		t.Fatal(err)
	}
	defer undo()
	shim, err := exec.LookPath("applesimutils")
	if err != nil || filepath.Dir(shim) != lease.shimDir {
		t.Fatalf("applesimutils on PATH is %q, not the lease's translator", shim)
	}
	body, _ := os.ReadFile(shim)
	if !strings.Contains(string(body), simlockAppleSimutilsCommand) || !strings.Contains(string(body), "device-udid") {
		t.Fatalf("shim does not call the translator for the leased device:\n%s", body)
	}
}

// Maestro 2.6 calls `simctl --set <SimLock set>` itself; `simlock simctl`
// refuses a caller-supplied --set, so Maestro reported the leased device as
// "not connected". Calls scoped to the lease's own set bypass SimLock.
func TestSimlockXcrunShimPassesLeaseScopedSetThrough(t *testing.T) {
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	for _, name := range []string{"simlock", "xcrun"} {
		body := "#!/bin/sh\nprintf '" + name + " %s\\n' \"$*\" >> " + simlockShellQuote(calls) + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	grant := simlockTestGrant(t, "ios")
	grant.Environment.IOSDeviceSet = "/sets/simlock ios"
	lease := &simlockRunnerLease{grant: grant, workflowID: "wf", done: make(chan struct{})}
	defer func() { _ = os.RemoveAll(lease.shimDir) }()
	t.Setenv("PREFLIGHT_SIMLOCK_TRANSLATOR", "/bin/true")
	options := runnerOnceOptions{hostIdentity: "test", xcrunPath: filepath.Join(dir, "xcrun")}
	// Xcode version probe for an isolated device set.
	if err := os.WriteFile(filepath.Join(dir, "xcodebuild"), []byte("#!/bin/sh\necho 'Xcode 27.2'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	undo, err := lease.configure(&options)
	if err != nil {
		t.Fatal(err)
	}
	defer undo()
	for _, args := range [][]string{
		{"simctl", "--set", "/sets/simlock ios", "list", "-j"},
		{"simctl", "--set", "/elsewhere", "list", "-j"},
		{"simctl", "boot", "device-udid"},
	} {
		if output, err := exec.Command(options.xcrunPath, args...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, output)
		}
	}
	data, _ := os.ReadFile(calls)
	want := "xcrun simctl --set /sets/simlock ios list -j\n" +
		"simlock --local simctl --lease our-lease --set /elsewhere list -j\n" +
		"simlock --local simctl --lease our-lease boot device-udid\n"
	if string(data) != want {
		t.Fatalf("shim routing:\n%s\nwant:\n%s", data, want)
	}
}
