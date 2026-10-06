package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSimulatorBuildKeepsProjectEntitlementsAndUsesAdHocSigning(t *testing.T) {
	appDir := t.TempDir()
	bin := t.TempDir()
	if err := os.MkdirAll(filepath.Join(appDir, "ios", "Fixture.xcworkspace"), 0755); err != nil {
		t.Fatal(err)
	}
	entitlements := filepath.Join(appDir, "ios", "Fixture.entitlements")
	original := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.developer.associated-domains</key><array><string>applinks:example.com</string></array></dict></plist>`
	if err := os.WriteFile(entitlements, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	arguments := filepath.Join(bin, "arguments.txt")
	installs := filepath.Join(bin, "installs.txt")
	t.Setenv("PREFLIGHT_TEST_XCODE_ARGS", arguments)
	t.Setenv("PREFLIGHT_TEST_INSTALL_ARGS", installs)
	script := `#!/bin/sh
printf '%s\n' "$@" > "$PREFLIGHT_TEST_XCODE_ARGS"
while [ "$#" -gt 0 ]; do
 if [ "$1" = '-derivedDataPath' ]; then shift; mkdir -p "$1/Build/Products/Debug-iphonesimulator/Fixture.app"; exit 0; fi
 shift
done
exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "xcodebuild"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	xcrun := filepath.Join(bin, "xcrun")
	if err := os.WriteFile(xcrun, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PREFLIGHT_TEST_INSTALL_ARGS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	log, err := os.CreateTemp(t.TempDir(), "build.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if err := buildAndInstallIOSSimulatorApp(log, runnerOnceOptions{xcrunPath: xcrun}, appDir, "owned-sim", apiRunnerJob{}, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	args := "\n" + string(data)
	for _, required := range []string{"CODE_SIGN_IDENTITY=-", "CODE_SIGNING_ALLOWED=YES", "CODE_SIGNING_REQUIRED=YES"} {
		if !strings.Contains(args, "\n"+required+"\n") {
			t.Errorf("simulator build must retain keychain-capable ad hoc signature; missing %s", required)
		}
	}
	for _, argument := range strings.Split(string(data), "\n") {
		for _, key := range []string{"CODE_SIGN_ENTITLEMENTS=", "DEVELOPMENT_TEAM=", "PROVISIONING_PROFILE="} {
			if strings.HasPrefix(argument, key) {
				t.Errorf("simulator build replaced project entitlements or invented provisioning: %s", argument)
			}
		}
	}
	for _, forbidden := range []string{"CODE_SIGNING_ALLOWED=NO", "CODE_SIGN_IDENTITY=", "-allowProvisioningUpdates"} {
		if strings.Contains(args, "\n"+forbidden+"\n") {
			t.Errorf("simulator build erased entitlements or requested provisioned signing: %s", forbidden)
		}
	}
	after, err := os.ReadFile(entitlements)
	if err != nil || string(after) != original {
		t.Fatal("project entitlements were changed")
	}
	installed, err := os.ReadFile(installs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "simctl\ninstall\nowned-sim\n") {
		t.Fatalf("wrong target installation: %s", installed)
	}
}
