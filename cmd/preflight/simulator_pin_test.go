package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSimulatorCannotSelectOtherReportedTarget(t *testing.T) {
	options := runnerOnceOptions{simulatorUDID: "PINNED", xcrunPath: filepath.Join(t.TempDir(), "no-live-xcrun")}
	for _, test := range []struct {
		name    string
		targets []apiTarget
		want    string
	}{
		{"reported stale target first", []apiTarget{{ProviderIdentity: "OTHER", Availability: "available", DisplayName: "iPhone"}, {ProviderIdentity: "pinned", Availability: "available", DisplayName: "Dedicated review device"}}, "pinned"},
		{"pin busy", []apiTarget{{ProviderIdentity: "OTHER", Availability: "available", DisplayName: "iPhone"}, {ProviderIdentity: "PINNED", Availability: "busy", DisplayName: "iPhone"}}, ""},
		{"pin missing", []apiTarget{{ProviderIdentity: "OTHER", Availability: "available", DisplayName: "iPhone"}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := preferredSimulatorTarget(options, "ios", test.targets)
			if test.want == "" {
				if selected != nil {
					t.Fatalf("selected foreign target: %+v", selected)
				}
				return
			}
			if selected == nil || selected.ProviderIdentity != test.want {
				t.Fatalf("wrong pinned selection: %+v", selected)
			}
		})
	}
}

func TestPinnedSimulatorMissingFromInventoryFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte(`{"devices":{"iOS":[{"udid":"OTHER","isAvailable":true}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if inventory, err := loadSimctlInventory(runnerOnceOptions{simulatorUDID: "PINNED", simctlJSON: path}); err == nil {
		t.Fatalf("missing pin exposed foreign inventory: %s", inventory)
	}
}

func TestPinnedSimulatorRejectsForeignDeviceJobsBeforeSourceOrNativeCommands(t *testing.T) {
	options := runnerOnceOptions{simulatorUDID: "PINNED", xcrunPath: filepath.Join(t.TempDir(), "no-live-xcrun")}
	for _, kind := range []string{"simulator.open", "maestro.run", "dev_session.start", "dev_session.open", "eas.build.dev"} {
		job := apiRunnerJob{Kind: kind, Payload: runnerJobPayload{Platform: "ios", Lane: "simulator", ProviderIdentity: "OTHER"}}
		if err := validateRunnerJobSourceBinding(options, job); err == nil {
			t.Errorf("%s accepted foreign simulator", kind)
		}
		job.Payload.ProviderIdentity = "pinned"
		if err := validateRunnerJobSourceBinding(options, job); err != nil {
			t.Errorf("%s rejected pin: %v", kind, err)
		}
		job.Payload.ProviderIdentity = ""
		job.TargetID = "OTHER"
		if err := validateRunnerJobSourceBinding(options, job); err == nil {
			t.Errorf("%s accepted foreign target fallback", kind)
		}
	}
	physical := apiRunnerJob{Kind: "maestro.run", Payload: runnerJobPayload{Platform: "ios", Lane: "development", TargetClass: "device", ProviderIdentity: "REAL-IPHONE"}}
	if err := validateRunnerJobSourceBinding(options, physical); err != nil {
		t.Fatalf("simulator pin rejected real iPhone job: %v", err)
	}
}
