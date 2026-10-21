package main

import (
	"strings"
	"testing"
)

func TestRunnerRejectsInvalidSimulatorBuildJobs(t *testing.T) {
	for _, value := range []string{"0", "-1", "33", "abc", "2.5", ""} {
		t.Run(value, func(t *testing.T) {
			_, err := parseRunnerOnceOptions([]string{"--ios-simulator-build-jobs", value})
			if err == nil || !strings.Contains(err.Error(), "--ios-simulator-build-jobs") {
				t.Fatalf("invalid bound accepted: %q: %v", value, err)
			}
		})
	}
	_, err := parseRunnerOnceOptions([]string{"--ios-simulator-build-jobs"})
	if err == nil {
		t.Fatal("missing bound accepted")
	}
}

func TestRunnerParsesSimulatorBuildJobs(t *testing.T) {
	options, err := parseRunnerOnceOptions([]string{"--api-url", "https://example.test", "--workspace-id", "workspace", "--ios-simulator-build-jobs", "2"})
	if err != nil {
		t.Fatal(err)
	}
	if options.iosSimulatorBuildJobs != 2 {
		t.Fatalf("lost configured bound: %d", options.iosSimulatorBuildJobs)
	}
}

func TestSimulatorBuildRejectsInvalidInternalBoundBeforeExecution(t *testing.T) {
	for _, jobs := range []int{-1, 33} {
		err := buildAndInstallIOSSimulatorApp(nil, runnerOnceOptions{iosSimulatorBuildJobs: jobs}, t.TempDir(), "owned-sim", apiRunnerJob{}, nil)
		if err == nil || !strings.Contains(err.Error(), "simulator build jobs") {
			t.Fatalf("invalid internal bound proceeded to workspace/build: %d: %v", jobs, err)
		}
	}
}
