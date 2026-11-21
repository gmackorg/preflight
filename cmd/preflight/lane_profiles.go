package main

// Local lane build profiles (PREFLT-66).
//
// The simulator and development lanes build on the runner with expo prebuild
// + xcodebuild/gradle. They used to read their settings from an app's eas.json;
// Preflight now derives them from the profile name and lane alone, and the
// store lanes (internal/beta/store) take theirs from the control plane's
// build profiles (`preflight build-profiles`).
//
//   - development lanes (simulator or physical device) build a development
//     client with APP_VARIANT=development; the app needs expo-dev-client.
//   - a profile named "preview", "preview-*" or "*-preview" on the simulator
//     lane builds a packaged app with embedded JavaScript (APP_VARIANT=preview)
//     that installs on a simulator/emulator without Metro.
//   - production profiles never build here: they go through the store build
//     workflow (`preflight build store`).

import (
	"fmt"
	"strings"
)

const defaultLaneProfileName = "development"

type laneProfile struct {
	name            string
	env             map[string]string
	envDigest       string
	packagedPreview bool
}

func isPreviewProfileName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	return normalized == "preview" ||
		strings.HasPrefix(normalized, "preview-") ||
		strings.HasSuffix(normalized, "-preview")
}

// isProductionBuildProfile reports whether a profile name denotes a
// production/store build, which only the store build workflow produces.
func isProductionBuildProfile(profileName string) bool {
	p := strings.ToLower(strings.TrimSpace(profileName))
	return p == "production" ||
		strings.HasPrefix(p, "production-") ||
		strings.HasSuffix(p, "-production")
}

// resolveLaneProfile turns a requested profile name into the settings a local
// simulator/development build uses. An empty name selects the development
// client profile.
func resolveLaneProfile(name string, platform string, lane string) (laneProfile, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultLaneProfileName
	}
	if isProductionBuildProfile(name) {
		return laneProfile{}, fmt.Errorf("production profiles require the separate store build workflow (preflight build store)")
	}
	variant := "development"
	packaged := false
	if isPreviewProfileName(name) {
		if lane != "simulator" {
			return laneProfile{}, fmt.Errorf("build profile %q builds a packaged simulator app; use --lane simulator", name)
		}
		if platform != "ios" && platform != "android" {
			return laneProfile{}, fmt.Errorf("build profile %q needs --platform ios or android", name)
		}
		variant = "preview"
		packaged = true
	}
	env := map[string]string{"APP_VARIANT": variant}
	return laneProfile{
		name:            name,
		env:             env,
		envDigest:       digestJSON(env),
		packagedPreview: packaged,
	}, nil
}

// laneProfileNameForJob is the profile a runner job was bound with.
func laneProfileNameForJob(job apiRunnerJob) string {
	if name := strings.TrimSpace(job.Payload.BuildProfileName); name != "" {
		return name
	}
	return strings.TrimSpace(job.Payload.SourceBinding.BuildProfileName)
}

func laneProfileForJob(job apiRunnerJob) laneProfile {
	name := laneProfileNameForJob(job)
	profile, err := resolveLaneProfile(name, jobPlatform(job), job.Payload.Lane)
	if err != nil {
		return laneProfile{name: name}
	}
	return profile
}

// laneProfileEnvForJob is the profile environment for simulator/development
// jobs. Store lanes take their environment from the job's build plan.
func laneProfileEnvForJob(job apiRunnerJob) map[string]string {
	switch strings.TrimSpace(job.Payload.Lane) {
	case "simulator", "development":
		return laneProfileForJob(job).env
	default:
		return nil
	}
}

func isPackagedIOSSimulatorJob(job apiRunnerJob) bool {
	return jobPlatform(job) == "ios" && job.Payload.Lane == "simulator" && laneProfileForJob(job).packagedPreview
}

func isPackagedAndroidSimulatorJob(job apiRunnerJob) bool {
	return jobPlatform(job) == "android" && job.Payload.Lane == "simulator" && laneProfileForJob(job).packagedPreview
}
