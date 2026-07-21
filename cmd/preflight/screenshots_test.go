package main

import (
	"strings"
	"testing"
)

func TestBuildScreenshotCapturePlan_EncodesTheRecipe(t *testing.T) {
	plan, err := buildScreenshotCapturePlan(screenshotPlanInput{
		Workspace:       "/repo/apps/mobile/ios/PreflightDev.xcworkspace",
		Scheme:          "PreflightDev",
		DerivedData:     "/repo/apps/mobile/.preflight/dd-screenshots",
		AppPath:         "/repo/.../Release-iphonesimulator/PreflightDev.app",
		BundleID:        "com.gmacko.preflight.dev",
		SimUDID:         "SIM-UDID",
		FlowPath:        "/repo/flow.yaml",
		ScreenshotDir:   "/repo/shots",
		StatusBarTime:   "9:41",
		AuthToken:       "gmk_secret",
		AuthWorkspaceID: "ws_1",
	})
	if err != nil {
		t.Fatal(err)
	}

	labels := make([]string, len(plan))
	for i, s := range plan {
		labels[i] = s.label
	}
	want := []string{"build", "boot", "status-bar", "install", "launch", "maestro"}
	if strings.Join(labels, ",") != strings.Join(want, ",") {
		t.Fatalf("plan order = %v, want %v", labels, want)
	}

	build := plan[0]
	joined := strings.Join(build.args, " ")
	for _, needed := range []string{"xcodebuild", "-configuration Release", "-sdk iphonesimulator", "CODE_SIGNING_ALLOWED=NO", "PreflightDev.xcworkspace"} {
		if !strings.Contains(joined, needed) {
			t.Errorf("build step missing %q in: %s", needed, joined)
		}
	}
	// Auth is baked into the build env (SecureStore throws on unsigned sims).
	if build.env["EXPO_PUBLIC_API_TOKEN"] != "gmk_secret" || build.env["EXPO_PUBLIC_WORKSPACE_ID"] != "ws_1" {
		t.Errorf("build env missing auth: %v", build.env)
	}

	// The maestro step runs in the screenshot dir so takeScreenshot lands there.
	maestro := plan[len(plan)-1]
	if maestro.dir != "/repo/shots" {
		t.Errorf("maestro dir = %q, want /repo/shots", maestro.dir)
	}
	if !strings.Contains(strings.Join(maestro.args, " "), "SIM-UDID") {
		t.Errorf("maestro not targeting the sim: %v", maestro.args)
	}
}

func TestBuildScreenshotCapturePlan_SkipsOptionalSteps(t *testing.T) {
	// No status bar time + no flow → those steps are omitted.
	plan, err := buildScreenshotCapturePlan(screenshotPlanInput{
		Workspace: "/w/App.xcworkspace",
		Scheme:    "App",
		AppPath:   "/App.app",
		BundleID:  "com.app",
		SimUDID:   "U",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range plan {
		if s.label == "status-bar" || s.label == "maestro" {
			t.Errorf("did not expect step %q", s.label)
		}
	}
}

func TestBuildScreenshotCapturePlan_RequiresCoreInputs(t *testing.T) {
	if _, err := buildScreenshotCapturePlan(screenshotPlanInput{Scheme: "S", SimUDID: "U", AppPath: "a", BundleID: "b"}); err == nil {
		t.Error("expected error when workspace is missing")
	}
	if _, err := buildScreenshotCapturePlan(screenshotPlanInput{Workspace: "w", Scheme: "S", AppPath: "a", BundleID: "b"}); err == nil {
		t.Error("expected error when sim udid is missing")
	}
}
