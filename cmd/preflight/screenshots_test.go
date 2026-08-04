package main

import (
	"path/filepath"
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
	for _, needed := range []string{"xcodebuild", "-configuration Release", "-sdk iphonesimulator", "CODE_SIGN_IDENTITY=-", "PreflightDev.xcworkspace"} {
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

func TestBuildScreenshotCapturePlan_AbsolutizesRelativeFlowPath(t *testing.T) {
	// maestro runs with cwd=ScreenshotDir so takeScreenshot lands there. A
	// relative flow path would then resolve against the screenshot dir and the
	// run dies with "Flow path does not exist: .../screenshots/.preflight/...".
	plan, err := buildScreenshotCapturePlan(screenshotPlanInput{
		Workspace:     "/repo/ios/App.xcworkspace",
		Scheme:        "App",
		AppPath:       "/repo/App.app",
		BundleID:      "com.example.app",
		SimUDID:       "SIM-UDID",
		FlowPath:      ".preflight/review/core-flow.maestro.yaml",
		ScreenshotDir: "/repo/.preflight/screenshots",
	})
	if err != nil {
		t.Fatal(err)
	}
	maestro := plan[len(plan)-1]
	if maestro.label != "maestro" {
		t.Fatalf("last step = %q, want maestro", maestro.label)
	}
	flow := maestro.args[len(maestro.args)-1]
	if !filepath.IsAbs(flow) {
		t.Fatalf("flow path %q is not absolute; it would resolve against %s", flow, maestro.dir)
	}
	if !strings.HasSuffix(flow, "/.preflight/review/core-flow.maestro.yaml") {
		t.Errorf("flow path lost its suffix: %s", flow)
	}
}

func TestBuildScreenshotCapturePlan_RaisesNodeHeapForMetro(t *testing.T) {
	// Metro bundles inside the xcodebuild script phase and dies silently at
	// node's default heap, surfacing later as a missing main.jsbundle.
	plan, err := buildScreenshotCapturePlan(screenshotPlanInput{
		Workspace: "/repo/ios/App.xcworkspace",
		Scheme:    "App",
		AppPath:   "/repo/App.app",
		BundleID:  "com.example.app",
		SimUDID:   "SIM-UDID",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan[0].env["NODE_OPTIONS"]; !strings.Contains(got, "max-old-space-size") {
		t.Errorf("build env NODE_OPTIONS = %q, want a raised heap", got)
	}
}

func TestBuildScreenshotCapturePlan_RecipeEnvOverridesNodeOptions(t *testing.T) {
	plan, err := buildScreenshotCapturePlan(screenshotPlanInput{
		Workspace:     "/repo/ios/App.xcworkspace",
		Scheme:        "App",
		AppPath:       "/repo/App.app",
		BundleID:      "com.example.app",
		SimUDID:       "SIM-UDID",
		ExtraBuildEnv: map[string]string{"NODE_OPTIONS": "--max-old-space-size=2048"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan[0].env["NODE_OPTIONS"]; got != "--max-old-space-size=2048" {
		t.Errorf("caller override lost: NODE_OPTIONS = %q", got)
	}
}
