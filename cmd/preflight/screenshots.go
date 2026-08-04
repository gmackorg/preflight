package main

// R5 screenshot capture harness. Turns the proven-but-manual App Store capture
// recipe (Release sim build → boot → install → launch → Maestro-drive → collect
// 1320×2868 PNGs) into one command: `preflight apps screenshots <app>`. The
// plan builder is pure + unit-tested; the executor is thin glue over xcrun +
// maestro. Live capture needs a per-app Maestro flow + auth (slice 2 content) —
// this slice is the reusable engine + `--dry-run` to inspect the exact commands.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// One command in the capture sequence. env is applied on top of os.Environ().
type screenshotStep struct {
	label string
	dir   string
	name  string
	args  []string
	env   map[string]string
}

// Everything the plan builder needs, already resolved by the caller (from the
// source binding + the filesystem). Kept explicit so the builder stays pure.
type screenshotPlanInput struct {
	Workspace       string // absolute path to ios/<App>.xcworkspace
	Scheme          string
	DerivedData     string // where the Release build lands
	AppPath         string // <DerivedData>/Build/Products/Release-iphonesimulator/<App>.app
	BundleID        string
	SimUDID         string
	FlowPath        string // per-app Maestro flow (takeScreenshot steps)
	ScreenshotDir   string // CWD for maestro so captures land here
	StatusBarTime   string // e.g. "9:41"; "" skips the override
	AuthToken       string // baked into the Release build so the sim app is signed in
	AuthWorkspaceID string
	XcrunPath       string // default "xcrun"
	MaestroPath     string // default "maestro"
	SkipBuild       bool   // reuse an existing .app (re-capture without rebuilding)
	// ExtraBuildEnv: recipe-provided public env layered into the xcodebuild
	// step (EXPO_PUBLIC_* URLs etc.). Flags/process env still win at runtime
	// since exec inherits os.Environ after these.
	ExtraBuildEnv map[string]string
}

// buildScreenshotCapturePlan encodes the proven recipe as an ordered command
// list. Pure — no I/O — so the sequence + flags are unit-testable.
func buildScreenshotCapturePlan(in screenshotPlanInput) ([]screenshotStep, error) {
	if in.Workspace == "" || in.Scheme == "" {
		return nil, fmt.Errorf("workspace and scheme are required")
	}
	if in.SimUDID == "" {
		return nil, fmt.Errorf("simulator udid is required")
	}
	if in.AppPath == "" || in.BundleID == "" {
		return nil, fmt.Errorf("app path and bundle id are required")
	}
	xcrun := firstNonEmptyStr(in.XcrunPath, "xcrun")
	maestro := firstNonEmptyStr(in.MaestroPath, "maestro")

	// Auth is baked into the Release build: SecureStore throws on unsigned sim
	// builds, so the app falls back to these env vars embedded at bundle time.
	// Metro bundles the whole app inside xcodebuild's "Bundle React Native code
	// and images" phase. At node's default heap it dies *silently* on larger
	// apps: the phase exits 0 having written no main.jsbundle, and the build
	// fails later in hermesc with "Failed to open file: main.jsbundle" — which
	// reads like a missing-file bug, not an OOM. Observed on bizpulse
	// (2570 modules). Callers can still override.
	buildEnv := map[string]string{
		"APP_VARIANT":  "preview",
		"NODE_OPTIONS": "--max-old-space-size=8192",
	}
	for k, v := range in.ExtraBuildEnv {
		buildEnv[k] = v
	}
	if in.AuthToken != "" {
		buildEnv["EXPO_PUBLIC_API_TOKEN"] = in.AuthToken
	}
	if in.AuthWorkspaceID != "" {
		buildEnv["EXPO_PUBLIC_WORKSPACE_ID"] = in.AuthWorkspaceID
	}

	var steps []screenshotStep
	if !in.SkipBuild {
		steps = append(steps, screenshotStep{
			label: "build",
			name:  xcrun,
			args: []string{
				"xcodebuild",
				"-workspace", in.Workspace,
				"-scheme", in.Scheme,
				"-configuration", "Release",
				"-sdk", "iphonesimulator",
				"-destination", "generic/platform=iOS Simulator",
				"-derivedDataPath", in.DerivedData,
				"build",
				// Ad-hoc sign (not CODE_SIGNING_ALLOWED=NO): fully unsigned sim
				// builds break keychain access, so SecureStore throws in-app.
				"CODE_SIGN_IDENTITY=-",
			},
			env: buildEnv,
		})
	}
	steps = append(steps, screenshotStep{
		label: "boot",
		name:  xcrun,
		args:  []string{"simctl", "bootstatus", in.SimUDID, "-b"},
	})

	if in.StatusBarTime != "" {
		steps = append(steps, screenshotStep{
			label: "status-bar",
			name:  xcrun,
			args: []string{
				"simctl", "status_bar", in.SimUDID, "override",
				"--time", in.StatusBarTime,
				"--batteryState", "charged", "--batteryLevel", "100",
				"--cellularBars", "4",
			},
		})
	}

	steps = append(steps,
		screenshotStep{
			label: "install",
			name:  xcrun,
			args:  []string{"simctl", "install", in.SimUDID, in.AppPath},
		},
		screenshotStep{
			label: "launch",
			name:  xcrun,
			args:  []string{"simctl", "launch", in.SimUDID, in.BundleID},
		},
	)

	if in.FlowPath != "" {
		// maestro runs with cwd=ScreenshotDir so takeScreenshot lands there,
		// which means a relative --flow would resolve against the screenshot
		// dir instead of the app dir ("Flow path does not exist: …/
		// .preflight/screenshots/.preflight/review/core-flow.maestro.yaml").
		// Absolutize against the caller's cwd, which is what the path meant.
		flowPath := in.FlowPath
		if !filepath.IsAbs(flowPath) {
			if abs, err := filepath.Abs(flowPath); err == nil {
				flowPath = abs
			}
		}
		steps = append(steps, screenshotStep{
			label: "maestro",
			dir:   in.ScreenshotDir, // takeScreenshot writes relative to CWD
			name:  maestro,
			args:  []string{"--device", in.SimUDID, "test", flowPath},
		})
	}

	return steps, nil
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// resolveIOSWorkspace finds the .xcworkspace under an app's ios/ dir, preferring
// one whose name matches the scheme (variant projects like PreflightDev).
func resolveIOSWorkspace(appDir, scheme string) (string, error) {
	iosDir := filepath.Join(appDir, "ios")
	entries, err := os.ReadDir(iosDir)
	if err != nil {
		return "", fmt.Errorf("read ios dir: %w", err)
	}
	var workspaces []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".xcworkspace") {
			workspaces = append(workspaces, filepath.Join(iosDir, e.Name()))
		}
	}
	if len(workspaces) == 0 {
		return "", fmt.Errorf("no .xcworkspace under %s", iosDir)
	}
	if scheme != "" {
		for _, w := range workspaces {
			if strings.TrimSuffix(filepath.Base(w), ".xcworkspace") == scheme {
				return w, nil
			}
		}
	}
	return workspaces[0], nil
}

// runScreenshotStep runs one step with its env layered onto the process env.
func runScreenshotStep(step screenshotStep, stdout, stderr io.Writer) error {
	cmd := exec.Command(step.name, step.args...)
	if step.dir != "" {
		cmd.Dir = step.dir
	}
	if len(step.env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range step.env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// collectScreenshots returns the .png files a capture run produced, sorted so
// upload order is stable.
func collectScreenshots(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var pngs []string
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".png") {
			pngs = append(pngs, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(pngs)
	return pngs, nil
}

// uploadScreenshot POSTs one PNG's raw bytes to the store-listing screenshots
// route (which stores it in R2 and appends it to the listing).
func uploadScreenshot(client *http.Client, apiURL, token, appID, pngPath, displayType, locale string) error {
	data, err := os.ReadFile(pngPath)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + appID + "/store-listing/screenshots"
	// Matrix coordinates (P7): tag the upload with device class + locale so
	// the listing groups into (displayType × locale) sets. Defaults server-side
	// are APP_IPHONE_67 / en-US.
	query := url.Values{}
	if strings.TrimSpace(displayType) != "" {
		query.Set("displayType", strings.ToUpper(strings.TrimSpace(displayType)))
	}
	if strings.TrimSpace(locale) != "" {
		query.Set("locale", strings.TrimSpace(locale))
	}
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "image/png")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// runAppsScreenshots is the R5 capture harness command. Resolves the app's ios
// workspace, builds the capture plan, and (unless --dry-run) executes it, then
// collects the PNGs and — with --upload — pushes them to the listing + publishes
// kind=screenshots (the proven delivery pipeline carries them to ASC).
func runAppsScreenshots(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	config, _ := loadPreflightCLIConfig()
	in := screenshotPlanInput{StatusBarTime: "9:41", XcrunPath: "xcrun", MaestroPath: "maestro"}
	workspaceRoot, packagePath, appPathOverride := "", "", ""
	appID := ""
	displayType, uploadLocale := "", ""
	dryRun, doUpload, doSaveRecipe := false, false, false
	apiURL := firstNonEmpty(os.Getenv("PREFLIGHT_API_URL"), config.APIURL, defaultPreflightAPIURL)
	token := firstNonEmpty(os.Getenv("PREFLIGHT_TOKEN"), config.Token)

	set := func(dst *string, args []string, i *int) bool {
		v, ok := nextFlagValue(args, i)
		if !ok {
			return false
		}
		*dst = v
		return true
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--app":
			if !set(&appID, args, &i) {
				return 2
			}
		case "--workspace-root":
			if !set(&workspaceRoot, args, &i) {
				return 2
			}
		case "--package-path":
			if !set(&packagePath, args, &i) {
				return 2
			}
		case "--scheme":
			if !set(&in.Scheme, args, &i) {
				return 2
			}
		case "--sim":
			if !set(&in.SimUDID, args, &i) {
				return 2
			}
		case "--bundle-id":
			if !set(&in.BundleID, args, &i) {
				return 2
			}
		case "--flow":
			if !set(&in.FlowPath, args, &i) {
				return 2
			}
		case "--derived-data":
			if !set(&in.DerivedData, args, &i) {
				return 2
			}
		case "--app-path":
			if !set(&appPathOverride, args, &i) {
				return 2
			}
		case "--status-bar-time":
			if !set(&in.StatusBarTime, args, &i) {
				return 2
			}
		case "--auth-token":
			if !set(&in.AuthToken, args, &i) {
				return 2
			}
		case "--auth-workspace-id":
			if !set(&in.AuthWorkspaceID, args, &i) {
				return 2
			}
		case "--maestro-path":
			if !set(&in.MaestroPath, args, &i) {
				return 2
			}
		case "--skip-build":
			in.SkipBuild = true
		case "--dry-run":
			dryRun = true
		case "--upload":
			doUpload = true
		case "--save-recipe":
			doSaveRecipe = true
		case "--display-type":
			if !set(&displayType, args, &i) {
				return 2
			}
		case "--locale":
			if !set(&uploadLocale, args, &i) {
				return 2
			}
		case "--help", "-h":
			printScreenshotsHelp(stdout)
			return 0
		}
	}

	// With --app, unset inputs come from the stored recipe (flags still win).
	var recipeBuildEnv map[string]string
	if appID != "" {
		recipe, err := fetchScreenshotRecipe(client, apiURL, token, appID)
		if err != nil {
			fmt.Fprintf(stderr, "fetch recipe: %v (continuing with flags)\n", err)
		} else if env, err := applyRecipeDefaults(recipe, &in, &workspaceRoot, &packagePath, stdout); err != nil {
			fmt.Fprintf(stderr, "apply recipe: %v\n", err)
			return 1
		} else {
			recipeBuildEnv = env
		}
	}

	if in.Scheme == "" || in.SimUDID == "" {
		fmt.Fprintln(stderr, "--scheme and --sim are required (or store a recipe with --save-recipe; see --help)")
		return 2
	}
	if workspaceRoot == "" {
		workspaceRoot, _ = os.Getwd()
	}
	appDir := workspaceRoot
	if packagePath != "" {
		appDir = filepath.Join(workspaceRoot, packagePath)
	}
	workspace, err := resolveIOSWorkspace(appDir, in.Scheme)
	if err != nil {
		fmt.Fprintf(stderr, "resolve ios workspace: %v\n", err)
		return 1
	}
	in.Workspace = workspace
	if in.DerivedData == "" {
		in.DerivedData = filepath.Join(appDir, ".preflight", "dd-screenshots")
	}
	in.ScreenshotDir = filepath.Join(appDir, ".preflight", "screenshots")
	in.AppPath = appPathOverride
	if in.AppPath == "" {
		in.AppPath = filepath.Join(in.DerivedData, "Build", "Products",
			"Release-iphonesimulator", in.Scheme+".app")
	}

	in.ExtraBuildEnv = recipeBuildEnv
	plan, err := buildScreenshotCapturePlan(in)
	if err != nil {
		fmt.Fprintf(stderr, "build plan: %v\n", err)
		return 1
	}

	if dryRun {
		fmt.Fprintf(stdout, "Screenshot capture plan for %s (%s):\n\n", in.Scheme, appDir)
		for i, s := range plan {
			env := ""
			if len(s.env) > 0 {
				var keys []string
				for k := range s.env {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				env = "  [env: " + strings.Join(keys, ",") + "]"
			}
			fmt.Fprintf(stdout, "  %d. %-11s %s %s%s\n", i+1, s.label, s.name, strings.Join(s.args, " "), env)
		}
		fmt.Fprintf(stdout, "\nCaptures → %s\n", in.ScreenshotDir)
		return 0
	}

	if err := os.MkdirAll(in.ScreenshotDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir screenshots: %v\n", err)
		return 1
	}
	for _, s := range plan {
		fmt.Fprintf(stdout, "[%s] %s %s\n", s.label, s.name, strings.Join(s.args, " "))
		if err := runScreenshotStep(s, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "step %q failed: %v\n", s.label, err)
			return 1
		}
	}

	pngs, err := collectScreenshots(in.ScreenshotDir)
	if err != nil {
		fmt.Fprintf(stderr, "collect screenshots: %v\n", err)
		return 1
	}
	if doSaveRecipe {
		if appID == "" {
			fmt.Fprintln(stderr, "--save-recipe needs --app <app-id>")
		} else {
			flowYaml := ""
			if in.FlowPath != "" {
				if raw, err := os.ReadFile(in.FlowPath); err == nil {
					flowYaml = string(raw)
				}
			}
			recipe := screenshotRecipe{
				Platform:    "ios",
				Scheme:      in.Scheme,
				PackagePath: packagePath,
				SimDevice:   in.SimUDID,
				BuildEnv:    recipeBuildEnv,
				FlowYaml:    flowYaml,
			}
			if err := saveScreenshotRecipe(client, apiURL, token, appID, recipe); err != nil {
				fmt.Fprintf(stderr, "save recipe: %v\n", err)
			} else {
				fmt.Fprintln(stdout, "[recipe] saved")
			}
		}
	}
	fmt.Fprintf(stdout, "\nCaptured %d screenshot(s) in %s\n", len(pngs), in.ScreenshotDir)
	if !doUpload || len(pngs) == 0 {
		if len(pngs) > 0 {
			fmt.Fprintln(stdout, "Review them, then re-run with --upload to push to the listing.")
		}
		return 0
	}

	if appID == "" {
		fmt.Fprintln(stderr, "--upload needs --app <app-id> to know which listing to attach to")
		return 2
	}
	uploaded := 0
	for _, p := range pngs {
		if err := uploadScreenshot(client, apiURL, token, appID, p, displayType, uploadLocale); err != nil {
			fmt.Fprintf(stderr, "  upload %s failed: %v\n", filepath.Base(p), err)
			continue
		}
		uploaded++
		fmt.Fprintf(stdout, "  uploaded %s\n", filepath.Base(p))
	}
	if uploaded == 0 {
		return 1
	}
	// Publish the screenshots to ASC via the proven delivery pipeline.
	endpoint := strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + appID + "/store-listing/publish"
	if _, err := postPreflightJSON(client, endpoint, token, map[string]any{"kind": "screenshots"}); err != nil {
		fmt.Fprintf(stderr, "publish screenshots failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "\nUploaded %d + published to ASC (kind=screenshots).\n", uploaded)
	return 0
}

func printScreenshotsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight apps screenshots --scheme <Scheme> --sim <udid> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Capture App Store screenshots on a simulator (Release build → boot → install → launch → Maestro).")
	fmt.Fprintln(w, "  --workspace-root <dir>   app repo root (default: cwd)")
	fmt.Fprintln(w, "  --package-path <rel>     path to the app package under the root")
	fmt.Fprintln(w, "  --scheme <name>          Xcode scheme to build (required)")
	fmt.Fprintln(w, "  --sim <udid>             booted/target simulator udid (required)")
	fmt.Fprintln(w, "  --bundle-id <id>         app bundle id (for install/launch)")
	fmt.Fprintln(w, "  --flow <flow.yaml>       per-app Maestro flow with takeScreenshot steps")
	fmt.Fprintln(w, "  --auth-token / --auth-workspace-id   baked into the Release build for signed-in captures")
	fmt.Fprintln(w, "  --status-bar-time <t>    status bar time override (default 9:41)")
	fmt.Fprintln(w, "  --app <app-id> --upload  push captures to the listing + publish kind=screenshots")
	fmt.Fprintln(w, "  --app <app-id>           also loads the stored capture recipe (scheme/flow/env defaults)")
	fmt.Fprintln(w, "  --save-recipe            store this run's inputs as the app's recipe")
	fmt.Fprintln(w, "  --display-type <t>       ASC display type tag for uploads (default APP_IPHONE_67)")
	fmt.Fprintln(w, "  --locale <l>             locale tag for uploads (default en-US)")
	fmt.Fprintln(w, "  --dry-run                print the capture plan without running it")
}
