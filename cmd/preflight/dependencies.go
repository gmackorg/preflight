package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// depSnapshot is a per-app Expo dependency snapshot for fleet SDK/plugin
// tracking. It captures what `expo-sdk-align` computes transiently plus the
// full plugin + expo/react-native package set, so the fleet can see SDK drift
// and plugin/native-module skew at a glance — the class of failure that
// otherwise costs a ~45-minute iOS build to discover.
type depSnapshot struct {
	AppDir       string            `json:"appDir"`
	Repo         string            `json:"repo,omitempty"`
	ExpoSDK      string            `json:"expoSdk"`
	ExpoMajor    int               `json:"expoMajor"`
	ReactNative  string            `json:"reactNative,omitempty"`
	Plugins      []string          `json:"plugins,omitempty"`
	ExpoPackages map[string]string `json:"expoPackages,omitempty"` // expo-* / @expo/*
	RNPackages   map[string]string `json:"rnPackages,omitempty"`   // react-native / react-native-*
	Drift        []string          `json:"drift,omitempty"`        // pkgs whose major != expo's
}

var (
	// Grab the first `plugins` array body from an app config. `[^\n]*?` before
	// the `[:=]` tolerates a TypeScript type annotation, so the typed template
	// form `const plugins: ExpoConfig["plugins"] = [` matches as well as the
	// plain `plugins: [` / `plugins = [`.
	appConfigPluginsRe = regexp.MustCompile(`(?s)plugins\b[^\n]*?[:=]\s*\[(.*?)\]`)
	pluginStringRe     = regexp.MustCompile(`["']([@a-zA-Z0-9/_.-]+)["']`)
)

// readAppDeps merges an app's dependencies + devDependencies into one map.
func readAppDeps(appDir string) (map[string]string, error) {
	doc, err := readJSONMap(filepath.Join(appDir, "package.json"))
	if err != nil {
		return nil, err
	}
	deps := map[string]string{}
	for _, key := range []string{"dependencies", "devDependencies"} {
		if section, ok := doc[key].(map[string]any); ok {
			for name, v := range section {
				if spec, ok := v.(string); ok {
					deps[name] = spec
				}
			}
		}
	}
	return deps, nil
}

// extractExpoPlugins pulls the config-plugin identifiers out of the first
// `plugins` array in app.config.*/app.json. It intentionally ignores plugin
// option objects and keeps only the plugin package names.
func extractExpoPlugins(appDir string) []string {
	for _, name := range []string{"app.config.ts", "app.config.js", "app.json"} {
		raw, err := os.ReadFile(filepath.Join(appDir, name))
		if err != nil {
			continue
		}
		m := appConfigPluginsRe.FindSubmatch(raw)
		if m == nil {
			continue
		}
		seen := map[string]bool{}
		var plugins []string
		for _, pm := range pluginStringRe.FindAllSubmatch(m[1], -1) {
			p := string(pm[1])
			// Keep only package-name-shaped strings: a config plugin is either
			// scoped ("@sentry/react-native") or hyphenated ("expo-router").
			// This drops plugin option-object keys/values (e.g. camelCase
			// "backgroundColor", asset paths, hex colors) that share the array.
			if !strings.HasPrefix(p, "@") && !strings.Contains(p, "-") {
				continue
			}
			if strings.Contains(p, "/") && !strings.HasPrefix(p, "@") {
				continue // asset path like ./assets/x-y.png
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			plugins = append(plugins, p)
		}
		if len(plugins) > 0 {
			sort.Strings(plugins)
			return plugins
		}
	}
	return nil
}

// snapshotAppDeps builds a dependency snapshot from an app's package.json +
// app config. Returns nil (no error) for a directory that has no `expo`
// dependency, so callers can skip non-Expo apps.
func snapshotAppDeps(appDir string) (*depSnapshot, error) {
	deps, err := readAppDeps(appDir)
	if err != nil {
		return nil, err
	}
	expoSpec, ok := deps["expo"]
	if !ok {
		return nil, nil
	}
	snap := &depSnapshot{
		AppDir:       filepath.Clean(appDir),
		ExpoSDK:      expoSpec,
		ExpoMajor:    semverMajor(expoSpec),
		ReactNative:  deps["react-native"],
		Plugins:      extractExpoPlugins(appDir),
		ExpoPackages: map[string]string{},
		RNPackages:   map[string]string{},
	}
	for name, spec := range deps {
		switch {
		case name == "expo":
			// captured as ExpoSDK
		case strings.HasPrefix(name, "expo-") || strings.HasPrefix(name, "@expo/"):
			snap.ExpoPackages[name] = spec
			if m := semverMajor(spec); m > 0 && snap.ExpoMajor > 0 && m != snap.ExpoMajor {
				snap.Drift = append(snap.Drift,
					fmt.Sprintf("%s@%s (expo %d)", name, spec, snap.ExpoMajor))
			}
		case name == "react-native" || strings.HasPrefix(name, "react-native-"):
			snap.RNPackages[name] = spec
		}
	}
	sort.Strings(snap.Drift)
	return snap, nil
}

// reportDepsSnapshot POSTs a snapshot to the app's dependencies route so it
// persists on the fleet board (append-only history for SDK drift over time).
func reportDepsSnapshot(client *http.Client, appID string, snap *depSnapshot) error {
	apiURL, token := preflightAPIConfig()
	if apiURL == "" || token == "" {
		return fmt.Errorf("no Preflight API url/token (set PREFLIGHT_API_URL/PREFLIGHT_TOKEN or run `preflight config`)")
	}
	payload := map[string]any{
		"expoSdk":      snap.ExpoSDK,
		"expoMajor":    snap.ExpoMajor,
		"reactNative":  snap.ReactNative,
		"plugins":      snap.Plugins,
		"expoPackages": snap.ExpoPackages,
		"rnPackages":   snap.RNPackages,
		"drift":        snap.Drift,
	}
	endpoint := strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/dependencies"
	_, err := postPreflightJSON(client, endpoint, token, payload)
	return err
}

func runAppsDeps(args []string, stdout io.Writer, stderr io.Writer, client *http.Client) int {
	path, root, appID := "", "", ""
	asJSON, all, doReport := false, false, false
	target := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "--root":
			if i+1 < len(args) {
				root = args[i+1]
				i++
			}
		case "--app":
			if i+1 < len(args) {
				appID = args[i+1]
				i++
			}
		case "--report":
			doReport = true
		case "--all":
			all = true
		case "--json":
			asJSON = true
		case "--target":
			if i+1 < len(args) {
				target = semverMajor(args[i+1])
				i++
			}
		case "--help", "-h":
			printAppsDepsHelp(stdout)
			return 0
		}
	}

	var appDirs []string
	switch {
	case path != "":
		appDirs = []string{path}
	default:
		if root == "" {
			if all {
				if cwd, err := os.Getwd(); err == nil {
					root = cwd
				} else {
					root = "."
				}
			} else {
				fmt.Fprintln(stderr, "apps deps: pass --path <app-dir>, or --all [--root <dir>] to sweep a fleet")
				printAppsDepsHelp(stderr)
				return 2
			}
		}
		appDirs = findEASAppDirs(root)
	}

	var snaps []*depSnapshot
	for _, dir := range appDirs {
		snap, err := snapshotAppDeps(dir)
		if err != nil {
			fmt.Fprintf(stderr, "warn: %s: %v\n", dir, err)
			continue
		}
		if snap == nil {
			continue // not an Expo app
		}
		if root != "" {
			snap.Repo = repoNameUnderRoot(root, dir)
		}
		snaps = append(snaps, snap)
	}
	sort.Slice(snaps, func(i, j int) bool {
		if snaps[i].Repo != snaps[j].Repo {
			return snaps[i].Repo < snaps[j].Repo
		}
		return snaps[i].AppDir < snaps[j].AppDir
	})

	if doReport {
		if appID == "" {
			fmt.Fprintln(stderr, "apps deps --report needs --app <id> (single-app reporting; fleet-wide auto-mapping is not yet wired)")
			return 2
		}
		if len(snaps) != 1 {
			fmt.Fprintf(stderr, "apps deps --report --app expects exactly one Expo app (found %d); scope it with --path <app-dir>\n", len(snaps))
			return 2
		}
		if err := reportDepsSnapshot(client, appID, snaps[0]); err != nil {
			fmt.Fprintf(stderr, "report failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "reported dependency snapshot for app %s (expo %s)\n", appID, snaps[0].ExpoSDK)
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"target": target, "apps": snaps})
		return depsExitCode(snaps, target)
	}
	renderDepsTable(stdout, snaps, target)
	return depsExitCode(snaps, target)
}

// depsExitCode is 1 when any app has declared drift or lags the --target SDK,
// so the command can gate CI / cron the way the other doctor sweeps do.
func depsExitCode(snaps []*depSnapshot, target int) int {
	for _, s := range snaps {
		if len(s.Drift) > 0 {
			return 1
		}
		if target > 0 && s.ExpoMajor > 0 && s.ExpoMajor < target {
			return 1
		}
	}
	return 0
}

func renderDepsTable(w io.Writer, snaps []*depSnapshot, target int) {
	if len(snaps) == 0 {
		fmt.Fprintln(w, "No Expo apps found.")
		return
	}
	label := func(s *depSnapshot) string {
		if s.Repo != "" {
			return s.Repo
		}
		return filepath.Base(s.AppDir)
	}
	width := len("APP")
	for _, s := range snaps {
		if l := len(label(s)); l > width {
			width = l
		}
	}
	fmt.Fprintf(w, "%-*s  %-9s  %-11s  %-8s  %s\n",
		width, "APP", "EXPO", "REACT-NATIVE", "PLUGINS", "DRIFT")
	spread := map[int]int{}
	lagging, drifting := 0, 0
	for _, s := range snaps {
		spread[s.ExpoMajor]++
		flag := ""
		if target > 0 && s.ExpoMajor > 0 && s.ExpoMajor < target {
			flag = fmt.Sprintf("  ⤺ below SDK %d", target)
			lagging++
		}
		driftCell := "-"
		if len(s.Drift) > 0 {
			driftCell = fmt.Sprintf("%d ⚠", len(s.Drift))
			drifting++
		}
		rn := s.ReactNative
		if rn == "" {
			rn = "-"
		}
		fmt.Fprintf(w, "%-*s  %-9s  %-11s  %-8d  %s%s\n",
			width, label(s), s.ExpoSDK, rn, len(s.Plugins), driftCell, flag)
	}
	fmt.Fprintln(w)
	// SDK spread summary
	majors := make([]int, 0, len(spread))
	for m := range spread {
		majors = append(majors, m)
	}
	sort.Ints(majors)
	var parts []string
	for _, m := range majors {
		mm := fmt.Sprintf("SDK %d", m)
		if m <= 0 {
			mm = "SDK ?"
		}
		parts = append(parts, fmt.Sprintf("%s×%d", mm, spread[m]))
	}
	fmt.Fprintf(w, "%d Expo app(s): %s\n", len(snaps), strings.Join(parts, ", "))
	if drifting > 0 {
		fmt.Fprintf(w, "%d app(s) with declared expo-package major drift (see --json for the packages).\n", drifting)
	}
	if target > 0 && lagging > 0 {
		fmt.Fprintf(w, "%d app(s) below target SDK %d.\n", lagging, target)
	}
	if drifting == 0 && lagging == 0 {
		fmt.Fprintln(w, "No declared drift.")
	}
}

func printAppsDepsHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  preflight apps deps --path <app-dir> [--json]")
	fmt.Fprintln(w, "  preflight apps deps --all [--root <dir>] [--target <sdk>] [--json]")
	fmt.Fprintln(w, "  preflight apps deps --path <app-dir> --app <app-id> --report   persist a snapshot to the board")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Snapshot each Expo app's SDK version, config plugins, and expo-*/@expo/*")
	fmt.Fprintln(w, "/react-native-* package versions, and flag SDK drift across the fleet.")
	fmt.Fprintln(w, "  --target <sdk>  flag apps whose expo major is below this SDK (e.g. 56)")
	fmt.Fprintln(w, "Exits 1 when any app has declared expo-package major drift or lags --target.")
}
