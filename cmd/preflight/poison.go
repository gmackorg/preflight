package main

// P1 — store-build poison detection. Static checks that catch the classes that
// nearly shipped during the fleet screenshot campaign:
//   - app.config defaulting an API URL to localhost (daily-dose, playtrek)
//   - .env baking E2E/bypass flags or localhost URLs into every bundle
//     (latchflow's EXPO_PUBLIC_E2E_BYPASS_AUTH=1)
//   - expo SDK dependency skew (habitplay's expo 54 + expo-font 56 Hermes
//     crash, festigram's expo-camera 55 prebuilt symbol mismatch)
// Plus `apps scan-bundle`, which scans a built artifact's JS bundle directly.
//
// All findings start at `warn` (poisonGateSeverity) per the rollout plan; flip
// to doctorBroken once the fleet is clean for a couple of weeks.

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const poisonGateSeverity = doctorWarn

// localhost-defaulted API URLs in app config: `?? "http://localhost:3000"`,
// `|| 'http://127.0.0.1:8081'`, and *.localhost (emulate) hosts.
var configLocalhostDefaultRe = regexp.MustCompile(
	`(\?\?|\|\|)\s*["'` + "`" + `]https?://(localhost|127\.0\.0\.1)[^"'` + "`" + `]*["'` + "`" + `]`,
)
var configDotLocalhostRe = regexp.MustCompile(
	`["'` + "`" + `]https?://[a-zA-Z0-9.-]+\.localhost[^"'` + "`" + `]*["'` + "`" + `]`,
)

var envLineRe = regexp.MustCompile(`^\s*(EXPO_PUBLIC_[A-Z0-9_]+)\s*=\s*(.+?)\s*$`)
var envFlagKeyRe = regexp.MustCompile(`E2E|BYPASS|STUB|FAKE`)

// checkConfigPoison: app config + dotenv files that would bake dev state into
// a store bundle.
func checkConfigPoison(appDir string) []doctorFinding {
	var findings []doctorFinding

	for _, name := range []string{"app.config.ts", "app.config.js", "app.json"} {
		path := filepath.Join(appDir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		src := string(raw)
		if m := configLocalhostDefaultRe.FindString(src); m != "" {
			findings = append(findings, doctorFinding{
				Check: "config-poison", Severity: poisonGateSeverity,
				Message: name + " defaults an API URL to localhost — a store build " +
					"without the env baked ships a dead app; set the prod URL env at " +
					"build time and remove the localhost fallback",
				Detail: strings.TrimSpace(m),
			})
		}
		if m := configDotLocalhostRe.FindString(src); m != "" {
			findings = append(findings, doctorFinding{
				Check: "config-poison", Severity: poisonGateSeverity,
				Message: name + " references a *.localhost URL (local emulation) — " +
					"must not reach store builds",
				Detail: strings.TrimSpace(m),
			})
		}
		break // only the first config file that exists is the active one
	}

	// Expo CLI auto-loads dotenv files at bundle time; EXPO_PUBLIC_* values in
	// them are inlined into every build made from this checkout.
	for _, name := range []string{".env", ".env.local", ".env.production"} {
		path := filepath.Join(appDir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			m := envLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key, value := m[1], strings.Trim(m[2], `"'`)
			lower := strings.ToLower(value)
			if strings.Contains(lower, "localhost") ||
				strings.Contains(lower, "127.0.0.1") {
				findings = append(findings, doctorFinding{
					Check: "config-poison", Severity: poisonGateSeverity,
					Message: name + " bakes " + key + " with a localhost URL into " +
						"every bundle built from this checkout",
					Detail: key + "=" + value,
				})
			}
			if envFlagKeyRe.MatchString(key) &&
				(value == "1" || strings.EqualFold(value, "true")) {
				findings = append(findings, doctorFinding{
					Check: "config-poison", Severity: poisonGateSeverity,
					Message: name + " enables " + key + " — E2E/bypass stubs get " +
						"compiled into store builds from this checkout",
					Detail: key + "=" + value,
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, doctorFinding{
			Check: "config-poison", Severity: doctorOK,
			Message: "no localhost defaults or baked E2E flags in app config/.env",
		})
	}
	return findings
}

// Packages whose major version tracks the Expo SDK line since SDK 54. Mixing
// majors here is the class that shipped the habitplay Hermes bytecode crash
// and festigram's prebuilt ExpoCamera symbol mismatch.
var sdkAlignedPackages = []string{
	"expo-modules-core", "expo-camera", "expo-font", "expo-secure-store",
	"expo-constants", "expo-haptics", "expo-linking", "expo-splash-screen",
	"expo-sqlite", "expo-updates", "expo-file-system", "expo-notifications",
	"expo-device", "expo-crypto", "expo-blur", "expo-image", "expo-av",
	"expo-location", "expo-media-library", "expo-web-browser",
}

func semverMajor(spec string) int {
	s := strings.TrimLeft(strings.TrimSpace(spec), "^~=v")
	if i := strings.IndexAny(s, ".x"); i > 0 {
		s = s[:i]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// checkExpoSDKAlign: every SDK-aligned expo-* dependency must share expo's
// major. `npx expo install --fix` is the standard repair.
func checkExpoSDKAlign(appDir string) []doctorFinding {
	doc, err := readJSONMap(filepath.Join(appDir, "package.json"))
	if err != nil {
		return nil
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
	expoSpec, ok := deps["expo"]
	if !ok {
		return nil
	}
	sdkMajor := semverMajor(expoSpec)
	if sdkMajor < 54 {
		// Alignment guarantee only holds from SDK 54 onward.
		return nil
	}
	var mismatched []string
	for _, name := range sdkAlignedPackages {
		spec, present := deps[name]
		if !present {
			continue
		}
		if m := semverMajor(spec); m > 0 && m != sdkMajor {
			mismatched = append(mismatched,
				fmt.Sprintf("%s@%s (expo %d)", name, spec, sdkMajor))
		}
	}
	if len(mismatched) > 0 {
		return []doctorFinding{{
			Check: "expo-sdk-align", Severity: poisonGateSeverity,
			Message: "expo dependency majors don't match the SDK line — this is " +
				"the Hermes-crash / prebuilt-symbol-mismatch class; run " +
				"`npx expo install --fix` and commit",
			Detail: strings.Join(mismatched, ", "),
		}}
	}
	return []doctorFinding{{
		Check: "expo-sdk-align", Severity: doctorOK,
		Message: fmt.Sprintf("expo-* majors aligned with SDK %d", sdkMajor),
	}}
}

// --- apps scan-bundle -------------------------------------------------------

var bundlePoisonPatterns = []struct {
	pattern string
	message string
}{
	{"http://localhost", "bundle contains an http://localhost URL"},
	{"https://localhost", "bundle contains an https://localhost URL"},
	{"http://127.0.0.1", "bundle contains a 127.0.0.1 URL"},
	{".emulate.localhost", "bundle references the local emulation stack"},
	{"E2E_BYPASS", "bundle references an E2E bypass flag"},
	{"EXPO_PUBLIC_E2E", "bundle references an EXPO_PUBLIC_E2E flag"},
}

// scanBundleBytes reports which poison patterns appear in a JS bundle. Works
// on plain bundles and Hermes bytecode (string table survives as raw bytes).
func scanBundleBytes(data []byte) []doctorFinding {
	var findings []doctorFinding
	for _, p := range bundlePoisonPatterns {
		if idx := strings.Index(string(data), p.pattern); idx >= 0 {
			start := idx - 40
			if start < 0 {
				start = 0
			}
			end := idx + len(p.pattern) + 40
			if end > len(data) {
				end = len(data)
			}
			context := strings.Map(func(r rune) rune {
				if r < 32 || r > 126 {
					return '.'
				}
				return r
			}, string(data[start:end]))
			findings = append(findings, doctorFinding{
				Check: "bundle-poison", Severity: poisonGateSeverity,
				Message: p.message, Detail: context,
			})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, doctorFinding{
			Check: "bundle-poison", Severity: doctorOK,
			Message: "no poison patterns in bundle",
		})
	}
	return findings
}

// loadBundleFromArtifact accepts a main.jsbundle path, a built .app directory,
// or an .ipa and returns the JS bundle bytes.
func loadBundleFromArtifact(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return os.ReadFile(filepath.Join(path, "main.jsbundle"))
	}
	if strings.HasSuffix(path, ".ipa") || strings.HasSuffix(path, ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if filepath.Base(f.Name) == "main.jsbundle" {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, 256<<20))
			}
		}
		return nil, fmt.Errorf("no main.jsbundle inside %s", path)
	}
	return os.ReadFile(path)
}

func runAppsScanBundle(args []string, stdout, stderr io.Writer) int {
	var path string
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "Usage: preflight apps scan-bundle <main.jsbundle | Foo.app | build.ipa> [--json]")
			fmt.Fprintln(stdout, "Scan a built artifact's JS bundle for store-poison patterns (localhost URLs, E2E flags).")
			fmt.Fprintln(stdout, "Store/production artifacts only: dev-client builds legitimately contain Metro localhost URLs.")
			return 0
		default:
			if !strings.HasPrefix(args[i], "-") && path == "" {
				path = args[i]
			}
		}
	}
	if path == "" {
		fmt.Fprintln(stderr, "scan-bundle needs an artifact path (see --help)")
		return 2
	}
	data, err := loadBundleFromArtifact(path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-bundle: %v\n", err)
		return 1
	}
	findings := scanBundleBytes(data)
	if asJSON {
		out, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Fprintln(stdout, string(out))
	} else {
		for _, f := range findings {
			fmt.Fprintf(stdout, "[%s] %s: %s\n", doctorLabel(f.Severity), f.Check, f.Message)
			if f.Detail != "" {
				fmt.Fprintf(stdout, "        %s\n", f.Detail)
			}
		}
	}
	for _, f := range findings {
		if f.Severity != doctorOK {
			return 1
		}
	}
	return 0
}
