package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDoctorFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSentryUpload_FlagsUncoveredProfileFollowingExtends(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "package.json", `{"dependencies":{"@sentry/react-native":"5.0.0"}}`)
	// production inherits the disable via extends->base; preview does not; base
	// is the conventional shared profile and must not be flagged.
	writeDoctorFile(t, dir, "eas.json", `{
	  "build": {
	    "base": { "env": { "SENTRY_DISABLE_AUTO_UPLOAD": "true" } },
	    "production": { "extends": "base", "env": {} },
	    "preview": { "env": {} }
	  }
	}`)
	findings := checkSentryUpload(dir)
	if len(findings) != 1 || findings[0].Severity != doctorWarn || !findings[0].Fixable {
		t.Fatalf("expected 1 fixable warn, got %+v", findings)
	}
	msg := findings[0].Message
	if !strings.Contains(msg, "preview") || strings.Contains(msg, "production") || strings.Contains(msg, "base") {
		t.Fatalf("expected only preview flagged, got %q", msg)
	}
}

func TestCheckSentryUpload_OkWhenNoSentryDep(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "package.json", `{"dependencies":{}}`)
	writeDoctorFile(t, dir, "eas.json", `{"build":{"production":{"env":{}}}}`)
	findings := checkSentryUpload(dir)
	if len(findings) != 1 || findings[0].Severity != doctorOK {
		t.Fatalf("expected ok when no @sentry/react-native, got %+v", findings)
	}
}

func TestCheckEASJson_RequiresProductionProfile(t *testing.T) {
	ok := t.TempDir()
	writeDoctorFile(t, ok, "eas.json", `{"build":{"production":{}}}`)
	if f := checkEASJson(ok); f[0].Severity != doctorOK {
		t.Fatalf("expected ok, got %+v", f)
	}
	missing := t.TempDir()
	writeDoctorFile(t, missing, "eas.json", `{"build":{"preview":{}}}`)
	if f := checkEASJson(missing); f[0].Severity != doctorBroken {
		t.Fatalf("expected broken (no production profile), got %+v", f)
	}
	none := t.TempDir()
	if f := checkEASJson(none); f[0].Severity != doctorBroken {
		t.Fatalf("expected broken (no eas.json), got %+v", f)
	}
}

func TestDoctorWorstSeverity(t *testing.T) {
	cases := []struct {
		in   []doctorFinding
		want doctorSeverity
	}{
		{nil, doctorOK},
		{[]doctorFinding{{Severity: doctorOK}, {Severity: doctorWarn}}, doctorWarn},
		{[]doctorFinding{{Severity: doctorWarn}, {Severity: doctorBroken}}, doctorBroken},
	}
	for _, c := range cases {
		if got := doctorWorstSeverity(c.in); got != c.want {
			t.Fatalf("worst(%+v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestCheckReactPin_FlagsOverrideMismatch(t *testing.T) {
	root := t.TempDir()
	writeDoctorFile(t, root, "pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
	writeDoctorFile(t, root, "package.json", `{"pnpm":{"overrides":{"react":"19.2.3","react-dom":"19.2.3"}}}`)
	if err := os.MkdirAll(filepath.Join(root, "packages", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, filepath.Join(root, "packages", "app"), "package.json", `{"dependencies":{"react":"19.2.7"}}`)
	f := checkReactPin(root)
	if len(f) != 1 || f[0].Severity != doctorWarn {
		t.Fatalf("expected warn, got %+v", f)
	}
	if !strings.Contains(f[0].Detail, "19.2.7") {
		t.Fatalf("expected mismatch detail, got %q", f[0].Detail)
	}
}

func TestCheckReactPin_OkWhenConsistentIgnoringRange(t *testing.T) {
	root := t.TempDir()
	writeDoctorFile(t, root, "pnpm-workspace.yaml", "packages:\n")
	writeDoctorFile(t, root, "package.json", `{"pnpm":{"overrides":{"react":"19.2.3"}}}`)
	if err := os.MkdirAll(filepath.Join(root, "packages", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, filepath.Join(root, "packages", "app"), "package.json", `{"dependencies":{"react":"^19.2.3"}}`)
	f := checkReactPin(root)
	if len(f) != 1 || f[0].Severity != doctorOK {
		t.Fatalf("expected ok (^19.2.3 == 19.2.3), got %+v", f)
	}
}

func TestFixSentryUpload_AddsFlagFollowingExtends(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "eas.json", `{"build":{"base":{"env":{"SENTRY_DISABLE_AUTO_UPLOAD":"true"}},"production":{"extends":"base"},"preview":{"env":{"APP_VARIANT":"preview"}}}}`)
	msg, err := fixSentryUpload(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "1 ") {
		t.Fatalf("expected 1 profile fixed, got %q", msg)
	}
	doc, _ := readJSONMap(filepath.Join(dir, "eas.json"))
	build := doc["build"].(map[string]any)
	prev := build["preview"].(map[string]any)["env"].(map[string]any)
	if prev["SENTRY_DISABLE_AUTO_UPLOAD"] != "true" || prev["APP_VARIANT"] != "preview" {
		t.Fatalf("preview env wrong after fix: %+v", prev)
	}
	if _, hasEnv := build["production"].(map[string]any)["env"]; hasEnv {
		t.Fatalf("production should stay untouched (inherits via extends)")
	}
}

func TestNormalizeGitRemote_BridgesSSHAndHTTPS(t *testing.T) {
	// ssh and https clone URLs of the same repo must normalize identically,
	// and a checkout must match its fleet record across protocols.
	cases := []struct{ in, want string }{
		{"git@github.com:gmackie/palantir-for-family-trips.git", "github.com/gmackie/palantir-for-family-trips"},
		{"https://github.com/gmackie/palantir-for-family-trips.git", "github.com/gmackie/palantir-for-family-trips"},
		{"https://github.com/gmackie/palantir-for-family-trips", "github.com/gmackie/palantir-for-family-trips"},
		{"git@git.forgegraf.com:gmackie/habitplay.git", "git.forgegraf.com/gmackie/habitplay"},
		{"ssh://git@git.forgegraf.com/gmackie/habitplay.git", "git.forgegraf.com/gmackie/habitplay"},
		{"", ""},
		{"not-a-remote", ""},
	}
	for _, c := range cases {
		if got := normalizeGitRemote(c.in); got != c.want {
			t.Errorf("normalizeGitRemote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// The whole point: differing protocols still collide on one key.
	if normalizeGitRemote("git@github.com:gmackie/habit.git") == normalizeGitRemote("git@git.forgegraf.com:gmackie/habitplay.git") {
		t.Error("distinct repos must not normalize equal")
	}
}

func TestPRCompareURL_GithubAndForgejo(t *testing.T) {
	cases := []struct{ url, want string }{
		{"git@github.com:gmackie/habit.git", "https://github.com/gmackie/habit/compare/preflight/doctor-fix?expand=1"},
		{"https://github.com/gmackie/habit.git", "https://github.com/gmackie/habit/compare/preflight/doctor-fix?expand=1"},
		{"git@git.forgegraf.com:gmackie/habitplay.git", "https://git.forgegraf.com/gmackie/habitplay/compare/main...preflight/doctor-fix"},
	}
	for _, c := range cases {
		if got := prCompareURL(c.url, "preflight/doctor-fix"); got != c.want {
			t.Errorf("prCompareURL(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestCheckPodsCodegen_SkipsWhenNotPrebuilt(t *testing.T) {
	// A managed-workflow app has no ios/ directory; there is nothing to be
	// stale, and warning here would fire on most of the fleet.
	dir := t.TempDir()
	writeDoctorFile(t, dir, "package.json", `{"dependencies":{"expo":"~56.0.0"}}`)
	if f := checkPodsCodegen(dir); f != nil {
		t.Fatalf("expected no findings without ios/, got %+v", f)
	}
}

func TestCheckPodsCodegen_BrokenWhenPodsNeverInstalled(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "ios/Podfile", "platform :ios")
	f := checkPodsCodegen(dir)
	if len(f) != 1 || f[0].Severity != doctorBroken || !f[0].Fixable {
		t.Fatalf("expected fixable broken, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "pod install") {
		t.Fatalf("message should name the remedy, got %q", f[0].Message)
	}
}

func TestCheckPodsCodegen_BrokenWhenCodegenOutputMissing(t *testing.T) {
	// The exact failure seen on five repos: Pods are installed but the
	// generated ReactCodegen tree was wiped (clean, branch switch, SSD churn),
	// so xcodebuild dies on "Build input file cannot be found: …-generated.mm".
	dir := t.TempDir()
	writeDoctorFile(t, dir, "ios/Podfile", "platform :ios")
	writeDoctorFile(t, dir, "ios/Podfile.lock", "COCOAPODS: 1.15.2")
	writeDoctorFile(t, dir, "ios/Pods/Manifest.lock", "COCOAPODS: 1.15.2")
	f := checkPodsCodegen(dir)
	if len(f) != 1 || f[0].Severity != doctorBroken || !f[0].Fixable {
		t.Fatalf("expected fixable broken for missing codegen, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "codegen") {
		t.Fatalf("expected codegen in message, got %q", f[0].Message)
	}
}

func TestCheckPodsCodegen_BrokenWhenManifestDivergesFromLock(t *testing.T) {
	// Pods/Manifest.lock != Podfile.lock is CocoaPods' own definition of
	// "sandbox is out of sync" — the build fails in a different, less obvious
	// place, so catch it here.
	dir := t.TempDir()
	writeDoctorFile(t, dir, "ios/Podfile", "platform :ios")
	writeDoctorFile(t, dir, "ios/Podfile.lock", "COCOAPODS: 1.15.2")
	writeDoctorFile(t, dir, "ios/Pods/Manifest.lock", "COCOAPODS: 1.14.0")
	writeDoctorFile(t, dir, "ios/build/generated/ios/ReactCodegen/x-generated.mm", "//")
	f := checkPodsCodegen(dir)
	if len(f) != 1 || f[0].Severity != doctorBroken {
		t.Fatalf("expected broken for manifest drift, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "out of sync") {
		t.Fatalf("expected out-of-sync message, got %q", f[0].Message)
	}
}

func TestCheckPodsCodegen_OkWhenInstalledAndGenerated(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "ios/Podfile", "platform :ios")
	writeDoctorFile(t, dir, "ios/Podfile.lock", "COCOAPODS: 1.15.2")
	writeDoctorFile(t, dir, "ios/Pods/Manifest.lock", "COCOAPODS: 1.15.2")
	writeDoctorFile(t, dir, "ios/build/generated/ios/ReactCodegen/safeareacontext/safeareacontext-generated.mm", "//")
	f := checkPodsCodegen(dir)
	if len(f) != 1 || f[0].Severity != doctorOK {
		t.Fatalf("expected ok, got %+v", f)
	}
}

func TestCheckWorkspaceDist_FlagsUnbuiltRuntimeDependency(t *testing.T) {
	// daily-dose: @dailydose/config resolves at runtime to ./dist/index.js,
	// which was never built, so Metro fails mid-bundle ~15 minutes into the
	// native build with an opaque "unable to resolve module" error.
	dir := t.TempDir()
	root := filepath.Dir(filepath.Dir(dir))
	_ = root
	writeDoctorFile(t, dir, "apps/expo/package.json",
		`{"dependencies":{"@dd/config":"workspace:*"}}`)
	writeDoctorFile(t, dir, "packages/config/package.json",
		`{"name":"@dd/config","exports":{".":{"types":"./dist/index.d.ts","default":"./dist/index.js"}}}`)
	f := checkWorkspaceDist(filepath.Join(dir, "apps/expo"))
	if len(f) != 1 || f[0].Severity != doctorBroken || !f[0].Fixable {
		t.Fatalf("expected fixable broken, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "@dd/config") {
		t.Fatalf("expected the package named, got %q", f[0].Message)
	}
}

func TestCheckWorkspaceDist_IgnoresSourceResolvingPackages(t *testing.T) {
	// analytics/i18n/monitoring point `default` at ./src/index.ts and only
	// reference dist under `types`. They need no build to bundle, and flagging
	// them would be a false positive on most of the fleet.
	dir := t.TempDir()
	writeDoctorFile(t, dir, "apps/expo/package.json",
		`{"dependencies":{"@dd/analytics":"workspace:*"}}`)
	writeDoctorFile(t, dir, "packages/analytics/package.json",
		`{"name":"@dd/analytics","exports":{".":{"types":"./dist/index.d.ts","default":"./src/index.ts"}}}`)
	f := checkWorkspaceDist(filepath.Join(dir, "apps/expo"))
	if len(f) != 1 || f[0].Severity != doctorOK {
		t.Fatalf("expected ok for source-resolving package, got %+v", f)
	}
}

func TestCheckWorkspaceDist_OkWhenBuilt(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "apps/expo/package.json",
		`{"dependencies":{"@dd/config":"workspace:*"}}`)
	writeDoctorFile(t, dir, "packages/config/package.json",
		`{"name":"@dd/config","exports":{".":{"default":"./dist/index.js"}}}`)
	writeDoctorFile(t, dir, "packages/config/dist/index.js", "export {}")
	f := checkWorkspaceDist(filepath.Join(dir, "apps/expo"))
	if len(f) != 1 || f[0].Severity != doctorOK {
		t.Fatalf("expected ok, got %+v", f)
	}
}

func TestCheckWorkspaceDist_SkipsNonWorkspaceApp(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, dir, "package.json", `{"dependencies":{"expo":"~56.0.0"}}`)
	if f := checkWorkspaceDist(dir); f != nil {
		t.Fatalf("expected no findings without workspace deps, got %+v", f)
	}
}
