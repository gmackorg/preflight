package main

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readStoreFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "store-build", "project.pbxproj"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func fixturePlanTargets() []storeBuildIOSTarget {
	return []storeBuildIOSTarget{
		{TargetName: "StoreApp", BundleID: "com.example.storeapp", ProfileSecretReferenceID: "ref_profile_app", ProfileUUID: "AAAA-1111", ProfileName: "StoreApp AppStore"},
		{TargetName: "NotificationService", BundleID: "com.example.storeapp.NotificationService", ProfileSecretReferenceID: "ref_profile_nse", ProfileUUID: "BBBB-2222", ProfileName: "StoreApp NSE AppStore"},
	}
}

func TestParsePBXNativeTargetsReadsReleaseSettings(t *testing.T) {
	targets, err := parsePBXNativeTargets(readStoreFixture(t), "Release")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %d, want 3", len(targets))
	}
	byName := map[string]pbxNativeTarget{}
	for _, target := range targets {
		byName[target.Name] = target
	}
	app := byName["StoreApp"]
	if app.BundleID != "com.example.storeapp" || app.InfoPlist != "StoreApp/Info.plist" || app.Configurations["Release"] != "13B07F951A680F5B00A75B9A" {
		t.Fatalf("app target parsed wrong: %+v", app)
	}
	nse := byName["NotificationService"]
	if nse.InfoPlist != "$(SRCROOT)/NotificationService/Info.plist" || !signableProductType(nse.ProductType) {
		t.Fatalf("extension parsed wrong: %+v", nse)
	}
	if signableProductType(byName["SharedKit"].ProductType) {
		t.Fatal("frameworks are not signable targets")
	}
}

func TestMatchIOSSigningTargetsReportsExtensionWithoutProfile(t *testing.T) {
	targets, err := parsePBXNativeTargets(readStoreFixture(t), "Release")
	if err != nil {
		t.Fatal(err)
	}
	matched, missing := matchIOSSigningTargets(targets, fixturePlanTargets()[:1])
	if len(matched) != 1 {
		t.Fatalf("matched = %v", matched)
	}
	if strings.Join(missing, ",") != "com.example.storeapp.NotificationService" {
		t.Fatalf("missing = %v", missing)
	}
	_, missing = matchIOSSigningTargets(targets, fixturePlanTargets())
	if len(missing) != 0 {
		t.Fatalf("full plan still missing %v", missing)
	}
}

func TestPatchIOSProjectForStoreSigningSetsManualSigningPerTarget(t *testing.T) {
	content := readStoreFixture(t)
	targets, err := parsePBXNativeTargets(content, "Release")
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := matchIOSSigningTargets(targets, fixturePlanTargets())
	patched, err := patchIOSProjectForStoreSigning(content, targets, matched, "Release", "TEAM123456", "0123456789ABCDEF0123456789ABCDEF01234567", "1.4.0", "42")
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := parsePBXNativeTargets(patched, "Release")
	if err != nil {
		t.Fatalf("patched project no longer parses: %v", err)
	}
	if len(reparsed) != 3 {
		t.Fatalf("patched project lost targets")
	}

	appRelease := pbxBuildSettingsBody(t, patched, "13B07F951A680F5B00A75B9A")
	for key, want := range map[string]string{
		"CODE_SIGN_STYLE":  "Manual",
		"DEVELOPMENT_TEAM": "TEAM123456",
		// Pinned to the imported certificate, not the ambiguous name.
		"CODE_SIGN_IDENTITY":                "0123456789ABCDEF0123456789ABCDEF01234567",
		"CODE_SIGN_IDENTITY[sdk=iphoneos*]": "0123456789ABCDEF0123456789ABCDEF01234567",
		"PROVISIONING_PROFILE_SPECIFIER":    "StoreApp AppStore",
		"MARKETING_VERSION":                 "1.4.0",
		"CURRENT_PROJECT_VERSION":           "42",
		"PRODUCT_BUNDLE_IDENTIFIER":         "com.example.storeapp",
		"OTHER_SWIFT_FLAGS":                 "$(inherited) -D EXPO_CONFIGURATION_RELEASE",
	} {
		if got := pbxTopLevelValue(appRelease, key); got != want {
			t.Errorf("app Release %s = %q, want %q", key, got, want)
		}
	}
	if pbxTopLevelValue(appRelease, "PROVISIONING_PROFILE") != "" {
		t.Error("legacy PROVISIONING_PROFILE uuid must be removed")
	}
	if strings.Count(appRelease, "CODE_SIGN_IDENTITY =") != 1 {
		t.Errorf("CODE_SIGN_IDENTITY duplicated:\n%s", appRelease)
	}
	if !strings.Contains(appRelease, `"$(inherited)",`) {
		t.Error("list values must survive patching")
	}

	nseRelease := pbxBuildSettingsBody(t, patched, "BB0000000000000000000004")
	if got := pbxTopLevelValue(nseRelease, "PROVISIONING_PROFILE_SPECIFIER"); got != "StoreApp NSE AppStore" {
		t.Errorf("extension profile = %q", got)
	}
	if got := pbxTopLevelValue(nseRelease, "MARKETING_VERSION"); got != "1.4.0" {
		t.Errorf("extension version must match the app, got %q", got)
	}

	// Debug keeps its signing but gets the same version numbers.
	appDebug := pbxBuildSettingsBody(t, patched, "13B07F941A680F5B00A75B9A")
	if pbxTopLevelValue(appDebug, "CODE_SIGN_STYLE") != "" || pbxTopLevelValue(appDebug, "CURRENT_PROJECT_VERSION") != "42" {
		t.Errorf("Debug configuration patched wrong:\n%s", appDebug)
	}
	// Non-signable targets are untouched.
	if pbxTopLevelValue(pbxBuildSettingsBody(t, patched, "CC0000000000000000000004"), "MARKETING_VERSION") != "" {
		t.Error("framework target must not be patched")
	}
	// Recorded target attributes follow the build settings.
	if !strings.Contains(patched, "ProvisioningStyle = Manual;") || strings.Contains(patched, "ProvisioningStyle = Automatic;") {
		t.Error("TargetAttributes ProvisioningStyle not switched to Manual")
	}
	if strings.Contains(patched, "DevelopmentTeam = OLDTEAM123;") {
		t.Error("TargetAttributes DevelopmentTeam not updated")
	}
	// Idempotent: patching twice is a no-op.
	again, err := patchIOSProjectForStoreSigning(patched, reparsed, matched, "Release", "TEAM123456", "0123456789ABCDEF0123456789ABCDEF01234567", "1.4.0", "42")
	if err != nil || again != patched {
		t.Fatalf("second patch changed the project (err %v)", err)
	}
}

// releaseProductionFixture is the store fixture as a bare-workflow app with
// custom configurations has it: the app target archives "Release-production"
// (com.example.storeapp) while Debug builds com.example.storeapp.dev; the
// extension only has Debug/Release, so Xcode builds its default (Release).
func releaseProductionFixture(t *testing.T) string {
	t.Helper()
	content := readStoreFixture(t)
	setConfigName := func(configID string, from string, to string) {
		open, end, ok := pbxObjectRange(content, configID)
		if !ok || !strings.Contains(content[open:end], from) {
			t.Fatalf("fixture configuration %s lacks %q", configID, from)
		}
		content = content[:open] + strings.Replace(content[open:end], from, to, 1) + content[end:]
	}
	setConfigName("13B07F951A680F5B00A75B9A", "name = Release;", "name = Release-production;")
	setConfigName("13B07F941A680F5B00A75B9A", "PRODUCT_BUNDLE_IDENTIFIER = com.example.storeapp;", "PRODUCT_BUNDLE_IDENTIFIER = com.example.storeapp.dev;")
	return content
}

func TestStoreSigningFollowsTheArchivedConfiguration(t *testing.T) {
	content := releaseProductionFixture(t)
	targets, err := parsePBXNativeTargets(content, "Release-production")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]pbxNativeTarget{}
	for _, target := range targets {
		byName[target.Name] = target
	}
	if app := byName["StoreApp"]; app.BundleID != "com.example.storeapp" || app.InfoPlist != "StoreApp/Info.plist" {
		t.Fatalf("app target read the wrong configuration: %+v", app)
	}
	if nse := byName["NotificationService"]; nse.BundleID != "com.example.storeapp.NotificationService" {
		t.Fatalf("extension must fall back to its default configuration: %+v", nse)
	}
	matched, missing := matchIOSSigningTargets(targets, fixturePlanTargets())
	if len(missing) != 0 || len(matched) != 2 {
		t.Fatalf("matched %v, missing %v", matched, missing)
	}
	patched, err := patchIOSProjectForStoreSigning(content, targets, matched, "Release-production", "TEAM123456", "", "1.4.0", "42")
	if err != nil {
		t.Fatal(err)
	}
	production := pbxBuildSettingsBody(t, patched, "13B07F951A680F5B00A75B9A")
	if pbxTopLevelValue(production, "CODE_SIGN_STYLE") != "Manual" || pbxTopLevelValue(production, "PROVISIONING_PROFILE_SPECIFIER") != "StoreApp AppStore" {
		t.Fatalf("Release-production not signed:\n%s", production)
	}
	if debug := pbxBuildSettingsBody(t, patched, "13B07F941A680F5B00A75B9A"); pbxTopLevelValue(debug, "CODE_SIGN_STYLE") != "" {
		t.Fatalf("Debug must keep its signing:\n%s", debug)
	}
	if nse := pbxBuildSettingsBody(t, patched, "BB0000000000000000000004"); pbxTopLevelValue(nse, "PROVISIONING_PROFILE_SPECIFIER") != "StoreApp NSE AppStore" {
		t.Fatalf("extension default configuration not signed:\n%s", nse)
	}

	// The dev bundle id is what a Debug archive would have to sign.
	debugTargets, _ := parsePBXNativeTargets(content, "Debug")
	if _, missing := matchIOSSigningTargets(debugTargets, fixturePlanTargets()); strings.Join(missing, ",") != "com.example.storeapp.dev" {
		t.Fatalf("Debug archive missing = %v", missing)
	}
}

func pbxBuildSettingsBody(t *testing.T, content string, configID string) string {
	t.Helper()
	open, end, ok := pbxBuildSettingsRange(content, configID)
	if !ok {
		t.Fatalf("no buildSettings for %s", configID)
	}
	return content[open+1 : end-1]
}

func TestSetInfoPlistVersionReplacesAndAddsKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Info.plist")
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>1.0.0</string>
	<key>CFBundleName</key>
	<string>StoreApp</string>
</dict>
</plist>
`
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, err := setInfoPlistVersion(path, "2.0.1", "77")
	if err != nil || !ok {
		t.Fatalf("setInfoPlistVersion = %v, %v", ok, err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	if !strings.Contains(text, "<key>CFBundleShortVersionString</key>\n\t<string>2.0.1</string>") || !strings.Contains(text, "<key>CFBundleVersion</key>\n\t<string>77</string>") {
		t.Fatalf("plist not patched:\n%s", text)
	}
	assertWellFormedXML(t, raw)

	// Build-setting references are left for MARKETING_VERSION to resolve.
	reference := strings.Replace(plist, "<string>1.0.0</string>", "<string>$(MARKETING_VERSION)</string>", 1)
	_ = os.WriteFile(path, []byte(reference), 0o644)
	if _, err := setInfoPlistVersion(path, "2.0.1", "77"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), "$(MARKETING_VERSION)") {
		t.Fatal("build setting reference was overwritten")
	}

	_ = os.WriteFile(path, []byte("bplist00binary"), 0o644)
	if ok, err := setInfoPlistVersion(path, "2.0.1", "77"); ok || err != nil {
		t.Fatalf("binary plist should report not-XML, got %v %v", ok, err)
	}
}

func TestResolveInfoPlistPath(t *testing.T) {
	if got := resolveInfoPlistPath("/x/ios", "$(SRCROOT)/NSE/Info.plist"); got != "/x/ios/NSE/Info.plist" {
		t.Fatalf("got %q", got)
	}
	if got := resolveInfoPlistPath("/x/ios", "App/Info.plist"); got != "/x/ios/App/Info.plist" {
		t.Fatalf("got %q", got)
	}
	if got := resolveInfoPlistPath("/x/ios", "$(TARGET_NAME)/Info.plist"); got != "" {
		t.Fatalf("unresolvable variable should be skipped, got %q", got)
	}
}

func TestIOSExportOptionsPlist(t *testing.T) {
	raw := iosExportOptionsPlist("app-store-connect", "TEAM123456", "ABCDEF", map[string]string{
		"com.example.storeapp.NotificationService": "StoreApp NSE AppStore",
		"com.example.storeapp":                     "StoreApp & Co",
	})
	assertWellFormedXML(t, raw)
	text := string(raw)
	for _, want := range []string{
		"<key>method</key>\n\t<string>app-store-connect</string>",
		"<key>teamID</key>\n\t<string>TEAM123456</string>",
		"<key>signingStyle</key>\n\t<string>manual</string>",
		"<key>signingCertificate</key>\n\t<string>ABCDEF</string>",
		"<key>uploadSymbols</key>\n\t<true/>",
		"<key>manageAppVersionAndBuildNumber</key>\n\t<false/>",
		"\t\t<key>com.example.storeapp</key>\n\t\t<string>StoreApp &amp; Co</string>",
		"\t\t<key>com.example.storeapp.NotificationService</key>\n\t\t<string>StoreApp NSE AppStore</string>",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("ExportOptions.plist missing %q:\n%s", want, text)
		}
	}
	if iosExportMethod(storeBuildPlan{Lane: "internal"}) != "release-testing" || iosExportMethod(storeBuildPlan{Lane: "store"}) != "app-store-connect" {
		t.Error("lane fallback export methods wrong")
	}
	if iosExportMethod(storeBuildPlan{Lane: "internal", IOS: &storeBuildIOSPlan{ExportMethod: "app-store-connect"}}) != "app-store-connect" {
		t.Error("plan export method must win over the lane")
	}
}

func assertWellFormedXML(t *testing.T, raw []byte) {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	decoder.Strict = true
	for {
		if _, err := decoder.Token(); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("not well-formed XML: %v\n%s", err, raw)
		}
	}
}

func TestStoreDeploymentTargetUsesSignedTargetsArchiveConfiguration(t *testing.T) {
	content := readStoreFixture(t)
	targets, err := parsePBXNativeTargets(content, "Release")
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := matchIOSSigningTargets(targets, fixturePlanTargets())
	if got := storeDeploymentTarget(content, targets, matched, "Release"); got != "15.1" {
		t.Fatalf("deployment target = %q, want 15.1", got)
	}
	if got := storeDeploymentTarget(content, targets, map[string]storeBuildIOSTarget{}, "Release"); got != "" {
		t.Fatalf("no signed targets should give no override, got %q", got)
	}
}

func TestCompareVersionStrings(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"15.1", "15.10", -1}, {"16.0", "15.4", 1}, {"15.1", "15.1.0", 0}} {
		if got := compareVersionStrings(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
