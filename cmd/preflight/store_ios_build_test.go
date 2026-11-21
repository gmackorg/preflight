package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type iosBuildFixture struct {
	t        *testing.T
	runtime  *storeJobRuntime
	runner   *fakeStoreRunner
	security *fakeSecurity
	certDER  []byte
	certSHA1 string
	plan     storeBuildPlan
	secrets  map[string]string
	// Observations made while xcodebuild archive "ran".
	archiveSawProfiles bool
	archiveSawKeychain bool
	archiveErr         error
	exportErr          error
	codesignTeam       string
}

func profilePayload(uuid, name, bundleID string) string {
	return fmt.Sprintf(`{"profileBase64":%q,"uuid":%q,"name":%q,"bundleId":%q,"profileType":"IOS_APP_STORE","teamId":"TEAM123456","certificateSerialNumbers":["5E1A1"],"expiresAt":%q}`,
		b64("profile-"+uuid), uuid, name, bundleID, time.Now().Add(240*time.Hour).UTC().Format(time.RFC3339))
}

func newIOSBuildFixture(t *testing.T) *iosBuildFixture {
	t.Setenv("PREFLIGHT_SIGNING_WWDR_PEM", "")
	der, sha := testCertificateDER(t)
	fixture := &iosBuildFixture{t: t, certDER: der, certSHA1: sha, codesignTeam: "TEAM123456"}
	fixture.security = newFakeSecurity(sha)
	fixture.secrets = map[string]string{
		"ref_cert": fmt.Sprintf(`{"p12Base64":%q,"p12Password":"p12-secret-password","serialNumber":"5E1A1","sha1Fingerprint":%q,"teamId":"TEAM123456","expiresAt":%q}`,
			b64("p12-bytes"), sha, time.Now().Add(240*time.Hour).UTC().Format(time.RFC3339)),
		"ref_profile_app": profilePayload("AAAA-1111", "StoreApp AppStore", "com.example.storeapp"),
		"ref_profile_nse": profilePayload("BBBB-2222", "StoreApp NSE AppStore", "com.example.storeapp.NotificationService"),
		"ref_env":         "sentry-auth-token-value",
	}
	fixture.plan = storeBuildPlan{
		AppID: "app_1", BuildID: "build_1", Platform: "ios", Lane: "store", Version: "1.4.0", BuildNumber: "42",
		Environment:                   map[string]string{"APP_VARIANT": "production"},
		SecretEnvironmentReferenceIDs: []string{"ref_env"},
		IOS: &storeBuildIOSPlan{
			TeamID: "TEAM123456", Configuration: "Release", ExportMethod: "app-store-connect",
			CertificateSecretReferenceID: "ref_cert",
			Targets:                      fixturePlanTargets(),
		},
	}
	fixture.runner = &fakeStoreRunner{handle: fixture.handle}
	fixture.runtime, _ = newTestStoreRuntime(t, fixture.runner, fixture.secrets)
	fixture.runtime.reveal = secretMapRevealer(fixture.secrets, map[string]string{"ref_env": "SENTRY_AUTH_TOKEN"})
	fixture.runtime.fetchWWDR = func() []byte { return []byte("-----BEGIN CERTIFICATE-----\nWWDR\n-----END CERTIFICATE-----\n") }
	return fixture
}

func argAfter(args []string, flag string) string {
	for index, arg := range args {
		if arg == flag && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func (fixture *iosBuildFixture) profilePaths(uuid string) []string {
	paths := []string{}
	for _, dir := range iosProvisioningProfileDirs(fixture.runtime.homeDir) {
		paths = append(paths, filepath.Join(dir, uuid+".mobileprovision"))
	}
	return paths
}

func (fixture *iosBuildFixture) handle(command storeCommand) ([]byte, error) {
	t := fixture.t
	appDir := fixture.runtime.appDir
	iosDir := filepath.Join(appDir, "ios")
	switch {
	case command.Name == "security":
		return fixture.security.handle(command)
	case command.Name == "npx":
		if strings.Join(command.Args, " ") != "expo prebuild --platform ios --clean --no-install" {
			t.Errorf("prebuild args = %v", command.Args)
		}
		env := strings.Join(command.Env, "\n")
		if !strings.Contains(env, "APP_VARIANT=production") || !strings.Contains(env, "SENTRY_AUTH_TOKEN=sentry-auth-token-value") {
			t.Errorf("prebuild env lacks plan or secret environment")
		}
		mustWrite(t, filepath.Join(iosDir, "StoreApp.xcodeproj", "project.pbxproj"), readStoreFixture(t))
		mustMkdir(t, filepath.Join(iosDir, "StoreApp.xcworkspace"))
		plist := "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>1.0.0</string>\n\t<key>CFBundleVersion</key>\n\t<string>1</string>\n</dict>\n</plist>\n"
		mustWrite(t, filepath.Join(iosDir, "StoreApp", "Info.plist"), plist)
		mustWrite(t, filepath.Join(iosDir, "NotificationService", "Info.plist"), plist)
	case command.Name == "pod":
		if command.Dir != iosDir {
			t.Errorf("pod install ran in %s", command.Dir)
		}
	case command.Name == "xcodebuild" && command.Args[0] == "archive":
		fixture.archiveSawProfiles = true
		for _, uuid := range []string{"AAAA-1111", "BBBB-2222"} {
			for _, path := range fixture.profilePaths(uuid) {
				if !filePresent(path) {
					fixture.archiveSawProfiles = false
				}
			}
		}
		keychain := fixture.security.list()[0]
		fixture.archiveSawKeychain = strings.HasSuffix(keychain, ".keychain-db") && strings.Contains(keychain, fixture.runtime.workDir)
		if command.Args[len(command.Args)-1] != "OTHER_CODE_SIGN_FLAGS=--keychain "+keychain {
			t.Errorf("archive does not pin the job keychain: %v", command.Args)
		}
		if fixture.archiveErr != nil {
			return []byte("error: something broke\n** ARCHIVE FAILED **\n"), fixture.archiveErr
		}
		mustMkdir(t, argAfter(command.Args, "-archivePath"))
	case command.Name == "xcodebuild" && command.Args[0] == "-exportArchive":
		if fixture.exportErr != nil {
			return nil, fixture.exportErr
		}
		mustWrite(t, filepath.Join(argAfter(command.Args, "-exportPath"), "StoreApp.ipa"), "ipa-bytes")
	case command.Name == "ditto":
		mustMkdir(t, filepath.Join(command.Args[len(command.Args)-1], "Payload", "StoreApp.app"))
	case command.Name == "codesign" && command.Args[0] == "-dv":
		return []byte("Identifier=com.example.storeapp\nTeamIdentifier=" + fixture.codesignTeam + "\n"), nil
	case command.Name == "codesign" && command.Args[0] == "-d":
		prefix := strings.TrimPrefix(command.Args[1], "--extract-certificates=")
		if err := os.WriteFile(prefix+"0", fixture.certDER, 0o600); err != nil {
			t.Fatal(err)
		}
	case command.Name == "codesign":
	default:
		t.Errorf("unexpected command %s", command.String())
	}
	return nil, nil
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func (fixture *iosBuildFixture) assertCleanedUp() {
	t := fixture.t
	fixture.t.Helper()
	if errs := fixture.runtime.cleanup.Run(); len(errs) > 0 {
		t.Errorf("cleanup errors: %v", errs)
	}
	for _, uuid := range []string{"AAAA-1111", "BBBB-2222"} {
		for _, path := range fixture.profilePaths(uuid) {
			if filePresent(path) {
				t.Errorf("profile left installed: %s", path)
			}
		}
	}
	if list := fixture.security.list(); strings.Join(list, ",") != "/Users/runner/Library/Keychains/login.keychain-db,/Library/Keychains/System.keychain" {
		t.Errorf("keychain search list not restored: %v", list)
	}
	if len(fixture.security.keychains) != 0 {
		t.Errorf("job keychain not deleted: %v", fixture.security.keychains)
	}
	if filePresent(filepath.Join(fixture.runtime.workDir, "keychain")) {
		t.Error("keychain directory (p12, WWDR) left behind")
	}
	if redactRegisteredSecrets("p12-secret-password") != "p12-secret-password" {
		t.Error("secret stayed registered with the redactor after cleanup")
	}
}

func TestRunIOSStoreBuildSignsArchivesExportsAndCleansUp(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	outcome, err := runIOSStoreBuild(fixture.runtime, fixture.plan, map[string]string{"SENTRY_AUTH_TOKEN": "sentry-auth-token-value"})
	if err != nil {
		t.Fatalf("runIOSStoreBuild: %v\n%s", err, strings.Join(fixture.runner.lines(), "\n"))
	}
	if outcome.kind != "ipa" || filepath.Base(outcome.artifactPath) != "StoreApp.ipa" {
		t.Fatalf("outcome = %+v", outcome)
	}
	if outcome.signing["teamId"] != "TEAM123456" || outcome.signing["certificateSerial"] != "5E1A1" {
		t.Fatalf("signing = %v", outcome.signing)
	}
	profiles := outcome.signing["profiles"].([]map[string]any)
	if len(profiles) != 2 || profiles[0]["uuid"] != "AAAA-1111" || profiles[1]["bundleId"] != "com.example.storeapp.NotificationService" {
		t.Fatalf("signing profiles = %v", profiles)
	}
	if !fixture.archiveSawProfiles || !fixture.archiveSawKeychain {
		t.Fatalf("archive ran without profiles (%v) or job keychain first in search list (%v)", fixture.archiveSawProfiles, fixture.archiveSawKeychain)
	}

	// Ordering: prebuild, pods, keychain, archive, export, verification.
	order := []string{"npx expo prebuild", "pod install", "security create-keychain", "security import", "security set-key-partition-list", "xcodebuild archive", "xcodebuild -exportArchive", "ditto", "codesign --verify"}
	lines := fixture.runner.lines()
	position := 0
	for _, line := range lines {
		if position < len(order) && strings.HasPrefix(line, order[position]) {
			position++
		}
	}
	if position != len(order) {
		t.Fatalf("command order wrong, stopped at %q:\n%s", order[position], strings.Join(lines, "\n"))
	}
	imports := fixture.runner.find("security import")
	if len(imports) != 2 || !strings.Contains(imports[0].String(), "-T /usr/bin/codesign -T /usr/bin/security") {
		t.Fatalf("p12 import or WWDR import missing: %v", imports)
	}

	pbxproj, _ := os.ReadFile(filepath.Join(fixture.runtime.appDir, "ios", "StoreApp.xcodeproj", "project.pbxproj"))
	if !strings.Contains(string(pbxproj), `PROVISIONING_PROFILE_SPECIFIER = "StoreApp NSE AppStore";`) {
		t.Fatal("pbxproj not patched for the extension")
	}
	plist, _ := os.ReadFile(filepath.Join(fixture.runtime.appDir, "ios", "NotificationService", "Info.plist"))
	if !strings.Contains(string(plist), "<string>1.4.0</string>") || !strings.Contains(string(plist), "<string>42</string>") {
		t.Fatalf("extension Info.plist version not set:\n%s", plist)
	}
	exportOptions, _ := os.ReadFile(filepath.Join(fixture.runtime.workDir, "ExportOptions.plist"))
	if !strings.Contains(string(exportOptions), "<string>StoreApp NSE AppStore</string>") || !strings.Contains(string(exportOptions), fixture.certSHA1) {
		t.Fatalf("ExportOptions.plist wrong:\n%s", exportOptions)
	}
	fixture.assertCleanedUp()
}

func TestRunIOSStoreBuildFailsBeforeSigningWhenATargetHasNoProfile(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.plan.IOS.Targets = fixturePlanTargets()[:1]
	_, err := runIOSStoreBuild(fixture.runtime, fixture.plan, testIOSSecretEnv)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "signing_target_missing_profile" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(failure.message, "com.example.storeapp.NotificationService") {
		t.Fatalf("failure does not name the bundle id: %s", failure.message)
	}
	if len(fixture.runner.find("security")) != 0 || len(fixture.runner.find("xcodebuild")) != 0 {
		t.Fatalf("signing or build ran despite the missing profile:\n%s", strings.Join(fixture.runner.lines(), "\n"))
	}
	fixture.assertCleanedUp()
}

func TestRunIOSStoreBuildCleansUpAfterArchiveFailure(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.archiveErr = errors.New("xcodebuild: exit status 65")
	_, err := runIOSStoreBuild(fixture.runtime, fixture.plan, testIOSSecretEnv)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "xcode_archive_failed" || !strings.Contains(failure.message, "error: something broke") {
		t.Fatalf("err = %v", err)
	}
	fixture.assertCleanedUp()
}

func TestRunIOSStoreBuildCleansUpAfterCancellation(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.archiveErr = fmt.Errorf("xcodebuild: %w", errCommandCancelled)
	_, err := runIOSStoreBuild(fixture.runtime, fixture.plan, testIOSSecretEnv)
	if !errors.Is(err, errCommandCancelled) {
		t.Fatalf("cancellation must propagate, got %v", err)
	}
	fixture.assertCleanedUp()
}

func TestRunIOSStoreBuildRejectsIPASignedByAnotherTeam(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.codesignTeam = "OTHERTEAM1"
	_, err := runIOSStoreBuild(fixture.runtime, fixture.plan, testIOSSecretEnv)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "signing_verification_failed" {
		t.Fatalf("err = %v", err)
	}
	fixture.assertCleanedUp()
}

func TestInstallIOSSigningUnwindsPartialSetup(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.security.failCommand = "set-key-partition-list"
	cert := iosCertificatePayload{P12Base64: b64("p12"), P12Password: "pw-secret", SHA1Fingerprint: fixture.certSHA1, TeamID: "TEAM123456"}
	_, err := installIOSSigning(fixture.runtime, "pfjob_store", cert, nil)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "signing_keychain_failed" {
		t.Fatalf("err = %v", err)
	}
	if len(fixture.security.keychains) != 1 {
		t.Fatal("keychain should exist until cleanup")
	}
	fixture.assertCleanedUp()
	if len(fixture.runner.find("security delete-keychain")) != 1 {
		t.Fatal("partially created keychain not deleted")
	}
}

func TestInstallIOSSigningReportsMissingIdentity(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.security.identity = "0000000000000000000000000000000000000000"
	fixture.runtime.fetchWWDR = nil
	cert := iosCertificatePayload{P12Base64: b64("p12"), P12Password: "pw-secret", SHA1Fingerprint: fixture.certSHA1, TeamID: "TEAM123456"}
	_, err := installIOSSigning(fixture.runtime, "pfjob_store", cert, nil)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "signing_identity_invalid" || !strings.Contains(failure.message, "WWDR") {
		t.Fatalf("err = %v", err)
	}
	fixture.assertCleanedUp()
}

func TestProvisioningProfileLeavesPreexistingAndSharedProfiles(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	var profile iosProvisioningProfilePayload
	if err := parseStoreSecretPayload("profile", fixture.secrets["ref_profile_app"], &profile); err != nil {
		t.Fatal(err)
	}
	// A profile installed by hand before the job must survive it.
	paths := fixture.profilePaths(profile.UUID)
	mustWrite(t, paths[0], "hand-installed")
	if err := installProvisioningProfile(fixture.runtime, "job_a", profile); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.cleanup.Run()
	if raw, _ := os.ReadFile(paths[0]); string(raw) != "hand-installed" {
		t.Fatal("hand-installed profile was changed or removed")
	}
	if filePresent(paths[1]) {
		t.Fatal("profile the job installed was left behind")
	}
	_ = os.Remove(paths[0])

	// Two concurrent jobs: the profile stays until the last one finishes.
	first := &storeCleanup{}
	second := &storeCleanup{}
	fixture.runtime.cleanup = first
	if err := installProvisioningProfile(fixture.runtime, "job_a", profile); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.cleanup = second
	if err := installProvisioningProfile(fixture.runtime, "job_b", profile); err != nil {
		t.Fatal(err)
	}
	first.Run()
	if !filePresent(paths[0]) || !filePresent(paths[1]) {
		t.Fatal("profile removed while another job still holds it")
	}
	second.Run()
	if filePresent(paths[0]) || filePresent(paths[1]) {
		t.Fatal("last job out did not remove the profile")
	}
}

func TestRevealIOSSigningMaterialValidatesPayloads(t *testing.T) {
	fixture := newIOSBuildFixture(t)
	fixture.secrets["ref_profile_nse"] = profilePayload("CCCC-3333", "Wrong", "com.example.storeapp.NotificationService")
	_, _, err := revealIOSSigningMaterial(fixture.runtime, fixture.plan)
	var failure *storeFailure
	if !errors.As(err, &failure) || failure.code != "signing_profile_mismatch" {
		t.Fatalf("err = %v", err)
	}

	delete(fixture.secrets, "ref_cert")
	_, _, err = revealIOSSigningMaterial(fixture.runtime, fixture.plan)
	if !errors.As(err, &failure) || failure.status != "setup_required" || failure.code != "signing_credential_unavailable" {
		t.Fatalf("missing certificate should be setup_required, got %v", err)
	}

	fixture.secrets["ref_cert"] = `{"p12Base64":"eA==","p12Password":"hunter2-secret"}`
	_, _, err = revealIOSSigningMaterial(fixture.runtime, fixture.plan)
	if !errors.As(err, &failure) || failure.code != "signing_credential_invalid" || strings.Contains(failure.message, "hunter2") {
		t.Fatalf("invalid certificate payload: %v", err)
	}
	fixture.runtime.cleanup.Run()
}

var testIOSSecretEnv = map[string]string{"SENTRY_AUTH_TOKEN": "sentry-auth-token-value"}
