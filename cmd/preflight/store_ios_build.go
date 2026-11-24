package main

// store.build for iOS (PREFLT-66): expo prebuild (skipped when ios/ is
// committed, PREFLT-71), CocoaPods, manual signing with leased credentials,
// xcodebuild archive + -exportArchive, signature verification. The artifact upload happens in runStoreBuild.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func storeCommandTimeout(name string, fallback time.Duration) time.Duration {
	return durationFromEnv(name, fallback)
}

// revealIOSSigningMaterial reveals and validates the certificate and one
// profile per plan target before any slow work starts.
func revealIOSSigningMaterial(rt *storeJobRuntime, plan storeBuildPlan) (iosCertificatePayload, []iosProvisioningProfilePayload, error) {
	ios := plan.IOS
	var cert iosCertificatePayload
	revealed, err := revealStoreSecret(rt.reveal, rt.cleanup, ios.CertificateSecretReferenceID, "iOS distribution certificate")
	if err != nil {
		return cert, nil, err
	}
	if err := parseStoreSecretPayload("ios_distribution_certificate", revealed.Value, &cert,
		"p12Base64", "p12Password", "serialNumber", "sha1Fingerprint", "teamId", "expiresAt"); err != nil {
		return cert, nil, err
	}
	registerPayloadSecrets(rt.cleanup, cert.P12Password, cert.P12Base64)
	if ios.TeamID != "" && cert.TeamID != ios.TeamID {
		return cert, nil, storeFailuref("signing_team_mismatch", "certificate belongs to team %s, plan team is %s", cert.TeamID, ios.TeamID)
	}
	if expires, err := time.Parse(time.RFC3339, cert.ExpiresAt); err == nil && expires.Before(time.Now()) {
		return cert, nil, storeSetupRequired("signing_certificate_expired", "distribution certificate %s expired at %s", cert.SerialNumber, cert.ExpiresAt)
	}
	if len(ios.Targets) == 0 {
		return cert, nil, storeFailuref("store_build_payload_invalid", "iOS store build plan lists no signing targets")
	}
	profiles := []iosProvisioningProfilePayload{}
	for _, target := range ios.Targets {
		revealed, err := revealStoreSecret(rt.reveal, rt.cleanup, target.ProfileSecretReferenceID, "provisioning profile for "+target.BundleID)
		if err != nil {
			return cert, nil, err
		}
		var profile iosProvisioningProfilePayload
		if err := parseStoreSecretPayload("ios_provisioning_profile", revealed.Value, &profile,
			"profileBase64", "uuid", "name", "bundleId", "profileType", "teamId", "expiresAt"); err != nil {
			return cert, nil, err
		}
		if profile.BundleID != target.BundleID {
			return cert, nil, storeFailuref("signing_profile_mismatch", "profile %s is for %s, plan target %s is %s", profile.UUID, profile.BundleID, target.TargetName, target.BundleID)
		}
		if target.ProfileUUID != "" && !strings.EqualFold(profile.UUID, target.ProfileUUID) {
			return cert, nil, storeFailuref("signing_profile_mismatch", "plan expects profile %s for %s, secret holds %s", target.ProfileUUID, target.BundleID, profile.UUID)
		}
		if profile.TeamID != cert.TeamID {
			return cert, nil, storeFailuref("signing_team_mismatch", "profile for %s belongs to team %s, certificate to %s", profile.BundleID, profile.TeamID, cert.TeamID)
		}
		if expires, err := time.Parse(time.RFC3339, profile.ExpiresAt); err == nil && expires.Before(time.Now()) {
			return cert, nil, storeSetupRequired("signing_profile_expired", "provisioning profile %s for %s expired at %s", profile.UUID, profile.BundleID, profile.ExpiresAt)
		}
		profiles = append(profiles, profile)
	}
	return cert, profiles, nil
}

// findIOSProject returns the generated workspace and project.
func findIOSProject(iosDir string) (string, string, error) {
	workspaces, _ := filepath.Glob(filepath.Join(iosDir, "*.xcworkspace"))
	projects, _ := filepath.Glob(filepath.Join(iosDir, "*.xcodeproj"))
	filtered := []string{}
	for _, project := range projects {
		if filepath.Base(project) != "Pods.xcodeproj" {
			filtered = append(filtered, project)
		}
	}
	if len(workspaces) != 1 || len(filtered) != 1 {
		return "", "", storeFailuref("ios_project_missing", "expected one .xcworkspace and one .xcodeproj in %s after prebuild, found %d and %d", iosDir, len(workspaces), len(filtered))
	}
	return workspaces[0], filtered[0], nil
}

func classifyPodInstallFailure(output string, err error) *storeFailure {
	lower := strings.ToLower(output)
	for _, marker := range []string{"could not resolve host", "failed to connect", "connection reset", "timed out", "ssl_connect", "couldn't connect", "cdn:", "network is unreachable", "http 5"} {
		if strings.Contains(lower, marker) {
			return storeFailuref("cocoapods_network", "pod install: %v", err)
		}
	}
	return storeFailuref("cocoapods_install_failed", "pod install: %v%s", err, storeOutputTail(output))
}

func classifyXcodeFailure(step string, output string, err error) *storeFailure {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "no profile for team") ||
		strings.Contains(lower, "doesn't match the entitlements") ||
		strings.Contains(lower, "doesn't include signing certificate") ||
		strings.Contains(lower, "provisioning profile") && strings.Contains(lower, "error:"):
		return storeFailuref("signing_profile_mismatch", "%s: %v%s", step, err, storeOutputTail(output))
	case strings.Contains(lower, "no signing certificate") || strings.Contains(lower, "errsecinternalcomponent"):
		return storeFailuref("signing_identity_invalid", "%s: %v%s", step, err, storeOutputTail(output))
	}
	if step == "xcodebuild -exportArchive" {
		return storeFailuref("xcode_export_failed", "%s: %v%s", step, err, storeOutputTail(output))
	}
	return storeFailuref("xcode_archive_failed", "%s: %v%s", step, err, storeOutputTail(output))
}

// storeOutputTail is a short, redacted excerpt for a failure message.
func storeOutputTail(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	errorLines := []string{}
	for _, line := range lines {
		if strings.Contains(line, "error:") || strings.Contains(line, "** ARCHIVE FAILED **") || strings.Contains(line, "** EXPORT FAILED **") {
			errorLines = append(errorLines, strings.TrimSpace(line))
		}
	}
	if len(errorLines) == 0 {
		start := len(lines) - 10
		if start < 0 {
			start = 0
		}
		errorLines = lines[start:]
	}
	if len(errorLines) > 15 {
		errorLines = errorLines[len(errorLines)-15:]
	}
	text := strings.TrimSpace(strings.Join(errorLines, "\n"))
	if text == "" {
		return ""
	}
	return "\n" + redactSetupTranscriptText(text)
}

// committedNativeProject reports whether the app's ios/ or android/
// directory is part of the source (a bare-workflow app) rather than absent or
// left behind by an earlier prebuild in a reused workspace. In a git checkout
// the directory must contain tracked files; outside git, existing is enough.
func committedNativeProject(appDir string, platform string) bool {
	info, err := os.Stat(filepath.Join(appDir, platform))
	if err != nil || !info.IsDir() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "git", "-C", appDir, "ls-files", "--", platform).Output()
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(output)) != ""
}

// runExpoStorePrebuild generates the native project for platform, unless the
// checkout commits one (a bare-workflow app): like EAS, the committed ios/ or
// android/ directory is then built as-is, keeping hand-made targets and build
// configurations that prebuild --clean would delete.
func runExpoStorePrebuild(rt *storeJobRuntime, platform string, env []string) error {
	if err := runStorePreBuildHook(rt, platform, env); err != nil {
		return err
	}
	if committedNativeProject(rt.appDir, platform) {
		_, _ = fmt.Fprintf(rt.log, "%s/ is committed in the checkout: using the committed native project, skipping expo prebuild\n", platform)
		return nil
	}
	output, err := rt.run.Run(storeCommand{
		Name:    "npx",
		Args:    []string{"expo", "prebuild", "--platform", platform, "--clean", "--no-install"},
		Dir:     rt.appDir,
		Env:     env,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_PREBUILD_TIMEOUT", 20*time.Minute),
	})
	if err != nil {
		return wrapStoreCommandError(err, storeFailuref("expo_prebuild_failed", "expo prebuild --platform %s: %v%s", platform, err, storeOutputTail(string(output))))
	}
	return nil
}

// wrapStoreCommandError keeps cancellation and lease loss distinguishable.
func wrapStoreCommandError(err error, failure *storeFailure) error {
	if isStoreCancellation(err) {
		return err
	}
	return failure
}

func isStoreCancellation(err error) bool {
	return err != nil && (jobLeaseLost(err) || errors.Is(err, errCommandCancelled))
}

func runIOSStoreBuild(rt *storeJobRuntime, plan storeBuildPlan, secretEnv map[string]string) (storeBuildOutcome, error) {
	ios := plan.IOS
	cert, profiles, err := revealIOSSigningMaterial(rt, plan)
	if err != nil {
		return storeBuildOutcome{}, err
	}
	teamID := ios.TeamID
	if teamID == "" {
		teamID = cert.TeamID
	}
	env, err := storeCommandEnv(plan.Environment, secretEnv)
	if err != nil {
		return storeBuildOutcome{}, err
	}

	configuration := strings.TrimSpace(ios.Configuration)
	if configuration == "" {
		configuration = "Release"
	}

	if err := runExpoStorePrebuild(rt, "ios", env); err != nil {
		return storeBuildOutcome{}, err
	}
	iosDir := filepath.Join(rt.appDir, "ios")
	if err := ensureXcodeEnvNodeBinary(rt.appDir, rt.log); err != nil {
		_, _ = fmt.Fprintf(rt.log, "warning: %v\n", err)
	}
	if output, err := rt.run.Run(storeCommand{Name: "pod", Args: []string{"install"}, Dir: iosDir, Env: env,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_POD_INSTALL_TIMEOUT", 30*time.Minute)}); err != nil {
		return storeBuildOutcome{}, wrapStoreCommandError(err, classifyPodInstallFailure(string(output), err))
	}

	workspace, project, err := findIOSProject(iosDir)
	if err != nil {
		return storeBuildOutcome{}, err
	}
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	raw, err := os.ReadFile(pbxprojPath)
	if err != nil {
		return storeBuildOutcome{}, storeFailuref("ios_project_missing", "read %s: %v", pbxprojPath, err)
	}
	targets, err := parsePBXNativeTargets(string(raw), configuration)
	if err != nil {
		return storeBuildOutcome{}, storeFailuref("ios_project_unreadable", "%s: %v", pbxprojPath, err)
	}
	matched, missing := matchIOSSigningTargets(targets, ios.Targets)
	if len(missing) > 0 {
		return storeBuildOutcome{}, storeFailuref("signing_target_missing_profile",
			"no provisioning profile in the store plan for signable target(s): %s", strings.Join(missing, ", "))
	}
	patched, err := patchIOSProjectForStoreSigning(string(raw), targets, matched, configuration, teamID, normalizeFingerprint(cert.SHA1Fingerprint), plan.Version, plan.BuildNumber)
	if err != nil {
		return storeBuildOutcome{}, storeFailuref("ios_project_patch_failed", "%v", err)
	}
	if err := os.WriteFile(pbxprojPath, []byte(patched), 0o644); err != nil {
		return storeBuildOutcome{}, err
	}
	for _, target := range targets {
		if !signableProductType(target.ProductType) {
			continue
		}
		plistPath := resolveInfoPlistPath(iosDir, target.InfoPlist)
		if plistPath == "" {
			continue
		}
		ok, err := setInfoPlistVersion(plistPath, plan.Version, plan.BuildNumber)
		if err != nil {
			return storeBuildOutcome{}, storeFailuref("ios_project_patch_failed", "set version in %s: %v", plistPath, err)
		}
		if !ok {
			// Binary plist: fall back to PlistBuddy.
			for key, value := range map[string]string{"CFBundleShortVersionString": plan.Version, "CFBundleVersion": plan.BuildNumber} {
				if _, err := rt.run.Run(storeCommand{Name: "/usr/libexec/PlistBuddy", Args: []string{"-c", "Set :" + key + " " + value, plistPath}, Timeout: time.Minute}); err != nil {
					return storeBuildOutcome{}, storeFailuref("ios_project_patch_failed", "PlistBuddy %s in %s: %v", key, plistPath, err)
				}
			}
		}
	}

	session, err := installIOSSigning(rt, rt.jobID, cert, profiles)
	if err != nil {
		return storeBuildOutcome{}, err
	}

	scheme := strings.TrimSpace(ios.Scheme)
	if scheme == "" {
		scheme = strings.TrimSuffix(filepath.Base(workspace), ".xcworkspace")
	}
	archivePath := filepath.Join(rt.workDir, scheme+".xcarchive")
	_ = os.RemoveAll(archivePath)
	archiveArgs := []string{
		"archive",
		"-workspace", workspace,
		"-scheme", scheme,
		"-configuration", configuration,
		"-destination", "generic/platform=iOS",
		"-archivePath", archivePath,
		"OTHER_CODE_SIGN_FLAGS=--keychain " + session.keychainPath,
	}
	if target := storeDeploymentTarget(patched, targets, matched, configuration); target != "" {
		archiveArgs = append(archiveArgs, "IPHONEOS_DEPLOYMENT_TARGET="+target)
	}
	output, err := rt.run.Run(storeCommand{
		Name:    "xcodebuild",
		Args:    archiveArgs,
		Dir:     iosDir,
		Env:     env,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_ARCHIVE_TIMEOUT", 60*time.Minute),
	})
	if err != nil {
		return storeBuildOutcome{}, wrapStoreCommandError(err, classifyXcodeFailure("xcodebuild archive", string(output), err))
	}

	profileNames := map[string]string{}
	signingProfiles := []map[string]any{}
	for _, target := range ios.Targets {
		profileNames[target.BundleID] = storeProfileSpecifier(target.ProfileUUID, target.ProfileName)
	}
	for _, profile := range profiles {
		signingProfiles = append(signingProfiles, map[string]any{"bundleId": profile.BundleID, "uuid": profile.UUID})
		if profileNames[profile.BundleID] == "" {
			profileNames[profile.BundleID] = storeProfileSpecifier(profile.UUID, profile.Name)
		}
	}
	sort.Slice(signingProfiles, func(i, j int) bool {
		return signingProfiles[i]["bundleId"].(string) < signingProfiles[j]["bundleId"].(string)
	})
	exportOptionsPath := filepath.Join(rt.workDir, "ExportOptions.plist")
	if err := os.WriteFile(exportOptionsPath, iosExportOptionsPlist(iosExportMethod(plan), teamID, normalizeFingerprint(cert.SHA1Fingerprint), profileNames), 0o644); err != nil {
		return storeBuildOutcome{}, err
	}
	exportPath := filepath.Join(rt.workDir, "output")
	_ = os.RemoveAll(exportPath)
	output, err = rt.run.Run(storeCommand{
		Name: "xcodebuild",
		Args: []string{
			"-exportArchive",
			"-archivePath", archivePath,
			"-exportPath", exportPath,
			"-exportOptionsPlist", exportOptionsPath,
		},
		Dir:     iosDir,
		Env:     env,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_EXPORT_TIMEOUT", 20*time.Minute),
	})
	if err != nil {
		return storeBuildOutcome{}, wrapStoreCommandError(err, classifyXcodeFailure("xcodebuild -exportArchive", string(output), err))
	}
	ipas, _ := filepath.Glob(filepath.Join(exportPath, "*.ipa"))
	if len(ipas) != 1 {
		return storeBuildOutcome{}, storeFailuref("xcode_export_failed", "export produced %d .ipa files in %s", len(ipas), exportPath)
	}
	if err := verifyIOSArchiveSignature(rt, ipas[0], cert.SHA1Fingerprint, teamID); err != nil {
		return storeBuildOutcome{}, err
	}
	return storeBuildOutcome{
		artifactPath: ipas[0],
		kind:         "ipa",
		signing: map[string]any{
			"teamId":            teamID,
			"certificateSerial": cert.SerialNumber,
			"profiles":          signingProfiles,
		},
	}, nil
}
