package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Require an explicit APK profile. Physical devices retain their existing
// development workflow; an iOS-only preview profile does not opt Android in.
func isPackagedAndroidSimulatorProfile(profile easBuildProfile, platform, lane string) bool {
	return platform == "android" && lane == "simulator" &&
		profile.DevelopmentClient != nil && !*profile.DevelopmentClient &&
		profile.Distribution == "internal" && profile.Android.BuildType == "apk" &&
		easProfileEnv(profile, platform)["APP_VARIANT"] == "preview"
}

func isPackagedSimulatorProfile(profile easBuildProfile, platform, lane string) bool {
	return isPackagedIOSSimulatorProfile(profile, platform, lane) || isPackagedAndroidSimulatorProfile(profile, platform, lane)
}

func isPackagedAndroidSimulatorJob(job apiRunnerJob) bool {
	config, err := loadEASJSON(appDirectoryForJob(runnerOnceOptions{}, job))
	if err != nil {
		return false
	}
	profile, ok := config.Build[easProfileNameForJob(job)]
	return ok && isPackagedAndroidSimulatorProfile(profile, jobPlatform(job), job.Payload.Lane)
}

type androidPreviewOutput struct {
	ApplicationID string `json:"applicationId"`
	VariantName   string `json:"variantName"`
	Elements      []struct {
		Type       string            `json:"type"`
		Filters    []json.RawMessage `json:"filters"`
		OutputFile string            `json:"outputFile"`
	} `json:"elements"`
}

var androidPreviewPackagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func androidPreviewAPK(releaseDir, packageID string) (string, error) {
	realRelease, err := filepath.EvalSymlinks(releaseDir)
	if err != nil {
		return "", err
	}
	releaseDir = realRelease
	metadataPath := filepath.Join(releaseDir, "output-metadata.json")
	metadataInfo, err := os.Lstat(metadataPath)
	if err != nil {
		return "", err
	}
	if !metadataInfo.Mode().IsRegular() || metadataInfo.Size() > 1<<20 {
		return "", fmt.Errorf("Release APK metadata is not a bounded regular file")
	}
	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		return "", fmt.Errorf("read Release APK metadata: %w", err)
	}
	var output androidPreviewOutput
	if err := json.Unmarshal(metadata, &output); err != nil {
		return "", fmt.Errorf("parse Release APK metadata: %w", err)
	}
	if !androidPreviewPackagePattern.MatchString(packageID) || output.ApplicationID != packageID || output.VariantName != "release" || len(output.Elements) != 1 {
		return "", fmt.Errorf("Release APK metadata must match the bound Android package and a single release output")
	}
	element := output.Elements[0]
	if element.Type != "SINGLE" || len(element.Filters) != 0 || filepath.Base(element.OutputFile) != element.OutputFile || !strings.HasSuffix(element.OutputFile, ".apk") {
		return "", fmt.Errorf("Release APK must be a single universal APK within its output directory")
	}
	path := filepath.Join(releaseDir, element.OutputFile)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", fmt.Errorf("Release APK is not a nonempty regular file")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return "", fmt.Errorf("Release APK path contains symlinks")
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("read Release APK ZIP: %w", err)
	}
	defer archive.Close()
	for _, name := range []string{"AndroidManifest.xml", "classes.dex", "assets/index.android.bundle"} {
		var entry *zip.File
		for _, candidate := range archive.File {
			if candidate.Name == name {
				if entry != nil {
					return "", fmt.Errorf("duplicate APK entry %s", name)
				}
				entry = candidate
			}
		}
		if entry == nil || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > 256<<20 {
			return "", fmt.Errorf("Release APK missing or invalid %s", name)
		}
		reader, err := entry.Open()
		if err != nil {
			return "", err
		}
		n, readErr := io.Copy(io.Discard, io.LimitReader(reader, (256<<20)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || uint64(n) != entry.UncompressedSize64 {
			return "", fmt.Errorf("invalid APK entry %s", name)
		}
	}
	return path, nil
}

func previewAPKSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func androidPreviewAAPT() (string, error) {
	if path, err := exec.LookPath("aapt2"); err == nil {
		return path, nil
	}
	for _, root := range androidSdkRoots() {
		paths, err := filepath.Glob(filepath.Join(root, "build-tools", "*", "aapt2"))
		if err != nil {
			return "", err
		}
		sort.Sort(sort.Reverse(sort.StringSlice(paths)))
		for _, path := range paths {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("packaged Android preview requires Android SDK build-tools aapt2")
}

func verifyAndroidPreviewPackage(logFile *os.File, apk, packageID string, cancellationCheck func() (bool, error)) error {
	tool, err := androidPreviewAAPT()
	if err != nil {
		return err
	}
	command := exec.Command(tool, "dump", "badging", apk)
	var output bytes.Buffer
	flush := attachRedactedCommandLog(command, io.MultiWriter(logFile, &output))
	err = runCommandWithTimeoutAndCancellation(command, defaultAndroidDeviceNameTimeout, cancellationCheck, runnerPollInterval())
	flush()
	if err != nil {
		return fmt.Errorf("inspect APK binary manifest: %w", err)
	}
	var packageLines []string
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "package: ") {
			packageLines = append(packageLines, line)
		}
	}
	if len(packageLines) != 1 || !strings.HasPrefix(packageLines[0], "package: name='"+packageID+"' ") {
		return fmt.Errorf("APK binary manifest does not match bound Android package")
	}
	return nil
}

func runAndroidPreviewADB(logFile *os.File, options runnerOnceOptions, cancellationCheck func() (bool, error), expected string, args ...string) error {
	if strings.TrimSpace(options.adbPath) == "" {
		return fmt.Errorf("packaged Android preview requires adb")
	}
	fmt.Fprintf(logFile, "$ %s %s\n", options.adbPath, strings.Join(args, " "))
	command := exec.Command(options.adbPath, args...)
	var output bytes.Buffer
	flush := attachRedactedCommandLog(command, io.MultiWriter(logFile, &output))
	err := runCommandWithTimeoutAndCancellation(command, androidDevelopmentOpenTimeout(), cancellationCheck, runnerPollInterval())
	flush()
	if err != nil {
		return err
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Error:") || strings.Contains(line, "Failure [") {
			return fmt.Errorf("Android preview adb refused operation")
		}
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.TrimSpace(line) == expected {
			return nil
		}
	}
	return fmt.Errorf("Android preview adb did not confirm %q", expected)
}

func buildAndInstallAndroidPreview(logFile *os.File, options runnerOnceOptions, appDir, serial string, job apiRunnerJob, cancellationCheck func() (bool, error)) error {
	if !strings.HasPrefix(serial, "emulator-") || !androidPreviewPackagePattern.MatchString(job.Payload.SourceBinding.AndroidPackage) {
		return fmt.Errorf("packaged Android preview requires an emulator and bound package")
	}
	realAppDir, err := filepath.EvalSymlinks(appDir)
	if err != nil {
		return err
	}
	androidDir := filepath.Join(realAppDir, "android")
	// The workspace itself may be reached through /var or a worktree symlink;
	// generated children must stay real directories before recursive cleanup.
	parent := realAppDir
	for _, child := range []string{"android", "app", "build", "outputs", "apk", "release"} {
		parent = filepath.Join(parent, child)
		info, statErr := os.Lstat(parent)
		if os.IsNotExist(statErr) {
			break
		}
		if statErr != nil {
			return statErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Android Release output ancestor is not a real directory")
		}
	}
	releaseDir := filepath.Join(androidDir, "app", "build", "outputs", "apk", "release")
	// Remove only this checkout's generated Release outputs before assembling,
	// so a successful no-output command cannot install a previous APK.
	if err := removePathWithin(androidDir, releaseDir); err != nil {
		return err
	}
	if err := runAndroidGradleCommand(logFile, androidDir, job, cancellationCheck, ":app:assembleRelease", "--no-daemon", "--max-workers=2"); err != nil {
		return fmt.Errorf("assemble packaged Android preview: %w", err)
	}
	if real, err := filepath.EvalSymlinks(releaseDir); err != nil || real != releaseDir {
		return fmt.Errorf("Release output directory changed to a symlink")
	}
	apk, err := androidPreviewAPK(releaseDir, job.Payload.SourceBinding.AndroidPackage)
	if err != nil {
		return err
	}
	before, err := previewAPKSHA(apk)
	if err != nil {
		return err
	}
	if err := verifyAndroidPreviewPackage(logFile, apk, job.Payload.SourceBinding.AndroidPackage, cancellationCheck); err != nil {
		return err
	}
	verified, err := previewAPKSHA(apk)
	if err != nil || before != verified {
		return fmt.Errorf("Release APK changed during manifest inspection")
	}
	fmt.Fprintf(logFile, "packaged Android preview APK sha256=%s path=%s\n", before, apk)
	if err := runAndroidPreviewADB(logFile, options, cancellationCheck, "Success", "-s", serial, "install", "-r", apk); err != nil {
		return err
	}
	after, err := previewAPKSHA(apk)
	if err != nil || before != after {
		return fmt.Errorf("Release APK changed during installation")
	}
	return nil
}
