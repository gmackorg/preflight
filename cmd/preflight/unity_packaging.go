package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type unityNativeCommand struct {
	Executable string
	Args       []string
	Directory  string
	Env        []string
}

type unityNativeCommandRunner func(unityNativeCommand) error

func unityEditorInstallRoot(editor string) string {
	root := filepath.Dir(editor)
	if filepath.Base(root) == "MacOS" && filepath.Base(filepath.Dir(root)) == "Contents" {
		return filepath.Dir(filepath.Dir(filepath.Dir(root)))
	}
	return root
}

func validateUnityNativePackagePlan(workspace string, job apiRunnerJob) error {
	output := job.Payload.CommandPlan.Output
	if output.ExportArtifactKind == "" && output.ExportOutputPath == "" {
		return nil
	}
	if job.ID == "" || strings.ContainsAny(job.ID, "/\\.") {
		return fmt.Errorf("invalid Unity native package job identity")
	}
	var name, lane, kind, method, target string
	switch output.ArtifactKind {
	case "ios_xcframework":
		name, lane, kind = "UnityFramework.xcframework", "ios-simulator", "ios_xcode_project"
		method, target = "HabitPlay.Games.Editor.HabitPlayBuild.ExportIosSimulator", "iOS"
	case "android_aar":
		name, lane, kind = "unityLibrary.aar", "android-library", "android_gradle_project"
		method, target = "HabitPlay.Games.Editor.HabitPlayBuild.ExportAndroidLibrary", "Android"
	default:
		return fmt.Errorf("unsupported Unity native package kind %s", output.ArtifactKind)
	}
	if output.OutputPath != filepath.Join(workspace, ".preflight", "unity-native-packages", job.ID, name) ||
		output.ExportOutputPath != filepath.Join(workspace, ".preflight", "unity-exports", job.ID, lane, "HabitPlayUnity") ||
		output.ExportRelativePath != "Build/exports/"+lane+"/HabitPlayUnity" || output.ExportArtifactKind != kind ||
		job.Payload.CommandPlan.InputPath == "" || len(job.Payload.SourceBinding.GitCommitSHA) != 40 ||
		output.BuildTarget != target || unityArgValue(job.Payload.CommandPlan.Args, "-executeMethod") != method {
		return fmt.Errorf("Unity native package requires exact job-owned source and export paths")
	}
	return validateUnityOwnedPath(workspace, output.OutputPath)
}

func packageUnityNativeLibrary(options runnerOnceOptions, job apiRunnerJob, stage, editor string, log io.Writer, cancellationCheck func() (bool, error), artifacts *unityBuildArtifacts) error {
	plan := job.Payload.CommandPlan
	if plan.Output.ExportArtifactKind == "" && plan.Output.ExportOutputPath == "" {
		return nil
	}
	workspace := firstNonEmpty(job.Payload.SourceBinding.WorkspaceRoot, options.workspaceRoot)
	if err := validateUnityNativePackagePlan(workspace, job); err != nil {
		return err
	}
	run := func(spec unityNativeCommand) error {
		command := exec.Command(spec.Executable, spec.Args...)
		command.Dir = spec.Directory
		command.Env = unityCommandEnv(os.Environ(), plan.Env)
		command.Env = append(command.Env, spec.Env...)
		fmt.Fprintf(log, "Preflight Unity packaging: %s %q\n", spec.Executable, spec.Args)
		flush := attachRedactedCommandLog(command, log)
		err := runCommandWithTimeoutAndCancellation(command, unityBuildTimeout(), cancellationCheck, runnerPollInterval())
		flush()
		return err
	}
	if plan.Output.ArtifactKind == "ios_xcframework" {
		companion := job
		companion.Payload.CommandPlan.Args = append([]string(nil), plan.Args...)
		for i, arg := range companion.Payload.CommandPlan.Args {
			if arg == "-executeMethod" && i+1 < len(companion.Payload.CommandPlan.Args) {
				companion.Payload.CommandPlan.Args[i+1] = "HabitPlay.Games.Editor.HabitPlayBuild.ExportIosDevice"
			}
			if arg == "-logFile" && i+1 < len(companion.Payload.CommandPlan.Args) {
				companion.Payload.CommandPlan.Args[i+1] = filepath.Join(filepath.Dir(stage), "unity-device-export.log")
			}
		}
		companion.Payload.CommandPlan.Output.ExportRelativePath = "Build/exports/ios-device/HabitPlayUnity"
		companion.Payload.CommandPlan.Output.ExportOutputPath = filepath.Join(workspace, ".preflight", "unity-exports", job.ID, "ios-device", "HabitPlayUnity")
		if err := run(unityNativeCommand{Executable: editor, Args: companion.Payload.CommandPlan.Args, Directory: stage}); err != nil {
			return fmt.Errorf("Unity companion device export: %w", err)
		}
		if err := promoteUnityExport(options, companion, stage); err != nil {
			return err
		}
	}
	var err error
	artifacts.ExportManifestSHA256, artifacts.ExportFileCount, err = unityDirectorySHA256(filepath.Dir(filepath.Dir(plan.Output.ExportOutputPath)))
	if err != nil {
		return err
	}
	if err := buildUnityNativePackage(workspace, job, editor, run); err != nil {
		return err
	}
	if plan.Output.ArtifactKind == "android_aar" {
		artifacts.NativeManifestSHA256, err = unityFileSHA256(plan.Output.OutputPath)
		artifacts.NativeFileCount = 1
	} else {
		artifacts.NativeManifestSHA256, artifacts.NativeFileCount, err = unityDirectorySHA256(plan.Output.OutputPath)
	}
	return err
}

func buildUnityNativePackage(workspace string, job apiRunnerJob, editor string, run unityNativeCommandRunner) error {
	if err := validateUnityNativePackagePlan(workspace, job); err != nil {
		return err
	}
	output := job.Payload.CommandPlan.Output
	if _, err := os.Lstat(filepath.Dir(output.OutputPath)); err == nil {
		return fmt.Errorf("Unity native package output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output.OutputPath), 0o755); err != nil {
		return err
	}
	if output.ArtifactKind == "ios_xcframework" {
		var frameworks []string
		for _, lane := range []struct{ name, sdk, destination string }{
			{"ios-device", "iphoneos", "generic/platform=iOS"},
			{"ios-simulator", "iphonesimulator", "generic/platform=iOS Simulator"},
		} {
			project := filepath.Join(workspace, ".preflight", "unity-exports", job.ID, lane.name, "HabitPlayUnity")
			if err := validateUnityOwnedPath(workspace, project); err != nil {
				return err
			}
			if err := verifyUnityExportChecksums(project); err != nil {
				return err
			}
			derived := filepath.Join(filepath.Dir(output.OutputPath), lane.name+"-derived")
			if err := run(unityNativeCommand{Executable: "xcrun", Directory: project, Args: []string{"xcodebuild", "-project", filepath.Join(project, "Unity-iPhone.xcodeproj"), "-scheme", "UnityFramework", "-configuration", "Release", "-sdk", lane.sdk, "-destination", lane.destination, "-derivedDataPath", derived, "CODE_SIGNING_ALLOWED=NO", "SDK_STAT_CACHE_ENABLE=NO", "build"}}); err != nil {
				return fmt.Errorf("Unity %s framework build: %w", lane.name, err)
			}
			framework := filepath.Join(derived, "Build", "Products", "Release-"+lane.sdk, "UnityFramework.framework")
			if !fileExists(filepath.Join(framework, "UnityFramework")) {
				return fmt.Errorf("Unity framework build produced no executable for %s", lane.name)
			}
			frameworks = append(frameworks, framework)
		}
		if err := run(unityNativeCommand{Executable: "xcrun", Directory: workspace, Args: []string{"xcodebuild", "-create-xcframework", "-framework", frameworks[0], "-framework", frameworks[1], "-output", output.OutputPath}}); err != nil {
			return err
		}
	} else {
		project := output.ExportOutputPath
		if err := validateUnityOwnedPath(workspace, project); err != nil {
			return err
		}
		if err := verifyUnityExportChecksums(project); err != nil {
			return err
		}
		android := filepath.Join(unityEditorInstallRoot(editor), "PlaybackEngines", "AndroidPlayer")
		gradle, err := filepath.Glob(filepath.Join(android, "Tools", "gradle", "lib", "*.jar"))
		if err != nil || len(gradle) == 0 || !fileExists(filepath.Join(android, "OpenJDK", "bin", "java")) {
			return fmt.Errorf("Unity Android module must provide its JDK and Gradle libraries")
		}
		if err := run(unityNativeCommand{Executable: filepath.Join(android, "OpenJDK", "bin", "java"), Directory: project, Env: []string{"JAVA_HOME=" + filepath.Join(android, "OpenJDK")}, Args: []string{"-cp", strings.Join(gradle, string(os.PathListSeparator)), "org.gradle.launcher.GradleMain", ":unityLibrary:assembleDebug", "--no-daemon", "-p", project}}); err != nil {
			return fmt.Errorf("Unity Android library build: %w", err)
		}
		built := filepath.Join(project, "unityLibrary", "build", "outputs", "aar", "unityLibrary-debug.aar")
		if err := validateUnityOwnedPath(workspace, built); err != nil {
			return err
		}
		data, err := os.ReadFile(built)
		if err != nil {
			return err
		}
		if err := os.WriteFile(output.OutputPath, data, 0o644); err != nil {
			return err
		}
	}
	if len(discoverUnityBuildArtifacts(output.ArtifactKind, output.OutputPath)) != 1 {
		return fmt.Errorf("Unity native packaging did not produce its expected artifact")
	}
	return nil
}
