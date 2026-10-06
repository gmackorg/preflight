package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativePackageFixture(t *testing.T, kind string) (string, apiRunnerJob) {
	t.Helper()
	workspace := t.TempDir()
	lane, rawKind, name, method, target := "ios-simulator", "ios_xcode_project", "UnityFramework.xcframework", "HabitPlay.Games.Editor.HabitPlayBuild.ExportIosSimulator", "iOS"
	if kind == "android_aar" {
		lane, rawKind, name, method, target = "android-library", "android_gradle_project", "unityLibrary.aar", "HabitPlay.Games.Editor.HabitPlayBuild.ExportAndroidLibrary", "Android"
	}
	job := apiRunnerJob{ID: "pfjob_native", Payload: runnerJobPayload{
		SourceBinding: runnerJobSourceBinding{WorkspaceRoot: workspace, GitCommitSHA: strings.Repeat("a", 40)},
		CommandPlan: runnerJobCommandPlan{InputPath: filepath.Join(workspace, "apps", "unity"), Args: []string{"-executeMethod", method}, Output: runnerJobCommandPlanOutput{
			ArtifactKind: kind, BuildTarget: target, ExportArtifactKind: rawKind,
			OutputPath:         filepath.Join(workspace, ".preflight", "unity-native-packages", "pfjob_native", name),
			ExportOutputPath:   filepath.Join(workspace, ".preflight", "unity-exports", "pfjob_native", lane, "HabitPlayUnity"),
			ExportRelativePath: "Build/exports/" + lane + "/HabitPlayUnity",
		}},
	}}
	return workspace, job
}

func writePackagingExport(t *testing.T, root, marker string) {
	t.Helper()
	path := filepath.Join(root, marker)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("source-bound exported native project")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(data), filepath.ToSlash(filepath.Join(filepath.Base(root), marker)))
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), "SHA256SUMS"), []byte(checksum), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUnityNativePackagingRejectsTamperedOwnedPathsBeforeExecution(t *testing.T) {
	for _, mutation := range []string{"native-output", "export-output", "method", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			workspace, job := nativePackageFixture(t, "ios_xcframework")
			switch mutation {
			case "native-output":
				job.Payload.CommandPlan.Output.OutputPath = filepath.Join(t.TempDir(), "UnityFramework.xcframework")
			case "export-output":
				job.Payload.CommandPlan.Output.ExportOutputPath = filepath.Join(workspace, ".preflight", "unity-exports", "pfjob_another", "ios-simulator", "HabitPlayUnity")
			case "method":
				job.Payload.CommandPlan.Args[1] = "Game.ArbitraryMethod"
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(workspace, ".preflight")); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := buildUnityNativePackage(workspace, job, "/Unity", func(unityNativeCommand) error { called = true; return nil })
			if err == nil || called {
				t.Fatalf("invalid package plan executed: err=%v, called=%v", err, called)
			}
		})
	}
}

func TestUnityXCFrameworkRequiresBothFreshFrameworks(t *testing.T) {
	workspace, job := nativePackageFixture(t, "ios_xcframework")
	for _, lane := range []string{"ios-device", "ios-simulator"} {
		writePackagingExport(t, filepath.Join(workspace, ".preflight", "unity-exports", job.ID, lane, "HabitPlayUnity"), "Unity-iPhone.xcodeproj/project.pbxproj")
	}
	var commands []unityNativeCommand
	run := func(command unityNativeCommand) error {
		commands = append(commands, command)
		if command.Args[1] == "-create-xcframework" {
			if err := os.MkdirAll(job.Payload.CommandPlan.Output.OutputPath, 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(job.Payload.CommandPlan.Output.OutputPath, "Info.plist"), []byte("two slices"), 0o644)
		}
		value := func(flag string) string {
			for i, arg := range command.Args {
				if arg == flag {
					return command.Args[i+1]
				}
			}
			return ""
		}
		binary := filepath.Join(value("-derivedDataPath"), "Build", "Products", "Release-"+value("-sdk"), "UnityFramework.framework", "UnityFramework")
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return err
		}
		return os.WriteFile(binary, []byte(value("-sdk")), 0o644)
	}
	if err := buildUnityNativePackage(workspace, job, "/Unity", run); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 3 || !strings.Contains(strings.Join(commands[0].Args, " "), "CODE_SIGNING_ALLOWED=NO") || !strings.Contains(strings.Join(commands[1].Args, " "), "iphonesimulator") {
		t.Fatalf("unexpected native commands: %+v", commands)
	}
	if err := buildUnityNativePackage(workspace, job, "/Unity", run); err == nil {
		t.Fatal("stale package accepted")
	}
}

func TestUnityAndroidAARUsesEditorJDKAndPreservesBuildFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			workspace, job := nativePackageFixture(t, "android_aar")
			writePackagingExport(t, job.Payload.CommandPlan.Output.ExportOutputPath, "unityLibrary/build.gradle")
			editor := filepath.Join(t.TempDir(), "Unity.app", "Contents", "MacOS", "Unity")
			android := filepath.Join(unityEditorInstallRoot(editor), "PlaybackEngines", "AndroidPlayer")
			for _, relative := range []string{"OpenJDK/bin/java", "Tools/gradle/lib/gradle-launcher.jar"} {
				path := filepath.Join(android, relative)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("SDK tool"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := buildUnityNativePackage(workspace, job, editor, func(command unityNativeCommand) error {
				if command.Executable != filepath.Join(android, "OpenJDK", "bin", "java") || len(command.Env) != 1 || !strings.Contains(command.Args[1], "gradle-launcher.jar") {
					t.Fatalf("system Java/Gradle escaped editor binding: %+v", command)
				}
				if fail {
					return errCommandCancelled
				}
				path := filepath.Join(command.Directory, "unityLibrary", "build", "outputs", "aar", "unityLibrary-debug.aar")
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("new library bytes"), 0o644)
			})
			if fail && err == nil || !fail && err != nil {
				t.Fatalf("failure propagation: %v", err)
			}
			if !fail {
				data, readErr := os.ReadFile(job.Payload.CommandPlan.Output.OutputPath)
				if readErr != nil || string(data) != "new library bytes" {
					t.Fatalf("wrong AAR bytes: %s %v", data, readErr)
				}
			}
		})
	}
}

func TestUnityNativeBuildRecordsSourceBothExportsAndPackagedArtifact(t *testing.T) {
	workspace, job := nativePackageFixture(t, "ios_xcframework")
	resolved, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	workspace = resolved
	job.Payload.SourceBinding.WorkspaceRoot = workspace
	output := &job.Payload.CommandPlan.Output
	output.OutputPath = filepath.Join(workspace, ".preflight", "unity-native-packages", job.ID, "UnityFramework.xcframework")
	output.ExportOutputPath = filepath.Join(workspace, ".preflight", "unity-exports", job.ID, "ios-simulator", "HabitPlayUnity")
	input := filepath.Join(workspace, "apps", "unity")
	for relative, content := range map[string]string{"Assets/Source.cs": "latest source", "ProjectSettings/ProjectVersion.txt": "m_EditorVersion: 6000.3.9f1", "Packages/manifest.json": `{"dependencies":{}}`} {
		path := filepath.Join(input, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	editor := filepath.Join(bin, "Unity")
	gitScript := "#!/bin/sh\nprintf 'apps/unity/Assets/Source.cs\\000apps/unity/Packages/manifest.json\\000apps/unity/ProjectSettings/ProjectVersion.txt\\000'\n"
	editorScript := `#!/bin/sh
method=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-executeMethod' ]; then shift; method="$1"; fi
  shift
done
case "$method" in
  *ExportIosSimulator) lane=ios-simulator ;;
  *ExportIosDevice) lane=ios-device ;;
  *) exit 61 ;;
esac
mkdir -p "Build/exports/$lane/HabitPlayUnity/Unity-iPhone.xcodeproj"
printf 'latest export' > "Build/exports/$lane/HabitPlayUnity/Unity-iPhone.xcodeproj/project.pbxproj"
cd "Build/exports/$lane"
shasum -a 256 HabitPlayUnity/Unity-iPhone.xcodeproj/project.pbxproj > SHA256SUMS
`
	xcrunScript := `#!/bin/sh
mode="$2"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -sdk) shift; sdk="$1" ;;
    -derivedDataPath) shift; derived="$1" ;;
    -output) shift; output="$1" ;;
  esac
  shift
done
if [ "$mode" = '-create-xcframework' ]; then
  mkdir -p "$output"
  printf 'both slices' > "$output/Info.plist"
else
  framework="$derived/Build/Products/Release-$sdk/UnityFramework.framework"
  mkdir -p "$framework"
  printf 'fresh framework' > "$framework/UnityFramework"
fi
`
	for name, script := range map[string]string{"git": gitScript, "Unity": editorScript, "xcrun": xcrunScript} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_UNITY_COMMAND", editor)
	stage := filepath.Join(workspace, ".preflight", "unity-projects", job.ID, "HabitPlayUnity")
	log := filepath.Join(filepath.Dir(stage), "unity-build.log")
	job.Payload.CommandPlan.InputPath = input
	job.Payload.CommandPlan.Tool = "unity"
	job.Payload.CommandPlan.Command = "batchmode"
	job.Payload.CommandPlan.Args = []string{"-batchmode", "-nographics", "-quit", "-projectPath", stage, "-executeMethod", "HabitPlay.Games.Editor.HabitPlayBuild.ExportIosSimulator", "-logFile", log}
	output.LogPath = log
	artifacts, err := runUnityBuildPlayer(runnerOnceOptions{workspaceRoot: workspace}, job)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.SourceCommit != strings.Repeat("a", 40) || artifacts.ExportFileCount != 4 || artifacts.NativeFileCount != 1 || len(artifacts.NativeManifestSHA256) != 64 || len(artifacts.BuildArtifacts) != 1 || artifacts.BuildArtifacts[0].Kind != "ios_xcframework" {
		t.Fatalf("incomplete native provenance: %+v", artifacts)
	}
	payload := unityBuildResultPayload(artifacts)
	if payload["nativeManifestSHA256"] != artifacts.NativeManifestSHA256 || payload["primaryArtifactPath"] != output.OutputPath {
		t.Fatalf("completion lost native proof: %+v", payload)
	}
}
