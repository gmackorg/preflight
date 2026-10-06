package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnityBuiltInNativeExportMethods(t *testing.T) {
	t.Setenv("PREFLIGHT_UNITY_EXECUTE_METHODS", "")
	for _, method := range []string{
		"HabitPlay.Games.Editor.HabitPlayBuild.ExportIosDevice",
		"HabitPlay.Games.Editor.HabitPlayBuild.ExportIosSimulator",
		"HabitPlay.Games.Editor.HabitPlayBuild.ExportAndroidLibrary",
	} {
		if !unityExecuteMethodAllowed(method) {
			t.Errorf("supported native export method rejected: %s", method)
		}
	}
	if unityExecuteMethodAllowed("HabitPlay.Games.Editor.HabitPlayBuild.ArbitraryMethod") {
		t.Fatal("unlisted project method allowed")
	}
}

func TestUnityStagingRejectsGeneratedAncestorSymlink(t *testing.T) {
	workspace := t.TempDir()
	input := filepath.Join(workspace, "apps", "unity")
	for relative, data := range map[string]string{"Assets/Source.cs": "current source", "ProjectSettings/ProjectVersion.txt": "version", "Packages/manifest.json": `{\"dependencies\":{}}`} {
		path := filepath.Join(input, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(workspace, ".preflight")); err != nil {
		t.Fatal(err)
	}
	_, err := stageUnityTrackedFiles(workspace, input, filepath.Join(workspace, ".preflight", "unity-projects", "job", "HabitPlayUnity"), []string{"apps/unity/Assets/Source.cs", "apps/unity/Packages/manifest.json", "apps/unity/ProjectSettings/ProjectVersion.txt"})
	if err == nil {
		t.Fatal("staging accepted an escaping generated ancestor")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("staging wrote outside workspace before rejecting escape")
	}
}

func TestUnityExportRejectsSymlinkProjectAndPromotionAncestor(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(workspace, ".preflight", "unity-projects", "job", "HabitPlayUnity")
	project := filepath.Join(stage, "Build", "exports", "ios-simulator", "HabitPlayUnity")
	marker := filepath.Join(project, "Unity-iPhone.xcodeproj", "project.pbxproj")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("native project")
	if err := os.WriteFile(marker, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(project), "SHA256SUMS"), []byte(fmt.Sprintf("%x  HabitPlayUnity/Unity-iPhone.xcodeproj/project.pbxproj\n", sha256.Sum256(content))), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(project, "external-directory")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyUnityExportChecksums(project); err == nil {
		t.Fatal("export accepted directory symlink")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, ".preflight", "unity-exports")); err != nil {
		t.Fatal(err)
	}
	job := apiRunnerJob{ID: "job", Payload: runnerJobPayload{SourceBinding: runnerJobSourceBinding{WorkspaceRoot: workspace}, CommandPlan: runnerJobCommandPlan{Output: runnerJobCommandPlanOutput{ArtifactKind: "ios_xcode_project", ExportRelativePath: "Build/exports/ios-simulator/HabitPlayUnity", OutputPath: filepath.Join(workspace, ".preflight", "unity-exports", "job", "ios-simulator", "HabitPlayUnity")}}}}
	if err := promoteUnityExport(runnerOnceOptions{workspaceRoot: workspace}, job, stage); err == nil {
		t.Fatal("promotion accepted generated ancestor symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("promotion wrote outside bound workspace")
	}
}

func TestUnityLocalPackageStagingRejectsSiblingSymlink(t *testing.T) {
	workspace := t.TempDir()
	input := filepath.Join(workspace, "apps", "unity")
	stage := filepath.Join(workspace, ".preflight", "unity-projects", "job", "HabitPlayUnity")
	for relative, data := range map[string]string{
		"apps/unity/Packages/manifest.json":       `{"dependencies":{"com.example.sdk":"file:../../../sdks/unity/com.example.sdk"}}`,
		"sdks/unity/com.example.sdk/package.json": `{"name":"com.example.sdk"}`,
	} {
		path := filepath.Join(workspace, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(filepath.Dir(stage), "local-packages")); err != nil {
		t.Fatal(err)
	}
	_, _, err := stageUnityLocalPackages(workspace, input, stage, []string{"sdks/unity/com.example.sdk/package.json"})
	if err == nil {
		t.Fatal("package staging accepted sibling symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("package staging wrote outside bound source")
	}
}

func TestUnityBuildPromotesCurrentChecksummedSourceExport(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(workspace, "apps", "unity")
	content := map[string]string{
		"Assets/Source.cs":                   "current source",
		"ProjectSettings/ProjectVersion.txt": "m_EditorVersion: 6000.3.9f1",
		"Packages/manifest.json":             `{"dependencies":{}}`,
	}
	for relative, data := range content {
		path := filepath.Join(input, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	gitScript := "#!/bin/sh\n[ \"$*\" = 'ls-files -z' ] || exit 40\nprintf 'apps/unity/Assets/Source.cs\\000apps/unity/Packages/manifest.json\\000apps/unity/ProjectSettings/ProjectVersion.txt\\000'\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(gitScript), 0o755); err != nil {
		t.Fatal(err)
	}
	bytes := []byte("new native project")
	editorScript := fmt.Sprintf("#!/bin/sh\nmkdir -p Build/exports/ios-simulator/HabitPlayUnity/Unity-iPhone.xcodeproj\nprintf 'new native project' > Build/exports/ios-simulator/HabitPlayUnity/Unity-iPhone.xcodeproj/project.pbxproj\nprintf '%x  HabitPlayUnity/Unity-iPhone.xcodeproj/project.pbxproj\\n' > Build/exports/ios-simulator/SHA256SUMS\n", sha256.Sum256(bytes))
	editor := filepath.Join(bin, "Unity")
	if err := os.WriteFile(editor, []byte(editorScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PREFLIGHT_UNITY_COMMAND", editor)
	t.Setenv("PREFLIGHT_UNITY_EXECUTE_METHODS", "Game.ExportSimulator")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	stage := filepath.Join(workspace, ".preflight", "unity-projects", "pfjob_current", "HabitPlayUnity")
	output := filepath.Join(workspace, ".preflight", "unity-exports", "pfjob_current", "ios-simulator", "HabitPlayUnity")
	job := apiRunnerJob{ID: "pfjob_current", Kind: "unity.build.player", Payload: runnerJobPayload{Platform: "ios", SourceBinding: runnerJobSourceBinding{WorkspaceRoot: workspace, GitCommitSHA: strings.Repeat("a", 40)}, CommandPlan: runnerJobCommandPlan{Tool: "unity", Command: "batchmode", InputPath: input, Args: []string{"-batchmode", "-nographics", "-quit", "-projectPath", stage, "-executeMethod", "Game.ExportSimulator", "-logFile", filepath.Join(workspace, ".preflight", "unity-build.log")}, Output: runnerJobCommandPlanOutput{BuildTarget: "iOS", ArtifactKind: "ios_xcode_project", OutputPath: output, ExportRelativePath: "Build/exports/ios-simulator/HabitPlayUnity", LogPath: filepath.Join(workspace, ".preflight", "unity-build.log")}}}}
	artifacts, err := runUnityBuildPlayer(runnerOnceOptions{workspaceRoot: workspace}, job)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.ExportFileCount != 2 || len(artifacts.SourceManifestSHA256) != 64 || len(artifacts.ExportManifestSHA256) != 64 || len(artifacts.BuildArtifacts) != 1 {
		t.Fatalf("source/export evidence missing: %+v", artifacts)
	}
	if err := verifyUnityExportChecksums(output); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(input, "Assets", "Source.cs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != "current source" {
		t.Fatal("authored source changed")
	}
	if _, err := runUnityBuildPlayer(runnerOnceOptions{workspaceRoot: workspace}, job); err == nil {
		t.Fatal("previous staged export reused")
	}
}

func TestUnityStagingPreservesAuthoredSourceAndLocalPackages(t *testing.T) {
	workspace := t.TempDir()
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(workspace, "apps", "unity")
	stage := filepath.Join(workspace, ".preflight", "unity-projects", "pfjob_fixture", "HabitPlayUnity")
	content := map[string]string{
		"apps/unity/Assets/Scene.cs":                           "latest source",
		"apps/unity/ProjectSettings/ProjectVersion.txt":        "m_EditorVersion: 6000.3.9f1",
		"apps/unity/ProjectSettings/EditorBuildSettings.asset": "authored settings",
		"apps/unity/Packages/manifest.json":                    `{"dependencies":{"com.example.sdk":"file:../../../sdks/unity/com.example.sdk"},"testables":["com.example.sdk"]}`,
		"sdks/unity/com.example.sdk/package.json":              `{"name":"com.example.sdk"}`,
		"sdks/unity/com.example.sdk/Runtime/Bridge.cs":         "latest bridge",
		"apps/unity/Library/old.cache":                         "stale generated state",
	}
	var tracked []string
	for relative, data := range content {
		path := filepath.Join(workspace, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o444); err != nil {
			t.Fatal(err)
		}
		tracked = append(tracked, relative)
	}
	files, err := stageUnityTrackedFiles(workspace, input, stage, tracked)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("unexpected authored staging: %+v", files)
	}
	if fileExists(filepath.Join(stage, "Library", "old.cache")) {
		t.Fatal("generated cache staged")
	}
	deps, rewrites, err := stageUnityLocalPackages(workspace, input, stage, tracked)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 || len(rewrites) != 1 {
		t.Fatalf("local SDK closure incomplete: %v %v", deps, rewrites)
	}
	data, err := os.ReadFile(filepath.Join(stage, "Packages", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Dependencies map[string]string `json:"dependencies"`
		Testables    []string          `json:"testables"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(manifest.Dependencies["com.example.sdk"], "file:"+filepath.Join(workspace, ".preflight")) || len(manifest.Testables) != 1 {
		t.Fatalf("generated package mapping invalid: %+v", manifest)
	}
	if err := os.WriteFile(filepath.Join(stage, "ProjectSettings", "EditorBuildSettings.asset"), []byte("generated settings"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(input, "ProjectSettings", "EditorBuildSettings.asset"))
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != "authored settings" {
		t.Fatal("editor mutated original source")
	}
	if _, err := stageUnityTrackedFiles(workspace, input, stage, tracked); err == nil {
		t.Fatal("existing staging project reused")
	}
}

func TestUnityExportChecksumBoundary(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "HabitPlayUnity")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(project, "data.bin")
	content := []byte("new source export")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}
	checksums := filepath.Join(root, "SHA256SUMS")
	valid := fmt.Sprintf("%x  HabitPlayUnity/data.bin\n", sha256.Sum256(content))
	if err := os.WriteFile(checksums, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyUnityExportChecksums(project); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("stale composition"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyUnityExportChecksums(project); err == nil {
		t.Fatal("changed export bytes accepted")
	}
	if err := os.WriteFile(checksums, []byte(fmt.Sprintf("%x  ../outside.bin\n", sha256.Sum256(content))), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyUnityExportChecksums(project); err == nil {
		t.Fatal("checksum path escaped export")
	}
}

func TestDiscoverUnityLibraryExports(t *testing.T) {
	for _, test := range []struct {
		kind   string
		marker string
	}{
		{"ios_xcode_project", "Unity-iPhone.xcodeproj/project.pbxproj"},
		{"android_gradle_project", "unityLibrary/build.gradle"},
		{"ios_xcframework", "Info.plist"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			root := t.TempDir()
			if artifacts := discoverUnityBuildArtifacts(test.kind, root); len(artifacts) != 0 {
				t.Fatalf("empty directory accepted as %s: %+v", test.kind, artifacts)
			}
			marker := filepath.Join(root, test.marker)
			if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, []byte("fixture"), 0o644); err != nil {
				t.Fatal(err)
			}
			artifacts := discoverUnityBuildArtifacts(test.kind, root)
			if len(artifacts) != 1 || artifacts[0].Kind != test.kind || artifacts[0].URI != root {
				t.Fatalf("expected exact exported project, got %+v", artifacts)
			}
		})
	}
}

func TestUnityBuildSupportRequiresInstalledModule(t *testing.T) {
	root := t.TempDir()
	editor := filepath.Join(root, "Unity.app", "Contents", "MacOS", "Unity")
	if err := os.MkdirAll(filepath.Dir(editor), 0o755); err != nil {
		t.Fatal(err)
	}
	if support := unityInstalledBuildSupport(editor); len(support) != 0 {
		t.Fatalf("nonexistent support advertised: %v", support)
	}
	for _, module := range []string{"iOSSupport", "AndroidPlayer"} {
		if err := os.MkdirAll(filepath.Join(root, "PlaybackEngines", module), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	support := unityInstalledBuildSupport(editor)
	if len(support) != 2 || support[0] != "unity.ios.build_support" || support[1] != "unity.android.build_support" {
		t.Fatalf("installed modules not detected: %v", support)
	}
}
