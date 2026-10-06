package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type unitySourceFile struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
	Symlink string `json:"symlink,omitempty"`
}

func unityFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func unityDirectorySHA256(root string) (string, int, error) {
	var files []unitySourceFile
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		item := unitySourceFile{Path: filepath.ToSlash(relative)}
		if entry.Type()&os.ModeSymlink != 0 {
			item.Symlink, err = os.Readlink(path)
		} else {
			info, statErr := entry.Info()
			if statErr != nil {
				return statErr
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("Unity output is not a regular file: %s", relative)
			}
			item.Bytes = info.Size()
			item.SHA256, err = unityFileSHA256(path)
		}
		if err != nil {
			return err
		}
		files = append(files, item)
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if len(files) == 0 {
		return "", 0, fmt.Errorf("Unity export empty")
	}
	data, err := json.Marshal(files)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), len(files), nil
}

type unitySourceManifest struct {
	SourceCommit    string            `json:"sourceCommit"`
	Files           []unitySourceFile `json:"files"`
	PackageRewrites map[string]string `json:"packageRewrites,omitempty"`
}

// Reject existing symlinks before creating source-bound staging or export files.
// Checking each descendant also covers paths whose final directory is absent.
func validateUnityOwnedPath(root, path string) error {
	if !pathWithin(root, path) {
		return fmt.Errorf("Unity path escapes its owned root: %s", path)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	current := root
	components := append([]string{""}, strings.Split(relative, string(os.PathSeparator))...)
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Unity owned path contains a symlink: %s", current)
		}
	}
	return nil
}

// Stage tracked authored files, so editor-generated settings never dirty the
// checkout used to validate subsequent workflow jobs.
func stageUnityTrackedFiles(workspace, input, destination string, tracked []string) ([]unitySourceFile, error) {
	if !pathWithin(workspace, input) || !pathWithin(workspace, destination) {
		return nil, fmt.Errorf("Unity staging paths must be inside the bound workspace")
	}
	if err := validateUnityOwnedPath(workspace, destination); err != nil {
		return nil, err
	}
	if _, err := os.Stat(destination); err == nil {
		return nil, fmt.Errorf("Unity staging destination already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	var files []unitySourceFile
	for _, relative := range tracked {
		path := filepath.Join(workspace, relative)
		if !pathWithin(input, path) {
			continue
		}
		if err := validateUnityOwnedPath(workspace, path); err != nil {
			return nil, err
		}
		suffix, err := filepath.Rel(input, path)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(filepath.ToSlash(suffix), "/")
		if parts[0] != "Assets" && parts[0] != "Packages" && parts[0] != "ProjectSettings" {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("Unity authored source must be a regular file: %s", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		target := filepath.Join(destination, suffix)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(target, data, info.Mode().Perm()|0o200); err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		files = append(files, unitySourceFile{Path: relative, SHA256: hex.EncodeToString(hash[:]), Bytes: int64(len(data))})
	}
	if !fileExists(filepath.Join(destination, "ProjectSettings", "ProjectVersion.txt")) || !fileExists(filepath.Join(destination, "Packages", "manifest.json")) {
		return nil, fmt.Errorf("Unity staged project is missing its version or package manifest")
	}
	return files, nil
}

func stageUnityBuildSource(options runnerOnceOptions, job apiRunnerJob) (string, error) {
	plan := job.Payload.CommandPlan
	if plan.InputPath == "" {
		return "", nil
	} // Existing standalone build plans do not require staging.
	if len(job.Payload.SourceBinding.GitCommitSHA) != 40 {
		return "", fmt.Errorf("Unity staged build requires an exact source commit")
	}
	workspace := firstNonEmpty(job.Payload.SourceBinding.WorkspaceRoot, options.workspaceRoot)
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return "", err
	}
	if job.ID == "" || strings.ContainsAny(job.ID, "/\\.") {
		return "", fmt.Errorf("invalid Unity build job identity")
	}
	input, err := filepath.EvalSymlinks(plan.InputPath)
	if err != nil {
		return "", err
	}
	stage := filepath.Join(workspace, ".preflight", "unity-projects", job.ID, "HabitPlayUnity")
	if filepath.Clean(unityArgValue(plan.Args, "-projectPath")) != stage {
		return "", fmt.Errorf("Unity project path must equal owned staging path %s", stage)
	}
	command := exec.Command("git", "ls-files", "-z")
	command.Dir = workspace
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read tracked Unity sources: %w", err)
	}
	tracked := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	files, err := stageUnityTrackedFiles(workspace, input, stage, tracked)
	if err != nil {
		return "", err
	}
	dependencyFiles, rewrites, err := stageUnityLocalPackages(workspace, input, stage, tracked)
	if err != nil {
		return "", err
	}
	files = append(files, dependencyFiles...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	manifest := unitySourceManifest{SourceCommit: job.Payload.SourceBinding.GitCommitSHA, Files: files, PackageRewrites: rewrites}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(filepath.Dir(stage), "source-manifest.json")
	if err := validateUnityOwnedPath(workspace, manifestPath); err != nil {
		return "", err
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	return stage, nil
}

func promoteUnityExport(options runnerOnceOptions, job apiRunnerJob, stagedProject string) error {
	plan := job.Payload.CommandPlan
	relative := filepath.Clean(plan.Output.ExportRelativePath)
	if filepath.IsAbs(relative) || !strings.HasPrefix(filepath.ToSlash(relative), "Build/exports/") || strings.Contains(relative, "..") {
		return fmt.Errorf("Unity exportRelativePath must select a generated Build/exports project")
	}
	output := filepath.Join(stagedProject, relative)
	if err := validateUnityOwnedPath(stagedProject, output); err != nil {
		return err
	}
	if len(discoverUnityBuildArtifacts(firstNonEmpty(plan.Output.ExportArtifactKind, plan.Output.ArtifactKind), output)) == 0 {
		return fmt.Errorf("Unity staged export is missing native project")
	}
	if err := verifyUnityExportChecksums(output); err != nil {
		return err
	}
	workspace := firstNonEmpty(job.Payload.SourceBinding.WorkspaceRoot, options.workspaceRoot)
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return err
	}
	ownedRoot := filepath.Join(workspace, ".preflight", "unity-exports", job.ID)
	target := filepath.Clean(firstNonEmpty(plan.Output.ExportOutputPath, plan.Output.OutputPath))
	if !pathWithin(ownedRoot, target) || filepath.Base(target) != filepath.Base(output) {
		return fmt.Errorf("Unity export output must be inside this job's owned export directory")
	}
	if err := validateUnityOwnedPath(workspace, target); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Dir(target)); err == nil {
		return fmt.Errorf("Unity output lane already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(target)), 0o755); err != nil {
		return err
	}
	return os.Rename(filepath.Dir(output), filepath.Dir(target))
}

func handleUnityReadinessJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}
	editor, err := resolveUnityExecutable(job.Payload.CommandPlan)
	if err == nil && job.Payload.Platform != "" {
		required := "unity." + job.Payload.Platform + ".build_support"
		if !containsString(unityInstalledBuildSupport(editor), required) {
			err = fmt.Errorf("Unity %s build support is not installed", job.Payload.Platform)
		}
	}
	result := map[string]any{"status": "ok", "unity": map[string]any{"ready": true, "editorPath": editor, "buildSupport": unityInstalledBuildSupport(editor), "licenseVerified": false}}
	if err != nil {
		result = map[string]any{"status": "failed", "failure": map[string]any{"code": "unity_readiness_failed", "message": err.Error()}}
	}
	if err := completeRunnerJob(client, options, registration, job, result); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "completed Unity readiness %s\n", job.ID)
	return nil
}

func stageUnityLocalPackages(workspace, input, stage string, tracked []string) ([]unitySourceFile, map[string]string, error) {
	if err := validateUnityOwnedPath(workspace, stage); err != nil {
		return nil, nil, err
	}
	manifestPath := filepath.Join(input, "Packages", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, err
	}
	var dependencies map[string]string
	if err := json.Unmarshal(manifest["dependencies"], &dependencies); err != nil {
		return nil, nil, err
	}
	rewrites := make(map[string]string)
	var files []unitySourceFile
	for name, reference := range dependencies {
		if !strings.HasPrefix(reference, "file:") {
			continue
		}
		path := strings.TrimPrefix(reference, "file:")
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(manifestPath), path)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, nil, err
		}
		if !pathWithin(workspace, resolved) {
			return nil, nil, fmt.Errorf("Unity local package escapes bound source: %s", name)
		}
		var packageFiles []unitySourceFile
		relative, err := filepath.Rel(workspace, resolved)
		if err != nil {
			return nil, nil, err
		}
		destination := filepath.Join(filepath.Dir(stage), "local-packages", relative)
		if err := validateUnityOwnedPath(workspace, destination); err != nil {
			return nil, nil, err
		}
		for _, sourceRelative := range tracked {
			source := filepath.Join(workspace, sourceRelative)
			if !pathWithin(resolved, source) {
				continue
			}
			if err := validateUnityOwnedPath(workspace, source); err != nil {
				return nil, nil, err
			}
			info, err := os.Lstat(source)
			if err != nil {
				return nil, nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("Unity local package source must be regular: %s", sourceRelative)
			}
			data, err := os.ReadFile(source)
			if err != nil {
				return nil, nil, err
			}
			suffix, err := filepath.Rel(resolved, source)
			if err != nil {
				return nil, nil, err
			}
			target := filepath.Join(destination, suffix)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(target, data, info.Mode().Perm()|0o200); err != nil {
				return nil, nil, err
			}
			hash := sha256.Sum256(data)
			packageFiles = append(packageFiles, unitySourceFile{Path: sourceRelative, SHA256: hex.EncodeToString(hash[:]), Bytes: int64(len(data))})
		}
		if !fileExists(filepath.Join(destination, "package.json")) {
			return nil, nil, fmt.Errorf("Unity local package has no tracked package.json: %s", name)
		}
		files = append(files, packageFiles...)
		dependencies[name] = "file:" + filepath.ToSlash(destination)
		rewrites[name] = dependencies[name]
	}
	if len(rewrites) != 0 {
		manifest["dependencies"], err = json.Marshal(dependencies)
		if err != nil {
			return nil, nil, err
		}
		data, err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(stage, "Packages", "manifest.json"), append(data, '\n'), 0o644); err != nil {
			return nil, nil, err
		}
	}
	return files, rewrites, nil
}

func verifyUnityExportChecksums(project string) error {
	root := filepath.Dir(project)
	if err := validateUnityOwnedPath(root, project); err != nil {
		return err
	}
	if err := validateUnityOwnedPath(root, filepath.Join(root, "SHA256SUMS")); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		return fmt.Errorf("read Unity export checksums: %w", err)
	}
	count := 0
	verified := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 || filepath.IsAbs(parts[1]) {
			return fmt.Errorf("invalid Unity export checksum line")
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return fmt.Errorf("invalid Unity export checksum digest")
		}
		path := filepath.Join(root, filepath.FromSlash(parts[1]))
		if err := validateUnityOwnedPath(root, path); err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("resolve Unity export file: %w", err)
		}
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil || !pathWithin(resolvedRoot, resolved) {
			return fmt.Errorf("Unity export checksum path escapes export")
		}
		file, err := os.Open(resolved)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, file)
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != parts[0] {
			return fmt.Errorf("Unity export checksum mismatch: %s", parts[1])
		}
		if verified[resolved] {
			return fmt.Errorf("duplicate Unity export checksum: %s", parts[1])
		}
		verified[resolved] = true
		count++
	}
	if count == 0 {
		return fmt.Errorf("Unity export checksums empty")
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := validateUnityOwnedPath(root, path); err != nil {
			return err
		}
		if entry.IsDir() || path == filepath.Join(root, "SHA256SUMS") {
			return nil
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if !verified[resolved] {
			return fmt.Errorf("Unity export file missing checksum: %s", path)
		}
		return nil
	})
}

// A Unity editor without its platform module cannot export a project for that platform.
func unityInstalledBuildSupport(editor string) []string {
	root := filepath.Dir(editor)
	if filepath.Base(root) == "MacOS" && filepath.Base(filepath.Dir(root)) == "Contents" {
		root = filepath.Dir(filepath.Dir(filepath.Dir(root)))
	}
	var support []string
	for _, module := range []struct{ directory, capability string }{
		{"iOSSupport", "unity.ios.build_support"},
		{"AndroidPlayer", "unity.android.build_support"},
	} {
		if info, err := os.Stat(filepath.Join(root, "PlaybackEngines", module.directory)); err == nil && info.IsDir() {
			support = append(support, module.capability)
		}
	}
	return support
}
