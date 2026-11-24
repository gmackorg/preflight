package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// storePreBuildHookScript is the package.json script a store build runs in the
// app directory before generating or building the native project. It is the
// Preflight counterpart of EAS's eas-build-pre-install: the place an app
// fetches build inputs that are not in git, such as HabitPlay's checksum-pinned
// Unity framework, which its config plugin refuses to prebuild without.
//
// eas-build-pre-install itself is deliberately not run: those hooks were
// written for EAS's image (global npm installs, corepack activation, checks of
// EAS-only environment variables) and fail or misbehave on a runner.
const storePreBuildHookScript = "preflight-build-pre-install"

// runStorePreBuildHook runs the app's preflight-build-pre-install script, if it
// has one, with the platform in PREFLIGHT_BUILD_PLATFORM and, for scripts
// ported from EAS that read it, EAS_BUILD_PLATFORM.
func runStorePreBuildHook(rt *storeJobRuntime, platform string, env []string) error {
	scripts, err := appPackageScripts(rt.appDir)
	if err != nil {
		return storeFailuref("store_pre_build_hook_failed", "read %s: %v", filepath.Join(rt.appDir, "package.json"), err)
	}
	if _, ok := scripts[storePreBuildHookScript]; !ok {
		if _, legacy := scripts["eas-build-pre-install"]; legacy {
			_, _ = fmt.Fprintf(rt.log, "package.json has eas-build-pre-install but no %s; Preflight does not run EAS hooks. Add a %s script for build inputs the native build needs.\n", storePreBuildHookScript, storePreBuildHookScript)
		}
		return nil
	}
	_, _ = fmt.Fprintf(rt.log, "running %s for %s\n", storePreBuildHookScript, platform)
	hookEnv := append(append([]string{}, env...),
		"PREFLIGHT_BUILD_PLATFORM="+platform,
		"EAS_BUILD_PLATFORM="+platform,
	)
	output, err := rt.run.Run(storeCommand{
		Name:    "npm",
		Args:    []string{"run", "--silent", storePreBuildHookScript},
		Dir:     rt.appDir,
		Env:     hookEnv,
		Timeout: storeCommandTimeout("PREFLIGHT_STORE_PRE_BUILD_HOOK_TIMEOUT", 20*time.Minute),
	})
	if err != nil {
		return wrapStoreCommandError(err, storeFailuref("store_pre_build_hook_failed", "%s (%s): %v%s", storePreBuildHookScript, platform, err, storeOutputTail(string(output))))
	}
	return nil
}

// appPackageScripts returns the scripts of appDir/package.json, or none when
// the app has no package.json.
func appPackageScripts(appDir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(appDir, "package.json"))
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if manifest.Scripts == nil {
		return map[string]string{}, nil
	}
	return manifest.Scripts, nil
}
