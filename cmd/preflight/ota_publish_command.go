package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type otaPublishReceipt struct {
	WorkflowID     string `json:"workflowId"`
	Platform       string `json:"platform"`
	RuntimeVersion string `json:"runtimeVersion"`
}

// Resolve exactly as expo-updates does for a native build, including fingerprint
// policies and platform-specific overrides. The project's installed CLI determines
// compatibility with its SDK.
func resolvePublishRuntime(appDir, platform, channel string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npx", "--no-install", "expo-updates", "runtimeversion:resolve", "--platform", platform)
	cmd.Dir = appDir
	cmd.Env = upsertEnvValues(os.Environ(), map[string]string{
		"APP_VARIANT": channel, "EXPO_NO_DOTENV": "1", "EXPO_NO_TELEMETRY": "1",
	})
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve %s runtime in %s with the installed expo-updates CLI: %w", platform, appDir, err)
	}
	var result struct {
		RuntimeVersion string `json:"runtimeVersion"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return "", fmt.Errorf("decode %s runtime: %w", platform, err)
	}
	if strings.TrimSpace(result.RuntimeVersion) == "" {
		return "", fmt.Errorf("expo-updates returned an empty %s runtime in %s", platform, appDir)
	}
	return result.RuntimeVersion, nil
}

func runOTAPublish(args []string, stdout, stderr io.Writer, client *http.Client) int {
	if subcommandHelpRequested(args) {
		printOTAHelp(stdout)
		return 0
	}
	input, ok := parseAPICommand("ota publish", args, []apiFlag{
		{name: "--app", key: "app"}, {name: "--channel", key: "channel"}, {name: "--platform", key: "platform"},
		{name: "--app-dir", key: "appDir"}, {name: "--workspace-root", key: "workspaceRoot"},
		{name: "--runtime-version", key: "runtimeVersion"}, {name: "--message", key: "message"},
	}, stderr)
	if !ok {
		return 2
	}
	opts := input.options
	channel := opts["channel"]
	if opts["app"] == "" || (channel != "development" && channel != "preview" && channel != "production") {
		fmt.Fprintln(stderr, "pass --app and --channel development|preview|production")
		return 2
	}
	platforms := []string{opts["platform"]}
	switch opts["platform"] {
	case "all":
		platforms = []string{"ios", "android"}
	case "ios", "android":
	default:
		fmt.Fprintln(stderr, "pass --platform ios|android|all")
		return 2
	}
	appDir, err := filepath.Abs(firstNonEmpty(opts["appDir"], "."))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	root := findWorkspaceRoot(appDir)
	if override := opts["workspaceRoot"]; override != "" {
		relative, err := filepath.Rel(root, appDir)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		root, err = filepath.Abs(override)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		appDir = filepath.Join(root, relative)
	}
	// Resolve both platforms before publishing either. A broken Android config
	// must not leave an unexpected iOS update queued by an "all" request.
	var updates []otaPublishReceipt
	for _, platform := range platforms {
		version := strings.TrimSpace(opts["runtimeVersion"])
		if version == "" {
			version, err = resolvePublishRuntime(appDir, platform, channel)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		updates = append(updates, otaPublishReceipt{Platform: platform, RuntimeVersion: version})
	}
	for i, update := range updates {
		body := map[string]string{"platform": update.Platform, "channel": channel, "runtimeVersion": update.RuntimeVersion, "workspaceRoot": root}
		if opts["message"] != "" {
			body["message"] = opts["message"]
		}
		data, err := requestPreflightAPI(client, input, http.MethodPost, appPath(opts["app"], "/ota/publish"), body, false)
		var result struct {
			WorkflowID string `json:"workflowId"`
		}
		if err == nil {
			err = decodeEnvelopeData(data, &result)
		}
		if err != nil || result.WorkflowID == "" {
			fmt.Fprintf(stderr, "%s OTA publish returned no confirmed workflow: %v\n", update.Platform, err)
			if input.json {
				_ = json.NewEncoder(stdout).Encode(updates[:i])
			}
			return 1
		}
		updates[i].WorkflowID = result.WorkflowID
		if !input.json {
			fmt.Fprintf(stdout, "queued %s %s update for runtime %s: %s\n", update.Platform, channel, update.RuntimeVersion, result.WorkflowID)
		}
	}
	if input.json {
		_ = json.NewEncoder(stdout).Encode(updates)
	}
	return 0
}
