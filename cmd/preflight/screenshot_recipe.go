package main

// P3 — screenshot recipes: fetch/apply/save the per-app capture instruction so
// `preflight apps screenshots --app X` needs no other flags. Explicit flags
// always win over recipe values; --save-recipe upserts after a successful run.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type screenshotRecipe struct {
	Platform       string            `json:"platform,omitempty"`
	Scheme         string            `json:"scheme,omitempty"`
	PackagePath    string            `json:"packagePath,omitempty"`
	SimDevice      string            `json:"simDevice,omitempty"`
	BuildEnv       map[string]string `json:"buildEnv,omitempty"`
	FlowYaml       string            `json:"flowYaml,omitempty"`
	DemoAccountRef string            `json:"demoAccountRef,omitempty"`
	// Demo state is perishable — a fast left running past its window renders a
	// nonsense timer, an account with no activity renders an empty tab. The
	// recipe carries the script that restores a photogenic state and how long
	// that state stays good.
	SeedScript            string `json:"seedScript,omitempty"`
	SeedStaleAfterMinutes int    `json:"seedStaleAfterMinutes,omitempty"`
	SeedLastRunAt         string `json:"seedLastRunAt,omitempty"`
	Notes                 string `json:"notes,omitempty"`
}

func recipeEndpoint(apiURL, appID string) string {
	return strings.TrimRight(apiURL, "/") +
		"/api/preflight/v1/apps/" + url.PathEscape(appID) + "/screenshot-recipe"
}

func fetchScreenshotRecipe(
	client *http.Client, apiURL, token, appID string,
) (*screenshotRecipe, error) {
	raw, err := getPreflightJSON(client, recipeEndpoint(apiURL, appID)+"?platform=ios", token)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Recipe *screenshotRecipe `json:"recipe"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	return envelope.Recipe, nil
}

func saveScreenshotRecipe(
	client *http.Client, apiURL, token, appID string, recipe screenshotRecipe,
) error {
	endpoint := recipeEndpoint(apiURL, appID)
	body, err := json.Marshal(recipe)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("save recipe: HTTP %d: %s", res.StatusCode, payload)
	}
	return nil
}

// applyRecipeDefaults fills unset capture inputs from the stored recipe.
// Returns the flow path (possibly a temp file materialized from flowYaml) and
// the recipe build env to layer under the process env at build time.
func applyRecipeDefaults(
	recipe *screenshotRecipe,
	in *screenshotPlanInput,
	workspaceRoot *string,
	packagePath *string,
	stdout io.Writer,
) (map[string]string, error) {
	if recipe == nil {
		return nil, nil
	}
	if in.Scheme == "" && recipe.Scheme != "" {
		in.Scheme = recipe.Scheme
	}
	if in.SimUDID == "" && recipe.SimDevice != "" {
		in.SimUDID = recipe.SimDevice
	}
	if *packagePath == "" && recipe.PackagePath != "" {
		*packagePath = recipe.PackagePath
	}
	if in.FlowPath == "" && strings.TrimSpace(recipe.FlowYaml) != "" {
		tmp, err := os.CreateTemp("", "pf-recipe-flow-*.yaml")
		if err != nil {
			return nil, err
		}
		if _, err := tmp.WriteString(recipe.FlowYaml); err != nil {
			tmp.Close()
			return nil, err
		}
		tmp.Close()
		in.FlowPath = tmp.Name()
		fmt.Fprintf(stdout, "[recipe] flow → %s\n", filepath.Base(tmp.Name()))
	}
	if warning := seedStalenessWarning(recipe, time.Now()); warning != "" {
		fmt.Fprintln(stdout, warning)
	}
	if len(recipe.BuildEnv) > 0 {
		fmt.Fprintf(stdout, "[recipe] build env: %s\n",
			strings.Join(sortedKeys(recipe.BuildEnv), ","))
	}
	return recipe.BuildEnv, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// seedStalenessWarning reports when an app's demo data needs re-seeding before
// capture. Silent when the recipe has no seed policy.
//
// This exists because captures degrade silently: crucible shipped a Today
// screen reading "125:06:12 / 100% complete" against a 16h target because the
// seeded fast had been running for five days. Nothing failed — the screenshot
// was just wrong, and only a human looking at the image would catch it.
func seedStalenessWarning(recipe *screenshotRecipe, now time.Time) string {
	if recipe == nil || recipe.SeedStaleAfterMinutes <= 0 {
		return ""
	}
	if strings.TrimSpace(recipe.SeedLastRunAt) == "" {
		return "[recipe] demo data has never been seeded — run the recipe seedScript before capturing"
	}
	lastRun, err := time.Parse(time.RFC3339, recipe.SeedLastRunAt)
	if err != nil {
		return ""
	}
	age := now.Sub(lastRun)
	limit := time.Duration(recipe.SeedStaleAfterMinutes) * time.Minute
	if age <= limit {
		return ""
	}
	return fmt.Sprintf(
		"[recipe] demo data is stale (seeded %s ago, goes stale after %s) — re-run the seedScript or captures will show degraded state",
		age.Round(time.Minute), limit,
	)
}
