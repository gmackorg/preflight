package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workOrderClientFixture(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("PREFLIGHT_API_URL", server.URL)
	t.Setenv("PREFLIGHT_WORKSPACE_ID", "workspace_fixture")
	t.Setenv("PREFLIGHT_TOKEN", "fixture-token")
	return server
}

func writeWorkOrderApp(t *testing.T) string {
	t.Helper()
	app := writeExpoFixture(t)
	runGit(t, app, "init")
	runGit(t, app, "add", ".")
	runGit(t, app, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "app fixture")
	bin := t.TempDir()
	script := `#!/bin/sh
printf '{"slug":"fixture","scheme":"fixture-%s","ios":{"bundleIdentifier":"fixture.%s"},"android":{"package":"fixture.%s"}}' "$APP_VARIANT" "$APP_VARIANT" "$APP_VARIANT"
`
	if err := os.WriteFile(filepath.Join(bin, "npx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PREFLIGHT_FORCE_EXPO_CONFIG_CLI", "1")
	return app
}

func TestBuildWorkOrderUsesDispatchLaneAndExactProfile(t *testing.T) {
	for _, tc := range []struct{ kind, platform, flag, profile, lane, variant string }{
		{"build", "ios", "", "development", "development", "development"},
		{"build", "ios", "--profile", "qa-device", "development", "development"},
		{"device_test", "ios", "--build-profile", "qa-device", "development", "development"},
		{"build_matrix", "android", "--profile", "qa-android", "development", "development"},
		{"simulator_test", "ios", "--profile", "preview-simulator", "simulator", "preview"},
		{"e2e_suite", "ios", "", "development", "simulator", "development"},
	} {
		t.Run(tc.kind+"/"+tc.platform+"/"+tc.profile, func(t *testing.T) {
			app := writeWorkOrderApp(t)
			var received struct {
				SourceBinding sourceBinding `json:"sourceBinding"`
			}
			probeLane, posts := "", 0
			server := workOrderClientFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/preflight/v1/runners/capacity":
					probeLane = r.URL.Query().Get("lane")
					fmt.Fprint(w, `{"data":{"capacity":{"status":"ready"}}}`)
				case r.Method == http.MethodPost && r.URL.Path == "/api/preflight/v1/work-orders":
					posts++
					if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
						t.Error(err)
					}
					fmt.Fprint(w, `{"data":{"workOrder":{"id":"pfwo_fixture","status":"queued"}}}`)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			})
			args := []string{"build", "--app", "pfapp_fixture", "--app-dir", app, "--platform", tc.platform, "--kind", tc.kind, "--json"}
			if tc.flag != "" {
				args = append(args, tc.flag, tc.profile)
			}
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut, server.Client()); code != 0 {
				t.Fatalf("build returned %d: %s", code, &errOut)
			}
			binding := received.SourceBinding
			if posts != 1 || binding.Lane != tc.lane || probeLane != tc.lane || binding.BuildProfileName != tc.profile {
				t.Fatalf("wrong dispatch/profile: posts=%d probe=%s binding=%+v", posts, probeLane, binding)
			}
			if binding.AppScheme != "fixture-"+tc.variant || binding.ProfileEnvDigest == "" {
				t.Fatalf("profile environment did not bind app identity: %+v", binding)
			}
		})
	}
}

func TestBuildWorkOrderRejectsInvalidProfileBeforeRequests(t *testing.T) {
	for _, tc := range []struct{ platform, kind, profile, want string }{
		{"ios", "build", "preview", "packaged simulator app"},
		{"android", "device_test", "preview-android", "packaged simulator app"},
		{"ios", "release_candidate", "production", "separate store build workflow"},
	} {
		t.Run(tc.kind+"/"+tc.profile, func(t *testing.T) {
			app := writeWorkOrderApp(t)
			calls := 0
			server := workOrderClientFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(400)
			})
			var out, errOut bytes.Buffer
			code := run([]string{"build", "--app", "pfapp_fixture", "--app-dir", app, "--platform", tc.platform, "--kind", tc.kind, "--profile", tc.profile}, &out, &errOut, server.Client())
			if code != 2 || calls != 0 || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("invalid profile: code=%d calls=%d stderr=%s", code, calls, &errOut)
			}
		})
	}
	for _, flags := range [][]string{{"--profile"}, {"--profile", "--json"}, {"--profiel", "qa-device"}} {
		var out, errOut bytes.Buffer
		if code := run(append([]string{"build", "--app", "pfapp_fixture"}, flags...), &out, &errOut, http.DefaultClient); code != 2 {
			t.Fatalf("bad flags must fail before network: %v => %d", flags, code)
		}
	}
}

func TestCancelWorkOrderCancelsWorkflowBeforeOrder(t *testing.T) {
	for _, active := range []string{"", "pfw_active"} {
		t.Run("workflow="+active, func(t *testing.T) {
			var calls []string
			server := workOrderClientFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				if r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("x-preflight-workspace-id") != "workspace_fixture" {
					t.Error("request lost workspace authentication")
				}
				if r.Method == http.MethodPost {
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["workspaceId"] != "workspace_fixture" {
						t.Error("cancellation lost workspace scope")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/preflight/v1/work-orders/pfwo_selected":
					fmt.Fprintf(w, `{"data":{"workOrder":{"id":"pfwo_selected","workspaceId":"workspace_fixture","status":"running","activeWorkflowId":%q}}}`, active)
				case "/api/preflight/v1/workflows/pfw_active/cancel":
					fmt.Fprint(w, `{"data":{"workflowProjection":{"workflowId":"pfw_active","status":"cancelled"}}}`)
				case "/api/preflight/v1/work-orders/pfwo_selected/cancel":
					fmt.Fprint(w, `{"data":{"workOrder":{"id":"pfwo_selected","workspaceId":"workspace_fixture","status":"cancelled"}}}`)
				default:
					t.Errorf("unexpected route %s", r.URL.Path)
					w.WriteHeader(400)
				}
			})
			var out, errOut bytes.Buffer
			if code := run([]string{"cancel", "pfwo_selected", "--json"}, &out, &errOut, server.Client()); code != 0 {
				t.Fatalf("cancel returned %d: %s", code, &errOut)
			}
			want := "GET /api/preflight/v1/work-orders/pfwo_selected|"
			if active != "" {
				want += "POST /api/preflight/v1/workflows/pfw_active/cancel|"
			}
			want += "POST /api/preflight/v1/work-orders/pfwo_selected/cancel"
			if strings.Join(calls, "|") != want || !strings.Contains(out.String(), `"status": "cancelled"`) {
				t.Fatalf("wrong cancellation sequence/output: %v %s", calls, &out)
			}
		})
	}
}

func TestCancelWorkOrderPreservesScopeAndExistingOutcomes(t *testing.T) {
	for _, body := range []string{
		`{"workOrder":null}`,
		`{"workOrder":{"id":"pfwo_other","workspaceId":"workspace_fixture","status":"running"}}`,
		`{"workOrder":{"id":"pfwo_selected","workspaceId":"another_workspace","status":"running"}}`,
		`{"workOrder":{"id":"pfwo_selected","workspaceId":"workspace_fixture","status":"succeeded"}}`,
		`{"workOrder":{"id":"pfwo_selected","workspaceId":"workspace_fixture","status":"failed"}}`,
	} {
		posts := 0
		server := workOrderClientFixture(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				posts++
			}
			fmt.Fprintf(w, `{"data":%s}`, body)
		})
		var out, errOut bytes.Buffer
		if code := run([]string{"cancel", "pfwo_selected"}, &out, &errOut, server.Client()); code != 1 || posts != 0 {
			t.Fatalf("unsafe cancel: code=%d posts=%d input=%s", code, posts, body)
		}
	}
}

func TestCancelWorkOrderDoesNotHideWorkflowFailure(t *testing.T) {
	for _, status := range []string{"forbidden", "passed", "missing", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			orderPosts := 0
			server := workOrderClientFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					// Retrying a legacy metadata-only cancellation still cancels its workflow.
					fmt.Fprint(w, `{"data":{"workOrder":{"id":"pfwo_selected","workspaceId":"workspace_fixture","status":"cancelled","activeWorkflowId":"pfw_active"}}}`)
				} else if r.URL.Path == "/api/preflight/v1/workflows/pfw_active/cancel" {
					if status == "forbidden" {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, `{"error":{"code":"forbidden","message":"not permitted"}}`)
					} else if status == "missing" {
						fmt.Fprint(w, `{"data":{}}`)
					} else {
						fmt.Fprintf(w, `{"data":{"workflowProjection":{"workflowId":"pfw_active","status":%q}}}`, status)
					}
				} else {
					orderPosts++
					w.WriteHeader(http.StatusConflict)
					fmt.Fprint(w, `{"error":{"code":"conflict","message":"retry"}}`)
				}
			})
			var out, errOut bytes.Buffer
			code := run([]string{"cancel", "pfwo_selected"}, &out, &errOut, server.Client())
			wantPosts := 0
			if status == "cancelled" {
				wantPosts = 1
			}
			if code != 1 || orderPosts != wantPosts || out.Len() != 0 {
				t.Fatalf("partial failure reported success: code=%d posts=%d out=%s err=%s", code, orderPosts, &out, &errOut)
			}
		})
	}
}

func TestCancelWorkOrderRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"pfw_workflow"}, {"pfwo_a", "pfwo_b"}, {"pfwo_../escape"}, {"pfwo_a", "--all"}} {
		var out, errOut bytes.Buffer
		if code := run(append([]string{"cancel"}, args...), &out, &errOut, http.DefaultClient); code != 2 {
			t.Fatalf("invalid cancel arguments %v returned %d", args, code)
		}
	}
}
