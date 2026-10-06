package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Captured from the current plan-only API on 2026-10-06. Only local absolute
// paths were normalized; envelope, command IDs and runtime records are real.
func currentSimulatorProofEnvelope(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/simulator-proof-plan-current-api.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeStandaloneProofFixture(t *testing.T) string {
	t.Helper()
	appDir := writeExpoFixture(t)
	writeExpoConfigIdentity(t, appDir)
	flowPath := filepath.Join(appDir, ".maestro", "01-app-launches.yaml")
	if err := os.MkdirAll(filepath.Dir(flowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flowPath, []byte("appId: com.gmacko.forgegraph.dev\n---\n- launchApp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return appDir
}

func TestStandaloneSimulatorPlanPostsCurrentReadinessContract(t *testing.T) {
	appDir := writeStandaloneProofFixture(t)
	t.Setenv("PREFLIGHT_TOKEN", "contract-test-token")
	var body struct {
		DevelopmentReadiness struct {
			SourceBinding sourceBinding   `json:"sourceBinding"`
			PackageJSON   packageJSON     `json:"packageJson"`
			EASJSON       json.RawMessage `json:"easJson"`
			MaestroFlows  []struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			} `json:"maestroFlows"`
		} `json:"developmentReadiness"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		_, _ = w.Write(currentSimulatorProofEnvelope(t))
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"prove-app", "--standalone-plan", "--api-url", server.URL, "--workspace-id", "ws_contract", "--app-dir", appDir, "--target-key", "SIM-UDID"}, &stdout, &stderr, server.Client())
	if code != 0 {
		t.Fatalf("plan exit %d: %s", code, stderr.String())
	}
	readiness := body.DevelopmentReadiness
	if readiness.SourceBinding.AppScheme != "forgegraph" || readiness.PackageJSON.Dependencies["expo"] == "" || readiness.PackageJSON.Dependencies["expo-dev-client"] == "" || len(readiness.EASJSON) == 0 || len(readiness.MaestroFlows) != 1 {
		t.Fatalf("missing current readiness contract: %#v", readiness)
	}
	if readiness.MaestroFlows[0].Path != filepath.Join(appDir, ".maestro", "01-app-launches.yaml") || !strings.Contains(readiness.MaestroFlows[0].Content, "com.gmacko.forgegraph.dev") {
		t.Fatalf("wrong readiness flow: %#v", readiness.MaestroFlows)
	}
}

func TestStandaloneSimulatorPlanDecodesCurrentAPIEnvelope(t *testing.T) {
	appDir := writeStandaloneProofFixture(t)
	t.Setenv("PREFLIGHT_TOKEN", "contract-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(currentSimulatorProofEnvelope(t))
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"prove-app", "--standalone-plan", "--api-url", server.URL, "--workspace-id", "ws_contract", "--app-dir", appDir, "--target-key", "SIM-UDID"}, &stdout, &stderr, server.Client())
	if code != 0 {
		t.Fatalf("plan exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "simulator proof plan pfw_festigram_standalone_plan_probe_") || !strings.Contains(stdout.String(), "maestro --platform ios --device") {
		t.Fatalf("current data.plan silently decoded as no commands: %s", stdout.String())
	}
}

func TestStandaloneSimulatorRunRejectsEmptyPlanBeforeSideEffects(t *testing.T) {
	appDir := writeStandaloneProofFixture(t)
	t.Setenv("PREFLIGHT_TOKEN", "contract-test-token")
	for _, response := range []string{`{"data":{"plan":{}}}`, `{"data":{"plan":{"workflowId":"pfw_empty","commands":[]}}}`, `{"data":{}}`} {
		t.Run(response, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			code := run([]string{"prove-app", "--standalone-run", "--api-url", server.URL, "--workspace-id", "ws_contract", "--app-dir", appDir, "--target-key", "SIM-UDID"}, &stdout, &stderr, server.Client())
			if code == 0 || strings.Contains(stdout.String(), "passed") || calls != 1 {
				t.Fatalf("empty plan accepted or published state: exit=%d calls=%d stdout=%s stderr=%s", code, calls, stdout.String(), stderr.String())
			}
		})
	}
}

// The fake npx executes this test binary in its own process group. Its listener
// belongs to the launched command, rather than to the API test process.
func TestStandaloneMetroHelperProcess(t *testing.T) {
	if os.Getenv("PREFLIGHT_TEST_METRO_HELPER") != "1" {
		return
	}
	port := os.Getenv("PREFLIGHT_TEST_METRO_PORT")
	ready := false
	err := http.ListenAndServe("127.0.0.1:"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		if !ready {
			ready = true
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := os.WriteFile(os.Getenv("PREFLIGHT_METRO_READY_MARKER"), []byte("ready"), 0o644); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func setupStandaloneMetroHelper(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PREFLIGHT_TEST_BINARY", binary)
	t.Setenv("PREFLIGHT_TEST_METRO_HELPER", "1")
	t.Setenv("PREFLIGHT_TEST_METRO_PORT", strconv.Itoa(port))
	t.Setenv("PREFLIGHT_METRO_READY_MARKER", filepath.Join(t.TempDir(), "metro-ready"))
	t.Setenv("PREFLIGHT_EXPO_START_TIMEOUT", "3s")
	return port
}

type standalonePortResponseWriter struct {
	http.ResponseWriter
	port int
}

func (w standalonePortResponseWriter) Write(body []byte) (int, error) {
	_, err := w.ResponseWriter.Write(bytes.ReplaceAll(body, []byte("19000"), []byte(strconv.Itoa(w.port))))
	return len(body), err
}

func TestStandaloneSimulatorRunRejectsOccupiedMetroBeforeCommands(t *testing.T) {
	appDir := writeStandaloneProofFixture(t)
	metro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("packager-status:running"))
	}))
	defer metro.Close()
	var envelope struct {
		Data struct {
			Plan simulatorProofPlanData `json:"plan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(currentSimulatorProofEnvelope(t), &envelope); err != nil {
		t.Fatal(err)
	}
	plan := envelope.Data.Plan
	plan.AdvertisedURL = metro.URL
	plan.Commands[0].CWD = appDir
	plan.Commands[1].Command = "sh"
	plan.Commands[1].Args = []string{"-c", "exit 7"}
	// Starting or publishing any command/state is forbidden when another server
	// already owns the requested port, even when its status endpoint looks ready.
	plan.Commands[1].Command = "sh"
	plan.Commands[1].Args = []string{"-c", "exit 7"}
	sideEffects := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sideEffects++
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer api.Close()
	var stdout, stderr bytes.Buffer
	code := executeStandaloneSimulatorProofPlan(proveAppOptions{apiURL: api.URL}, sourceBinding{}, plan, &stdout, &stderr, api.Client())
	if code == 0 || sideEffects != 0 || !strings.Contains(stderr.String(), "occupied") {
		t.Fatalf("occupied Metro used as proof: exit=%d posts=%d stdout=%s stderr=%s", code, sideEffects, stdout.String(), stderr.String())
	}
}

func TestStandaloneSimulatorRunFailsWhenExpoExitsBeforeReady(t *testing.T) {
	appDir := writeStandaloneProofFixture(t)
	port := setupStandaloneMetroHelper(t)
	var envelope struct {
		Data struct {
			Plan simulatorProofPlanData `json:"plan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(currentSimulatorProofEnvelope(t), &envelope); err != nil {
		t.Fatal(err)
	}
	plan := envelope.Data.Plan
	plan.AdvertisedURL = "http://127.0.0.1:" + strconv.Itoa(port)
	plan.Commands[0] = simulatorProofPlanCommand{ID: "expo_start", Command: "sh", Args: []string{"-c", "exit 9"}, CWD: appDir}
	plan.Commands[1].Command = "sh"
	plan.Commands[1].Args = []string{"-c", "exit 7"}
	sideEffects := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sideEffects++
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer api.Close()
	var stdout, stderr bytes.Buffer
	started := time.Now()
	code := executeStandaloneSimulatorProofPlan(proveAppOptions{apiURL: api.URL}, sourceBinding{}, plan, &stdout, &stderr, api.Client())
	if code == 0 || sideEffects != 0 || !strings.Contains(stderr.String(), "exited before Metro") || time.Since(started) > 2*time.Second {
		t.Fatalf("Expo exit ignored: exit=%d posts=%d stdout=%s stderr=%s", code, sideEffects, stdout.String(), stderr.String())
	}
}

func TestStandaloneSimulatorMaestroRejectsMissingOrFailingReport(t *testing.T) {
	for _, test := range []struct{ name, content string }{
		{"missing", ""}, {"empty-suite", `<testsuite tests="0"/>`},
		{"failed", `<testsuite tests="1" failures="1"/>`},
		{"error", `<testsuite tests="1"><testcase><error/></testcase></testsuite>`},
		{"malformed", `not XML`},
		{"claimed-count-only", `<testsuite tests="1"/>`},
		{"skipped-only", `<testsuite tests="1" skipped="1"><testcase><skipped/></testcase></testsuite>`},
		{"inconsistent-count", `<testsuite tests="2"><testcase/></testsuite>`},
		{"aggregate-failures", `<testsuites failures="1"><testsuite tests="1"><testcase/></testsuite></testsuites>`},
		{"aggregate-errors", `<testsuites errors="1"><testsuite tests="1"><testcase/></testsuite></testsuites>`},
		{"aggregate-skipped", `<testsuites skipped="1"><testsuite tests="1"><testcase/></testsuite></testsuites>`},
		{"aggregate-count", `<testsuites tests="0"><testsuite tests="1"><testcase/></testsuite></testsuites>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			report := filepath.Join(directory, "report.xml")
			command := simulatorProofPlanCommand{Command: "sh", Args: []string{"-c", `if [ -n "$REPORT_BODY" ]; then printf '%s' "$REPORT_BODY" > "$REPORT_PATH"; fi`}, Env: map[string]string{"REPORT_BODY": test.content, "REPORT_PATH": report}}
			var stderr bytes.Buffer
			if err := runStandaloneSimulatorMaestro(command, standaloneMaestroRunArtifacts{ReportPath: report}, &stderr); err == nil {
				t.Fatalf("accepted %s report", test.name)
			}
		})
	}
}

func currentSimulatorProofRunEnvelope(t *testing.T, appDir, workspaceID, workflowID string, port int, reportPath, outputDir, debugDir string) []byte {
	t.Helper()
	var envelope struct {
		Data struct {
			Plan simulatorProofPlanData `json:"plan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(currentSimulatorProofEnvelope(t), &envelope); err != nil {
		t.Fatal(err)
	}
	plan := &envelope.Data.Plan
	plan.WorkflowID = workflowID
	plan.TargetKey = "SIM-UDID"
	plan.AdvertisedURL = "http://127.0.0.1:" + strconv.Itoa(port)
	plan.DeepLinkURL = "forgegraph://expo-development-client/?url=" + url.QueryEscape(plan.AdvertisedURL)
	for _, record := range []map[string]any{plan.DevSession, plan.TargetSession, plan.TargetRun} {
		record["appId"] = "pfapp_forgegraph_mobile"
		record["workspaceId"] = workspaceID
		record["workflowId"] = workflowID
	}
	plan.DevSession["id"] = "pfds_artifacts"
	plan.DevSession["appScheme"] = "forgegraph"
	plan.DevSession["advertisedUrl"] = plan.AdvertisedURL
	plan.DevSession["port"] = port
	plan.DevSession["metadata"] = map[string]any{"appDirectory": appDir, "targetKey": "SIM-UDID"}
	plan.TargetSession["id"] = "pftsess_artifacts"
	plan.TargetSession["targetId"] = "SIM-UDID"
	plan.TargetSession["devSessionId"] = "pfds_artifacts"
	plan.TargetSession["openedUrl"] = plan.DeepLinkURL
	plan.TargetRun["id"] = "pftrun_artifacts"
	plan.TargetRun["targetId"] = "SIM-UDID"
	plan.TargetRun["targetSessionId"] = "pftsess_artifacts"
	plan.TargetRun["flowPath"] = filepath.Join(appDir, ".maestro", "01-app-launches.yaml")
	plan.TargetRun["reportArtifactId"] = reportPath
	plan.TargetRun["metadata"] = map[string]any{"format": "junit", "testOutputDirectory": outputDir, "debugOutputDirectory": debugDir, "logPath": filepath.Join(debugDir, "maestro.log")}
	plan.Commands[0].CWD = appDir
	plan.Commands[0].Args[len(plan.Commands[0].Args)-1] = strconv.Itoa(port)
	plan.Commands[1].Args = []string{"simctl", "openurl", "SIM-UDID", plan.DeepLinkURL}
	maestro := &plan.Commands[2]
	maestro.Args = []string{"--platform", "ios", "--device", "SIM-UDID", "test", "--format", "junit", "--output", reportPath, "--test-output-dir", outputDir, "--debug-output", debugDir, filepath.Join(appDir, ".maestro", "01-app-launches.yaml")}
	maestro.Env["APP_ID"] = "forgegraph"
	maestro.Env["PREFLIGHT_WORKFLOW_ID"] = workflowID
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestStandaloneSimulatorProfileEnvironmentMatchesSourceAndMetro(t *testing.T) {
	for _, test := range []struct{ name, override, wantAPI string }{
		{"profile-default", "", "https://profile.example.test"},
		{"explicit-live-override", "https://live.example.test", "https://live.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			appDir := writeStandaloneProofFixture(t)
			port := setupStandaloneMetroHelper(t)
			fakeBin := t.TempDir()
			envLog := filepath.Join(t.TempDir(), "metro-env.log")
			artifacts := t.TempDir()
			reportPath := filepath.Join(artifacts, "report.xml")
			outputDir := filepath.Join(artifacts, "output")
			debugDir := filepath.Join(artifacts, "debug")
			eas := `{"build":{"development":{"developmentClient":true,"distribution":"internal","env":{"APP_VARIANT":"development","PREFLIGHT_TEST_BUNDLE_SUFFIX":"profile","EXPO_PUBLIC_TEST_API":"https://profile.example.test"},"ios":{"simulator":true}}}}`
			if err := os.WriteFile(filepath.Join(appDir, "eas.json"), []byte(eas), 0o644); err != nil {
				t.Fatal(err)
			}
			if test.override != "" {
				t.Setenv("EXPO_PUBLIC_TEST_API", test.override)
			} else {
				t.Setenv("EXPO_PUBLIC_TEST_API", "")
				_ = os.Unsetenv("EXPO_PUBLIC_TEST_API")
			}
			t.Setenv("APP_VARIANT", "")
			_ = os.Unsetenv("APP_VARIANT")
			for name, script := range map[string]string{
				"npx": `#!/usr/bin/env sh
if [ "$2" = "config" ]; then
 printf '{"scheme":"forgegraph","slug":"forgegraf","ios":{"bundleIdentifier":"com.gmacko.forgegraph.%s"}}\n' "$PREFLIGHT_TEST_BUNDLE_SUFFIX"
 exit 0
fi
printf '%s %s %s\n' "$APP_VARIANT" "$PREFLIGHT_TEST_BUNDLE_SUFFIX" "$EXPO_PUBLIC_TEST_API" > "$PREFLIGHT_ENV_LOG"
exec "$PREFLIGHT_TEST_BINARY" -test.run=^TestStandaloneMetroHelperProcess$
`,
				"xcrun": "#!/usr/bin/env sh\nexit 0\n",
				"maestro": `#!/usr/bin/env sh
printf '<testsuite tests="1"><testcase status="SUCCESS"/></testsuite>\n' > "$PREFLIGHT_TEST_REPORT"
`,
			} {
				if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("PREFLIGHT_FORCE_EXPO_CONFIG_CLI", "1")
			t.Setenv("PREFLIGHT_TOKEN", "contract-token")
			t.Setenv("PREFLIGHT_ENV_LOG", envLog)
			t.Setenv("PREFLIGHT_TEST_REPORT", reportPath)
			var readiness struct {
				DevelopmentReadiness struct {
					SourceBinding sourceBinding `json:"sourceBinding"`
				} `json:"developmentReadiness"`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "simulator-proof-plans") {
					if err := json.NewDecoder(r.Body).Decode(&readiness); err != nil {
						t.Error(err)
					}
					_, _ = w.Write(currentSimulatorProofRunEnvelope(t, appDir, "ws_environment", "pfw_environment", port, reportPath, outputDir, debugDir))
					return
				}
				_, _ = w.Write([]byte(`{"data":{}}`))
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			code := run([]string{"prove-app", "--standalone-run", "--api-url", server.URL, "--workspace-id", "ws_environment", "--app-dir", appDir, "--target-key", "SIM-UDID", "--port", strconv.Itoa(port)}, &stdout, &stderr, server.Client())
			if code != 0 {
				t.Fatalf("profile run exit=%d stderr=%s", code, stderr.String())
			}
			if readiness.DevelopmentReadiness.SourceBinding.IOSBundleID != "com.gmacko.forgegraph.profile" {
				t.Fatalf("profile bundle lost at source binding: %#v", readiness)
			}
			environment, err := os.ReadFile(envLog)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(environment)) != "development profile "+test.wantAPI {
				t.Fatalf("profile/runtime mismatch: %q", environment)
			}
		})
	}
}
