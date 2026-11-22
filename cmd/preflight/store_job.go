package main

// store.build and store.upload job handling (PREFLT-66: replace EAS with
// Preflight). The contract lives in the control plane:
// packages/api/src/preflight/signing-credentials.ts (plan, payloads, artifact)
// and the "store.build"/"store.upload" entries of runner-job-contracts.ts.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

type storeBuildIOSTarget struct {
	TargetName               string `json:"targetName"`
	BundleID                 string `json:"bundleId"`
	ProfileSecretReferenceID string `json:"profileSecretReferenceId"`
	ProfileUUID              string `json:"profileUuid"`
	ProfileName              string `json:"profileName"`
}

type storeBuildIOSPlan struct {
	TeamID                       string                `json:"teamId"`
	Scheme                       string                `json:"scheme"`
	Configuration                string                `json:"configuration"`
	ExportMethod                 string                `json:"exportMethod"`
	CertificateSecretReferenceID string                `json:"certificateSecretReferenceId"`
	Targets                      []storeBuildIOSTarget `json:"targets"`
}

type storeBuildAndroidPlan struct {
	KeystoreSecretReferenceID string `json:"keystoreSecretReferenceId"`
	GradleTask                string `json:"gradleTask"`
	ApplicationID             string `json:"applicationId"`
}

type storeBuildPlan struct {
	AppID                         string                 `json:"appId"`
	BuildID                       string                 `json:"buildId"`
	Platform                      string                 `json:"platform"`
	Lane                          string                 `json:"lane"`
	AppDirectory                  string                 `json:"appDirectory"`
	Version                       string                 `json:"version"`
	BuildNumber                   string                 `json:"buildNumber"`
	Environment                   map[string]string      `json:"environment"`
	SecretEnvironmentReferenceIDs []string               `json:"secretEnvironmentReferenceIds"`
	IOS                           *storeBuildIOSPlan     `json:"ios"`
	Android                       *storeBuildAndroidPlan `json:"android"`
}

type storeBuildArtifact struct {
	Kind       string `json:"kind"`
	FileName   string `json:"fileName"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"sizeBytes"`
	StorageKey string `json:"storageKey"`
}

func (artifact storeBuildArtifact) toMap() map[string]any {
	return map[string]any{
		"kind":       artifact.Kind,
		"fileName":   artifact.FileName,
		"sha256":     artifact.SHA256,
		"sizeBytes":  artifact.SizeBytes,
		"storageKey": artifact.StorageKey,
	}
}

// Decrypted secret payloads.

type iosCertificatePayload struct {
	P12Base64       string `json:"p12Base64"`
	P12Password     string `json:"p12Password"`
	SerialNumber    string `json:"serialNumber"`
	SHA1Fingerprint string `json:"sha1Fingerprint"`
	TeamID          string `json:"teamId"`
	ExpiresAt       string `json:"expiresAt"`
}

type iosProvisioningProfilePayload struct {
	ProfileBase64 string `json:"profileBase64"`
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	BundleID      string `json:"bundleId"`
	ProfileType   string `json:"profileType"`
	TeamID        string `json:"teamId"`
	ExpiresAt     string `json:"expiresAt"`
}

type androidUploadKeystorePayload struct {
	KeystoreBase64    string `json:"keystoreBase64"`
	KeystorePassword  string `json:"keystorePassword"`
	KeyAlias          string `json:"keyAlias"`
	KeyPassword       string `json:"keyPassword"`
	SHA1Fingerprint   string `json:"sha1Fingerprint"`
	SHA256Fingerprint string `json:"sha256Fingerprint"`
}

type ascAPIKeyPayload struct {
	KeyID        string `json:"keyId"`
	IssuerID     string `json:"issuerId"`
	PrivateKeyP8 string `json:"privateKeyP8"`
	TeamID       string `json:"teamId"`
}

type googleServiceAccountPayload struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	ClientEmail        string `json:"clientEmail"`
	ProjectID          string `json:"projectId"`
}

// parseStoreSecretPayload decodes a revealed JSON payload and names missing
// fields (never values), mirroring parseSigningCredentialPayload.
func parseStoreSecretPayload(kind string, raw string, output any, required ...string) error {
	if err := json.Unmarshal([]byte(raw), output); err != nil {
		return storeFailuref("signing_credential_invalid", "%s payload is not valid JSON", kind)
	}
	var record map[string]any
	_ = json.Unmarshal([]byte(raw), &record)
	missing := []string{}
	for _, field := range required {
		if value, ok := record[field].(string); !ok || strings.TrimSpace(value) == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		return storeFailuref("signing_credential_invalid", "%s payload is missing %s", kind, strings.Join(missing, ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

// storeFailure is a classified job failure reported as result.failure.
type storeFailure struct {
	status  string // "failed" (default) or "setup_required"
	code    string
	message string
}

func (failure *storeFailure) Error() string { return failure.code + ": " + failure.message }

func storeFailuref(code string, format string, args ...any) *storeFailure {
	return &storeFailure{code: code, message: fmt.Sprintf(format, args...)}
}

func storeSetupRequired(code string, format string, args ...any) *storeFailure {
	return &storeFailure{status: "setup_required", code: code, message: fmt.Sprintf(format, args...)}
}

// storeFailureFor classifies err, defaulting to fallbackCode.
func storeFailureFor(err error, fallbackCode string) *storeFailure {
	var failure *storeFailure
	if errors.As(err, &failure) {
		return failure
	}
	if errors.Is(err, errCommandTimedOut) {
		return storeFailuref(fallbackCode+"_timeout", "%s", err.Error())
	}
	return storeFailuref(fallbackCode, "%s", err.Error())
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

type storeSecretRevealer func(secretReferenceID string) (runnerJobSecretRevealData, error)

// revealStoreSecret reveals one secret, registers its value (and its
// multi-line fragments) with the log redactor until release runs, and maps a
// refused reveal to setup_required.
func revealStoreSecret(reveal storeSecretRevealer, cleanup *storeCleanup, secretReferenceID string, what string) (runnerJobSecretRevealData, error) {
	if strings.TrimSpace(secretReferenceID) == "" {
		return runnerJobSecretRevealData{}, storeSetupRequired("signing_credential_unavailable", "the store plan has no secret reference for the %s", what)
	}
	data, err := reveal(secretReferenceID)
	if err != nil {
		if jobLeaseLost(err) {
			return runnerJobSecretRevealData{}, err
		}
		return runnerJobSecretRevealData{}, storeSetupRequired("signing_credential_unavailable", "reveal %s (%s): %v", what, secretReferenceID, err)
	}
	release := registerRedactedSecrets(data.Value)
	cleanup.add("release redaction for "+what, func() error { release(); return nil })
	return data, nil
}

// registerPayloadSecrets registers decoded secret fields (passwords, base64
// key material) that may surface in a log on their own.
func registerPayloadSecrets(cleanup *storeCleanup, values ...string) {
	release := registerRedactedSecrets(values...)
	cleanup.add("release payload redaction", func() error { release(); return nil })
}

func storeSecretEnvironment(reveal storeSecretRevealer, cleanup *storeCleanup, job apiRunnerJob, ids []string) (map[string]string, error) {
	env := map[string]string{}
	for _, id := range ids {
		data, err := revealStoreSecret(reveal, cleanup, id, "build environment secret")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(data.SecretReference.Key)
		if key == "" {
			for _, reference := range job.Payload.SecretReferences {
				if reference.ID == id {
					key = strings.TrimSpace(reference.Key)
				}
			}
		}
		if !isSafeEnvironmentKey(key) {
			return nil, storeFailuref("store_secret_environment_invalid", "secret reference %s has invalid environment key %q", id, key)
		}
		env[key] = data.Value
	}
	return env, nil
}

// storeSecretReferenceFor finds the job's secret reference for a purpose.
func storeSecretReferenceFor(job apiRunnerJob, purpose string, key string) string {
	for _, reference := range job.Payload.SecretReferences {
		if reference.Purpose == purpose || (key != "" && reference.Key == key) {
			return reference.ID
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

func storeWorkspaceRoot(options runnerOnceOptions, job apiRunnerJob) string {
	root := strings.TrimSpace(job.Payload.SourceBinding.WorkspaceRoot)
	if root == "" {
		root = options.workspaceRoot
	}
	return root
}

// storeAppDirectory resolves the Expo app: the source binding's package path
// when present, otherwise the plan's repo-relative appDirectory.
func storeAppDirectory(options runnerOnceOptions, job apiRunnerJob, plan storeBuildPlan) string {
	packagePath := strings.TrimSpace(job.Payload.SourceBinding.PackagePath)
	if packagePath == "" || packagePath == "." {
		if dir := strings.TrimSpace(plan.AppDirectory); dir != "" && dir != "." && !filepath.IsAbs(dir) && !strings.Contains(dir, "..") {
			return filepath.Join(storeWorkspaceRoot(options, job), dir)
		}
	}
	return appDirectoryForJob(options, job)
}

func storeJobWorkDir(options runnerOnceOptions, job apiRunnerJob) string {
	return filepath.Join(storeWorkspaceRoot(options, job), ".preflight", "store-builds", job.ID)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// storeToolProbeForJobs is a seam for handler tests.
var storeToolProbeForJobs = defaultStoreToolProbe

type storeJobRuntime struct {
	jobID     string
	run       storeCommandRunner
	reveal    storeSecretRevealer
	uploads   *storeArtifactClient
	log       io.Writer
	homeDir   string
	workDir   string
	appDir    string
	cleanup   *storeCleanup
	fetchWWDR func() []byte
}

func newStoreJobRuntime(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, log io.Writer, appDir string) (*storeJobRuntime, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cleanup := &storeCleanup{log: log}
	return &storeJobRuntime{
		jobID: job.ID,
		run:   newStoreCommandRunner(log, runnerJobCancellationCheck(client, options, registration, job)),
		reveal: func(id string) (runnerJobSecretRevealData, error) {
			return revealRunnerJobSecret(client, options, registration, job, id)
		},
		uploads: &storeArtifactClient{
			client:   client,
			baseURL:  strings.TrimRight(options.apiURL, "/"),
			runnerID: registration.Runner.ID,
			jobID:    job.ID,
			token:    registration.Token,
		},
		log:     log,
		homeDir: home,
		workDir: storeJobWorkDir(options, job),
		appDir:  appDir,
		cleanup: cleanup,
		fetchWWDR: func() []byte {
			return fetchWWDRIntermediate(client, options, registration)
		},
	}, nil
}

func openStoreJobLog(workDir string, stdout io.Writer) (io.Writer, func(), error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(filepath.Join(workDir, "store.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return io.MultiWriter(file, stdout), func() { _ = file.Close() }, nil
}

func decodeStoreBuildPlan(job apiRunnerJob) (storeBuildPlan, error) {
	var plan storeBuildPlan
	if len(job.Payload.StorePlan) == 0 {
		return plan, storeFailuref("store_build_payload_invalid", "store.build requires plan")
	}
	if err := json.Unmarshal(job.Payload.StorePlan, &plan); err != nil {
		return plan, storeFailuref("store_build_payload_invalid", "decode store build plan: %v", err)
	}
	if plan.Platform == "" {
		plan.Platform = job.Payload.Platform
	}
	if plan.Lane == "" {
		plan.Lane = job.Payload.Lane
	}
	if plan.BuildID == "" {
		plan.BuildID = job.Payload.BuildID
	}
	if strings.TrimSpace(plan.Version) == "" || strings.TrimSpace(plan.BuildNumber) == "" {
		return plan, storeFailuref("store_build_payload_invalid", "store build plan requires version and buildNumber")
	}
	switch plan.Platform {
	case "ios":
		if plan.IOS == nil {
			return plan, storeFailuref("store_build_payload_invalid", "iOS store build plan has no ios section")
		}
	case "android":
		if plan.Android == nil {
			return plan, storeFailuref("store_build_payload_invalid", "Android store build plan has no android section")
		}
	default:
		return plan, storeFailuref("store_build_payload_invalid", "unsupported store build platform %q", plan.Platform)
	}
	return plan, nil
}

// completeStoreJobFailure reports a classified failure or cancellation. A
// lost lease is returned so the runner stops acting on the job.
func completeStoreJobFailure(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer, err error, fallbackCode string, extra map[string]any) error {
	if jobLeaseLost(err) {
		return err
	}
	result := map[string]any{}
	for key, value := range extra {
		result[key] = value
	}
	if errors.Is(err, errCommandCancelled) {
		result["status"] = "cancelled"
		if completeErr := completeRunnerJob(client, options, registration, job, result); completeErr != nil {
			return completeErr
		}
		fmt.Fprintf(stdout, "cancelled %s job %s\n", job.Kind, job.ID)
		return nil
	}
	failure := storeFailureFor(err, fallbackCode)
	status := failure.status
	if status == "" {
		status = "failed"
	}
	result["status"] = status
	result["failure"] = map[string]any{
		"code":    failure.code,
		"message": truncateRunnerOutput(redactSetupTranscriptText(failure.message)),
	}
	if status == "setup_required" {
		result["setupRequired"] = map[string]any{"code": failure.code, "message": redactSetupTranscriptText(failure.message)}
	}
	if completeErr := completeRunnerJob(client, options, registration, job, result); completeErr != nil {
		return completeErr
	}
	fmt.Fprintf(stdout, "%s %s job %s: %s\n", status, job.Kind, job.ID, failure.code)
	return nil
}

func handleStoreBuildJob(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, stdout io.Writer) error {
	defer startJobHeartbeat(client, options, registration, job)()

	plan, err := decodeStoreBuildPlan(job)
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_build_payload_invalid", nil)
	}
	if err := validateRunnerJobSourceBinding(options, job); err != nil {
		return completeSourceBindingMismatchJob(client, options, registration, job, stdout, err)
	}
	appDir := storeAppDirectory(options, job, plan)
	if err := requireAppDirectory(appDir); err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, storeFailuref("store_build_app_missing", "%v", err), "", nil)
	}
	if err := ensureBuildDiskHeadroom(appDir, stdout); err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, storeFailuref("runner_disk_low", "%v", err), "", nil)
	}
	if plan.Platform == "ios" {
		if missing := missingStoreTools(storeToolProbeForJobs(), "xcodebuild", "xcode.archive"); len(missing) > 0 {
			return completeStoreJobFailure(client, options, registration, job, stdout,
				storeSetupRequired("store_build_tooling_missing", "this runner lacks %s", strings.Join(missing, ", ")), "", nil)
		}
	} else if missing := missingStoreTools(storeToolProbeForJobs(), "android.sdk", "java"); len(missing) > 0 {
		return completeStoreJobFailure(client, options, registration, job, stdout,
			storeSetupRequired("store_build_tooling_missing", "this runner lacks %s", strings.Join(missing, ", ")), "", nil)
	}

	workDir := storeJobWorkDir(options, job)
	log, closeLog, err := openStoreJobLog(workDir, stdout)
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_build_workspace_failed", nil)
	}
	defer closeLog()
	runtime, err := newStoreJobRuntime(client, options, registration, job, log, appDir)
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_build_workspace_failed", nil)
	}
	// Runs on success, failure and cancellation alike.
	defer runtime.cleanup.Run()

	if plan.Platform == "ios" {
		cleanupStaleCiBuildProcesses(stdout, preflightCiCheckoutSegment(appDir))
	}
	result, err := runStoreBuild(runtime, job, plan)
	if err != nil {
		return completeStoreJobFailure(client, options, registration, job, stdout, err, "store_build_failed", nil)
	}
	if err := completeRunnerJob(client, options, registration, job, result); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "completed store.build %s (%s %s)\n", job.ID, plan.Platform, plan.BuildNumber)
	return nil
}

// runStoreBuild is the platform dispatch shared by the handler and tests.
func runStoreBuild(runtime *storeJobRuntime, job apiRunnerJob, plan storeBuildPlan) (map[string]any, error) {
	secretEnv, err := storeSecretEnvironment(runtime.reveal, runtime.cleanup, job, plan.SecretEnvironmentReferenceIDs)
	if err != nil {
		return nil, err
	}
	var outcome storeBuildOutcome
	if plan.Platform == "ios" {
		outcome, err = runIOSStoreBuild(runtime, plan, secretEnv)
	} else {
		outcome, err = runAndroidStoreBuild(runtime, plan, secretEnv)
	}
	if err != nil {
		return nil, err
	}
	artifact, err := runtime.uploads.upload(outcome.artifactPath, outcome.kind)
	if err != nil {
		if jobLeaseLost(err) {
			return nil, err
		}
		return nil, storeFailuref("store_artifact_upload_failed", "%v", err)
	}
	return map[string]any{
		"status":   "ok",
		"buildId":  plan.BuildID,
		"artifact": artifact.toMap(),
		"signing":  outcome.signing,
	}, nil
}

type storeBuildOutcome struct {
	artifactPath string
	kind         string
	signing      map[string]any
}
