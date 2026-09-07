# preflight-runner: API and service usage review

Go CLI/build-runner client for Preflight mobile build/release control plane

Source revision: `2997d2f896b5cb6a8924a061e526a2ae1f917e48`. Authority: **registered repository revision**.

Static source review plus local runtime implementation on the recorded baseline. Not deployed; no live SLA or execution proof. BizPulse mobile.triggerSubmission accepts optional selection {appId,ascBuildId,version,buildNumber}; missing selection gives explicit precondition; selected app must match unique startup slug mapping. New CLI --list-builds exposes current TestFlight IDs/version/buildNumber. Single submit requires --asc-build-id/--version/--build-number. Fleet --fire requires --selections-file JSON keyed by appId; all ready rows need complete selection before first write. Provider revalidates each immutable ASC resource.

## Provided APIs

No additional external REST or GraphQL provider contract established in this review. See exclusions and followups; this does not certify absence.

## Consumed services

### github (rest)

- `GET /repos/{owner}/{repo}/releases/latest`

Binary updater uses configurable PREFLIGHT_UPDATE_REPO and downloads release/checksum assets; build-time/user CLI execution, not deployment service dependency.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/update.go:168 — Release lookup

### preflight-app (rest)

- `POST /api/v1/targets`
- `GET /api/v1/targets`
- `POST /api/preflight/v1/secret-refs`
- `GET /api/preflight/v1/secret-refs`
- `POST /api/preflight/v1/provider-accounts`
- `GET /api/preflight/v1/provider-accounts`
- `POST /api/preflight/v1/apps/{appId}/provider-readiness`
- `GET /api/preflight/v1/apps/{appId}/provider-readiness`
- `GET /api/preflight/v1/apps/{appId}/provider-setup-plan`
- `POST /api/preflight/v1/provider-accounts/{providerAccountId}/credential-flows`
- `GET /api/preflight/v1/provider-accounts/{providerAccountId}/credential-flows`
- `POST /api/preflight/v1/oauth-clients/configure`
- `POST /api/preflight/v1/oauth-clients`
- `GET /api/preflight/v1/oauth-clients`
- `POST /api/preflight/v1/setup-transcripts`
- `POST /api/preflight/v1/workflows/{workflowId}/resume-setup`
- `GET /api/preflight/v1/runners/{runnerId}/signing-cert`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/{jobId}/targets/{targetId}/lock`
- `POST /api/preflight/v1/runners/{runnerId}/targets/android-emulators`
- `POST /api/preflight/v1/runners/{runnerId}/targets/ios-devices`
- `POST /api/preflight/v1/runners/{runnerId}/targets/ios-simulators`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/{jobId}/targets/{targetId}/installations`
- `POST /api/preflight/v1/apps/{appId}/simulator-proof-plans`
- `POST /api/preflight/v1/apps/{appId}/development-build-plans`
- `POST /api/preflight/v1/apps/{appId}/development-build-results`
- `POST /api/preflight/v1/apps/{appId}/development-session-plans`
- `POST /api/preflight/v1/apps/{appId}/runtime-artifacts`
- `POST /api/preflight/v1/apps/{appId}/dev-sessions`
- `POST /api/preflight/v1/apps/{appId}/target-sessions`
- `POST /api/preflight/v1/apps/{appId}/target-runs`
- `GET /api/preflight/v1/runners/capacity`
- `POST /api/preflight/v1/work-orders`
- `GET /api/preflight/v1/work-orders/{workOrderId}`
- `GET /api/preflight/v1/work-orders`
- `GET /api/preflight/v1/nodes`
- `GET /api/preflight/v1/health`
- `POST /api/preflight/v1/nodes/{nodeId}/retire`
- `POST /api/preflight/v1/testflight/enroll`
- `POST /api/preflight/v1/apps/{appId}/store-listing/publish`
- `GET /api/preflight/v1/apps/{appId}/screenshot-recipe`
- `GET /api/preflight/v1/apps/{appId}/errors/analysis-queue`
- `POST /api/preflight/v1/apps/{appId}/errors/{errorId}/analysis`
- `POST /api/preflight/v1/apps/{appId}/session-health`
- `POST /api/preflight/v1/apps/{appId}/performance`
- `POST /api/preflight/v1/apps/{appId}/errors`
- `POST /api/preflight/v1/crashes/alerts/evaluate`
- `POST /api/preflight/v1/apps/{appId}/review-notes`
- `POST /api/preflight/v1/apps/{appId}/dependencies`
- `POST /api/preflight/v1/apps/{appId}/build-health`
- `GET /api/preflight/v1/uptime/check-queue`
- `POST /api/preflight/v1/uptime/{monitorId}/result`
- `POST /api/preflight/v1/runners/register`
- `POST /api/preflight/v1/runners/{runnerId}/heartbeat`
- `POST /api/preflight/v1/runners/{runnerId}/reconcile`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/claim`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/{jobId}/artifacts`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/{jobId}/complete`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/{jobId}/secrets/{secretRefId}/reveal`
- `POST /api/preflight/v1/runners/{runnerId}/jobs/{jobId}/heartbeat`
- `GET /api/preflight/v1/runners/{runnerId}/jobs/{jobId}`
- `GET /api/preflight/v1/workflows/{workflowId}`
- `GET /api/preflight/v1/release-status`
- `GET /api/preflight/v1/apps/{appId}/release-status`
- `POST /api/preflight/v1/apps/{appId}/submit-for-review`
- `putApiPreflightV1AppsIdReleaseChecklist`
- `GET /api/preflight/v1/apps/{id}/testflight/builds`

20-second PER ATTEMPT deadline from PREFLIGHT_API_REQUEST_TIMEOUT override;4attempts total,network/5xx only;500/1000/2000ms exponential backoff.4xx immediate;success data envelope unwrapped. User or runner Bearer and workspace headers where workspace helper is used. Target origin PREFLIGHT_API_URL; provider operationIds unresolved.

Client settings: {"timeoutMs":20000,"retries":{"maxAttempts":4,"backoff":"exponential"}}
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:13854 — JSON helper retry policy
cmd/preflight/main.go:13895 — Per-attempt timeout
cmd/preflight/main.go:13784 — runnerEndpoint concatenates without rewriting /api/v1 path

### preflight-app (rest)

- `POST /api/preflight/v1/cli/auth/device/start`
- `POST /api/preflight/v1/apps/{appId}/store-listing/screenshots`
- `PUT /api/preflight/v1/apps/{appId}/screenshot-recipe`
- `PUT /api/preflight/v1/runners/{runnerId}/artifacts/{artifactId}/blob`
- `POST /api/preflight/v1/workflows/prove-app`

Raw client.Do path; main injects http.DefaultClient. No explicit deadline/retry at these callsites. Do not inherit JSON-helper defaults. Target origin PREFLIGHT_API_URL; provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:13854 — JSON helper retry policy
cmd/preflight/main.go:13895 — Per-attempt timeout
cmd/preflight/main.go:13784 — runnerEndpoint concatenates without rewriting /api/v1 path

### preflight-app (rest)

- `POST /api/preflight/v1/cli/auth/device/token`

Device authorization poll interval default5s,expirydefault600s from serverresponse; raw request itself has no explicitdeadline. Poll retries are protocol behavior. Target origin PREFLIGHT_API_URL; provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:13854 — JSON helper retry policy
cmd/preflight/main.go:13895 — Per-attempt timeout
cmd/preflight/main.go:13784 — runnerEndpoint concatenates without rewriting /api/v1 path

### preflight-app (rest)

- `GET /api/preflight/v1/runners/{runnerId}/jobs/stream`

GET SSE waits for job availability; no explicitrequestdeadline. Stream errors fall back to normal job-claim path; do not evaluate as ordinary REST p99. Target origin PREFLIGHT_API_URL; provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:13854 — JSON helper retry policy
cmd/preflight/main.go:13895 — Per-attempt timeout
cmd/preflight/main.go:13784 — runnerEndpoint concatenates without rewriting /api/v1 path

### preflight-app (rest)

- `GET /api/preflight/v1/workflows/{workflowId}/events`

GET SSE bounded by options.watchTimeout(default10minutes) via requestcontext; ordinary JSON polling used as fallback. Watch duration is not per-operationSLA. Target origin PREFLIGHT_API_URL; provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:13854 — JSON helper retry policy
cmd/preflight/main.go:13895 — Per-attempt timeout
cmd/preflight/main.go:13784 — runnerEndpoint concatenates without rewriting /api/v1 path

### preflight-app (rest)

- `GET /api/preflight/v1/capabilities`

Capability compatibility helper uses20s/4attempts; standalone capabilities CLI atmain.go531 bypasses helper with raw client.Do. Separate callsite observations required. Target origin PREFLIGHT_API_URL; provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:13854 — JSON helper retry policy
cmd/preflight/main.go:13895 — Per-attempt timeout
cmd/preflight/main.go:13784 — runnerEndpoint concatenates without rewriting /api/v1 path

### app-store-connect (rest)

- `GET /v1/apps`
- `GET /v1/bundleIds`
- `GET /v1/certificates`
- `POST /v1/certificates`

Third-party provider verification/signing paths. JWT Bearer built with issuer/key/private key. apps probe limit1;bundleIds includes bundleIdCapabilities;certificate list limit200. Raw client.Do,does not inherit Preflight JSON helper20s/4attempts. Provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:1350 — Provider verification invokes apps probe
cmd/preflight/main.go:2536 — GETapps
cmd/preflight/main.go:2583 — GETbundleIds
cmd/preflight/main.go:2984 — Certificate list
cmd/preflight/main.go:3054 — Certificate create

### google-play (rest)

- `POST /androidpublisher/v3/applications/{packageName}/edits`
- `GET /androidpublisher/v3/applications/{packageName}/edits/{editId}/tracks`
- `DELETE /androidpublisher/v3/applications/{packageName}/edits/{editId}`

Verification inserts temporary edit,lists tracks,then deletes edit;OAuth Bearer. Raw helper lacks per-request timeout/retry;source limit4096byte response read. Provider operationIds unresolved.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:2388 — Probe invokes temporary-edit lifecycle
cmd/preflight/main.go:2442 — Create edit
cmd/preflight/main.go:2465 — Tracks query
cmd/preflight/main.go:2494 — Delete edit

### google-oauth (rest)

- `POST {serviceAccount.token_uri}`

JWT-bearer service-account grant;provider target comes from credential JSON token_uri,not guessed fixedhost. Form-urlencoded body. Raw client.Do.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:2296 — Service-account token exchange

### sentry (rest)

- `GET /api/0/projects/{orgSlug}/{projectSlug}/`

Provider credentials/readiness probe;Bearer,raw client.Do without JSON-helper retries.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:1688 — Verification calls probe
cmd/preflight/main.go:2705 — Exact probeendpoint

### sentry (rest)

- `GET /api/0/organizations/{orgSlug}/projects/`
- `GET /api/0/projects/{orgSlug}/{projectSlug}/issues/`
- `GET /api/0/issues/{issueId}/events/latest/`
- `GET /api/0/organizations/{orgSlug}/sessions/`
- `GET /api/0/organizations/{orgSlug}/events/`

Sentry-sync actual helper:Bearer,minimuminterval throttle,429only retries up to5attempts total,Retry-After seconds or1500ms fallback. No explicitrequestdeadline. This differs from Preflightcontrol-plane retries;do not average p95observations into SLA.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/sentry_sync.go:788 — sentryGet throttle/retry
cmd/preflight/sentry_sync.go:829 — Projects
cmd/preflight/sentry_sync.go:843 — Issues
cmd/preflight/sentry_sync.go:857 — Latestevent
cmd/preflight/sentry_sync.go:885 — Sessions
cmd/preflight/sentry_sync.go:942 — Performanceevents

### configured-uptime-target (rest)

- `configuredMonitorHttpProbe`

preflight uptime check probes each monitor URL with configured Method (defaults GET), User-Agent preflight-uptime/1.0. No invented REST operationId/path or credentials; client is supplied by caller.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/uptime.go:50 — 

### configured-screenshot-artifact (rest)

- `GET configuredScreenshotUrl`

Screenshot materialization downloads per-ref URL with dedicated60s HTTPclient, no API Bearer inherited.

Client settings: {"timeoutMs":60000}
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/main.go:8578 — 

### github-release-asset (rest)

- `GET configuredReleaseAssetUrl`

Updater downloads selected release asset URL in addition to already-declared releases/latest metadata GET; not a fixed GitHub REST route.

Client settings: Not explicitly configured in reviewed callsite; library defaults not promoted to a guarantee.
Traffic requirements: Undeclared; cadence, quotas and caps are not typical/peak traffic.
SLA requirements: Undeclared.

cmd/preflight/update.go:241 — 

## Usage truth audit

```json
{
  "coverage": "partial",
  "inventoryComplete": false,
  "runtime": "unobserved",
  "scope": "Source caller review; file hashes detect drift, not runtime activation or inventory completeness.",
  "additions": 3,
  "corrections": [
    {
      "app": "preflight-runner",
      "service": "preflight",
      "change": "Preserve existing split helper/raw/SSE groups: JSON helper20s per attempt with4 attempts on network/5xx; raw CLI endpoints do not inherit helper retries/deadline. New screenshot download60s and monitor probe remain separate dynamic destinations."
    }
  ],
  "reviewCoverage": {
    "app": "preflight-runner",
    "sourceRevision": "2997d2f896b5cb6a8924a061e526a2ae1f917e48",
    "sourceRoot": "/tmp/forgegraph-service-contracts/detail/sources/preflight-runner-2997d2f8",
    "workspace": "/Users/mackieg/.config/superpowers/worktrees/service-contracts-fleet/preflight-runner-master",
    "additionGroups": 3,
    "status": "source-reviewed; conditional reachability, not deployed traffic",
    "limits": "Focused on concrete REST/GraphQL/SDK omissions and runtime paths listed. Generic libraries without demonstrated caller and non-HTTP protocols are not asserted as observed usage."
  }
}
```

## Inactive usages

```json
[]
```

## Outbound endpoint details

```json
[
  {
    "method": "POST",
    "path": "/api/v1/targets",
    "requestNotes": "Workspace-scoped target upsert: workspaceId,runnerId,platform,kind,targetKey,displayName,providerIdentity,availability,capabilities. NOTE path deliberately /api/v1,not/preflight/v1.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 780,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/v1/targets",
    "requestNotes": "Filters platform,kind,runnerId,availability; workspace header.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 838,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/secret-refs",
    "requestNotes": "workspaceId,provider,purpose,key,value,laneScope,optionalappId; value from env/file/stdin CLI credential resolver.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 951,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/secret-refs",
    "requestNotes": "Filters workspaceId,appId,provider.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 1002,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/provider-accounts",
    "requestNotes": "workspaceId,provider,displayName,externalIds,capabilities,credentialReferenceIds,status,optionalappId; verification also upserts at1883.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 1133,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/provider-accounts",
    "requestNotes": "Filters workspaceId,appId,provider.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 1184,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/provider-readiness",
    "requestNotes": "Provider verification facts/capability/status/adapterVersion/credential refs; explicit record CLI at3235 adds optional lane,blocker,nextAction,requiredHumanRole.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 1931,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/apps/{appId}/provider-readiness",
    "requestNotes": "Filters workspaceId,provider,capability.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 3291,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/apps/{appId}/provider-setup-plan",
    "requestNotes": "Filters workspaceId,platform,lane.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 3355,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/provider-accounts/{providerAccountId}/credential-flows",
    "requestNotes": "workspaceId,provider,capability,action,credential refs and optionalapp/lane/status/context; verification calls same path at1967.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 3498,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/provider-accounts/{providerAccountId}/credential-flows",
    "requestNotes": "Filters workspaceId,appId,provider,status.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 3559,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/oauth-clients/configure",
    "requestNotes": "workspaceId,appId,provider,clientKind,displayName,redirectUris,javascriptOrigins,scopes,secretReferenceIds; optionalproviderAccountId,cloudProject,externalClientId,bundleId,Androidpackage/fingerprint,Appleteam/services. all-required loops same endpoint3747.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 3801,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/oauth-clients",
    "requestNotes": "Upsert OAuth client metadata including status and platform identifiers, no secret literal disclosure.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 3982,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/oauth-clients",
    "requestNotes": "Filters workspaceId,appId,provider,clientKind,status.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 4041,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/setup-transcripts",
    "requestNotes": "workflowId,sourceBindingId,status,summary,redactedContent,changedFiles; redacted setup command evidence.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 4978,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/workflows/{workflowId}/resume-setup",
    "requestNotes": "Resume server-owned workflow after setup transcript.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 5041,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/runners/{runnerId}/signing-cert",
    "requestNotes": "Runner Bearer; fleet signing identity only on macOS;404/no configured cert tolerated.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 5961,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}/targets/{targetId}/lock",
    "requestNotes": "Runner lease lockOwner.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9859,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/targets/android-emulators",
    "requestNotes": "Discovered emulator snapshot and runner identity.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9890,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/targets/ios-devices",
    "requestNotes": "Physical device discovery; repeated reporting branch9951 same endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9912,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/targets/ios-simulators",
    "requestNotes": "Simulator discovery snapshot.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9932,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}/targets/{targetId}/installations",
    "requestNotes": "Target installation result for job/runner scope.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 11696,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/simulator-proof-plans",
    "requestNotes": "Standalone simulator plan from source binding and requested proof options.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 14781,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/development-build-plans",
    "requestNotes": "Standalone development build plan.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 14878,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/development-build-results",
    "requestNotes": "Record executed development build result.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 15003,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/development-session-plans",
    "requestNotes": "Request development session from build plan,targetId.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 15045,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/runtime-artifacts",
    "requestNotes": "Generic runtime-state helper collection traced to literal runtime-artifacts at15245/15294/15368/15847.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 15245,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/dev-sessions",
    "requestNotes": "Literal collection passed through postStandaloneRuntimeState→postStandaloneRuntimeStateData.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 15099,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/target-sessions",
    "requestNotes": "Literal collection traced through generic helper.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 15107,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/target-runs",
    "requestNotes": "Literal collection records running/completed/failed target execution.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 15673,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/runners/capacity",
    "requestNotes": "Capacity query built by preflightRunnerCapacityEndpoint and read through JSON helper.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 16171,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/work-orders",
    "requestNotes": "Queue requested work order kind/app/source/payload.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/buildops.go",
        "line": 288,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/work-orders/{workOrderId}",
    "requestNotes": "Poll work-order status.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/buildops.go",
        "line": 332,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/work-orders",
    "requestNotes": "Queue filters in query.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/buildops.go",
        "line": 439,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/nodes",
    "requestNotes": "Farm nodes,workspace query.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/buildops.go",
        "line": 540,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/health",
    "requestNotes": "Control-plane health.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/buildops.go",
        "line": 699,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/nodes/{nodeId}/retire",
    "requestNotes": "Retire matched node.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/buildops.go",
        "line": 796,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/testflight/enroll",
    "requestNotes": "Tester enrollment payload,optionalworkspaceId.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/testflight.go",
        "line": 130,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/store-listing/publish",
    "requestNotes": "kind:screenshots.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/screenshots.go",
        "line": 512,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/apps/{appId}/screenshot-recipe",
    "requestNotes": "platform=ios.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/screenshot_recipe.go",
        "line": 45,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/apps/{appId}/errors/analysis-queue",
    "requestNotes": "Queued crash analysis filters.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/crashes.go",
        "line": 273,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/errors/{errorId}/analysis",
    "requestNotes": "Agent analysis result.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/crashes.go",
        "line": 316,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/session-health",
    "requestNotes": "sessions and optionalcrashFreePercent.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/sentry_sync.go",
        "line": 907,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/performance",
    "requestNotes": "transactions array with p50/p95/count/failure-rate observations,notSLA.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/sentry_sync.go",
        "line": 979,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/errors",
    "requestNotes": "events array.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/sentry_sync.go",
        "line": 993,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/crashes/alerts/evaluate",
    "requestNotes": "Empty object evaluates crash alerts.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/sentry_sync.go",
        "line": 1012,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/review-notes",
    "requestNotes": "Store reviewer notes and workflow steps.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/trueflight.go",
        "line": 474,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/dependencies",
    "requestNotes": "Dependency snapshot.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/dependencies.go",
        "line": 158,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/build-health",
    "requestNotes": "Doctor findings/build readiness snapshot.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/doctor.go",
        "line": 616,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/uptime/check-queue",
    "requestNotes": "Fetch monitored endpoints.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/uptime.go",
        "line": 120,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/uptime/{monitorId}/result",
    "requestNotes": "Record configured monitor probe result.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/uptime.go",
        "line": 143,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/cli/auth/device/start",
    "requestNotes": "Anonymous start; no body; returns device_code,user_code,verification_uri,interval,expires_in.",
    "policy": "direct",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 322,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/cli/auth/device/token",
    "requestNotes": "device_code payload; polls serverinterval(default5s) until expires(default600s). Per-attempt network error continues poll; no request deadline.",
    "policy": "device-poll",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 359,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/store-listing/screenshots",
    "requestNotes": "image/png bytes;query displayType,locale; Bearer.",
    "policy": "direct",
    "evidence": [
      {
        "path": "cmd/preflight/screenshots.go",
        "line": 260,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "PUT",
    "path": "/api/preflight/v1/apps/{appId}/screenshot-recipe",
    "requestNotes": "JSON screenshotRecipe;Bearer.",
    "policy": "direct",
    "evidence": [
      {
        "path": "cmd/preflight/screenshot_recipe.go",
        "line": 66,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/register",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 5915,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/heartbeat",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 6170,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/reconcile",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 6180,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/claim",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 6199,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/stream",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "runner-sse",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 6246,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}/artifacts",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 8934,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "PUT",
    "path": "/api/preflight/v1/runners/{runnerId}/artifacts/{artifactId}/blob",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "direct",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 8972,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}/complete",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9270,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}/secrets/{secretRefId}/reveal",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9287,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}/heartbeat",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9326,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/runners/{runnerId}/jobs/{jobId}",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 9307,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/workflows/prove-app",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "direct",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 14400,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/workflows/{workflowId}",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 16273,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/workflows/{workflowId}/events",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "workflow-sse",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 16232,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/capabilities",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "mixed-capabilities",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 16064,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/release-status",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 17620,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/apps/{appId}/release-status",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 17723,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "POST",
    "path": "/api/preflight/v1/apps/{appId}/submit-for-review",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 17798,
        "note": "Actual request construction and helper call"
      }
    ]
  },
  {
    "method": "GET",
    "path": "/api/preflight/v1/apps/{appId}/release-checklist",
    "requestNotes": "Primary lifecycle endpoint.",
    "policy": "json-helper",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 18007,
        "note": "Actual request construction and helper call"
      }
    ]
  }
]
```

## Contract mismatches

```json
[]
```

## SLA evidence

```json
{
  "status": "undeclared",
  "evidence": [],
  "notes": "No normative provider SLO or consumer SLA was established in the reviewed runtime/configuration files. No measured traffic or latency is inferred."
}
```

## Other dependencies

```json
[
  {
    "name": "EAS/Expo and local device/build toolchains",
    "protocol": "subprocess CLI",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 40,
        "note": "Maestro/EAS/Expo process deadlines are distinct from HTTPcalls"
      }
    ]
  },
  {
    "name": "Configured uptime monitor hosts",
    "protocol": "dynamic HTTP method per monitor",
    "evidence": [
      {
        "path": "cmd/preflight/uptime.go",
        "line": 50,
        "note": "Probe method/URL supplied by monitored endpoint configuration;not one fixed app dependency"
      }
    ]
  },
  {
    "app": "preflight-runner",
    "service": "local-metro",
    "protocol": "development-loopback-http",
    "notes": "Runner polls Metro statusURL and probes localhost port to prove dev-session readiness. This is a local tool process interface, not a fleet public REST contract.",
    "evidence": [
      {
        "path": "cmd/preflight/main.go",
        "line": 10882,
        "source": "/Users/mackieg/.config/superpowers/worktrees/service-contracts-fleet/preflight-runner-master/cmd/preflight/main.go"
      },
      {
        "path": "cmd/preflight/main.go",
        "line": 11911,
        "source": "/Users/mackieg/.config/superpowers/worktrees/service-contracts-fleet/preflight-runner-master/cmd/preflight/main.go"
      }
    ]
  }
]
```

## Excluded interfaces

```json
[
  {
    "path": "cmd/preflight",
    "reason": "Command-line consumer and local tooling; no provided HTTP REST/GraphQL server"
  }
]
```

## Followups and observed mismatches

```json
[
  "Bind these exact CLI method/path identities to Preflight provider operationIds, preserving /api/v1/targets versus /api/preflight/v1 paths.",
  "Align direct upload/prove-app/recipe and streaming transport deadlines deliberately; JSON helper timeout/retry does not apply to those callsites."
]
```

## Validation boundary

Validation and reporting are advisory. No deployment gate is added. Source compatibility does not establish live SLA compliance. Missing provider guarantees, telemetry windows and payload schemas remain unknown. Full machine-readable evidence is in `review.json`.
