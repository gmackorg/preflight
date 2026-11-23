# preflight

Command-line client for the [Preflight](https://preflight.forgegraf.com) mobile
build/release control plane. It registers a machine as a build runner, executes
build and test jobs, and gives you a view of the farm from a terminal.

```
preflight nodes            # machines: engines, free disk, agents, live jobs
preflight queue            # what is queued/running/blocked, and why
preflight build --app <id> # queue a build/test work order
preflight build store --app <id> --platform ios --lane beta --wait # signed store build + upload
preflight cancel <pfwo_id> # cancel one work order and its active workflow
preflight disk             # free space here and across the farm
preflight integrations     # is the API and its upstreams reachable
```

`build` and `device_test` build a development client on the device lane;
`simulator_test` and `e2e_suite` use the simulator lane. `--profile` (also
`--build-profile`) names the lane profile: `development` (the default) builds a
development client with `APP_VARIANT=development`, and a `preview`,
`preview-*` or `*-preview` profile on a simulator kind builds a packaged app
with embedded JavaScript (`APP_VARIANT=preview`). Production profiles fail
before queueing; store and TestFlight/Play builds use `preflight build store`
(see [Store builds](#store-builds-signing-push-and-ota)).

`cancel` uses the configured workspace and cancels the active workflow before
recording work-order cancellation. If recording fails, retry the same command.
It preserves work orders that have already succeeded or failed.

## Install

```sh
go install github.com/gmackorg/preflight/cmd/preflight@latest
```

Or download a binary from [Releases](https://github.com/gmackorg/preflight/releases).
Once installed, it updates itself:

```sh
preflight update --check   # report what's available
preflight update           # verify checksum, install atomically
```

`update` downloads the asset for your platform, verifies it against the
`checksums.txt` published with the release, and installs by atomic rename. A
checksum mismatch aborts without touching the binary you're running, and the
previous binary is kept alongside as `preflight.previous`.

## Getting started

```sh
preflight login            # device-code auth against the control plane
preflight nodes            # confirm the farm can see you
```

Configuration lives in `~/.config/preflight/config.json`. Useful overrides:

| Variable | Purpose |
|---|---|
| `PREFLIGHT_API_URL` | Control-plane URL (default `https://preflight.forgegraf.com`) |
| `PREFLIGHT_TOKEN` | API token, instead of the stored login |
| `PREFLIGHT_WORKSPACE_ID` | Workspace to operate on |
| `PREFLIGHT_MIN_FREE_DISK_GB` | Free-space floor below which a runner declines jobs |
| `PREFLIGHT_IOS_SIMULATOR_BOOT_TIMEOUT` | Total iOS boot/readiness deadline (default `3m`); runner cancellation also stops the wait |
| `PREFLIGHT_COMMAND_OUTPUT_DRAIN_TIMEOUT` | Output pipe drain grace after a command exits (default `5s`); an incomplete drain still fails the command. iOS boot probes retain their explicit `250ms` grace |
| `PREFLIGHT_UPDATE_REPO` | Where `update` looks for releases |
| `PREFLIGHT_OTA_STORE` | Runner's filesystem OTA store when the control plane has no store of its own |
| `PREFLIGHT_OTA_SERVER_STORE` | `off` publishes OTA updates to the filesystem store, `r2` always uploads; unset asks the control plane |

## Running a build host

Unity build work orders can request `sourceBinding.unity.nativePackage` as
`ios-xcframework` with an `ios-simulator` export, or `android-aar` with an
`android-library` export. The runner stages tracked source, verifies the raw
export checksums, then builds both unsigned iOS framework slices and their
XCFramework or an Android AAR using the selected editor's bundled JDK/Gradle.
Native output and intermediate builds belong to
`.preflight/unity-native-packages/<jobId>`; completion records native and export
hashes separately. Pin these libraries into the hybrid app before its normal
simulator build and journeys. Unity packaging alone does not prove gameplay.

A runner is a long-lived process that claims jobs. On macOS it's a launchd
agent; `ops/` has a working example plus the hourly disk sweep the build farm
uses.

For an Android emulator sharing a host with other services, select an isolated
Metro port with `preflight runner once --metro-port 18111`. Android keeps 8081
when the flag is omitted. Startup records the selected port in its dev session;
native open and the development-client deep link consume that same port. An
occupied port is reused only when its listener is verified as this app's live
Metro process. Otherwise startup refuses the collision without terminating the
listener; select a free port and start a new workflow.

Disk is the failure mode worth knowing about: below
`PREFLIGHT_MIN_FREE_DISK_GB` a runner *declines* work rather than failing it,
so a host that quietly fills up looks idle instead of sick. `preflight disk`
and `preflight nodes` both surface that. Automatic checks only probe free
space on the build and home volumes; they never scan or delete shared Xcode
caches. `PREFLIGHT_MIN_FREE_DISK_GB` is the single opt-in floor for claims and
simulator builds. A configured floor also refuses work when a volume cannot
be probed. Inspect ownership and preserve required native products before an
explicit `preflight disk --reclaim` or `preflight cleanup builds` operation.

An idle runner retains its registration and liveness heartbeat while disk
admission is refused. It rechecks space on the same 10–60 second backoff as
empty claims, and resumes claiming only when both volumes meet the configured
floor. The idle window stays bounded (10 minutes by default); a zero idle wait
keeps the single-attempt behavior. No cache deletion or floor change happens
automatically.

### Building a pushed commit (`--ci`)

A runner only claims work orders whose `sourceBinding.workspaceRoot` is under
its `--workspace-root`, and it never writes in a developer checkout there. On
the fleet (2026-11-23) gmacko-mini's three agents serve
`/Users/mackieg/preflight-ci` and labtop's agent serves
`/Volumes/dev/preflight-ci` (both internal disks; labtop moved off the external
`/Volumes/dev-ssd` on 2026-11-23, see ops/RUNNER-HOSTS.md). No runner serves
`/Volumes/dev` itself or `/Volumes/dev-ssd`. To build a pushed or merged commit from anywhere
(a clean clone in `~/work`, or a jj workspace), check that commit out and run:

```sh
preflight build --app <id> --platform ios --ci --ci-root /Users/mackieg/preflight-ci --wait
```

`--ci` binds the order to a Preflight-owned checkout,
`<ci-root>/.preflight-ci/<repo>`. The claiming runner clones the remote there,
fetches the commit and hard-resets to it, so nothing is written in your
checkout or in a seed. The commit must be on the remote; the CLI checks this
before queueing. Set the default once with `PREFLIGHT_CI_ROOT` or `"ciRoot"`
in the CLI config. Without a CI root the checkout goes next to yours, which
only a runner serving that directory can reach (`runner_workspace_missing`).
For jj workspaces, the fetch URL of the remote holding the commit is used,
including when the remote has a separate push URL.

For queued iOS builds, pass the **app directory** (the directory containing
`.preflight`) as the cleanup root:

```sh
preflight cleanup builds --root /path/to/checkout/apps/mobile --max-age 24h --dry-run
preflight cleanup builds --root /path/to/checkout/apps/mobile --max-age 24h
```

This also reclaims stale `Build/Intermediates.noindex`, `ModuleCache.noindex`,
`Index.noindex` and `SDKStatCaches.noindex` inside Preflight's simulator/device
DerivedData directories. Maintenance takes the builder's checkout mutex and
skips a checkout that is building. Every descendant must be older than the
cutoff; an old parent directory alone does not establish inactivity. Installable
`Build/Products`, build logs, recordings and source are retained. Linked generated
paths or an unusable mutex refuse native cleanup. Dry runs count the selected
entries without creating a mutex or deleting resources. This does not scan
other checkouts or change the retention of shared Xcode caches.
`preflight disk --reclaim --root <app-directory>` uses the same native cleanup;
its JSON output remains parseable, reports dry-run candidate counts, and exits
unsuccessfully if cleanup fails. Invalid or non-positive retention is refused
before maintenance starts.

Bounded build commands also terminate descendants left in their own process
group after either successful or failed completion. Persistent Metro sessions
have a separate lifecycle; unrelated process groups are preserved.

Native commands also stop when the control plane revokes their job or device
lease, requeues or finishes the job, or returns a different claim identity.
The runner preserves the server's state instead of submitting a stale completion.
Temporary heartbeat/read failures are tolerated only until the last confirmed
lease expires or its heartbeat becomes five minutes stale, whichever comes first.

### App readiness

`preflight prove-app --local-readiness` (and work orders, which run the same
discovery) checks Preflight's conventions without calling the API:

- an Expo app config — `app.config.ts`, `app.config.js` or `app.json` — whose
  `ios.bundleIdentifier` and/or `android.package` names the native app;
- an `expo-dev-client` dependency for development-client lanes (packaged
  preview builds do not need one) and a scheme or slug for its deep links;
- the `.maestro/01-app-launches.yaml` smoke flow (or `--flow-path`), whose
  `appId` matches the native app.

No hosted-build config file is read: local lane settings come from the profile
name, store lane settings from `preflight build-profiles`. Development builds
run on the runner (`expo prebuild` + `xcodebuild`/`gradle`); `--build-strategy`
accepts only `local`.

Queued iOS simulator proofs can select a packaged preview profile with
`prove-app --lane simulator --build-strategy local --build-profile preview-simulator`.
Preflight runs prebuild, CocoaPods and the Release simulator build with
`APP_VARIANT=preview`, requires an embedded `main.jsbundle`, installs it, and
launches the bound bundle ID. The source binding records the profile and its
evaluated native identity. Local readiness requires a Maestro flow matching that
bundle; an external flow may be supplied with `--flow-path`. For queued
execution, the workflow's Maestro suite binding must also select that flow and
its tags. Packaged previews require the local queued runner path.

Android emulator proofs can use `--platform android --lane simulator
--build-strategy local --build-profile preview-android`. The queued runner
prebuilds, assembles the Release APK, checks its generated application ID and
embedded `assets/index.android.bundle`, installs on the selected emulator, and
launches only the bound package. Split APK outputs, physical-device preview
lanes and standalone packaged plans are refused. Android development-client
builds keep their build and Metro launch behavior.

For a standalone simulator proof, `prove-app --standalone-run --target-key <id>`
requires a readable Maestro flow. Choose a free Metro port and a fresh artifact
directory. The CLI launches its own Metro, waits for readiness, opens the
development client, and publishes Maestro reports, logs, screenshots and videos.
A passing proof requires a fresh JUnit report with executed passing tests;
skipped or missing tests fail the run. When the command exits, it stops its
Metro and closes the runtime session records. Standalone plans cover the
simulator lane only; development builds use the queued runner workflow.

Standalone Metro and source identity resolution both use the development app
variant and preserve explicit process environment overrides, including live
API URLs.

## Store builds, signing, push and OTA

Store builds, their signing material, push and over-the-air updates all run
through Preflight. Every command below takes `--api-url`, `--workspace-id` and
`--json`, and authenticates with `PREFLIGHT_TOKEN` or the saved login.

### Signing credentials

The control plane keeps certificates, profiles, keystores and API keys in its
signing vault; runners receive them per job and never store them.

```sh
preflight credentials list --app <id>                 # app + team credentials
preflight credentials upload --kind ios_distribution_certificate --file dist.p12 --password-env P12_PASSWORD
preflight credentials upload --kind android_upload_keystore --app <id> --file upload.jks \
  --password-env KEYSTORE_PASSWORD --field keyAlias=upload --field keyPassword=…
preflight credentials upload --kind asc_api_key --file AuthKey_ABC123.p8 --field keyId=ABC123 --field issuerId=…
preflight credentials doctor --app <id>               # what a store build is missing
preflight credentials doctor --app <id> --fix         # create bundle ids, capabilities, profiles
```

Team kinds (`asc_api_key`, `apns_key`, `ios_distribution_certificate`,
`ios_development_certificate`, `play_service_account`) upload without `--app`;
app kinds (`ios_provisioning_profile`, `android_upload_keystore`,
`fcm_service_account`) need it. `credentials refs` (or `list --app-id`) still
lists generic secret references, and `credentials create` adds one.

Moving an app off its old hosted-build account is a one-time import:

```sh
preflight credentials import-eas --app <id> --expo-token-env EXPO_ACCESS_TOKEN
preflight credentials import-eas --all                # every linked app in the workspace
preflight build-profiles import-eas --app <id> --file <old build config> --dry-run
```

`--expo-token-env` stores the account token in the vault first; the import
reads it from there and reports each credential as imported, unchanged,
missing or failed.

### Signing targets and build profiles

```sh
preflight signing-targets get --app <id>
preflight signing-targets set --app <id> --file targets.json   # [{targetName, bundleId, capabilities}]
preflight build-profiles get --app <id>
preflight build-profiles set --app <id> --file profiles.json   # one entry per lane
```

A build profile holds a lane's (`internal`, `beta`, `store`) non-secret
environment, the ids of secret build-environment references, the iOS scheme,
the Gradle task, the version source and the app directory. `get --json`
prints a document `set` accepts.

### Store builds

```sh
preflight build store --app <id> --platform ios --lane beta --git-ref main --wait
preflight build store --app <id> --platform android --lane internal --destination play_internal --wait
```

The control plane resolves the lane's build profile and signing material
(a missing certificate, profile, keystore or upload credential fails the
request with `signing_material_missing`), allocates the build number, and
queues a `store.build` job. A runner checks out the ref, runs `expo prebuild`,
then archives and exports with `xcodebuild` (iOS) or builds the bundle with
Gradle (Android), signs with the vault material and uploads through
`store.upload`: `altool` to TestFlight, the Google Play Developer API to the
chosen track. `--destination none` builds without uploading. `--wait` polls
until the build is uploaded or fails and prints the App Store Connect build id
or the Play version code.

### Push

```sh
preflight push keys create --app <id> --scope send       # server secret for the app backend
preflight push keys create --app <id> --scope register   # public key for the mobile app
preflight push send --app <id> --file message.json       # {to, notification, ios?, android?}
```

Push goes straight to APNs and FCM with the app's vault credentials.

### OTA updates

```sh
preflight ota code-signing generate --app <id> --out certs/preflight-ota-certificate.pem
preflight ota rollback --app <id> --channel production --to-embedded
preflight ota rollback --app <id> --channel production --to <updateId>
preflight ota republish --app <id> --update <updateId> --channel production --rollout 25
```

`code-signing generate` keeps the private key in the vault and prints the
`updates.codeSigningCertificate` / `codeSigningMetadata` app config. Rollback
takes `--to-embedded`, `--to <updateId>`, `--previous` (the default), `--pause`
or `--resume`, for one `--platform` or both.

Runners execute `ota.export` and `ota.publish` jobs. When the control plane
serves updates from its own store (R2, reported by `/api/preflight/v1/ota/health`),
`ota.publish` stages the update locally, uploads each asset and then the
update record through `PUT /api/preflight/v1/apps/<id>/ota/store/<updateId>/<file>`,
and discards the staging copy. Otherwise it publishes into the runner's
filesystem store (`PREFLIGHT_OTA_STORE`). `PREFLIGHT_OTA_SERVER_STORE=off`
forces the filesystem store; `=r2` forces uploads.

Unity library builds use `unity.build.player` with a source-bound command plan.
LevelForge's build entry point and HabitPlay's three native library exports are
permitted by default. Set `PREFLIGHT_UNITY_EXECUTE_METHODS` for additional permitted
editor methods and `UNITY_EDITOR` to the installed editor. Platform capabilities reflect installed
`PlaybackEngines/iOSSupport` and `PlaybackEngines/AndroidPlayer` modules.

For a library export, `commandPlan.inputPath` selects the authored Unity project,
`-projectPath` selects `.preflight/unity-projects/<jobId>/HabitPlayUnity`, and
`output.exportRelativePath` identifies the editor-generated project under
`Build/exports`. The runner stages tracked Assets, Packages and ProjectSettings,
copies tracked local SDK packages, and rewrites local package references in the
staged manifest. Editor-generated settings stay in that staging directory.
Exports must include a complete parent `SHA256SUMS`; the runner verifies those
files before moving the lane to `.preflight/unity-exports/<jobId>/<lane>`.
The completion result includes source-file provenance, source commit, the whole
export digest and file count. Xcode and Gradle project exports need subsequent
native library packaging and an Expo simulator proof to validate a hybrid app.

## Development

```sh
go build ./cmd/preflight
go test ./...
```

Releases are cut by pushing a `v*` tag; the workflow builds darwin/linux on
amd64/arm64 and publishes them with checksums. The asset naming and
`checksums.txt` format are a contract with `preflight update` — changing either
breaks self-update for already-installed binaries.

### Unity diagnostic log retention

Unity editor logs are retained separately from the mutable editor log. The runner redacts a content-addressed, read-only snapshot before registering it and uploads those exact bytes. Registration alone is a local reference, with no content digest. A successful byte upload records the actual SHA-256 and size, makes the blob downloadable, and marks it uploaded. Unity log uploads are immutable: identical retries succeed; different bytes require a new artifact. Failed builds remain failed even when their diagnostic logs are retained, and an upload failure leaves the local snapshot available. Existing historical log records are preserved; recovering one creates a new artifact with provenance back to the original.

### Simulator compiler limits

On memory-constrained Macs, run the official worker with an explicit compiler limit:

```sh
preflight runner once --workspace-root /path/to/source --ios-simulator-build-jobs 2
```

The optional flag accepts integers from 1 to 32 and passes `-jobs` to the iOS
simulator's Xcode build. Invalid or missing values fail before registration or
execution. Leaving the flag unset preserves Xcode's automatic parallelism. This
limits simulator compilation only; it does not change store builds.
Keep disk admission/runtime guards enabled and retain partial derived data when a
build is interrupted. Lower parallelism may reduce memory and swap pressure, but
its effect must be measured on the actual host before repeating a failed proof.

For a task-owned worker on a shared host, add `--workflow-id <id>` to claim
only that proof workflow. The control plane filters before acquiring a lease,
including stream offers and lease recovery. The runner refuses this option
against a server that does not advertise workflow claim support. Checkout,
capability, source and resource admission checks still apply; this option does
not reserve the host or increase its build capacity.


### Shared SimLock devices

`preflight runner once --simlock` (or `PREFLIGHT_SIMLOCK=1`) leases a local
simulator/emulator for its workflow, renews it through native build and Maestro
validation, and returns it on exit. T3 Code can keep using its SimLock gateway;
local and gateway clients consume the same worker slots. Do not pass a pinned
simulator UDID with this mode. Workflow-scoped claims must be supported by the
control plane. Resuming a job tied to an expired device requires rediscovery.

iOS requires Xcode 27+ for the isolated device set. Maestro's iOS process runs
with Android ADB/console ports denied through macOS `sandbox-exec`, so its
cross-platform discovery cannot probe another client's Android device.
Android Maestro uses the grant's direct emulator endpoint rather than default
ADB discovery. The existing physical-device lanes are unchanged.

Run `go test ./...` for the runner checks. On a configured worker, opt into the
real lease/Settings-flow check with `PREFLIGHT_SIMLOCK_LIVE=ios` or `android`
and `go test ./cmd/preflight -run '^TestSimlockLive$' -v -count=1`.
