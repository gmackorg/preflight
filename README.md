# preflight

Command-line client for the [Preflight](https://preflight.forgegraf.com) mobile
build/release control plane. It registers a machine as a build runner, executes
build and test jobs, and gives you a view of the farm from a terminal.

```
preflight nodes            # machines: engines, free disk, agents, live jobs
preflight queue            # what is queued/running/blocked, and why
preflight build --app <id> # queue a build/test work order
preflight disk             # free space here and across the farm
preflight integrations     # is the API and its upstreams reachable
```

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
| `PREFLIGHT_UPDATE_REPO` | Where `update` looks for releases |

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

Disk is the failure mode worth knowing about: below
`PREFLIGHT_MIN_FREE_DISK_GB` a runner *declines* work rather than failing it,
so a host that quietly fills up looks idle instead of sick. `preflight disk`
and `preflight nodes` both surface that. Automatic checks only probe free
space on the build and home volumes; they never scan or delete shared Xcode
caches. `PREFLIGHT_MIN_FREE_DISK_GB` is the single opt-in floor for claims and
simulator builds. A configured floor also refuses work when a volume cannot
be probed. Inspect ownership and preserve required native products before an
explicit `preflight disk --reclaim` or `preflight cleanup builds` operation.

Queued iOS simulator proofs can select a packaged preview profile with
`prove-app --lane simulator --build-strategy local --build-profile preview-simulator`.
The selected profile must inherit or declare `developmentClient: false`,
`distribution: "internal"`, `ios.simulator: true`, and `APP_VARIANT: "preview"`.
Preflight preserves that profile's environment through prebuild, CocoaPods, and
the Release simulator build, requires an embedded `main.jsbundle`, installs it,
and launches the bound bundle ID. The source binding records the selected
profile and its evaluated native identity. Local readiness requires a Maestro
flow matching that bundle; an external flow may be supplied with `--flow-path`.
For queued execution, the workflow's Maestro suite binding must also select that
flow and its tags. Packaged previews currently require the local queued runner
path; EAS and standalone plans keep their development-client requirements.

For a standalone simulator proof, `prove-app --standalone-run --target-key <id>`
requires a readable Maestro flow and the simulator development profile. Choose a
free Metro port and a fresh artifact directory. The CLI launches its own Metro,
waits for readiness, opens the development client, and publishes Maestro reports,
logs, screenshots and videos. A passing proof requires a fresh JUnit report with
executed passing tests; skipped or missing tests fail the run. When the command
exits, it stops its Metro and closes the runtime session records.

Standalone Metro uses the selected EAS profile environment as defaults and
preserves explicit process environment overrides, including live API URLs.
Both source identity resolution and Metro use the development app variant.

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
