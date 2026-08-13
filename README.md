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
| `PREFLIGHT_UPDATE_REPO` | Where `update` looks for releases |

## Running a build host

A runner is a long-lived process that claims jobs. On macOS it's a launchd
agent; `ops/` has a working example plus the hourly disk sweep the build farm
uses.

Disk is the failure mode worth knowing about: below
`PREFLIGHT_MIN_FREE_DISK_GB` a runner *declines* work rather than failing it,
so a host that quietly fills up looks idle instead of sick. `preflight disk`
and `preflight nodes` both surface that, and `preflight disk --reclaim` prunes
regenerable build caches.

## Development

```sh
go build ./cmd/preflight
go test ./...
```

Releases are cut by pushing a `v*` tag; the workflow builds darwin/linux on
amd64/arm64 and publishes them with checksums. The asset naming and
`checksums.txt` format are a contract with `preflight update` — changing either
breaks self-update for already-installed binaries.
