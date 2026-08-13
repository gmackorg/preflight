# Running a build host

## Canonical binary path

Runner scripts must invoke **`$HOME/.local/bin/preflight`**:

```sh
BIN="$HOME/.local/bin/preflight"
```

Not the repo build output. `go build ./...` writes a `preflight` binary into
the repository root, so a runner pointed there silently swaps to whatever was
last compiled — an unversioned `dev` build, possibly mid-edit. labtop ran that
way until 2026-08-13, which is how it and gmacko-mini ended up on different
builds without anything reporting a problem. The repo path also lives on the
volume that fills.

Verify a host is not depending on the repo copy:

```sh
grep -h '^BIN=' ~/.local/bin/preflight-runner-*.sh | sort -u
# expect only: BIN="$HOME/.local/bin/preflight"
```

## Installing / updating

```sh
preflight update            # verifies checksum, installs atomically
launchctl kickstart -k gui/$(id -u)/com.forgegraph.preflight-runner.<name>
```

A running runner keeps its old binary until restarted, so an update is not live
until the kickstart.

**Never `cp` over a binary that is executing.** Copying mutates the inode in
place, which on macOS invalidates the code signature and gets the next exec
SIGKILLed (exit 137) — the running process survives, so the breakage only
appears at the next restart. `preflight update` renames instead, which is safe.
If you must place a binary by hand:

```sh
rm -f <target> && cp <new> <target> && xattr -c <target> && codesign --force --sign - <target>
<target> version   # must print, and exit 0
```

## Disk

Below `PREFLIGHT_MIN_FREE_DISK_GB` (15 on the Macs) a runner *declines* jobs
rather than failing them, so a host that fills up looks idle rather than sick.
`com.forgegraph.preflight-disk-sweep` runs hourly at a 40GB headroom; check with
`preflight disk`. Keep large regenerable trees (CI checkouts, DerivedData) off
the boot volume — `/Volumes/dev/.preflight-ci` is a symlink to external storage
for this reason.
