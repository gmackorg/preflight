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
`preflight disk`.

**Runner workspaces live on internal storage**, never on an external drive:
labtop uses `/Volumes/dev/preflight-ci` (an internal APFS volume in the boot
container), gmacko-mini uses `~/preflight-ci`. Keep the pnpm store on the same
volume as the workspace (`/Volumes/dev/.pnpm-store` on labtop) so pnpm
hard-links instead of copying.

Until 2026-11-23 labtop's workspace sat on the USB SSD `/Volumes/dev-ssd`.
External drives are gated by macOS privacy (TCC "Removable Volumes"). When
access isn't granted, every directory read waits on a consent prompt that
nobody at a headless host answers. It blocked about 20s, then failed with
EINTR (or EPERM after a reboot), even for raw device reads as root. The runner
wedged in its startup cleanup without ever claiming, every process touching
the drive piled up, and the host reported load 400-900 that looked like build
pressure. A rebuilt ad-hoc-signed binary counts as a new app to TCC, so a
grant can silently stop applying after a deploy. Internal storage needs no
such grant. A full internal disk only makes the runner decline claims, which
the floor above already handles.

Diagnose before blaming hardware: `/usr/bin/log show --last 1m --predicate
'process == "tccd"' | grep SystemPolicyRemovableVolumes`. In zsh, plain `log`
is a builtin.
