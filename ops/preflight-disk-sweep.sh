#!/bin/bash
# Hourly disk guard for a build host.
#
# The runner's own guard only fires when it tries to CLAIM a job, and it
# declines rather than recovering — so a host that drifts under the floor
# between claims just stops taking work and looks idle. Worse, on 2026-08-13
# every labtop runner logged "low disk: 10.4 GiB free (< 15 GiB) after sweeping
# 0 cache entries — declining claims" and then died outright when the volume
# hit 100%: their StandardOutPath logs live on the volume that filled.
#
# This sweeps on a timer instead of on demand, and logs the free-space number
# either way so the trend is visible before it becomes an outage.
set -uo pipefail

PREFLIGHT_BIN="${PREFLIGHT_BIN:-$HOME/go/bin/preflight}"
FLOOR_GB="${PREFLIGHT_MIN_FREE_DISK_GB:-15}"
# Sweep well above the floor: reclaiming at the floor is already too late,
# because a Release sim build peaks ~6 GiB after it has been admitted.
HEADROOM_GB="${PREFLIGHT_DISK_SWEEP_GB:-40}"

free_gb() { df -g "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }

for volume in / /Volumes/dev; do
  [ -d "$volume" ] || continue
  before=$(free_gb "$volume")
  [ -z "$before" ] && continue
  if [ "$before" -ge "$HEADROOM_GB" ]; then
    echo "$(date -u +%FT%TZ) $volume ${before}GB free — above ${HEADROOM_GB}GB, no sweep"
    continue
  fi
  echo "$(date -u +%FT%TZ) $volume ${before}GB free — below ${HEADROOM_GB}GB, sweeping"
  # `disk` is newer than some deployed runner binaries (gmacko-mini still runs
  # an Aug-12 build and cannot be rebuilt in place — no source, no git access).
  # Fall back to the older `cleanup builds`, which every build host has.
  if "$PREFLIGHT_BIN" disk --help >/dev/null 2>&1; then
    "$PREFLIGHT_BIN" disk --reclaim --max-age 12h 2>&1 | sed 's/^/  /'
  else
    # NOT "$volume": managedCacheDirs includes "tmp", so a root of "/" would
    # sweep /tmp — system temp, not a build cache. Only ever pass roots that
    # Preflight owns.
    for root in /Volumes/dev "$HOME/Library/Developer/Xcode"; do
      [ -d "$root" ] || continue
      "$PREFLIGHT_BIN" cleanup builds --root "$root" --max-age 12h 2>&1 | sed 's/^/  /'
    done
  fi
  after=$(free_gb "$volume")
  echo "$(date -u +%FT%TZ) $volume ${before}GB -> ${after}GB"
  if [ -n "$after" ] && [ "$after" -lt "$FLOOR_GB" ]; then
    # Say it plainly: below the floor the runners decline every claim, and
    # nothing else on this machine will tell you why the farm went quiet.
    echo "$(date -u +%FT%TZ) WARNING $volume ${after}GB is BELOW the ${FLOOR_GB}GB floor — runners will decline claims"
  fi
done
