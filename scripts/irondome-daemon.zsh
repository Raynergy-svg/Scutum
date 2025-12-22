#!/usr/bin/env zsh
set -euo pipefail

# Usage:
#   irondome-daemon.zsh [workdir] [interval_seconds]
#   irondome-daemon.zsh [interval_seconds]
#
# Runs the full pipeline (irondome-run.zsh) in a loop.
# Intended to be wrapped by caffeinate from launchd, e.g.:
#   /usr/bin/caffeinate -dimsu /bin/zsh irondome-daemon.zsh <workdir> 60

base_dir="${IRONDOME_BASE_DIR:-$HOME/Library/Application Support/IronDome}"
default_workdir="$base_dir/work/buddy"

arg1="${1:-}"
arg2="${2:-}"

# If only one arg is provided and it's numeric, treat it as interval.
if [[ -n "$arg1" && -z "$arg2" && "$arg1" == <-> ]]; then
  workdir="${IRONDOME_WORKDIR:-$default_workdir}"
  interval="$arg1"
else
  workdir="${arg1:-${IRONDOME_WORKDIR:-$default_workdir}}"
  interval="${arg2:-${IRONDOME_INTERVAL_SECONDS:-60}}"
fi

# normalize interval
interval=${interval//[^0-9]/}
[[ -z "$interval" ]] && interval=60
if [[ "$interval" -lt 10 ]]; then
  interval=10
fi

mkdir -p "$workdir"
script_dir=$(cd "$(dirname "$0")" && pwd)

echo "[irondome-daemon] start workdir=$workdir interval=${interval}s"

while true; do
  start_epoch=$(date +%s)
  now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if /bin/zsh "$script_dir/irondome-run.zsh" "$workdir"; then
    echo "[irondome-daemon] ok time=$now_iso"
  else
    rc=$?
    echo "[irondome-daemon] error rc=$rc time=$now_iso" >&2
    # brief backoff on failure
    sleep 5
  fi

  end_epoch=$(date +%s)
  elapsed=$(( end_epoch - start_epoch ))
  sleep_for=$(( interval - elapsed ))
  if [[ "$sleep_for" -gt 0 ]]; then
    sleep "$sleep_for"
  fi

done
