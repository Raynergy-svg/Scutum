#!/usr/bin/env zsh
set -euo pipefail

# Launch wrapper for launchd.
# - Ensures venv exists (prefers Homebrew Python)
# - Runs Sentinel using venv python

root_dir=$(cd "$(dirname "$0")/.." && pwd)
base_dir=${IRONDOME_BASE_DIR:-"$HOME/Library/Application Support/IronDome"}
workdir=${IRONDOME_WORKDIR:-"$base_dir/work/sentinel"}
mkdir -p "$workdir"

# Bootstrap venv (idempotent)
/bin/zsh "$root_dir/scripts/irondome-venv-bootstrap.zsh" >>"$workdir/sentinel.venv.log" 2>&1 || true

venv_py="$root_dir/.venv/bin/python"
if [[ ! -x "$venv_py" ]]; then
  echo "[sentinel-launch] venv python missing at $venv_py" >>"$workdir/sentinel.venv.log"
  # Fallback to system python (may warn about LibreSSL)
  venv_py="/usr/bin/python3"
fi

exec "$venv_py" "$root_dir/scripts/irondome-sentinel.py"
