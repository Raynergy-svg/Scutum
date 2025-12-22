#!/usr/bin/env zsh
set -euo pipefail

# Creates/updates a dedicated venv for Sentinel with modern TLS.
# Prefers Homebrew Python (OpenSSL) if present.

root_dir=$(cd "$(dirname "$0")/.." && pwd)
venv_dir="$root_dir/.venv"
req="$root_dir/requirements.txt"

# Pick Python interpreter.
py=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 "$(command -v python3 || true)"; do
  [[ -n "$candidate" && -x "$candidate" ]] || continue
  py="$candidate"
  break
done

if [[ -z "$py" ]]; then
  echo "[venv] python3 not found" >&2
  exit 2
fi

echo "[venv] using python: $py"

# Create venv if missing.
if [[ ! -x "$venv_dir/bin/python" ]]; then
  "$py" -m venv "$venv_dir"
fi

# Upgrade pip/setuptools/wheel.
"$venv_dir/bin/python" -m pip -q install --upgrade pip setuptools wheel

# Install deps.
if [[ -f "$req" ]]; then
  "$venv_dir/bin/python" -m pip -q install -r "$req"
fi

echo "[venv] ready: $venv_dir"
