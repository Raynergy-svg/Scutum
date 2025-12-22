#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
VENV_PY="$ROOT/.venv/bin/python"
PLIST="$ROOT/launchd/com.irondome.sentinel.plist"

if [[ ! -x "$VENV_PY" ]]; then
  echo "Missing venv python: $VENV_PY" >&2
  echo "Run: /bin/zsh $ROOT/scripts/irondome-venv-bootstrap.zsh" >&2
  exit 1
fi

if [[ -z "${SENTINEL_ALLOWED_HANDLES:-}" ]]; then
  if [[ -f "$PLIST" ]]; then
    # Pull from plist so this script mirrors launchd config.
    from_plist=$(/usr/bin/plutil -extract EnvironmentVariables.SENTINEL_ALLOWED_HANDLES raw -o - "$PLIST" 2>/dev/null || true)
    from_plist="${from_plist//$'\n'/}"
    from_plist="${from_plist//\"/}"
    if [[ -n "$from_plist" ]]; then
      export SENTINEL_ALLOWED_HANDLES="$from_plist"
      echo "Using SENTINEL_ALLOWED_HANDLES from plist: $SENTINEL_ALLOWED_HANDLES"
    fi
  fi
fi

if [[ -z "${SENTINEL_ALLOWED_HANDLES:-}" ]]; then
  echo "Set SENTINEL_ALLOWED_HANDLES (comma-separated), or set it in $PLIST." >&2
  echo "Example:" >&2
  echo "  export SENTINEL_ALLOWED_HANDLES=+14135550123" >&2
  exit 2
fi

first_handle="${SENTINEL_ALLOWED_HANDLES%%,*}"
first_handle="${first_handle//[[:space:]]/}"

if [[ -z "$first_handle" ]]; then
  echo "SENTINEL_ALLOWED_HANDLES is empty." >&2
  exit 3
fi

echo "Using python: $VENV_PY"
"$VENV_PY" -c 'import ssl,sys; print("OpenSSL:", ssl.OPENSSL_VERSION); print("Python:", sys.executable)'

echo "\n1) Sanity check chat.db access"
/bin/zsh "$ROOT/scripts/irondome-chatdb-selftest.zsh"

echo "\n2) Recent inbound messages for: $first_handle"
tail_out=$("$VENV_PY" "$ROOT/scripts/irondome-chatdb-tail.py" "$first_handle" --limit 12 || true)
if [[ -z "${tail_out}" ]]; then
  echo "(none found yet)"
  echo "If you just sent a message and it still doesn't show up, discover the exact sender id with:"
  echo "  $VENV_PY $ROOT/scripts/irondome-chatdb-recent.py --limit 25"
else
  echo "$tail_out"
fi

echo "\n3) Next: from your phone, send: status"
echo "   Then re-run this script and look for the message text."
