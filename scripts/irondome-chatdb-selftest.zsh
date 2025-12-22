#!/usr/bin/env zsh
set -euo pipefail

venv_py="/Users/mirelacertan/.continue/.venv/bin/python"
db="$HOME/Library/Messages/chat.db"

echo "python: $venv_py"
echo "db:     $db"

if [[ ! -x "$venv_py" ]]; then
  echo "ERROR: venv python not found at $venv_py" >&2
  exit 2
fi

if [[ ! -f "$db" ]]; then
  echo "ERROR: chat.db not found at $db" >&2
  exit 3
fi

"$venv_py" -c 'import sqlite3, pathlib, sys; p=pathlib.Path("~/Library/Messages/chat.db").expanduser(); uri=f"file:{p.as_posix()}?mode=ro"; 
try:
  con=sqlite3.connect(uri, uri=True, timeout=1.0)
  try:
    con.execute("select 1").fetchone()
  finally:
    con.close()
  print("OK: opened chat.db")
except Exception as e:
  print("FAIL: cannot open chat.db:", e)
  print("HINT: System Settings → Privacy & Security → Full Disk Access → add:")
  print("  ", sys.executable)
  print("  /opt/homebrew/bin/python3 (optional)")
  raise
'
