#!/usr/bin/env zsh
set -euo pipefail

# Usage:
#   irondome-imessage.zsh <to> <message>
# Environment:
#   IRONDOME_IMESSAGE_DRY_RUN 1|0  (default 0) prints message to stdout, does not send
#   IRONDOME_IMESSAGE_DEBUG   1|0  (default 0) prints diagnostics to stderr
# Notes:
# - Requires macOS Messages.app logged into iMessage.
# - This runs as the current user (LaunchAgent), not root.

to=${1:-""}
message=${2:-""}
dry_run=${IRONDOME_IMESSAGE_DRY_RUN:-0}
debug=${IRONDOME_IMESSAGE_DEBUG:-0}

if [[ -z "$to" || -z "$message" ]]; then
  echo "usage: $(basename "$0") <to> <message>" >&2
  exit 2
fi

# Normalize common US input formats to E.164 (+1XXXXXXXXXX) to improve buddy lookup.
raw_to="$to"
to=$(echo "$to" | tr -d ' ()-.' | tr -d $'\t\r\n')
if [[ "$to" == 1[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] ]]; then
  to="+${to}"
elif [[ "$to" == [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] ]]; then
  to="+1${to}"
elif [[ "$to" != +* ]]; then
  # Leave Apple ID emails as-is; add + if it looks numeric and missing.
  if echo "$to" | grep -qE '^[0-9]+$'; then
    to="+${to}"
  fi
fi

if [[ "$debug" == "1" ]]; then
  echo "[irondome-imessage] to_raw=$raw_to to_norm=$to dry_run=$dry_run" >&2
fi

if [[ "$dry_run" == "1" ]]; then
  print -r -- "$to"
  echo "---" 
  print -r -- "$message"
  exit 0
fi

# If the caller passed literal "\\n" sequences, turn them into real newlines.
# (Some shells/UIs preserve backslashes; iMessage should display actual newlines.)
message=${message//\\n/$'\n'}

osascript_out=""
if ! osascript_out=$(/usr/bin/osascript - "$to" "$message" 2>&1 <<'APPLESCRIPT'
on run argv
  set recipient to item 1 of argv
  set theMessage to item 2 of argv

  tell application "Messages"
    -- Prefer iMessage, but fall back to SMS if available (requires Text Message Forwarding).
    try
      set svc to 1st service whose service type is iMessage
      set b to buddy recipient of svc
      try
        set c to make new text chat with properties {service:svc, participants:{b}}
        send theMessage to c
      on error
        send theMessage to b
      end try
    on error errMsg number errNum
      -- Fallback: SMS via Continuity (if enabled)
      try
        set svc to 1st service whose service type is SMS
        set b to buddy recipient of svc
        try
          set c to make new text chat with properties {service:svc, participants:{b}}
          send theMessage to c
        on error
          send theMessage to b
        end try
      on error errMsg2 number errNum2
        error "iMessage failed and SMS unavailable. Ensure Messages is signed into iMessage and (optional) enable Text Message Forwarding on your iPhone. iMessage error: " & errMsg & " | SMS error: " & errMsg2 number errNum
      end try
    end try
  end tell
end run
APPLESCRIPT
); then
  rc=$?
  if [[ "$debug" == "1" ]]; then
    echo "[irondome-imessage] osascript_failed rc=$rc out=$osascript_out" >&2
  fi
  exit $rc
fi

if [[ "$debug" == "1" && -n "$osascript_out" ]]; then
  echo "[irondome-imessage] osascript_out=$osascript_out" >&2
fi
