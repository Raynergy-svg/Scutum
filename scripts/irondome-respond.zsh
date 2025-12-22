#!/usr/bin/env zsh
set -euo pipefail

# Usage:
#   irondome-respond.zsh <workdir>
# Environment:
#   OLLAMA_URL      (default http://localhost:11434)
#   OLLAMA_MODEL    (default llama3.2:8b-instruct-qat)
#   IRONDOME_MODE   notify|enforce  (default notify)
#   IRONDOME_NOTIFY 1|0            (default 1)
#   IRONDOME_ACTIONS_ALLOWLIST comma-separated actions (default: notify_only)
# NOTE: iMessage sending is handled by Sentinel.
# The responder no longer sends iMessages directly.
#
# Writes:
#   <workdir>/actions-latest.txt
#   <workdir>/ai-decision-latest.json
#   <workdir>/notifications.log

workdir=${1:-/tmp/irondome}
mkdir -p "$workdir"

script_dir=$(cd "$(dirname "$0")" && pwd)

alerts_txt="$workdir/alerts-latest.txt"
alerts_jsonl="$workdir/alerts-latest.jsonl"
actions_txt="$workdir/actions-latest.txt"
ai_json="$workdir/ai-decision-latest.json"
notif_log="$workdir/notifications.log"
persistence_json="$workdir/persistence.json"
pending_json="$workdir/pending-verifications.json"

ollama_url=${OLLAMA_URL:-http://localhost:11434}
ollama_model=${OLLAMA_MODEL:-llama3.2:8b-instruct-qat}
mode=${IRONDOME_MODE:-notify}
notify=${IRONDOME_NOTIFY:-1}
allow_actions=${IRONDOME_ACTIONS_ALLOWLIST:-notify_only}
imessage_to=""

# Deprecated: direct iMessage notifications from the responder.
if [[ -n "${IRONDOME_IMESSAGE_TO:-}" ]]; then
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] deprecated: IRONDOME_IMESSAGE_TO is ignored (Sentinel is the only notifier)" >> "$notif_log"
fi

now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
host=$(scutil --get ComputerName 2>/dev/null || hostname)

: > "$actions_txt"

if [[ ! -f "$alerts_txt" ]]; then
  echo "[$now_iso] No alerts file at $alerts_txt" >> "$actions_txt"
  exit 0
fi

overall=$(grep -E '^overall_severity:' "$alerts_txt" | awk '{print $2}' || true)
if [[ -z "$overall" ]]; then overall="none"; fi

# Track repeated alerts across runs (persistence).
_persistence_update() {
  python3 - "$alerts_txt" "$persistence_json" <<'PY'
import json, os, sys, time, hashlib

alerts_path, state_path = sys.argv[1], sys.argv[2]

def load_state():
  try:
    with open(state_path, 'r', encoding='utf-8') as f:
      return json.load(f)
  except Exception:
    return {"by_id": {}, "last_run": None}

def save_state(state):
  tmp = state_path + ".tmp"
  with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(state, f, ensure_ascii=False, indent=2)
  os.replace(tmp, state_path)

state = load_state()

# Extract alert lines.
lines = []
with open(alerts_path, 'r', encoding='utf-8', errors='replace') as f:
  for line in f:
    line = line.rstrip('\n')
    if line.startswith('[') and ' severity=' in line and ' kind=' in line:
      lines.append(line)

cur_ids = set()
for line in lines:
  # Fingerprint on the line content only (stable).
  alert_id = hashlib.sha256(line.encode('utf-8', errors='ignore')).hexdigest()[:16]
  cur_ids.add(alert_id)
  rec = state["by_id"].get(alert_id, {"count": 0, "last_seen": None, "line": line})
  rec["count"] = int(rec.get("count", 0)) + 1
  rec["last_seen"] = int(time.time())
  rec["line"] = line
  state["by_id"][alert_id] = rec

# Decrement/expire old alerts not seen this run.
now = int(time.time())
for alert_id, rec in list(state["by_id"].items()):
  if alert_id not in cur_ids:
    # If not seen in 10 minutes, drop it.
    last = int(rec.get('last_seen') or 0)
    if now - last > 600:
      state["by_id"].pop(alert_id, None)

state["last_run"] = now
save_state(state)

# Print summary to stdout for shell to read.
max_count = 0
max_line = ""
for rec in state["by_id"].values():
  c = int(rec.get('count') or 0)
  if c > max_count:
    max_count = c
    max_line = rec.get('line') or ''

print(json.dumps({"max_count": max_count, "max_line": max_line}, ensure_ascii=False))
PY
}

# Notify via macOS Notification Center.
_notify() {
  local title="$1"; shift
  local msg="$1"; shift

  if [[ "$notify" != "1" ]]; then
    return 0
  fi

  # osascript is built-in on macOS.
  /usr/bin/osascript -e "display notification \"${msg//\"/\\\"}\" with title \"${title//\"/\\\"}\"" >/dev/null 2>&1 || true
  echo "[$now_iso] notify title=$title msg=$msg" >> "$notif_log"
}

# Small helper: check if a value is in comma-separated allowlist.
_is_allowed() {
  local needle="$1"
  echo ",$allow_actions," | grep -qi ",$needle," 
}

# Ask local model for a decision (JSON) using Ollama /api/generate.
# We keep a strict schema and limited action set.
_generate_ai_decision() {
  local prompt
  prompt=$(cat <<'PROMPT'
You are Iron Dome Buddy, a defensive home-network guardian.
Rules:
- Base conclusions ONLY on the alerts text provided.
- Output ONLY valid JSON. No markdown.
- Choose actions ONLY from this allowed set:
  ["notify_only","collect_more_evidence","recommend_pf_block","recommend_isolate_device","recommend_disable_port_forward","recommend_stop_service"]
- Never claim you executed an action; only recommend.
- Do NOT output shell commands. The system will generate/run any commands separately.
- If PENDING VERIFICATION CODES are present, include the exact code value(s) in "summary" and tell me what to ask the guest/device owner to confirm (code + MAC/IP). In that case, include "notify_only" as the FIRST recommended action.
Schema:
{
  "overall_severity": "none|low|medium|high",
  "confidence": 0.0,
  "summary": "...",
  "top_findings": ["..."],
  "recommended_actions": [
    {"action": "...", "why": "..."}
  ]
}

Confidence:
- Output a numeric confidence in [0.0, 1.0] that reflects how likely it is this is a true positive.
- Use lower confidence for single weak signals and higher confidence for persistent/repeated strong signals.

ALERTS TEXT:
---
PROMPT
)
  prompt+="$(cat "$alerts_txt")\n"

  if [[ -f "$pending_json" ]]; then
    prompt+=$'\nPENDING VERIFICATION CODES (generated locally):\n---\n'
    prompt+="$(cat "$pending_json" 2>/dev/null || true)\n"
  fi

  # Build request JSON in Python (robust escaping).
  local payload
  payload=$(python3 -c 'import json,sys; model=sys.argv[1]; prompt=sys.stdin.read(); print(json.dumps({"model":model,"prompt":prompt,"stream":False,"options":{"temperature":0.1,"num_predict":400}}))' "$ollama_model" <<< "$prompt")

  # Call Ollama.
  local raw
  raw=$(curl -sS "$ollama_url/api/generate" -H 'Content-Type: application/json' -d "$payload" || true)

  # Extract JSON decision from Ollama response.
  python3 -c 'import json,sys; raw=sys.stdin.read().strip();
try:
  obj=json.loads(raw) if raw else None
except Exception:
  obj=None
if not obj:
  print(json.dumps({"error":"invalid_ollama_response","raw":raw}))
  raise SystemExit
resp=(obj.get("response") or "").strip()
try:
  decision=json.loads(resp)
except Exception:
  decision={"error":"model_did_not_return_json","response":resp}
print(json.dumps(decision, ensure_ascii=False))' <<< "$raw"
}

_sanitize_ai_decision() {
  python3 -c 'import json,sys
allowed={"notify_only","collect_more_evidence","recommend_pf_block","recommend_isolate_device","recommend_disable_port_forward","recommend_stop_service"}
raw=sys.stdin.read().strip()
try:
  obj=json.loads(raw)
except Exception:
  print(json.dumps({"error":"invalid_ai_json","raw":raw}))
  raise SystemExit

if not isinstance(obj, dict):
  print(json.dumps({"error":"invalid_ai_shape","raw":obj}))
  raise SystemExit

out={}
sev=obj.get("overall_severity")
if sev not in ("none","low","medium","high"):
  sev="none"
out["overall_severity"]=sev

conf=obj.get("confidence")
val=None
if isinstance(conf,(int,float)):
  val=float(conf)
elif isinstance(conf,str):
  try:
    val=float(conf.strip())
  except Exception:
    val=None
if val is None:
  # Backward-compatible default when models omit confidence.
  val={"none":0.1,"low":0.3,"medium":0.6,"high":0.85}.get(sev,0.1)
if val!=val or val==float("inf") or val==float("-inf"):
  val=0.0
if val<0.0: val=0.0
if val>1.0: val=1.0
out["confidence"]=round(val, 3)

summary=obj.get("summary")
out["summary"]=summary if isinstance(summary,str) else ""

tf=obj.get("top_findings")
if isinstance(tf,list):
  out["top_findings"]=[x for x in tf if isinstance(x,str)][:10]
else:
  out["top_findings"]=[]

ra=obj.get("recommended_actions")
san=[]
if isinstance(ra,list):
  for item in ra:
    if not isinstance(item, dict):
      continue
    action=item.get("action")
    why=item.get("why")
    if action not in allowed:
      continue
    if not isinstance(why,str):
      why=""
    san.append({"action": action, "why": why})
out["recommended_actions"]=san[:6]

print(json.dumps(out, ensure_ascii=False))'
}

# Minimal local (non-AI) responder: always notify, never changes system state.
_local_fallback_plan() {
  cat <<EOF
{"overall_severity":"$overall","confidence":0.1,"summary":"No AI decision (fallback).","top_findings":[],"recommended_actions":[{"action":"notify_only","why":"Fallback mode."}]} 
EOF
}

# Decide whether to call AI.
ai_decision=""
if [[ "${IRONDOME_OLLAMA_DISABLE:-0}" == "1" ]]; then
  ai_decision=$(_local_fallback_plan)
elif curl -sS "$ollama_url/api/tags" >/dev/null 2>&1; then
  ai_decision=$(_generate_ai_decision || true)
else
  ai_decision=$(_local_fallback_plan)
fi

# Sanitize model output to prevent arbitrary command injection.
ai_decision=$(_sanitize_ai_decision <<< "$ai_decision" || _local_fallback_plan)

# Floor AI severity to at least the detector's overall severity.
ai_decision=$(python3 -c 'import json,sys
floor=(sys.argv[1] or "none").strip().lower()
raw=sys.stdin.read().strip()
order={"none":0,"low":1,"medium":2,"high":3}
try:
  obj=json.loads(raw) if raw else {}
except Exception:
  obj={}
if not isinstance(obj, dict):
  obj={}
sev=str(obj.get("overall_severity") or "none").strip().lower()
if sev not in order: sev="none"
if floor not in order: floor="none"
if order[sev] < order[floor]:
  obj["overall_severity"]=floor
print(json.dumps(obj, ensure_ascii=False))
' "$overall" <<< "$ai_decision")

echo "$ai_decision" > "$ai_json"

pending_notice=""
if [[ -f "$pending_json" ]]; then
  pending_notice=$(python3 -c 'import json,sys
try:
  d=json.load(open(sys.argv[1],"r",encoding="utf-8"))
except Exception:
  d={}
items=d.get("pending") if isinstance(d,dict) else None
if isinstance(items,list) and items:
  it=items[0] if isinstance(items[0],dict) else {}
  code=str(it.get("code",""))
  name=str(it.get("name",""))
  if not name or name in ("?","(incomplete)"):
    name="Unknown device"
  msg=f"New device {name} code={code}".strip()
  print(msg)
' "$pending_json" 2>/dev/null || true)
fi

# Always notify on medium/high.
if [[ "$overall" == "high" ]]; then
  if [[ -n "$pending_notice" ]]; then
    _notify "Iron Dome: HIGH" "$pending_notice. See $actions_txt"
  else
    _notify "Iron Dome: HIGH" "Threat signals detected. See $actions_txt"
  fi
elif [[ "$overall" == "medium" ]]; then
  if [[ -n "$pending_notice" ]]; then
    _notify "Iron Dome: MEDIUM" "$pending_notice. See $actions_txt"
  else
    _notify "Iron Dome: MEDIUM" "Potential threat signals. See $actions_txt"
  fi
fi

# Persistence escalation (same alert repeating across runs).
persistence=$(_persistence_update || true)
persist_count=$(python3 -c 'import json,sys; print((json.loads(sys.stdin.read()) or {}).get("max_count",0))' <<< "$persistence" 2>/dev/null || echo 0)
persist_line=$(python3 -c 'import json,sys; print((json.loads(sys.stdin.read()) or {}).get("max_line",""))' <<< "$persistence" 2>/dev/null || echo "")

if [[ "$persist_count" -ge 3 && ( "$overall" == "medium" || "$overall" == "high" ) ]]; then
  _notify "Iron Dome: PERSISTENT" "Repeated threat signal ($persist_count runs). See $actions_txt"
fi

# Build actions report (what we did + what we'd do).
{
  echo "=== Iron Dome Actions ==="
  echo "time: $now_iso"
  echo "host: $host"
  echo "mode: $mode"
  echo "alerts: $alerts_txt"
  echo "ai_decision: $ai_json"
  echo
  echo "[note] This responder is safe-by-default. It does not run privileged remediation automatically."
  echo
} >> "$actions_txt"

# If we have pending guest verification codes, print them with clear next steps.
if [[ -f "$pending_json" ]]; then
  python3 - "$pending_json" "$actions_txt" <<'PY'
import json, sys
src, out = sys.argv[1], sys.argv[2]
try:
  data = json.load(open(src, 'r', encoding='utf-8'))
except Exception:
  data = {}
items = data.get('pending') if isinstance(data, dict) else None
if not isinstance(items, list) or not items:
  raise SystemExit(0)

lines = []
lines.append('[guest verification] pending new-device checks')
for it in items[:10]:
  if not isinstance(it, dict):
    continue
  code = it.get('code','')
  ip = it.get('ip','')
  mac = it.get('mac','')
  name = it.get('name','')
  lines.append(f"- code={code} ip={ip} mac={mac} name={name}")
lines.append('')
lines.append('[how to verify]')
lines.append('- If this is a friend: ask them to confirm the code shown above and the MAC in their Wi‑Fi/device details.')
lines.append('- If confirmed, allow it: /bin/zsh ~/.continue/scripts/irondome-allowlist.zsh add-mac <mac> "<label>"')
lines.append('- Or to allow everything currently connected (after checking Spectrum app): /bin/zsh ~/.continue/scripts/irondome-allowlist.zsh import-current /tmp/irondome')
lines.append('')

with open(out, 'a', encoding='utf-8') as f:
  f.write("\n".join(lines))
PY
fi

{
  echo "[persistence]"
  echo "state: $persistence_json"
  echo "max_repeats: $persist_count"
  if [[ -n "$persist_line" ]]; then
    echo "example: $persist_line"
  fi
  echo
} >> "$actions_txt"

# Render the AI JSON in a readable way without jq.
python3 - "$ai_json" "$actions_txt" <<'PY'
import json, sys
src, out = sys.argv[1], sys.argv[2]
try:
  data = json.load(open(src, 'r', encoding='utf-8'))
except Exception as e:
  data = {"error": "cannot_parse_ai_json", "detail": str(e)}

lines = []
lines.append("[ai] decision")
lines.append(json.dumps(data, ensure_ascii=False, indent=2))
lines.append("")

with open(out, 'a', encoding='utf-8') as f:
  f.write("\n".join(lines))
PY

# Optional: enforce mode for *non-privileged* actions only (currently none executed).
# We keep the framework here, but do not auto-run commands unless explicitly allowlisted.
if [[ "$mode" == "enforce" ]]; then
  if _is_allowed "notify_only"; then
    : # already notified
  fi

  # Optional safe enforcement: disable Wi-Fi on persistent medium/high.
  # This is defensive containment, not "hack back".
  if [[ "$persist_count" -ge 3 && ( "$overall" == "medium" || "$overall" == "high" ) ]] && _is_allowed "wifi_off"; then
    wifi_dev=$(/usr/sbin/networksetup -listallhardwareports 2>/dev/null | awk 'BEGIN{dev=""} /Hardware Port: (Wi-Fi|AirPort)/{getline; if ($1=="Device:") {print $2; exit}}')
    [[ -z "$wifi_dev" ]] && wifi_dev="en0"
    if /usr/sbin/networksetup -setairportpower "$wifi_dev" off >/dev/null 2>&1; then
      echo "[enforce] wifi_off executed on $wifi_dev" >> "$actions_txt"
      _notify "Iron Dome: ENFORCED" "Wi-Fi disabled ($wifi_dev) due to persistent threat signals."
    else
      echo "[enforce] wifi_off failed (may require admin). Recommended:" >> "$actions_txt"
      echo "  sudo /usr/sbin/networksetup -setairportpower $wifi_dev off" >> "$actions_txt"
    fi
  fi
fi

echo "[irondome] wrote $actions_txt"
