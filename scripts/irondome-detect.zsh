#!/usr/bin/env zsh
set -euo pipefail

# Usage:
#   irondome-detect.zsh <workdir> <evidence_file>
# Outputs:
#   <workdir>/alerts-latest.txt
#   <workdir>/alerts-latest.jsonl

workdir=${1:-/tmp/irondome}
evidence_file=${2:-"$workdir/irondome-latest.txt"}
mkdir -p "$workdir"

alerts_txt="$workdir/alerts-latest.txt"
alerts_jsonl="$workdir/alerts-latest.jsonl"

now_epoch=$(date +%s)
now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
host=$(scutil --get ComputerName 2>/dev/null || hostname)

baseline="$workdir/network-baseline.txt"
current="$workdir/network-current.txt"

allowlist_path=${IRONDOME_ALLOWLIST:-$HOME/.continue/data/irondome/allowlist.json}
pending_json="$workdir/pending-verifications.json"
mkdir -p "$(dirname "$allowlist_path")"

# Ensure ARP snapshots exist.
if [[ ! -f "$baseline" ]]; then
  arp -a | sort > "$baseline" || true
fi
arp -a | sort > "$current" || true

# Helper: emit alert to both txt and jsonl.
_emit_alert() {
  local severity="$1"; shift
  local kind="$1"; shift
  local message="$1"; shift
  local evidence="$1"; shift

  {
    echo "[$now_iso] severity=$severity kind=$kind msg=$message"
    if [[ -n "$evidence" ]]; then
      echo "  evidence: $evidence"
    fi
  } >> "$alerts_txt"

  # JSONL (no jq dependency; use python to escape strings)
  python3 - <<'PY' "$alerts_jsonl" "$now_iso" "$host" "$severity" "$kind" "$message" "$evidence"
import json, sys
out, ts, host, severity, kind, message, evidence = sys.argv[1:]
rec = {
  "time": ts,
  "host": host,
  "severity": severity,
  "kind": kind,
  "message": message,
  "evidence": evidence,
}
with open(out, "a", encoding="utf-8") as f:
  f.write(json.dumps(rec, ensure_ascii=False) + "\n")
PY
}

# Start fresh each run.
: > "$alerts_txt"
: > "$alerts_jsonl"
{
  echo "=== Iron Dome Alerts ==="
  echo "time: $now_iso"
  echo "host: $host"
  echo "evidence_file: $evidence_file"
  echo
} >> "$alerts_txt"

# 1) New LAN devices (ARP diff)
arp_diff=$(diff -u "$baseline" "$current" || true)
if echo "$arp_diff" | grep -qE '^\+[^+]' ; then
  # Identify this Mac on Wi‑Fi so we don't flag ourselves as a "new device".
  wifi_dev=$(networksetup -listallhardwareports 2>/dev/null | awk 'BEGIN{dev=""} /Hardware Port: (Wi-Fi|AirPort)/{getline; if ($1=="Device:") {print $2; exit}}')
  [[ -z "$wifi_dev" ]] && wifi_dev="en0"
  self_mac=$(/usr/sbin/networksetup -getmacaddress "$wifi_dev" 2>/dev/null | awk '{print $3}' | tr '[:upper:]' '[:lower:]' || true)
  self_ip=$(/usr/sbin/ipconfig getifaddr "$wifi_dev" 2>/dev/null || true)

  # Extract added lines (skip +++ header)
  new_lines=$(echo "$arp_diff" | awk '/^\+[^+]/ {print $0}' | head -50)
  new_lines=$(python3 -c 'import sys
self_mac=(sys.argv[1] or "").strip().lower()
self_ip=(sys.argv[2] or "").strip()
raw=sys.stdin.read().splitlines()
out=[]
for line in raw:
  l=line.lower()
  if self_mac and self_mac in l:
    continue
  if self_ip and (f"({self_ip})" in line):
    continue
  out.append(line)
sys.stdout.write("\n".join(out))
' "$self_mac" "$self_ip" <<< "$new_lines" || true)

  # Filter out allowlisted devices and generate verification codes for unknown devices.
  new_lines=$(python3 -c 'import json, os, re, sys, time, random

allowlist_path=sys.argv[1]
pending_path=sys.argv[2]
raw=sys.stdin.read().splitlines()

now=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
expiry_seconds=2*60*60

def load_json(path, default):
  try:
    with open(path, "r", encoding="utf-8") as f:
      obj=json.load(f)
    return obj if isinstance(obj, dict) else default
  except Exception:
    return default

def save_json(path, obj):
  os.makedirs(os.path.dirname(path), exist_ok=True)
  tmp=path+".tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(obj, f, ensure_ascii=False, indent=2)
  os.replace(tmp, path)

allow=load_json(allowlist_path, {})
allowed_macs=set(m.lower() for m in (allow.get("allowed_macs") or []) if isinstance(m, str))
allowed_ips=set(ip for ip in (allow.get("allowed_ips") or []) if isinstance(ip, str))

pending=load_json(pending_path, {"pending": []})
items=pending.get("pending") if isinstance(pending.get("pending"), list) else []

now_epoch=int(time.time())
kept=[]
for it in items:
  if not isinstance(it, dict):
    continue
  last=int(it.get("last_seen_epoch") or it.get("first_seen_epoch") or 0)
  if last and (now_epoch - last) > expiry_seconds:
    continue
  kept.append(it)
items=kept

def find_existing(mac, ip):
  for it in items:
    if mac and (it.get("mac") or "").lower()==mac.lower():
      return it
    if ip and (it.get("ip") or "")==ip:
      return it
  return None

line_re=re.compile(r"^\+?(?P<name>[^\s]+|\?)\s*\((?P<ip>(\d{1,3}\.){3}\d{1,3})\)\s+at\s+(?P<mac>(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b", re.I)

out_lines=[]
unknown_count=0
for line in raw:
  m=line_re.search(line.strip())
  if not m:
    # Keep unparsable lines as evidence, but they will not get a code.
    out_lines.append(line)
    continue
  name=m.group("name")
  ip=m.group("ip")
  mac_raw=m.group("mac").lower()
  parts=mac_raw.split(":")
  mac=":".join((p or "").zfill(2) for p in parts) if len(parts)==6 else mac_raw

  if mac in allowed_macs or ip in allowed_ips:
    continue

  unknown_count += 1
  out_lines.append(line)

  ex=find_existing(mac, ip)
  if ex:
    ex["last_seen"]=now
    ex["last_seen_epoch"]=now_epoch
    ex.setdefault("name", name)
    ex.setdefault("ip", ip)
    ex.setdefault("mac", mac)
    continue

  code=str(random.randint(100000, 999999))
  items.append({
    "code": code,
    "name": "" if name in ("?", "(incomplete)") else name,
    "ip": ip,
    "mac": mac,
    "first_seen": now,
    "last_seen": now,
    "first_seen_epoch": now_epoch,
    "last_seen_epoch": now_epoch,
    "status": "pending"
  })

pending={"updated_at": now, "pending": items}
save_json(pending_path, pending)

sys.stdout.write("\n".join(out_lines))
' "$allowlist_path" "$pending_json" <<< "$new_lines" || true)

  if [[ -n "$new_lines" ]]; then
    _emit_alert "medium" "new_device" "New device(s) appeared on LAN (ARP diff vs baseline)" "$new_lines"
  fi
fi

# 2) Suspicious auth-ish log keywords already included in evidence file
if [[ -f "$evidence_file" ]]; then
  # Simple counters
  failed_count=$(grep -Eic 'failed password|authentication failure|login failed' "$evidence_file" 2>/dev/null || echo 0)
  # Note: macOS/BSD grep does not reliably support \b word boundaries.
  deny_count=$(grep -Eic 'deny|blocked|pf:|drop' "$evidence_file" 2>/dev/null || echo 0)

  # Normalize counts to digits-only (avoid zsh numeric compare errors)
  failed_count=${failed_count//[^0-9]/}
  deny_count=${deny_count//[^0-9]/}
  [[ -z "$failed_count" ]] && failed_count=0
  [[ -z "$deny_count" ]] && deny_count=0

  if [[ "$failed_count" -ge 5 ]]; then
    sample=$(grep -Ein 'failed password|authentication failure|login failed' "$evidence_file" | tail -5 | sed 's/\t/ /g')
    _emit_alert "high" "auth_bruteforce" "Possible brute-force/auth failures (>=5 in last scan window)" "$sample"
  elif [[ "$failed_count" -ge 1 ]]; then
    sample=$(grep -Ein 'failed password|authentication failure|login failed' "$evidence_file" | tail -3 | sed 's/\t/ /g')
    _emit_alert "low" "auth_failure" "Some auth failures observed" "$sample"
  fi

  if [[ "$deny_count" -ge 10 ]]; then
    sample=$(grep -Ein '\bdeny\b|blocked|pf:|drop' "$evidence_file" | tail -5 | sed 's/\t/ /g')
    _emit_alert "medium" "blocked_events" "Many deny/blocked/drop events observed" "$sample"
  fi
fi

# 3) Unexpected listeners: compare lsof output lines to an allowlist of ports.
# Allowlist is conservative: 11434 (ollama), 22 (ssh), 80/443 (web), 5353 (mDNS), 53 (dns), 631 (ipp).
allow_ports_re=':(22|53|80|443|631|5353|11434)\b'
listeners=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true)
if [[ -n "$listeners" ]]; then
  # Only care about listeners exposed beyond localhost (wildcard, non-loopback).
  exposed=$(echo "$listeners" | egrep -E 'TCP \*:\d+ \(LISTEN\)|TCP \[::\]:\d+ \(LISTEN\)|TCP ([0-9]{1,3}\.){3}[0-9]{1,3}:\d+ \(LISTEN\)' \
    | egrep -v 'TCP (127\.0\.0\.1|\[::1\])' \
    || true)
  # Ignore known macOS daemons that commonly listen on high ports.
  exposed=$(echo "$exposed" | egrep -vi '^(rapportd|sharingd|ControlCe|ControlCenter|AirPlay|Bonjour|mDNSResponder)\b' || true)

  unexpected=$(echo "$exposed" | egrep -v "$allow_ports_re" | head -25 || true)
  if [[ -n "$unexpected" ]]; then
    _emit_alert "medium" "unexpected_listener" "Unexpected listening TCP ports detected (outside allowlist)" "$unexpected"
  fi
fi

# Summary line
sev_rank() {
  case "$1" in
    high) echo 3;;
    medium) echo 2;;
    low) echo 1;;
    *) echo 0;;
  esac
}
max_sev="none"
max_rank=0
while read -r line; do
  sev=$(echo "$line" | sed -n 's/.*severity=\([a-z]*\).*/\1/p')
  r=$(sev_rank "$sev")
  if [[ "$r" -gt "$max_rank" ]]; then
    max_rank="$r"
    max_sev="$sev"
  fi
done < <(grep -E '^\[.*\] severity=' "$alerts_txt" 2>/dev/null || true)

echo >> "$alerts_txt"
echo "overall_severity: $max_sev" >> "$alerts_txt"

echo "[irondome] wrote $alerts_txt"
