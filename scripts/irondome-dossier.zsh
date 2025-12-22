#!/usr/bin/env zsh
set -euo pipefail

# Create a comprehensive suspect dossier from *real* local evidence.
#
# Usage:
#   irondome-dossier.zsh <workdir>
#
# Inputs (best-effort):
#   <workdir>/irondome-latest.txt
#   <workdir>/alerts-latest.txt
#   <workdir>/alerts-latest.jsonl
#   <workdir>/actions-latest.txt
#   <workdir>/ai-decision-latest.json
#   <workdir>/persistence.json
#   <workdir>/spectrum-playbook-latest.txt
#   <workdir>/spectrum-playbook-latest.json
#
# Outputs:
#   <workdir>/suspects/dossier-<epoch>.txt
#   <workdir>/suspects/dossier-<epoch>.json
#   <workdir>/dossier-latest.txt
#   <workdir>/dossier-latest.json
#
# Environment:
#   IRONDOME_DOSSIER_FORCE=1 (generate even if severity is none/low)
#   IRON_DOME_ROUTER_MODEL (default SBE1V1K)

workdir=${1:-/tmp/irondome}
mkdir -p "$workdir"

force=${IRONDOME_DOSSIER_FORCE:-0}
router_model=${IRON_DOME_ROUTER_MODEL:-SBE1V1K}

alerts_txt="$workdir/alerts-latest.txt"
persistence_json="$workdir/persistence.json"

# Determine whether to generate (medium/high or persistent repeats >= 3 or force).
overall="none"
if [[ -f "$alerts_txt" ]]; then
  overall=$(grep -E '^overall_severity:' "$alerts_txt" | awk '{print $2}' || true)
  [[ -z "$overall" ]] && overall="none"
fi

repeats=0
if [[ -f "$persistence_json" ]]; then
  repeats=$(python3 -c 'import json,sys; 
try:
  s=json.load(open(sys.argv[1],"r",encoding="utf-8"))
  mx=0
  for rec in (s.get("by_id") or {}).values():
    try: mx=max(mx,int(rec.get("count") or 0))
    except: pass
  print(mx)
except Exception:
  print(0)
' "$persistence_json" 2>/dev/null || echo 0)
fi

should=0
if [[ "$force" == "1" ]]; then
  should=1
elif [[ "$overall" == "medium" || "$overall" == "high" ]]; then
  should=1
elif [[ "$repeats" -ge 3 ]]; then
  should=1
fi

if [[ "$should" != "1" ]]; then
  echo "[irondome] dossier not generated (overall=$overall repeats=$repeats). Set IRONDOME_DOSSIER_FORCE=1 to force." >&2
  exit 0
fi

outdir="$workdir/suspects"
mkdir -p "$outdir"

ts=$(date +%s)
now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
host=$(scutil --get ComputerName 2>/dev/null || hostname)
user=$(whoami)

out_txt="$outdir/dossier-$ts.txt"
out_json="$outdir/dossier-$ts.json"

# Build dossier via Python (hashes, parsing, and report assembly)
python3 - "$workdir" "$router_model" "$now_iso" "$host" "$user" "$overall" "$repeats" "$out_txt" "$out_json" <<'PY'
import hashlib, json, os, re, subprocess, sys, textwrap

workdir, router_model, now_iso, host, user, overall, repeats, out_txt, out_json = sys.argv[1:]
repeats = int(repeats)

def read_file(path, max_bytes=None):
  try:
    with open(path, 'rb') as f:
      data = f.read() if max_bytes is None else f.read(max_bytes)
    return data
  except Exception:
    return None

def sha256_file(path):
  try:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
      for chunk in iter(lambda: f.read(1024 * 1024), b''):
        h.update(chunk)
    return h.hexdigest()
  except Exception:
    return None

def stat_file(path):
  try:
    st = os.stat(path)
    return {"path": path, "size": st.st_size, "mtime": st.st_mtime}
  except Exception:
    return {"path": path, "size": None, "mtime": None}

def run_cmd(cmd):
  try:
    p = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=20)
    out = p.stdout.strip()
    err = p.stderr.strip()
    return {
      "cmd": cmd,
      "returncode": p.returncode,
      "stdout": out[:20000],
      "stderr": err[:20000],
    }
  except Exception as e:
    return {"cmd": cmd, "error": str(e)}

paths = {
  "evidence": os.path.join(workdir, "irondome-latest.txt"),
  "alerts_txt": os.path.join(workdir, "alerts-latest.txt"),
  "alerts_jsonl": os.path.join(workdir, "alerts-latest.jsonl"),
  "actions_txt": os.path.join(workdir, "actions-latest.txt"),
  "ai_json": os.path.join(workdir, "ai-decision-latest.json"),
  "persistence_json": os.path.join(workdir, "persistence.json"),
  "spectrum_playbook_txt": os.path.join(workdir, "spectrum-playbook-latest.txt"),
  "spectrum_playbook_json": os.path.join(workdir, "spectrum-playbook-latest.json"),
}

# Extract indicators from alerts JSONL if available.
indicators = {"ips": set(), "macs": set(), "hostnames": set()}
alerts_records = []
if os.path.exists(paths["alerts_jsonl"]):
  for line in open(paths["alerts_jsonl"], 'r', encoding='utf-8', errors='replace'):
    line=line.strip()
    if not line:
      continue
    try:
      rec=json.loads(line)
      alerts_records.append(rec)
      ev = str(rec.get('evidence',''))
      # IP
      for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', ev):
        indicators['ips'].add(ip)
      # MAC (accept 1-2 hex-digit octets, then normalize)
      for mac in re.findall(r'\b((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b', ev, re.I):
        parts = mac.lower().split(':')
        norm = ':'.join(p.zfill(2) for p in parts) if len(parts) == 6 else mac.lower()
        indicators['macs'].add(norm)
      # hostname-ish
      for hn in re.findall(r'\b([a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)\b', ev):
        indicators['hostnames'].add(hn)
    except Exception:
      continue
else:
  # Best effort: parse from alerts_txt
  if os.path.exists(paths["alerts_txt"]):
    txt=open(paths["alerts_txt"], 'r', encoding='utf-8', errors='replace').read()
    for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', txt):
      indicators['ips'].add(ip)
    for mac in re.findall(r'\b((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b', txt, re.I):
      parts = mac.lower().split(':')
      norm = ':'.join(p.zfill(2) for p in parts) if len(parts) == 6 else mac.lower()
      indicators['macs'].add(norm)

# Pull device list from Spectrum playbook JSON (if present).
new_devices = []
if os.path.exists(paths["spectrum_playbook_json"]):
  try:
    pb=json.load(open(paths["spectrum_playbook_json"], 'r', encoding='utf-8'))
    for d in pb.get('new_devices', [])[:50]:
      new_devices.append(d)
      if 'ip' in d: indicators['ips'].add(d['ip'])
      if 'mac' in d: indicators['macs'].add(str(d['mac']).lower())
      if 'name' in d and d['name']: indicators['hostnames'].add(d['name'])
  except Exception:
    pass

# Evidence files metadata + hashes
files = []
for key, path in paths.items():
  rec = stat_file(path)
  rec['key'] = key
  if rec['size'] is not None:
    rec['sha256'] = sha256_file(path)
  else:
    rec['sha256'] = None
  files.append(rec)

# Capture small additional context snapshots (best effort, no sudo)
context_cmds = [
  ["sw_vers"],
  ["uname", "-a"],
  ["ifconfig", "-a"],
  ["arp", "-a"],
  ["netstat", "-anv"],
  ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
  ["log", "show", "--style", "syslog", "--last", "1h", "--predicate", 'eventMessage CONTAINS[c] "deny" OR eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "invalid" OR eventMessage CONTAINS[c] "blocked" OR eventMessage CONTAINS[c] "ssh"'],
]
cmd_outputs = [run_cmd(c) for c in context_cmds]

# Dossier JSON (authorities-friendly structure)
dossier = {
  "time": now_iso,
  "host": host,
  "user": user,
  "router_model": router_model,
  "trigger": {
    "overall_severity": overall,
    "persistence_max_repeats": repeats,
  },
  "indicators": {
    "ips": sorted(indicators['ips']),
    "macs": sorted(indicators['macs']),
    "hostnames": sorted(indicators['hostnames']),
    "new_devices": new_devices,
  },
  "evidence_files": files,
  "context": {
    "commands": cmd_outputs,
  },
  "notes": [
    "This dossier is generated from local evidence files and command outputs.",
    "Any AI analysis (if present in actions/ai-decision files) is advisory and derived from the alerts, not an independent forensic source.",
  ],
}

# Write JSON
os.makedirs(os.path.dirname(out_json), exist_ok=True)
with open(out_json, 'w', encoding='utf-8') as f:
  json.dump(dossier, f, ensure_ascii=False, indent=2)

# Write human-readable TXT
lines = []
lines.append("=== Iron Dome Suspect Dossier ===")
lines.append(f"time: {now_iso}")
lines.append(f"host: {host}")
lines.append(f"user: {user}")
lines.append(f"router_model: {router_model}")
lines.append(f"trigger.overall_severity: {overall}")
lines.append(f"trigger.persistence_max_repeats: {repeats}")
lines.append("")

lines.append("[indicators]")
if dossier['indicators']['ips']:
  lines.append("- IPs:")
  lines.extend([f"  - {ip}" for ip in dossier['indicators']['ips']])
if dossier['indicators']['macs']:
  lines.append("- MACs:")
  lines.extend([f"  - {m}" for m in dossier['indicators']['macs']])
if dossier['indicators']['hostnames']:
  lines.append("- Hostnames:")
  lines.extend([f"  - {h}" for h in dossier['indicators']['hostnames']])
if new_devices:
  lines.append("- New devices (from Spectrum playbook):")
  for d in new_devices[:25]:
    lines.append(f"  - name={d.get('name','')} ip={d.get('ip','')} mac={d.get('mac','')}")
lines.append("")

lines.append("[evidence_files]")
for fmeta in files:
  lines.append(f"- {fmeta['key']}: {fmeta['path']}")
  lines.append(f"  size: {fmeta['size']}")
  lines.append(f"  sha256: {fmeta['sha256']}")
lines.append("")

lines.append("[context_snapshots]")
for c in cmd_outputs:
  cmd = ' '.join(c.get('cmd', []))
  lines.append(f"== $ {cmd}")
  if 'error' in c:
    lines.append(f"error: {c['error']}")
  else:
    if c.get('stdout'):
      lines.append(c['stdout'])
    if c.get('stderr'):
      lines.append("-- stderr --")
      lines.append(c['stderr'])
  lines.append("")

# Append core evidence tails for convenience
append_paths = [
  ("alerts", paths['alerts_txt']),
  ("actions", paths['actions_txt']),
  ("spectrum_playbook", paths['spectrum_playbook_txt']),
  ("evidence", paths['evidence']),
]
lines.append("[evidence_excerpts]")
for name, path in append_paths:
  lines.append(f"== {name}: {path}")
  if os.path.exists(path):
    txt = open(path, 'r', encoding='utf-8', errors='replace').read().splitlines()
    excerpt = "\n".join(txt[-220:])
    lines.append(excerpt)
  else:
    lines.append("(missing)")
  lines.append("")

with open(out_txt, 'w', encoding='utf-8') as f:
  f.write("\n".join(lines))

PY

# Update latest pointers
cp -f "$out_txt" "$workdir/dossier-latest.txt"
cp -f "$out_json" "$workdir/dossier-latest.json"

echo "[irondome] wrote $out_txt"
