#!/usr/bin/env zsh
set -euo pipefail

# Generate a concrete containment playbook for Spectrum/Charter router workflows.
# Usage:
#   irondome-spectrum-playbook.zsh <workdir>
# Inputs:
#   <workdir>/alerts-latest.txt
#   <workdir>/persistence.json (optional)
# Outputs:
#   <workdir>/spectrum-playbook-latest.txt
#   <workdir>/spectrum-playbook-latest.json

workdir=${1:-/tmp/irondome}
mkdir -p "$workdir"

alerts_txt="$workdir/alerts-latest.txt"
persistence_json="$workdir/persistence.json"
out_txt="$workdir/spectrum-playbook-latest.txt"
out_json="$workdir/spectrum-playbook-latest.json"

router_model=${IRON_DOME_ROUTER_MODEL:-SBE1V1K}

python3 - "$alerts_txt" "$persistence_json" "$router_model" "$out_json" <<'PY' > "$out_txt"
import json, os, re, sys, time

alerts_path, persistence_path, router_model, out_json = sys.argv[1:]

now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

alerts = open(alerts_path, 'r', encoding='utf-8', errors='replace').read() if os.path.exists(alerts_path) else ''

# overall severity
m = re.search(r'^overall_severity:\s*(\w+)', alerts, re.M)
overall = m.group(1) if m else 'none'

# extract new devices evidence block (best-effort)
new_devices = []
# lines like: +? (192.168.1.69) at 20:1b:a5:1:96:9a on en0 ...
for line in alerts.splitlines():
    if line.strip().startswith('evidence:'):
        continue
    if '(192.' in line or '(10.' in line or '(172.' in line:
        ipm = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
        macm = re.search(r'\bat\s+((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b', line, re.I)
        hostm = re.search(r'^\+?([^\s]+)\s*\(\d+\.\d+\.\d+\.\d+\)', line)
        if ipm and macm:
            parts = macm.group(1).lower().split(':')
            mac = ':'.join(p.zfill(2) for p in parts) if len(parts) == 6 else macm.group(1).lower()
            new_devices.append({
                'ip': ipm.group(1),
                'mac': mac,
                'name': hostm.group(1) if hostm else ''
            })

# persistence info
persist = {"max_repeats": 0, "example": ""}
if os.path.exists(persistence_path):
    try:
        state = json.load(open(persistence_path, 'r', encoding='utf-8'))
        max_rec = max(state.get('by_id', {}).values(), key=lambda r: int(r.get('count', 0)), default=None)
        if max_rec:
            persist['max_repeats'] = int(max_rec.get('count', 0))
            persist['example'] = max_rec.get('line', '')
    except Exception:
        pass

# produce playbook
steps = []

# Always: confirm it's not your device
if new_devices:
    steps.append({
        "priority": "P0",
        "title": "Confirm unknown device(s)",
        "details": [
            "Open Spectrum app → Internet → Router → Connected Devices.",
            "Match by IP/MAC below. If it is yours, rename it so Iron Dome stops flagging it.",
            "If unknown: Pause/Block it immediately (wording varies)."
        ],
    })

# Aggressive containment guidance
if overall in ('medium','high'):
    steps.append({
        "priority": "P0",
        "title": "Containment (Spectrum router)",
        "details": [
            "Pause/Block the unknown device(s) in Connected Devices.",
            "Rotate Wi‑Fi password (forces all clients to re-auth).",
            "Disable WPS and UPnP (if the app exposes these toggles).",
            "Remove any Port Forwarding / Remote Management settings.",
            "Move IoT devices to Guest Wi‑Fi (enable client isolation if available)."
        ],
    })

# Escalation if persistent
if persist['max_repeats'] >= 3 and overall in ('medium','high'):
    steps.append({
        "priority": "P0",
        "title": "Escalation (persistence detected)",
        "details": [
            f"Same alert repeated {persist['max_repeats']} runs.",
            "Temporarily pause all unknown devices.",
            "Consider changing admin password for the router account in Spectrum app.",
            "If issues persist: consider replacing the Spectrum router with a router that supports VLAN/quarantine automation (UniFi/Omada/etc)."
        ],
    })

# Endpoint checks
steps.append({
    "priority": "P1",
    "title": "Endpoint verification (Mac/iPhone)",
    "details": [
        "Mac: System Settings → Privacy & Security → Camera/Microphone (review app access).",
        "Mac: System Settings → General → Login Items (remove unknown).",
        "iPhone: Settings → Privacy & Security → Camera/Mic + Local Network permissions.",
        "Keep OS updates current."
    ],
})

# Write JSON for automation
playbook = {
    "time": now,
    "router_model": router_model,
    "overall_severity": overall,
    "new_devices": new_devices,
    "persistence": persist,
    "steps": steps,
}
try:
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(playbook, f, ensure_ascii=False, indent=2)
except Exception:
    pass

# Human-readable output
print(f"=== Spectrum Containment Playbook ({router_model}) ===")
print(f"time: {now}")
print(f"overall_severity: {overall}")
print(f"persistence_max_repeats: {persist['max_repeats']}")
print("")

if new_devices:
    print("[suspects] new/unknown LAN devices")
    for d in new_devices[:25]:
        label = d['name'] + ' ' if d.get('name') else ''
        print(f"- {label}ip={d['ip']} mac={d['mac']}")
    print("")

print("[steps]")
for s in steps:
    print(f"- {s['priority']}: {s['title']}")
    for line in s['details']:
        print(f"  - {line}")

PY

echo "[irondome] wrote $out_txt"
