#!/usr/bin/env zsh
set -euo pipefail

# Manage allowed devices for Iron Dome.
#
# Usage:
#   irondome-allowlist.zsh [list]
#   irondome-allowlist.zsh add-mac <mac> [label]
#   irondome-allowlist.zsh add-ip <ip> [label]
#   irondome-allowlist.zsh import-current <workdir>
#
# Env:
#   IRONDOME_ALLOWLIST (default: ~/.continue/data/irondome/allowlist.json)

cmd=${1:-list}
shift || true

allowlist_path=${IRONDOME_ALLOWLIST:-$HOME/.continue/data/irondome/allowlist.json}
mkdir -p "$(dirname "$allowlist_path")"

python3 - "$cmd" "$allowlist_path" "$@" <<'PY'
import json, os, re, sys, time

cmd = sys.argv[1]
path = sys.argv[2]
args = sys.argv[3:]

now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def load():
  try:
    with open(path, 'r', encoding='utf-8') as f:
      obj = json.load(f)
    if not isinstance(obj, dict):
      return {}
    return obj
  except Exception:
    return {}


def save(obj):
  tmp = path + '.tmp'
  with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(obj, f, ensure_ascii=False, indent=2)
  os.replace(tmp, path)


def norm_mac(mac: str) -> str:
  mac = (mac or '').strip().lower()
  mac = mac.replace('-', ':')
  parts = mac.split(':')
  if len(parts) != 6:
    return ''
  if not all(re.fullmatch(r'[0-9a-f]{1,2}', p or '') for p in parts):
    return ''
  return ':'.join((p or '').zfill(2) for p in parts)


def norm_ip(ip: str) -> str:
  ip = (ip or '').strip()
  if re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', ip):
    return ip
  return ''


def ensure_shape(obj):
  obj.setdefault('updated_at', now)
  obj.setdefault('source', 'manual')
  obj.setdefault('allowed_macs', [])
  obj.setdefault('allowed_ips', [])
  obj.setdefault('labels', {})
  if not isinstance(obj['allowed_macs'], list):
    obj['allowed_macs'] = []
  if not isinstance(obj['allowed_ips'], list):
    obj['allowed_ips'] = []
  if not isinstance(obj['labels'], dict):
    obj['labels'] = {}
  return obj


def uniq(seq):
  seen = set()
  out = []
  for x in seq:
    if x in seen:
      continue
    seen.add(x)
    out.append(x)
  return out


def cmd_list():
  obj = ensure_shape(load())
  print(f'allowlist: {path}')
  print(f'updated_at: {obj.get("updated_at","") }')
  print(f'source: {obj.get("source","") }')
  print('')
  if obj['allowed_macs']:
    print('[allowed_macs]')
    for m in obj['allowed_macs']:
      label = obj['labels'].get(m, '')
      print(f'- {m}' + (f' ({label})' if label else ''))
    print('')
  if obj['allowed_ips']:
    print('[allowed_ips]')
    for ip in obj['allowed_ips']:
      label = obj['labels'].get(ip, '')
      print(f'- {ip}' + (f' ({label})' if label else ''))
    print('')


def cmd_add_mac():
  if not args:
    raise SystemExit('missing mac')
  mac = norm_mac(args[0])
  if not mac:
    raise SystemExit('invalid mac')
  label = ' '.join(args[1:]).strip()
  obj = ensure_shape(load())
  obj['allowed_macs'] = uniq(obj['allowed_macs'] + [mac])
  if label:
    obj['labels'][mac] = label
  obj['updated_at'] = now
  obj['source'] = obj.get('source') or 'manual'
  save(obj)
  print(f'added mac: {mac}')


def cmd_add_ip():
  if not args:
    raise SystemExit('missing ip')
  ip = norm_ip(args[0])
  if not ip:
    raise SystemExit('invalid ip')
  label = ' '.join(args[1:]).strip()
  obj = ensure_shape(load())
  obj['allowed_ips'] = uniq(obj['allowed_ips'] + [ip])
  if label:
    obj['labels'][ip] = label
  obj['updated_at'] = now
  obj['source'] = obj.get('source') or 'manual'
  save(obj)
  print(f'added ip: {ip}')


def cmd_import_current():
  if not args:
    raise SystemExit('missing workdir')
  workdir = args[0]
  cur = os.path.join(workdir, 'network-current.txt')
  if not os.path.exists(cur):
    raise SystemExit(f'missing {cur} (run irondome-scan first)')

  macs = []
  ips = []
  labels = {}

  # ARP lines like: name (192.168.1.141) at aa:bb:... on en0 ...
  line_re = re.compile(r'^(?P<name>[^\s]+|\?)\s*\((?P<ip>(\d{1,3}\.){3}\d{1,3})\)\s+at\s+(?P<mac>(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b', re.I)
  with open(cur, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
      line = line.strip()
      m = line_re.search(line)
      if not m:
        continue
      ip = m.group('ip')
      mac = norm_mac(m.group('mac'))
      name = m.group('name')
      if mac == '(incomplete)'.lower():
        continue
      macs.append(mac)
      ips.append(ip)
      if name and name != '?' and name != '(incomplete)':
        labels[mac] = name

  obj = ensure_shape(load())
  obj['allowed_macs'] = uniq(obj['allowed_macs'] + macs)
  obj['allowed_ips'] = uniq(obj['allowed_ips'] + ips)
  obj['labels'].update(labels)
  obj['updated_at'] = now
  obj['source'] = 'arp_snapshot_confirmed_in_spectrum'
  save(obj)
  print(f'imported {len(set(macs))} mac(s) and {len(set(ips))} ip(s) from {cur}')


if cmd == 'list':
  cmd_list()
elif cmd == 'add-mac':
  cmd_add_mac()
elif cmd == 'add-ip':
  cmd_add_ip()
elif cmd == 'import-current':
  cmd_import_current()
else:
  raise SystemExit('unknown command')
PY
