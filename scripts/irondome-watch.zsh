#!/usr/bin/env zsh
set -euo pipefail

interval_sec=${1:-60}
workdir=${2:-/tmp/irondome}
mkdir -p "$workdir"

baseline="$workdir/network-baseline.txt"

if [[ ! -f "$baseline" ]]; then
  arp -a | sort > "$baseline"
fi

echo "[irondome] interval=${interval_sec}s workdir=$workdir"
echo "[irondome] baseline=$baseline"

while true; do
  ts=$(date +%s)
  out="$workdir/irondome-$ts.txt"
  {
    echo "=== Iron Dome Buddy (macOS) ==="
    echo "time: $(date -u +\"%Y-%m-%dT%H:%M:%SZ\")"
    echo

    echo "[network] arp diff vs baseline"
    cur="$workdir/network-current.txt"
    arp -a | sort > "$cur"
    diff -u "$baseline" "$cur" || true
    echo

    echo "[host] listeners on common ports"
    lsof -nP -iTCP -sTCP:LISTEN | egrep ':(22|80|443|11434)\b' || true
    echo

    echo "[logs] recent system.log lines"
    tail -n 80 /var/log/system.log || true
    echo

    echo "[logs] unified log quick scan (last 10m)"
    log show --style syslog --last 10m --predicate 'eventMessage CONTAINS[c] "deny" OR eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "invalid" OR eventMessage CONTAINS[c] "blocked" OR eventMessage CONTAINS[c] "ssh"' | tail -120 || true
  } > "$out"

  cp -f "$out" "$workdir/irondome-latest.txt"

  echo "[irondome] wrote $out"
  sleep "$interval_sec"
done
