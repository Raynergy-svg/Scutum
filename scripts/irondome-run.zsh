#!/usr/bin/env zsh
set -euo pipefail

# Orchestrator: scan -> detect -> respond
# Usage:
#   irondome-run.zsh [workdir]

workdir=${1:-/tmp/irondome}
mkdir -p "$workdir"

script_dir=$(cd "$(dirname "$0")" && pwd)

/bin/zsh "$script_dir/irondome-scan.zsh" "$workdir"
/bin/zsh "$script_dir/irondome-detect.zsh" "$workdir" "$workdir/irondome-latest.txt"
/bin/zsh "$script_dir/irondome-respond.zsh" "$workdir"
/bin/zsh "$script_dir/irondome-spectrum-playbook.zsh" "$workdir"
/bin/zsh "$script_dir/irondome-dossier.zsh" "$workdir" || true
