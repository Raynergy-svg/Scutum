#!/usr/bin/env zsh
set -euo pipefail

# Installs + (re)loads the Buddy LaunchAgent for the current user.
# Uses the modern launchctl bootstrap/bootout flow.

root_dir=$(cd "$(dirname "$0")/.." && pwd)
plist_src="$root_dir/launchd/com.irondome.buddy.plist"
plist_dst="$HOME/Library/LaunchAgents/com.irondome.buddy.plist"
uidn="$(id -u)"
label="com.irondome.buddy"

mkdir -p "$HOME/Library/LaunchAgents"
cp -f "$plist_src" "$plist_dst"

# launchd plists require absolute paths. Patch ProgramArguments to this install location.
/usr/bin/plutil -replace ProgramArguments.3 -string "$root_dir/scripts/irondome-daemon.zsh" "$plist_dst" >/dev/null

plutil -lint "$plist_dst" >/dev/null

# Best-effort unload (bootout may return 5 if not loaded; ignore)
launchctl bootout "gui/$uidn" "$plist_dst" >/dev/null 2>&1 || true

# Load + start
launchctl bootstrap "gui/$uidn" "$plist_dst" >/dev/null 2>&1 || true
launchctl enable "gui/$uidn/$label" >/dev/null 2>&1 || true
launchctl kickstart -k "gui/$uidn/$label" >/dev/null 2>&1 || true

launchctl print "gui/$uidn/$label" | head -n 80
