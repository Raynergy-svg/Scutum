# Iron Dome Sentinel (24/7 macOS + Messages)

This adds an always-on **Sentinel** that:
- runs your existing pipeline (`scripts/irondome-run.zsh`) on an interval
- sends threat/event alerts via macOS **Messages.app** (iMessage + SMS Relay)
- supports **bidirectional remote control** via inbound Messages from *your* allowed handle(s)

Files added:
- `scripts/irondome-sentinel.py`
- `scripts/irondome-venv-bootstrap.zsh`
- `scripts/irondome-sentinel-launch.zsh`
- `scripts/irondome-sentinel-install-launchagent.zsh`
- `launchd/com.irondome.sentinel.plist`

## 1) Prerequisites & macOS setup

### Messages + SMS relay
1. On iPhone: **Settings → Messages → Text Message Forwarding** → enable your Mac.
2. On Mac: open **Messages.app**, sign into iMessage, and confirm you can send/receive.

### Allow automation
The first time you run, macOS will prompt:
- **Automation** permission for `/usr/bin/osascript` (and the process running it) to control “Messages”.

If you don’t get prompts or it fails:
- macOS **System Settings → Privacy & Security → Automation**
- ensure your terminal / python launcher is allowed to control Messages

### Full Disk Access (for inbound command polling)
By default, inbound command polling reads the local Messages database:
- `~/Library/Messages/chat.db`

macOS may block background processes from reading it unless you grant **Full Disk Access**.
Add these to **System Settings → Privacy & Security → Full Disk Access**:
- `/Users/mirelacertan/.continue/.venv/bin/python`
- (optional fallback) `/opt/homebrew/bin/python3`

Verify access:

```zsh
/bin/zsh /Users/mirelacertan/.continue/scripts/irondome-chatdb-selftest.zsh
```

### Keep the Mac awake (lid closed)
Your existing LaunchAgent already uses `caffeinate -dimsu` which prevents idle sleep.

Notes (macOS behavior):
- True “clamshell mode” generally requires power + external display + input devices.
- If the Mac still sleeps with lid closed, consider leaving it open or using an approved wake/sleep policy in **System Settings → Battery**.

### Docker + Ollama
Your `docker-compose.yaml` already has `restart: unless-stopped` for `ollama`.
Bring it up once and verify:

```zsh
cd /Users/mirelacertan/.continue
docker compose up -d ollama
curl -s http://localhost:11434/api/tags | head
```

## 2) Install the LaunchAgent (autostart)

Because Messages control requires a logged-in user session, this should be installed as a **LaunchAgent**.

1. Copy the plist into your LaunchAgents directory:

```zsh
mkdir -p "$HOME/Library/LaunchAgents"
cp -f /Users/mirelacertan/.continue/launchd/com.irondome.sentinel.plist "$HOME/Library/LaunchAgents/"
```

2. Edit it to set your phone/iMessage handle:
- `SENTINEL_TO`
- `SENTINEL_ALLOWED_HANDLES`
- (optional) `SENTINEL_SHARED_SECRET`

3. Load it (modern `launchctl` flow):

```zsh
UIDN=$(id -u)
launchctl bootout "gui/$UIDN" "$HOME/Library/LaunchAgents/com.irondome.sentinel.plist" 2>/dev/null || true
launchctl bootstrap "gui/$UIDN" "$HOME/Library/LaunchAgents/com.irondome.sentinel.plist"
launchctl kickstart -k "gui/$UIDN/com.irondome.sentinel"
launchctl print "gui/$UIDN/com.irondome.sentinel" | head
```

Or run the helper (recommended; idempotent):

```zsh
/bin/zsh /Users/mirelacertan/.continue/scripts/irondome-sentinel-install-launchagent.zsh
```

Logs:
- `/tmp/irondome/sentinel.log`
- `/tmp/irondome/sentinel.launchd.out.log`
- `/tmp/irondome/sentinel.launchd.err.log`
- `/tmp/irondome/sentinel.venv.log`

## 3) How remote command control works

Inbound messages are polled from the allowed handle(s) and parsed case-insensitively.

Supported commands:
- `status`
- `scan now`
- `dossier list`
- `legal now` (capture evidence + possibly create a report draft)
- `reports` (list recent drafts)
- `report show <name>` (show one draft’s full text)
- `log`
- `shutdown` (two-step confirm)
- `reboot` (two-step confirm)

Security:
- Only `SENTINEL_ALLOWED_HANDLES` are accepted.
- Optional shared secret: set `SENTINEL_SHARED_SECRET` and send commands as:
  - `<secret> status`
  - `<secret> scan now`

Power commands:
- `shutdown` / `reboot` require confirmation.
- They use `sudo -n` and will fail unless you configure non-interactive sudo for the shutdown command.

## 4) Test plan

### Create/update the venv (recommended)

```zsh
/bin/zsh /Users/mirelacertan/.continue/scripts/irondome-venv-bootstrap.zsh
```

### Local smoke test (interactive)
Run once manually to trigger Automation prompts:

```zsh
/Users/mirelacertan/.continue/.venv/bin/python /Users/mirelacertan/.continue/scripts/irondome-sentinel.py --once
```

### Legal module (optional)
Enable the legal evidence chain + report drafts:

Install optional Python deps (for RDAP/WHOIS enrichment):

```zsh
/Users/mirelacertan/.continue/.venv/bin/python -m pip install -r /Users/mirelacertan/.continue/requirements.txt
```

```zsh
export SENTINEL_LEGAL_ENABLE=1
export SENTINEL_LEGAL_MIN_CONFIDENCE=0.85
export SENTINEL_LEGAL_MIN_PERSISTENCE=3
export SENTINEL_LEGAL_MAX_REPORTS_PER_DAY=3
export SENTINEL_LEGAL_WHOIS=1
export SENTINEL_LEGAL_RDAP=1
export SENTINEL_LEGAL_MAX_SNAPSHOT_BYTES=200000
```

Then send `legal now` from your phone, or run locally and check:
- `/tmp/irondome/legal/evidence-chain.jsonl` (hash-chained audit log)
- `/tmp/irondome/legal/YYYY-MM-DD/incident-*/` (per-incident dossier + snapshots + drafts)

Confidence gating note:
- When available, the Legal module uses the model’s explicit `confidence` field from `/tmp/irondome/ai-decision-latest.json` (clamped to 0..1).
- If the model omits it, the module falls back to a conservative severity-based estimate.

Then start it in foreground for a minute:

```zsh
SENTINEL_TO=+14135550676 SENTINEL_ALLOWED_HANDLES=+14135550676 \
/Users/mirelacertan/.continue/.venv/bin/python /Users/mirelacertan/.continue/scripts/irondome-sentinel.py
```

### Remote test (over iCloud)
From your phone, text the Mac:
- `status`
- `scan now`

You should receive an auto-reply.

## 5) Safety notes

- This Sentinel is designed for **defensive monitoring + local response**.
- Do **not** implement “counterattack” automation; keep actions lawful and limited to your own devices/network.
