# Iron Dome Buddy (macOS)

This is a **local-first** home-network protection loop:

1) `irondome-scan.zsh` collects evidence into `/tmp/irondome/irondome-*.txt`
2) `irondome-detect.zsh` turns evidence into alerts (`/tmp/irondome/alerts-latest.*`)
3) `irondome-respond.zsh` optionally asks your **local Ollama model** for a structured decision, then:
   - sends macOS notifications
   - writes an action report (`/tmp/irondome/actions-latest.txt`)

By default it is **safe-by-default** (notify + recommend only). It does not auto-run privileged remediation.

## Run once

```zsh
/bin/zsh ~/.continue/scripts/irondome-run.zsh /tmp/irondome
```

## Enable background monitoring (launchd)

Continue command:
- `/irondome-start`

Or manually:

```zsh
mkdir -p /tmp/irondome
cp -f ~/.continue/launchd/com.irondome.buddy.plist ~/Library/LaunchAgents/com.irondome.buddy.plist
launchctl unload -w ~/Library/LaunchAgents/com.irondome.buddy.plist 2>/dev/null || true
launchctl load -w ~/Library/LaunchAgents/com.irondome.buddy.plist
```

## View results

- Evidence: `/tmp/irondome/irondome-latest.txt`
- Alerts: `/tmp/irondome/alerts-latest.txt`
- Actions: `/tmp/irondome/actions-latest.txt`
- Suspect dossier: `/tmp/irondome/dossier-latest.txt` (and JSON: `/tmp/irondome/dossier-latest.json`)

Continue commands:
- `/irondome-status`
- `/irondome-alerts`
- `/irondome-dossier`
- `/irondome-dossier-run`

## Local model signaling

The responder calls Ollama at `http://localhost:11434/api/generate` and asks for **JSON-only** output.
Set these in the plist (or your environment):

- `OLLAMA_URL` (default `http://localhost:11434`)
- `OLLAMA_MODEL` (default `llama3.2:8b-instruct-qat`)

## Auto-act when you're away

Recommended approach:
- Keep `IRONDOME_MODE=notify` for day-to-day.
- "Fight back" (attacking systems/people) is not part of Iron Dome.
- If you want auto-containment while you're away, use `IRONDOME_MODE=enforce` with a tight allowlist.
   Currently supported safe enforcement action: `wifi_off` (disables Wi‑Fi after the same medium/high alert repeats 3+ runs).
   Set in LaunchAgent env: `IRONDOME_MODE=enforce` and `IRONDOME_ACTIONS_ALLOWLIST=notify_only,wifi_off`.
