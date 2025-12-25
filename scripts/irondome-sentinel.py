#!/usr/bin/env python3
"""Iron Dome Sentinel (macOS + Messages + Ollama).

Defensive-only automation wrapper:
- Runs the existing Iron Dome pipeline (scripts/irondome-run.zsh) on an interval.
- Watches outputs in workdir (alerts/actions/dossiers) and sends SMS/iMessage alerts.
- Polls incoming Messages from a single allowed handle and executes safe commands.

Messages automation requires user-session access (LaunchAgent) and macOS Automation
permission for osascript/Python.

Config via environment variables (recommended):
  IRONDOME_WORKDIR=/tmp/irondome
  IRONDOME_INTERVAL_SECONDS=60
  SENTINEL_TO=+14135550676                # where to send alerts/replies
  SENTINEL_ALLOWED_HANDLES=+14135550676   # who may send commands (comma-separated)
  SENTINEL_SHARED_SECRET=                 # optional: require messages to start with this
  SENTINEL_POLL_SECONDS=5
  SENTINEL_ALERT_COOLDOWN_SECONDS=60
  SENTINEL_MAX_MESSAGE_CHARS=900

Optional Legal module (local evidence chain + report drafts):
    SENTINEL_LEGAL_ENABLE=1
    SENTINEL_LEGAL_MIN_CONFIDENCE=0.85
    SENTINEL_LEGAL_MIN_PERSISTENCE=3
    SENTINEL_LEGAL_MAX_REPORTS_PER_DAY=3
    SENTINEL_LEGAL_WHOIS=1
"""

from __future__ import annotations

import dataclasses
import hashlib
import datetime
import json
import os
import re
import shutil
import shlex
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

try:
    from irondome_legal import maybe_generate_legal_artifacts
except Exception:  # pragma: no cover
    maybe_generate_legal_artifacts = None  # type: ignore[assignment]


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = WORKSPACE_ROOT / "scripts"

DEFAULT_BASE_DIR = Path("~/Library/Application Support/IronDome").expanduser()


def _load_json_dict(path: Path) -> dict:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _write_json_dict(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _env_int(name: str, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        value = default
    else:
        raw_digits = re.sub(r"[^0-9]", "", raw)
        value = int(raw_digits) if raw_digits else default
    if min_value is not None:
        value = max(min_value, value)
    if max_value is not None:
        value = min(max_value, value)
    return value


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _normalize_handle(handle: str) -> str:
    h = (handle or "").strip()
    # Keep Apple ID emails as-is.
    if "@" in h:
        return h.lower()

    # Remove common punctuation/spaces.
    digits = re.sub(r"[^0-9+]", "", h)

    # If the user provided +E.164 already, keep it.
    if digits.startswith("+"):
        return "+" + re.sub(r"[^0-9]", "", digits)

    # Convert US 10-digit or 11-digit (leading 1) to +1...
    only = re.sub(r"[^0-9]", "", digits)
    if len(only) == 10:
        return "+1" + only
    if len(only) == 11 and only.startswith("1"):
        return "+" + only

    # Fallback: return stripped.
    return h


_PRINTABLE_RUN_RE = re.compile(r"[\x20-\x7E]{2,}")


def _extract_text_from_attributed_body(body: bytes | None) -> str:
    if not body:
        return ""
    try:
        s = body.decode("utf-8", "ignore")
    except Exception:
        return ""

    runs = [m.group(0).strip() for m in _PRINTABLE_RUN_RE.finditer(s)]
    runs = [r for r in runs if r]
    if not runs:
        return ""

    junk_exact = {
        "NSObject",
        "NSString",
        "NSNumber",
        "NSDictionary",
        "NSValue",
        "NSAttributedString",
        "NSMutableAttributedString",
        "NSMutableString",
        "streamtyped",
    }

    filtered: list[str] = []
    for r in runs:
        if r in junk_exact:
            continue
        if r.startswith(("__", "NS")):
            continue
        if "kIM" in r or "AttributeName" in r:
            continue
        filtered.append(r)

    # Choose the longest plausible run; if everything looked like metadata, fall back.
    pool = filtered or runs
    pool.sort(key=len, reverse=True)
    return pool[0].strip()


def _coalesce_message_text(text: str, attributed_body: object) -> str:
    t = (text or "").strip()
    if t:
        return t
    if attributed_body is None:
        return ""
    try:
        if isinstance(attributed_body, (bytes, bytearray)):
            b = bytes(attributed_body)
        else:
            # sqlite3 may return a memoryview for BLOBs.
            b = bytes(attributed_body)
    except Exception:
        return ""
    return _extract_text_from_attributed_body(b)


@dataclasses.dataclass(frozen=True)
class IncomingMessage:
    message_id: str
    sender_handle: str
    date_sent: str
    text: str


class RateLimiter:
    def __init__(self, min_interval_seconds: int) -> None:
        self._min_interval = max(0, int(min_interval_seconds))
        self._last_sent_epoch = 0.0

    def allow(self) -> bool:
        now = time.time()
        if now - self._last_sent_epoch >= self._min_interval:
            self._last_sent_epoch = now
            return True
        return False

def _stable_alert_fingerprint(alerts_text: str) -> str:
    """Compute a stable fingerprint for alerts-latest.txt.

    The pipeline rewrites the file each run and includes timestamps (e.g. `time:` and
    per-alert bracketed times). Those should not cause repeated notifications.
    """
    if not alerts_text:
        return ""

    kept: list[str] = []
    for ln in alerts_text.splitlines():
        s = ln.strip()
        if not s:
            continue
        # Drop run-specific timestamps and volatile pointers.
        if s.startswith("time:"):
            continue
        if s.startswith("evidence_file:"):
            continue
        # Drop per-alert timestamp prefix: [2025-..Z]
        s = re.sub(r"^\[[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\]]+\]\s*", "", s)
        kept.append(s)

    normalized = "\n".join(kept).strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest() if normalized else ""


class Sentinel:
    def __init__(self) -> None:
        self.base_dir = Path(os.environ.get("IRONDOME_BASE_DIR", str(DEFAULT_BASE_DIR))).expanduser()
        self.config_path = Path(
            os.environ.get("IRONDOME_CONFIG_PATH", str(self.base_dir / "config.json"))
        ).expanduser()

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.config: dict = _load_json_dict(self.config_path)
        if not self.config_path.exists():
            self.config = {"router_model": "spectrum"}
            _write_json_dict(self.config_path, self.config)

        default_workdir = self.base_dir / "work" / "sentinel"
        default_state_dir = self.base_dir / "state"
        self.workdir = Path(
            os.environ.get("IRONDOME_WORKDIR", str(self.config.get("workdir") or default_workdir))
        ).expanduser()
        self.state_dir = Path(
            os.environ.get("SENTINEL_STATE_DIR", str(self.config.get("state_dir") or default_state_dir))
        ).expanduser()
        self.interval_seconds = _env_int("IRONDOME_INTERVAL_SECONDS", 60, min_value=10)
        self.poll_seconds = _env_int("SENTINEL_POLL_SECONDS", 5, min_value=2)
        # Separate throttles: alerts vs command replies.
        self.alert_min_interval_seconds = _env_int("SENTINEL_ALERT_MIN_INTERVAL_SECONDS", 900, min_value=30)
        self.reply_min_interval_seconds = _env_int("SENTINEL_REPLY_MIN_INTERVAL_SECONDS", 5, min_value=1)
        self.max_message_chars = _env_int("SENTINEL_MAX_MESSAGE_CHARS", 900, min_value=200, max_value=1800)
        self.daily_summary_enabled = os.environ.get("SENTINEL_DAILY_SUMMARY", "0").strip() == "1"

        # Control-plane UX.
        self.power_direct = os.environ.get("SENTINEL_POWER_DIRECT", "0").strip() == "1"
        self.online_on_boot = os.environ.get("SENTINEL_ONLINE_ON_BOOT", "1").strip() == "1"

        self.to_handle = _normalize_handle(os.environ.get("SENTINEL_TO", "").strip())
        allowed_raw = os.environ.get("SENTINEL_ALLOWED_HANDLES", "").strip()
        self.allowed_handles = {
            _normalize_handle(x) for x in re.split(r"\s*,\s*", allowed_raw) if x.strip()
        }
        self.shared_secret = os.environ.get("SENTINEL_SHARED_SECRET", "").strip()

        self.ollama_prompt_dismissed_path = self.base_dir / ".ollama_prompt_dismissed"

        self.state_path = self.state_dir / "sentinel-state.json"
        self.log_path = self.workdir / "sentinel.log"

        self._stop = False
        self._alert_rl = RateLimiter(self.alert_min_interval_seconds)
        self._reply_rl = RateLimiter(self.reply_min_interval_seconds)

        self._pending_confirm: dict[str, dict] = {}

        self.workdir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self._maybe_migrate_state()
        self._state = self._load_state()

        # Backward-compatible defaults for existing state files.
        if not isinstance(self._state.get("device_approvals"), dict):
            self._state["device_approvals"] = {}
        if not isinstance(self._state.get("device_denied_macs"), list):
            self._state["device_denied_macs"] = []

        # Boot marker used for online announcements + pre-boot message filtering.
        if not isinstance(self._state.get("last_online_boot_id"), str):
            self._state["last_online_boot_id"] = ""
        self._boot_id = self._get_boot_id()
        self._boot_epoch = self._get_boot_epoch()

        if not self.to_handle:
            # Still allow running without outbound alerting (useful during setup).
            self._log("warn", "SENTINEL_TO is not set; outbound alerts are disabled")

        if not self.allowed_handles:
            self._log("warn", "SENTINEL_ALLOWED_HANDLES is not set; inbound command control is disabled")

        # Helpful diagnostics for macOS privacy issues (Full Disk Access).
        try:
            db_path = Path("~/Library/Messages/chat.db").expanduser()
            self._log(
                "info",
                "runtime",
                python=sys.executable,
                poll_backend=os.environ.get("SENTINEL_POLL_BACKEND", "chatdb"),
                chatdb_path=str(db_path),
                chatdb_exists=db_path.exists(),
            )
        except Exception:
            pass

    # --------- logging/state ---------

    def _log(self, level: str, msg: str, **fields: object) -> None:
        rec = {
            "time": _now_iso(),
            "level": level,
            "msg": msg,
            **fields,
        }
        line = json.dumps(rec, ensure_ascii=False)
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            # As a last resort, stderr.
            print(line, file=sys.stderr)

    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {
                "last_message_id": "",
                "last_alert_hash": "",
                "last_scan_epoch": 0,
                "last_daily_summary_ymd": "",
                "device_approvals": {},
                "device_denied_macs": [],
                "last_online_boot_id": "",
                "ollama_prompt": {},
            }

    def _save_state(self) -> None:
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    def _maybe_migrate_state(self) -> None:
        """If an old state exists in workdir, copy it to state_dir once."""
        try:
            if self.state_path.exists():
                return
            legacy = self.workdir / "sentinel-state.json"
            if not legacy.exists():
                return
            tmp = self.state_path.with_suffix(".json.migrate.tmp")
            tmp.write_bytes(legacy.read_bytes())
            tmp.replace(self.state_path)
            self._log("info", "migrated_state", from_path=str(legacy), to_path=str(self.state_path))
        except Exception as e:
            self._log("warn", "state_migration_failed", error=str(e))

    def _get_boot_id(self) -> str:
        """Best-effort per-boot identifier (stable for one boot)."""
        try:
            p = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            s = (p.stdout or "").strip()
            if p.returncode == 0 and s:
                return s
        except Exception:
            pass

        # Fallback: boottime seconds.
        try:
            p = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "kern.boottime"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            raw = (p.stdout or "").strip()
            m = re.search(r"sec\s*=\s*(\d+)", raw)
            if p.returncode == 0 and m:
                return f"boottime:{m.group(1)}"
        except Exception:
            pass

        return ""

    def _get_boot_epoch(self) -> int:
        """Best-effort boot time epoch seconds (for replay protection)."""
        try:
            p = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "kern.boottime"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            raw = (p.stdout or "").strip()
            m = re.search(r"sec\s*=\s*(\d+)", raw)
            if p.returncode == 0 and m:
                return int(m.group(1))
        except Exception:
            pass
        return 0

    def _iso_to_epoch(self, iso: str) -> int:
        s = (iso or "").strip()
        if not s:
            return 0
        if s.endswith(("Z", "z")):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return int(dt.timestamp())
        except Exception:
            return 0

    def _maybe_send_online(self) -> None:
        if not self.online_on_boot:
            return
        if not self.to_handle:
            return
        if not self._boot_id:
            return
        last = str(self._state.get("last_online_boot_id") or "")
        if last == self._boot_id:
            return
        self._state["last_online_boot_id"] = self._boot_id
        self._save_state()
        self.send_message(f"[Iron Dome] Sentinel online on {self._host_name()}. Monitoring resumed.")

    # --------- Messages (send) ---------

    def send_message(self, text: str) -> None:
        if not self.to_handle:
            return

        t = (text or "").strip()
        if not t:
            return

        chunks = self._split_message(t)
        for chunk in chunks:
            self._log("info", "send", to=self.to_handle, preview=chunk[:160])
            self._osascript_send(self.to_handle, chunk)
                if "--help" in argv or "-h" in argv:
                    # Show module doc + runtime commands help (help list is generated by Sentinel).
                    try:
                        s = Sentinel()
                        help_text = s._help_text()
                    except Exception:
                        help_text = ""
                    print((__doc__ or "") + ("\n\n" + help_text if help_text else ""))
                    return 0

                # If first arg looks like a subcommand, run it and exit. Commands mirror the
                # messages-based commands (so you can run `irondome-sentinel status` locally).
                if argv:
                    cmd = " ".join(argv).strip()
                    try:
                        s = Sentinel()
                    except Exception as e:
                        print(f"Error initializing Sentinel: {e}", file=sys.stderr)
                        return 2

                    lc = cmd.lower()
                    if lc in {"ping", "hi", "hello"}:
                        print("[Iron Dome] Sentinel is online.")
                        return 0

                    if lc in {"version", "about"}:
                        print(f"[Iron Dome] Sentinel (python={Path(sys.executable).name})")
                        return 0

                    if lc in {"status"}:
                        print(s._status_text())
                        return 0

                    if lc in {"scan", "scan now", "once"} or "--once" in argv:
                        ok = s.run_pipeline()
                        try:
                            s._maybe_send_alerts()
                        except Exception:
                            pass
                        print("Scan complete." if ok else "Scan failed.")
                        return 0 if ok else 2

                    if lc in {"dossier list", "dossier-list", "dossier"}:
                        print(s._dossier_list())
                        return 0

                    if lc in {"reports", "report list"}:
                        print(s._reports_list())
                        return 0

                    if lc.startswith("report show "):
                        target = cmd.strip()[len("report show ") :].strip()
                        print(s._report_show(target))
                        return 0

                    if lc == "log":
                        print(s._tail_log(60))
                        return 0

                    if lc in {"ollama status", "ai status"}:
                        u = (os.environ.get("OLLAMA_URL") or "http://localhost:11434").strip()
                        reachable = s._ollama_reachable(u)
                        dismissed = s.ollama_prompt_dismissed_path.exists()
                        print(f"AI: {'online' if reachable else 'offline'} (url={u})\nPrompt: {'dismissed' if dismissed else 'enabled'}")
                        return 0

                    if lc in {"ollama start", "ai start"}:
                        ok, msg = s._attempt_start_ollama()
                        if not ok:
                            print(f"Ollama start failed: {msg}")
                            return 2
                        u = (os.environ.get("OLLAMA_URL") or "http://localhost:11434").strip()
                        if s._ollama_reachable(u):
                            print("Ollama started. AI is online.")
                        else:
                            print("Ollama start attempted; AI may still be offline.")
                        return 0

                    if lc in {"ollama reset", "ollama reset-prompt", "ai reset"}:
                        try:
                            if s.ollama_prompt_dismissed_path.exists():
                                s.ollama_prompt_dismissed_path.unlink()
                        except Exception:
                            pass
                        s._state["ollama_prompt"] = {}
                        s._save_state()
                        print("Ollama prompt reset. You'll be prompted again when AI is offline.")
                        return 0

                    # Additional configured commands (from config.yaml): support irondome-* and
                    # a few helpful system-check commands. Prefer executing scripts under
                    # `scripts/` when present; otherwise run safe non-interactive variants.
                    def _run_script(script_name: str, args: list[str] | None = None) -> int:
                        path = SCRIPTS_DIR / script_name
                        if not path.exists():
                            print(f"Script not found: {path}", file=sys.stderr)
                            return 2
                        cmd = ["/bin/zsh", str(path)]
                        if args:
                            cmd += args
                        try:
                            p = subprocess.run(cmd, cwd=str(WORKSPACE_ROOT), capture_output=True, text=True, timeout=300)
                            out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
                            print(out.strip())
                            return 0 if p.returncode == 0 else 2
                        except Exception as e:
                            print(f"Script execution failed: {e}", file=sys.stderr)
                            return 2

                    if lc == "irondome-run":
                        ok = s.run_pipeline()
                        try:
                            s._maybe_send_alerts()
                        except Exception:
                            pass
                        print("Run complete." if ok else "Run failed.")
                        return 0 if ok else 2

                    if lc == "irondome-start":
                        # Prefer the buddy install script if present; fallback to sentinel installer.
                        for installer in ("irondome-buddy-install-launchagent.zsh", "irondome-sentinel-install-launchagent.zsh"):
                            rc = _run_script(installer)
                            if rc == 0:
                                return 0
                        # If installers missing, attempt launchctl load of buddy plist.
                        try:
                            p = subprocess.run(["/bin/zsh", "-c", "launchctl load -w ~/Library/LaunchAgents/com.irondome.buddy.plist"], capture_output=True, text=True)
                            print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                            return 0 if p.returncode == 0 else 2
                        except Exception as e:
                            print(f"Start failed: {e}", file=sys.stderr)
                            return 2

                    if lc == "irondome-stop":
                        try:
                            p = subprocess.run(["/bin/zsh", "-c", "launchctl unload -w ~/Library/LaunchAgents/com.irondome.buddy.plist"], capture_output=True, text=True)
                            print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                            return 0 if p.returncode == 0 else 2
                        except Exception as e:
                            print(f"Stop failed: {e}", file=sys.stderr)
                            return 2

                    if lc == "irondome-status":
                        # Show the most recent watcher report from /tmp/irondome if available.
                        try:
                            tmpdir = Path("/tmp/irondome")
                            if tmpdir.exists():
                                files = sorted(tmpdir.glob("irondome-*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
                                if files:
                                    p = files[0]
                                    print(f"== {p} ==")
                                    print(p.read_text(encoding="utf-8", errors="replace"))
                                    return 0
                            print("No /tmp/irondome reports yet. Start the watcher or run 'irondome-run'.")
                            return 0
                        except Exception as e:
                            print(f"Status error: {e}", file=sys.stderr)
                            return 2

                    if lc == "irondome-alerts":
                        try:
                            a = Path("/tmp/irondome/alerts-latest.txt")
                            act = Path("/tmp/irondome/actions-latest.txt")
                            if a.exists():
                                print(f"== {a} ==")
                                print(a.read_text(encoding="utf-8", errors="replace"))
                            else:
                                print("No alerts yet")
                            print("")
                            if act.exists():
                                print(f"== {act} ==")
                                print(act.read_text(encoding="utf-8", errors="replace"))
                            else:
                                print("No actions yet")
                            return 0
                        except Exception as e:
                            print(f"Alerts error: {e}", file=sys.stderr)
                            return 2

                    if lc.startswith("irondome-allowlist"):
                        # Delegate to script if present.
                        args = cmd.split()[1:]
                        return _run_script("irondome-allowlist.zsh", args) if (SCRIPTS_DIR / "irondome-allowlist.zsh").exists() else 2

                    if lc.startswith("irondome-spectrum"):
                        # spectrum-run -> spectrum-playbook
                        if "run" in lc or lc.endswith("-run"):
                            return _run_script("irondome-spectrum-playbook.zsh") if (SCRIPTS_DIR / "irondome-spectrum-playbook.zsh").exists() else 2

                    if lc.startswith("irondome-dossier") and "run" in lc:
                        return _run_script("irondome-dossier.zsh") if (SCRIPTS_DIR / "irondome-dossier.zsh").exists() else 2

                    # Defensive utility commands from config.yaml (non-interactive variants):
                    if lc == "monitor-network":
                        cmdline = "mkdir -p /tmp/irondome && (test -f /tmp/irondome/network-baseline.txt || (arp -a | sort > /tmp/irondome/network-baseline.txt)) && (arp -a | sort > /tmp/irondome/network-current.txt) && (diff -u /tmp/irondome/network-baseline.txt /tmp/irondome/network-current.txt && echo 'No changes') || true"
                        p = subprocess.run(["/bin/zsh", "-c", cmdline], capture_output=True, text=True)
                        print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                        return 0

                    if lc == "analyze-suricata":
                        cmdline = "LOG=~/.continue/suricata-logs/fast.log; if test -f \"$LOG\"; then tail -n 200 \"$LOG\" | egrep -i \"alert|drop\" || true; else echo \"Suricata log not found at $LOG\"; fi"
                        p = subprocess.run(["/bin/zsh", "-c", cmdline], capture_output=True, text=True)
                        print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                        return 0

                    if lc == "check-fail2ban":
                        cmdline = "echo 'macOS Application Firewall:'; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true; echo 'pf (packet filter) status:'; pfctl -s info 2>/dev/null || echo 'pfctl requires sudo for full output'; echo '---'; if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx 'buddy-fail2ban'; then docker exec buddy-fail2ban fail2ban-client status || true; else echo 'Fail2Ban container not running (or Docker is off).'; fi"
                        p = subprocess.run(["/bin/zsh", "-c", cmdline], capture_output=True, text=True)
                        print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                        return 0

                    if lc == "threat-summary":
                        cmdline = "log show --style syslog --last 24h --predicate 'eventMessage CONTAINS[c] \"deny\" OR eventMessage CONTAINS[c] \"failed\" OR eventMessage CONTAINS[c] \"invalid\" OR eventMessage CONTAINS[c] \"blocked\" OR eventMessage CONTAINS[c] \"ssh\"' | tail -200"
                        p = subprocess.run(["/bin/zsh", "-c", cmdline], capture_output=True, text=True)
                        print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                        return 0

                    # Pentest / slashCommands support (run/nmap/nuclei/ffuf/sqlmap/gobuster/etc.).
                    # These execute local tools when present; they expect an argument after
                    # the command (e.g., `nmap example.com`), except `run` which executes
                    # an arbitrary shell command (careful).
                    def _run_tool_shell(cmdline: str) -> int:
                        try:
                            p = subprocess.run(["/bin/zsh", "-c", cmdline], capture_output=True, text=True, timeout=1800)
                            print(((p.stdout or "") + ("\n" + p.stderr if p.stderr else "")).strip())
                            return 0 if p.returncode == 0 else 2
                        except Exception as e:
                            print(f"Execution failed: {e}", file=sys.stderr)
                            return 2

                    # 'run' -> execute arbitrary command provided by user
                    if lc.startswith("run ") or lc == "run":
                        if len(argv) < 2:
                            print("Usage: run <command>", file=sys.stderr)
                            return 2
                        cmdline = " ".join(argv[1:])
                        return _run_tool_shell(cmdline)

                    # Helper for templated commands that use a single target/input
                    def _single_input_template(template: str) -> int:
                        if len(argv) < 2:
                            print("Usage: <cmd> <target>", file=sys.stderr)
                            return 2
                        target = " ".join(argv[1:])
                        cmdline = template.replace("{{input}}", shlex.quote(target))
                        # Allow timestamp insertion
                        cmdline = cmdline.replace("$(date +%s)", str(int(time.time())))
                        return _run_tool_shell(cmdline)

                    if lc.startswith("nmap ") or lc == "nmap":
                        return _single_input_template("nmap -v -A -Pn -T4 -oN /tmp/nmap-$(date +%s).txt {{input}}")

                    if lc.startswith("nuclei ") or lc == "nuclei":
                        return _single_input_template("nuclei -u {{input}} -t ~/nuclei-templates/ -severity critical,high -rl 100 -o /tmp/nuclei-$(date +%s).txt")

                    if lc.startswith("ffuf ") or lc == "ffuf":
                        # expects base URL
                        return _single_input_template("ffuf -u {{input}}/FUZZ -w ~/wordlists/common.txt -o /tmp/ffuf-$(date +%s).json -of json -ac -fc 404 -recursion -resume")

                    if lc.startswith("sqlmap ") or lc == "sqlmap":
                        return _single_input_template("sqlmap -u {{input}} --batch --level=5 --risk=3 --threads=10 --dbs --tables --flush-session --output-dir=/tmp/sqlmap-$(date +%s)")

                    if lc.startswith("gobuster ") or lc == "gobuster":
                        return _single_input_template("gobuster dns -d {{input}} -w ~/wordlists/subdomains.txt -t 100 -q -o /tmp/gobuster-$(date +%s).txt")

                    if lc.startswith("nikto ") or lc == "nikto":
                        return _single_input_template("nikto -h {{input}} -output /tmp/nikto-$(date +%s).txt")

                    if lc.startswith("amass ") or lc == "amass":
                        return _single_input_template("amass enum -passive -d {{input}} -o /tmp/amass-$(date +%s).txt")

                    if lc.startswith("wayback ") or lc == "wayback":
                        if len(argv) < 2:
                            print("Usage: wayback <domain>", file=sys.stderr)
                            return 2
                        target = " ".join(argv[1:])
                        cmdline = f"curl -s \"https://web.archive.org/cdx/search/cdx?url={shlex.quote(target)}/*&output=json\" | jq -r '.[1:][] | .[2]' | sort -u"
                        return _run_tool_shell(cmdline)

                    if lc.startswith("eyewitness ") or lc == "eyewitness":
                        return _single_input_template("eyewitness --web -f /tmp/live-targets.txt --delay 2 --threads 10 --no-prompt --output /tmp/eyewitness-$(date +%s)")

                    if lc.startswith("crtsh ") or lc == "crtsh":
                        if len(argv) < 2:
                            print("Usage: crtsh <domain>", file=sys.stderr)
                            return 2
                        target = " ".join(argv[1:])
                        cmdline = f"curl -s \"https://crt.sh/?q=%25.{shlex.quote(target)}&output=json\" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u"
                        return _run_tool_shell(cmdline)

                    if lc.startswith("xsstrike ") or lc == "xsstrike":
                        return _single_input_template("python3 ~/XSStrike/xsstrike.py -u {{input}} --crawl --level 3")

                    # tail-logs -> non-interactive tail by default; pass --follow to follow
                    if lc.startswith("tail-logs") or lc == "tail-logs":
                        follow = "--follow" in argv or "-f" in argv
                        if follow:
                            # Interactive follow: spawn a blocking tail -f
                            p = subprocess.Popen(["/bin/zsh", "-c", "tail -f /var/log/system.log"])  # noqa: S604
                            try:
                                p.wait()
                                return 0
                            except KeyboardInterrupt:
                                p.terminate()
                                return 0
                        else:
                            p = subprocess.run(["/bin/zsh", "-c", "tail -n 200 /var/log/system.log"], capture_output=True, text=True)
                            print((p.stdout or "") + ("\n" + p.stderr if p.stderr else ""))
                            return 0

                    # Unknown subcommand: fall through to running as the background sentinel.

                # Default: run as the LaunchAgent/service.
                s = Sentinel()
                _install_signal_handlers(s)

                if "--once" in argv:
                    ok = s.run_pipeline()
                    s._maybe_send_alerts()
                    return 0 if ok else 2

                s.run_forever()
                return 0
        buddy_handle = _normalize_handle(buddy_handle)
        if not buddy_handle:
            return []

        # Backends:
        # - chatdb: use ~/Library/Messages/chat.db (requires Full Disk Access for this python under macOS privacy)
        # - applescript: use Messages AppleScript (often brittle under launchd)
        # - auto: try chatdb then applescript
        backend = os.environ.get("SENTINEL_POLL_BACKEND", "chatdb").strip().lower()
        if backend in {"chatdb", "db", "sqlite", "sqlite3", "auto"}:
            msgs = self._poll_messages_chatdb(buddy_handle, limit=limit)
            if msgs is not None:
                return msgs
            if backend != "auto":
                return []

        applescript = r'''
on _replace_chars(theText, searchString, replacementString)
  set AppleScript's text item delimiters to searchString
  set theItems to every text item of theText
  set AppleScript's text item delimiters to replacementString
  set theText to theItems as string
  set AppleScript's text item delimiters to ""
  return theText
end _replace_chars

on run argv
  set buddyHandle to item 1 of argv
  set maxCount to item 2 of argv

  set outLines to {}

  tell application "Messages"
    -- Prefer iMessage service; chat can still contain SMS relay when configured.
    set svc to 1st service whose service type is iMessage
    set b to buddy buddyHandle of svc

        set chatRef to missing value
        try
            set chatRef to 1st text chat whose id contains buddyHandle
        on error
            try
                set chatRef to 1st text chat whose name contains buddyHandle
            end try
        end try

        if chatRef is missing value then
            set chatRef to make new text chat with properties {service:svc, participants:{b}}
        end if

    set msgCount to count of messages of chatRef
    if msgCount is 0 then
      return ""
    end if

    set startIndex to msgCount - (maxCount as integer) + 1
    if startIndex < 1 then set startIndex to 1

    repeat with i from startIndex to msgCount
      set m to item i of messages of chatRef
      set mid to "" & (id of m)
      set mdate to "" & (date sent of m)
      set mtext to "" & (content of m)
      set sh to ""
      try
        set sh to "" & (handle of sender of m)
      on error
        try
          set sh to "" & (name of sender of m)
        on error
          set sh to ""
        end try
      end try

      -- Sanitize separators/newlines/tabs for a simple TSV protocol.
      set mtext to my _replace_chars(mtext, (ASCII character 10), "\\n")
      set mtext to my _replace_chars(mtext, (ASCII character 13), "")
      set mtext to my _replace_chars(mtext, (ASCII character 9), " ")

      set sh to my _replace_chars(sh, (ASCII character 10), "")
      set sh to my _replace_chars(sh, (ASCII character 13), "")
      set sh to my _replace_chars(sh, (ASCII character 9), "")

      set mid to my _replace_chars(mid, (ASCII character 9), "")
      set mdate to my _replace_chars(mdate, (ASCII character 9), " ")

            set end of outLines to (mid & (ASCII character 9) & sh & (ASCII character 9) & mdate & (ASCII character 9) & mtext)
    end repeat
  end tell

  set AppleScript's text item delimiters to (ASCII character 10)
  set outText to outLines as string
  set AppleScript's text item delimiters to ""
  return outText
end run
'''

        try:
            p = subprocess.run(
                ["/usr/bin/osascript", "-", buddy_handle, str(int(limit))],
                input=applescript,
                text=True,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            self._log("error", "osascript poll failed", rc=e.returncode, stderr=(e.stderr or "")[:2000])
            return []

        lines = [ln for ln in (p.stdout or "").splitlines() if ln.strip()]
        msgs: list[IncomingMessage] = []
        for ln in lines:
            parts = ln.split("\t", 3)
            if len(parts) != 4:
                continue
            mid, sender, date_sent, text = parts
            msgs.append(
                IncomingMessage(
                    message_id=mid.strip(),
                    sender_handle=_normalize_handle(sender.strip()),
                    date_sent=date_sent.strip(),
                    text=(text or "").replace("\\n", "\n"),
                )
            )
        return msgs

    def _poll_messages_chatdb(self, buddy_handle: str, *, limit: int = 20) -> list[IncomingMessage] | None:
        db_path = Path("~/Library/Messages/chat.db").expanduser()
        if not db_path.exists():
            return None

        # Candidate identifiers seen in chat.db handle.id.
        candidates: set[str] = {buddy_handle}
        if buddy_handle.startswith("+"):
            candidates.add(buddy_handle[1:])
        digits_only = re.sub(r"\D+", "", buddy_handle)
        if digits_only:
            candidates.add(digits_only)

        limit_i = max(1, min(int(limit), 200))

        def _msg_date_to_iso(raw: int | None) -> str:
            if raw is None:
                return ""
            try:
                v = int(raw)
            except Exception:
                return ""

            # Apple epoch: 2001-01-01.
            apple_epoch_unix = 978307200

            # Heuristic: newer macOS stores nanoseconds since 2001; older stores seconds.
            if v > 1_000_000_000_000:
                ts = (v / 1_000_000_000.0) + apple_epoch_unix
            else:
                ts = float(v) + apple_epoch_unix

            try:
                dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).replace(microsecond=0)
                return dt.isoformat().replace("+00:00", "Z")
            except Exception:
                return ""

        try:
            uri = f"file:{db_path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=1.0)
            conn.row_factory = sqlite3.Row
            try:
                qmarks = ",".join(["?"] * len(candidates))
                sql = f"""
                SELECT
                  m.ROWID AS mid,
                  COALESCE(h.id, '') AS sender,
                  m.date AS mdate,
                                    COALESCE(m.text, '') AS mtext,
                                    m.attributedBody AS abody
                FROM message m
                LEFT JOIN handle h ON h.ROWID = m.handle_id
                WHERE m.is_from_me = 0 AND h.id IN ({qmarks})
                ORDER BY m.date DESC
                LIMIT ?
                """.strip()
                rows = conn.execute(sql, [*sorted(candidates), limit_i]).fetchall()
            finally:
                conn.close()
        except Exception as e:
            msg = str(e)
            hint = ""
            if "unable to open database file" in msg.lower():
                hint = (
                    "Grant Full Disk Access to the exact Python binary running Sentinel: "
                    + sys.executable
                    + " (and/or /opt/homebrew/bin/python3), then restart the LaunchAgent."
                )
            self._log("error", "chatdb poll failed", err=msg[:2000], hint=hint)
            return None

        msgs: list[IncomingMessage] = []
        for r in rows:
            mid = str(r["mid"]) if r["mid"] is not None else ""
            sender = _normalize_handle(str(r["sender"] or ""))
            date_sent = _msg_date_to_iso(r["mdate"])  # type: ignore[arg-type]
            text = _coalesce_message_text(str(r["mtext"] or ""), r["abody"])  # type: ignore[index]
            msgs.append(IncomingMessage(message_id=mid, sender_handle=sender, date_sent=date_sent, text=text))

        # Oldest -> newest.
        msgs.reverse()
        return msgs

    # --------- Iron Dome pipeline ---------

    def run_pipeline(self) -> bool:
        """Run scripts/irondome-run.zsh <workdir>."""
        cmd = ["/bin/zsh", str(SCRIPTS_DIR / "irondome-run.zsh"), str(self.workdir)]
        env = os.environ.copy()

        # Ensure core vars exist if user relies on current compose/ollama.
        env.setdefault("OLLAMA_URL", env.get("OLLAMA_URL", "http://localhost:11434"))

        ollama_url = (env.get("OLLAMA_URL") or "http://localhost:11434").strip()
        if not self._ollama_reachable(ollama_url):
            # Notify-only fallback: keep scanning/alerting even when AI is offline.
            env["IRONDOME_OLLAMA_DISABLE"] = "1"
            env.setdefault("IRONDOME_MODE", "notify")
            env.setdefault("IRONDOME_ACTIONS_ALLOWLIST", "notify_only")

        start = time.time()
        try:
            p = subprocess.run(cmd, text=True, capture_output=True, env=env, timeout=180)
            ok = (p.returncode == 0)
            elapsed = time.time() - start
            self._log(
                "info" if ok else "error",
                "pipeline run",
                ok=ok,
                rc=p.returncode,
                elapsed_s=round(elapsed, 3),
                stdout_tail=(p.stdout or "")[-2000:],
                stderr_tail=(p.stderr or "")[-2000:],
            )
            return ok
        except subprocess.TimeoutExpired:
            self._log("error", "pipeline timeout", timeout_s=180)
            return False
        except Exception as e:
            self._log("error", "pipeline exception", error=str(e))
            return False

    def _ollama_reachable(self, base_url: str) -> bool:
        u = (base_url or "").strip().rstrip("/")
        if not u:
            return False
        try:
            req = urllib.request.Request(u + "/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                # Any 2xx/3xx response indicates the service is up.
                return 200 <= int(getattr(resp, "status", 200)) < 400
        except Exception:
            return False

    def _maybe_prompt_ollama_start(self) -> None:
        if not self.to_handle:
            return

        if self.ollama_prompt_dismissed_path.exists():
            return

        prompt_state = self._state.get("ollama_prompt")
        if isinstance(prompt_state, dict) and prompt_state.get("pending"):
            return

        env = os.environ.copy()
        env.setdefault("OLLAMA_URL", env.get("OLLAMA_URL", "http://localhost:11434"))
        ollama_url = (env.get("OLLAMA_URL") or "http://localhost:11434").strip()
        if self._ollama_reachable(ollama_url):
            return

        last_sent = 0
        if isinstance(prompt_state, dict):
            try:
                last_sent = int(prompt_state.get("last_sent_epoch") or 0)
            except Exception:
                last_sent = 0
        # Don't spam: re-prompt at most every 24h.
        if last_sent and (time.time() - last_sent) < 24 * 3600:
            return

        self.send_message(
            "[Iron Dome] AI (Ollama) is offline. Start it now?\n"
            "Reply YES/START or NO. Blank reply counts as YES.\n"
            "Any other reply counts as NO and dismisses this prompt.\n"
            "Send 'ollama reset' to allow prompting again."  # iMessage control-plane convenience
        )

        self._state["ollama_prompt"] = {
            "pending": True,
            "last_sent_epoch": int(time.time()),
            "url": ollama_url,
        }
        self._save_state()

    def _attempt_start_ollama(self) -> tuple[bool, str]:
        compose_path = WORKSPACE_ROOT / "docker-compose.yaml"
        if not compose_path.exists():
            return False, f"missing {compose_path.name}"

        docker = shutil.which("docker")
        if docker:
            cmd = [docker, "compose", "-f", str(compose_path), "up", "-d"]
            try:
                p = subprocess.run(cmd, cwd=str(WORKSPACE_ROOT), capture_output=True, text=True, timeout=60)
                if p.returncode == 0:
                    return True, "started via docker compose"
                err = (p.stderr or p.stdout or "").strip()
                if err:
                    return False, err[:300]
            except Exception as e:
                return False, str(e)[:300]

        docker_compose = shutil.which("docker-compose")
        if docker_compose:
            cmd = [docker_compose, "-f", str(compose_path), "up", "-d"]
            try:
                p = subprocess.run(cmd, cwd=str(WORKSPACE_ROOT), capture_output=True, text=True, timeout=60)
                if p.returncode == 0:
                    return True, "started via docker-compose"
                err = (p.stderr or p.stdout or "").strip()
                if err:
                    return False, err[:300]
            except Exception as e:
                return False, str(e)[:300]

        return False, "docker not installed"

    def _read_text(self, path: Path, max_bytes: int = 50_000) -> str:
        try:
            with path.open("rb") as f:
                data = f.read(max_bytes)
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _alerts_summary(self) -> str:
        overall, records = self._parse_alerts_latest()
        devices = self._extract_new_devices(records)
        self._update_device_state_from_alerts(devices)

        parts: list[str] = [f"Severity: {overall}"]

        if devices:
            pending = [d for d in devices if self._device_status(d.get("mac", "")) == "pending"]
            allowed = [d for d in devices if self._device_status(d.get("mac", "")) == "accepted"]
            denied = [d for d in devices if self._device_status(d.get("mac", "")) == "denied"]

            if pending:
                primary = self._select_primary_pending_device(pending)
                if primary:
                    more = max(0, len(pending) - 1)
                    suffix = f" (+{more} more)" if more else ""
                    parts.append("New device pending approval:" + suffix)
                    parts.append(f"- IP: {primary.get('ip','')}  MAC: {primary.get('mac','')}")
                    parts.append("Reply: ACCEPT or DENY")

            if allowed:
                parts.append("Approved device(s):")
                for d in allowed[:5]:
                    parts.append(f"- IP: {d.get('ip','')}  MAC: {d.get('mac','')}")

            if denied:
                parts.append("Denied device(s):")
                for d in denied[:5]:
                    parts.append(f"- IP: {d.get('ip','')}  MAC: {d.get('mac','')}")

        # Include a compact findings list (avoid actions-latest.txt; it contains JSON and verification-code noise).
        findings: list[str] = []
        for r in records:
            kind = (r.get("kind") or "").strip()
            msg = (r.get("msg") or "").strip()
            if not kind and not msg:
                continue
            if msg:
                findings.append(msg)
            elif kind:
                findings.append(kind.replace("_", " "))
        if findings:
            parts.append("Findings:")
            for f in findings[:4]:
                parts.append(f"- {f}")

        return "\n".join([p for p in parts if p.strip()]).strip()

    def _select_primary_pending_device(self, pending_devices: list[dict[str, str]]) -> dict[str, str] | None:
        """Pick the most recently seen pending device (so ACCEPT/DENY can be one tap)."""
        if not pending_devices:
            return None

        approvals = self._state.get("device_approvals")
        if not isinstance(approvals, dict):
            approvals = {}

        def score(d: dict[str, str]) -> int:
            mac = self._norm_mac(d.get("mac", ""))
            rec = approvals.get(mac) if isinstance(approvals.get(mac), dict) else {}
            if not isinstance(rec, dict):
                rec = {}
            try:
                return int(rec.get("last_seen") or 0)
            except Exception:
                return 0

        best = max(pending_devices, key=score)
        return best

    def _parse_alerts_latest(self) -> tuple[str, list[dict[str, str]]]:
        alerts_txt = self.workdir / "alerts-latest.txt"
        txt = self._read_text(alerts_txt, max_bytes=250_000) if alerts_txt.exists() else ""
        overall = "none"
        m = re.search(r"^overall_severity:\s*(\w+)\s*$", txt, re.M)
        if m:
            overall = m.group(1).strip().lower()

        lines = txt.splitlines()
        records: list[str] = []
        cur: list[str] = []
        for ln in lines:
            s = ln.rstrip("\n")
            if s.startswith("[") and "]" in s:
                if cur:
                    records.append(" ".join([x.strip() for x in cur if x.strip()]))
                cur = [s]
            else:
                if cur and s.strip() and not s.strip().startswith(("overall_severity:", "time:", "host:", "evidence_file:", "=== ")):
                    cur.append(s)
        if cur:
            records.append(" ".join([x.strip() for x in cur if x.strip()]))

        parsed: list[dict[str, str]] = []
        for rec in records:
            severity = ""
            kind = ""
            msg = ""
            evidence = ""
            mm = re.search(r"\bseverity=(\w+)", rec)
            if mm:
                severity = mm.group(1)
            mm = re.search(r"\bkind=([a-zA-Z0-9_]+)", rec)
            if mm:
                kind = mm.group(1)
            mm = re.search(r"\bmsg=([^\[]+?)\s+evidence:\s*(.+)$", rec)
            if mm:
                msg = mm.group(1).strip()
                evidence = mm.group(2).strip()
            else:
                mm = re.search(r"\bmsg=([^\[]+)$", rec)
                if mm:
                    msg = mm.group(1).strip()

            parsed.append({"raw": rec.strip(), "severity": severity, "kind": kind, "msg": msg, "evidence": evidence})

        return overall, parsed

    def _allowlist_path(self) -> Path:
        raw = os.environ.get("IRONDOME_ALLOWLIST", "").strip()
        if raw:
            return Path(raw).expanduser()
        return (Path.home() / ".continue" / "data" / "irondome" / "allowlist.json")

    def _load_allowlist(self) -> dict:
        path = self._allowlist_path()
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        return {}

    def _save_allowlist(self, obj: dict) -> None:
        path = self._allowlist_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    def _norm_mac(self, mac: str) -> str:
        s = (mac or "").strip().lower().replace("-", ":")
        parts = s.split(":")
        if len(parts) != 6:
            return ""
        if not all(re.fullmatch(r"[0-9a-f]{1,2}", p or "") for p in parts):
            return ""
        return ":".join((p or "").zfill(2) for p in parts)

    def _extract_new_devices(self, records: list[dict[str, str]]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for r in records:
            if (r.get("kind") or "").strip().lower() != "new_device":
                continue
            blob = (r.get("evidence") or "") + " " + (r.get("raw") or "")
            # Typical evidence snippet: "+? (172.20.10.1) at 62:81:... on en0"
            for m in re.finditer(r"\((?P<ip>(\d{1,3}\.){3}\d{1,3})\)\s+at\s+(?P<mac>(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}|ff:ff:ff:ff:ff:ff)", blob, re.I):
                ip = m.group("ip")
                mac = self._norm_mac(m.group("mac"))
                if not mac:
                    continue
                out.append({"ip": ip, "mac": mac, "name": ""})
        # de-dupe by mac
        seen: set[str] = set()
        uniq: list[dict[str, str]] = []
        for d in out:
            mac = d.get("mac", "")
            if not mac or mac in seen:
                continue
            seen.add(mac)
            uniq.append(d)
        return uniq

    def _device_status(self, mac: str) -> str:
        mac = self._norm_mac(mac)
        if not mac:
            return "unknown"

        denied = set(self._state.get("device_denied_macs") or [])
        if mac in denied:
            return "denied"

        allow = self._load_allowlist()
        allowed_macs = set(allow.get("allowed_macs") or []) if isinstance(allow, dict) else set()
        if mac in allowed_macs:
            return "accepted"

        approvals = self._state.get("device_approvals") or {}
        if isinstance(approvals, dict) and mac in approvals:
            st = str((approvals.get(mac) or {}).get("status") or "pending")
            return st
        return "pending"

    def _update_device_state_from_alerts(self, devices: list[dict[str, str]]) -> None:
        if not devices:
            return
        approvals = self._state.get("device_approvals")
        if not isinstance(approvals, dict):
            approvals = {}
        now = int(time.time())
        changed = False
        for d in devices:
            mac = self._norm_mac(d.get("mac", ""))
            if not mac:
                continue
            status = self._device_status(mac)
            rec = approvals.get(mac) if isinstance(approvals.get(mac), dict) else {}
            if not isinstance(rec, dict):
                rec = {}
            if not rec.get("first_seen"):
                rec["first_seen"] = now
                changed = True
            rec["last_seen"] = now
            rec["ip"] = d.get("ip", "")
            if status in {"accepted", "denied"}:
                rec["status"] = status
            else:
                rec.setdefault("status", "pending")
            approvals[mac] = rec
        if changed:
            self._state["device_approvals"] = approvals
            self._save_state()

    def _alerts_hash(self) -> str:
        # Back-compat name; now returns a stable fingerprint.
        p = self.workdir / "alerts-latest.txt"
        data = self._read_text(p, max_bytes=200_000)
        return _stable_alert_fingerprint(data)

    # --------- command control ---------

    def _authorized_sender(self, sender_handle: str) -> bool:
        if not self.allowed_handles:
            return False
        return _normalize_handle(sender_handle) in self.allowed_handles

    def _strip_secret(self, text: str) -> Optional[str]:
        t = (text or "").strip()
        if not t:
            return None
        if not self.shared_secret:
            return t
        # Require: "<secret> <command...>"
        if not t.lower().startswith(self.shared_secret.lower() + " "):
            return None
        return t[len(self.shared_secret) + 1 :].strip()

    def handle_command(self, sender_handle: str, text: str) -> Optional[str]:
        if not self._authorized_sender(sender_handle):
            return None
        cmd_text = self._strip_secret(text)
        if cmd_text is None:
            return "Unauthorized (missing shared secret)."

        normalized = re.sub(r"\s+", " ", cmd_text.strip()).lower()

        if normalized in {"ping", "hi", "hello"}:
            return "[Iron Dome] Sentinel is online."

        if normalized in {"version", "about"}:
            return f"[Iron Dome] Sentinel (python={Path(sys.executable).name})"

        # ACCEPT/DENY are reserved for approvals:
        # - power: bare "ACCEPT" / "DENY"
        # - devices: "ACCEPT <mac> [label]" / "DENY <mac>"
        if normalized.startswith("accept") or normalized.startswith("deny"):
            parts = cmd_text.strip().split()
            verb = parts[0].lower() if parts else ""
            if len(parts) == 1 and verb in {"accept", "deny"}:
                res = self._handle_accept_deny(sender_handle, verb)
                if res is not None:
                    return res
                # No pending power action: apply bare ACCEPT/DENY to the most recent pending device.
                target = self._most_recent_pending_device_mac()
                if not target:
                    return "No pending approval."
                parts = [verb, target]
            # Device approval
            if len(parts) >= 2 and verb in {"accept", "deny"}:
                mac = self._norm_mac(parts[1])
                if not mac:
                    return "Usage: ACCEPT or DENY"
                if verb == "deny":
                    denied = self._state.get("device_denied_macs")
                    if not isinstance(denied, list):
                        denied = []
                    if mac not in denied:
                        denied.append(mac)
                    self._state["device_denied_macs"] = denied
                    approvals = self._state.get("device_approvals")
                    if isinstance(approvals, dict):
                        rec = approvals.get(mac) if isinstance(approvals.get(mac), dict) else {}
                        if not isinstance(rec, dict):
                            rec = {}
                        rec["status"] = "denied"
                        approvals[mac] = rec
                        self._state["device_approvals"] = approvals
                    self._save_state()
                    return f"Denied. (MAC: {mac})"

                # accept
                label = " ".join(parts[2:]).strip() if len(parts) > 2 else ""
                if not label:
                    label = "approved"
                allow = self._load_allowlist()
                if not isinstance(allow, dict):
                    allow = {}
                allow.setdefault("allowed_macs", [])
                allow.setdefault("allowed_ips", [])
                allow.setdefault("labels", {})
                if not isinstance(allow.get("allowed_macs"), list):
                    allow["allowed_macs"] = []
                if mac not in allow["allowed_macs"]:
                    allow["allowed_macs"].append(mac)
                if label and isinstance(allow.get("labels"), dict):
                    allow["labels"][mac] = label
                allow["updated_at"] = _now_iso()
                allow.setdefault("source", "sentinel_accept")
                self._save_allowlist(allow)
                approvals = self._state.get("device_approvals")
                if isinstance(approvals, dict):
                    rec = approvals.get(mac) if isinstance(approvals.get(mac), dict) else {}
                    if not isinstance(rec, dict):
                        rec = {}
                    rec["status"] = "accepted"
                    approvals[mac] = rec
                    self._state["device_approvals"] = approvals
                # if previously denied, remove from denied list
                denied = self._state.get("device_denied_macs")
                if isinstance(denied, list) and mac in denied:
                    denied = [x for x in denied if x != mac]
                    self._state["device_denied_macs"] = denied
                self._save_state()
                return f"Approved. (MAC: {mac})"

        if normalized in ("help", "?", "commands"):
            return self._help_text()

        if normalized == "status":
            return self._status_text()

        if normalized in {"ollama status", "ai status"}:
            u = (os.environ.get("OLLAMA_URL") or "http://localhost:11434").strip()
            reachable = self._ollama_reachable(u)
            dismissed = self.ollama_prompt_dismissed_path.exists()
            return f"AI: {'online' if reachable else 'offline'} (url={u})\nPrompt: {'dismissed' if dismissed else 'enabled'}"

        if normalized in {"ollama start", "ai start"}:
            ok, msg = self._attempt_start_ollama()
            if not ok:
                return f"Ollama start failed: {msg}"
            u = (os.environ.get("OLLAMA_URL") or "http://localhost:11434").strip()
            if self._ollama_reachable(u):
                return "Ollama started. AI is online."
            return "Ollama start attempted, but AI is still offline."

        if normalized in {"ollama reset", "ollama reset-prompt", "ai reset"}:
            try:
                if self.ollama_prompt_dismissed_path.exists():
                    self.ollama_prompt_dismissed_path.unlink()
            except Exception:
                pass
            self._state["ollama_prompt"] = {}
            self._save_state()
            return "Ollama prompt reset. You'll be prompted again when AI is offline."

        if normalized == "scan now":
            ok = self.run_pipeline()
            self._state["last_scan_epoch"] = int(time.time())
            self._save_state()
            return ("Scan complete.\n" if ok else "Scan failed.\n") + self._alerts_summary()

        if normalized == "dossier list":
            return self._dossier_list()

        if normalized in ("legal now", "legal report now"):
            if maybe_generate_legal_artifacts is None:
                return "Legal module unavailable."
            res = maybe_generate_legal_artifacts(self.workdir, host=self._host_name())
            if not res.get("enabled"):
                return "Legal module disabled. Set SENTINEL_LEGAL_ENABLE=1."
            if res.get("report_created"):
                drafts = res.get("report_drafts") or []
                if isinstance(drafts, list) and drafts:
                    # Keep reply compact.
                    names = [str(p).split("/")[-1] for p in drafts[:5]]
                    return "Legal: drafts created:\n- " + "\n- ".join(names)
                return "Legal: drafts created. Send 'reports' to list."
            return f"Legal: evidence captured (no drafts). incident_id={res.get('incident_id','')}"

        if normalized == "reports":
            return self._reports_list()

        if normalized.startswith("report show "):
            target = cmd_text.strip()[len("report show ") :].strip()
            return self._report_show(target)

        if normalized == "log":
            return self._tail_log(60)

        # Power control.
        # - direct mode: exact "reboot" / "shutdown" executes immediately
        # - confirm mode (default): uses ACCEPT/DENY flow
        if normalized in {"reboot", "restart"}:
            if self.power_direct:
                if not self._power_preflight_ok("reboot"):
                    return "Reboot blocked: sudo needs a password. Configure passwordless shutdown/reboot for Sentinel."
                self.send_message("[Iron Dome] Rebooting now. I’ll message when Sentinel is back online.")
                ok, err = self._attempt_power("reboot")
                if not ok:
                    return f"Reboot failed: {err}" if err else "Reboot failed."
                return None
            return self._handle_power_command(sender_handle, "reboot")

        if normalized == "shutdown":
            if self.power_direct:
                if not self._power_preflight_ok("shutdown"):
                    return "Shutdown blocked: sudo needs a password. Configure passwordless shutdown/reboot for Sentinel."
                self.send_message("[Iron Dome] Shutting down now. Sentinel will be offline until this Mac starts again.")
                ok, err = self._attempt_power("shutdown")
                if not ok:
                    return f"Shutdown failed: {err}" if err else "Shutdown failed."
                return None
            return self._handle_power_command(sender_handle, "shutdown")

        if normalized.startswith("shutdown") or normalized.startswith("reboot"):
            return self._handle_power_command(sender_handle, normalized)

        # Avoid responding to normal chat messages; only reply on plausible command attempts.
        if normalized.split(" ", 1)[0] in {
            "help",
            "status",
            "scan",
            "dossier",
            "legal",
            "reports",
            "report",
            "log",
            "shutdown",
            "reboot",
        }:
            return "Unknown command. Send 'help'."
        return None

    def _help_text(self) -> str:
        base = [
            "Sentinel commands:",
            "- status",
            "- ping",
            "- ollama status",
            "- ollama start",
            "- ollama reset",
            "- scan now",
            "- dossier list",
            "- legal now",
            "- reports",
            "- report show <name>",
            "- log",
            "- accept / deny (approve the latest pending device)",
            "- shutdown (requires passwordless sudo; see scripts/irondome-configure-sudo.zsh)",
            "- reboot (requires passwordless sudo; see scripts/irondome-configure-sudo.zsh)",
        ]
        if self.shared_secret:
            base.append(f"Note: prefix commands with your shared secret.")
        return "\n".join(base)

    def _status_text(self) -> str:
        # Lightweight system health (keep it short; no JSON dumps).
        last_scan = int(self._state.get("last_scan_epoch") or 0)
        last_scan_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_scan)) if last_scan else "never"
        uptime = self._run_cmd(["/usr/bin/uptime"]).strip()
        if ", load averages:" in uptime:
            uptime = uptime.split(", load averages:", 1)[0].strip()
        alerts = self._alerts_summary()
        pending_ct = self._count_pending_devices()
        legal = "legal=disabled"
        if os.environ.get("SENTINEL_LEGAL_ENABLE", "0").strip() == "1":
            legal = "legal=enabled"

        ollama_url = (os.environ.get("OLLAMA_URL") or "http://localhost:11434").strip()
        ai = "ai=offline (notify-only)"
        if self._ollama_reachable(ollama_url):
            ai = "ai=online"
        return "\n".join([
            f"Time (UTC): {_now_iso()}",
            f"Interval: {self.interval_seconds}s   Poll: {self.poll_seconds}s",
            legal,
            ai,
            f"Last scan (local): {last_scan_s}",
            f"Pending approvals: {pending_ct}",
            "uptime: " + uptime,
            "\n" + alerts,
        ]).strip()

    def _most_recent_pending_device_mac(self) -> str:
        approvals = self._state.get("device_approvals")
        if not isinstance(approvals, dict) or not approvals:
            return ""
        best_mac = ""
        best_seen = -1
        for mac, rec in approvals.items():
            if not isinstance(rec, dict):
                continue
            if str(rec.get("status") or "pending") != "pending":
                continue
            try:
                seen = int(rec.get("last_seen") or 0)
            except Exception:
                seen = 0
            nmac = self._norm_mac(str(mac))
            if not nmac:
                continue
            if seen > best_seen:
                best_seen = seen
                best_mac = nmac
        return best_mac

    def _count_pending_devices(self) -> int:
        approvals = self._state.get("device_approvals")
        if not isinstance(approvals, dict):
            return 0
        n = 0
        for _mac, rec in approvals.items():
            if not isinstance(rec, dict):
                continue
            if str(rec.get("status") or "pending") == "pending":
                n += 1
        return n

    def _host_name(self) -> str:
        try:
            p = subprocess.run(["/usr/sbin/scutil", "--get", "ComputerName"], capture_output=True, text=True)
            if p.returncode == 0 and (p.stdout or "").strip():
                return (p.stdout or "").strip()
        except Exception:
            pass
        return os.uname().nodename

    def _dossier_list(self) -> str:
        suspects = self.workdir / "suspects"
        if not suspects.exists():
            return "No dossiers directory yet."
        dossiers = sorted(suspects.glob("dossier-*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not dossiers:
            return "No dossiers yet."
        lines = ["Recent dossiers:"]
        for p in dossiers[:8]:
            lines.append(f"- {p.name}")
        return "\n".join(lines)

    def _tail_log(self, n: int) -> str:
        try:
            txt = self.log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return "No log yet."

        lines = txt.splitlines()[-n:]
        out: list[str] = []
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
                ts = str(rec.get("time", ""))
                lvl = str(rec.get("level", ""))
                msg = str(rec.get("msg", ""))
                extras = {k: v for k, v in rec.items() if k not in {"time", "level", "msg"}}
                extra_s = ""
                if extras:
                    # keep compact
                    parts = []
                    for k in sorted(extras.keys()):
                        v = extras[k]
                        sv = str(v)
                        if len(sv) > 80:
                            sv = sv[:80] + "…"
                        parts.append(f"{k}={sv}")
                    extra_s = " " + " ".join(parts[:10])
                out.append(f"{ts} {lvl} {msg}{extra_s}".strip())
            except Exception:
                out.append(s)

        return "\n".join(out) if out else "No log yet."

    def _reports_glob(self) -> list[Path]:
        legal_dir = self.workdir / "legal"
        if not legal_dir.exists():
            return []
        # Drafts live in dated incident folders as *.eml and *.txt.
        drafts = list(legal_dir.glob("**/*.eml")) + list(legal_dir.glob("**/*.txt"))
        # Filter to only IC3/ISP/CERT drafts.
        keep = []
        for p in drafts:
            n = p.name.lower()
            if n.startswith(("isp-abuse-", "cert-", "ic3-")):
                keep.append(p)
        keep.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return keep

    def _reports_list(self) -> str:
        drafts = self._reports_glob()
        if not drafts:
            return "No report drafts yet. (Enable SENTINEL_LEGAL_ENABLE=1 and run 'legal now'.)"
        lines = ["Recent report drafts:"]
        for p in drafts[:12]:
            rel = str(p).replace(str(self.workdir) + "/", "")
            lines.append(f"- {rel}")
        lines.append("Use: report show <name>")
        return "\n".join(lines)

    def _report_show(self, target: str) -> str:
        target = (target or "").strip()
        if not target:
            return "Usage: report show <name>"
        drafts = self._reports_glob()
        matches = []
        for p in drafts:
            if target.lower() in p.name.lower() or target.lower() in str(p).lower():
                matches.append(p)
        if not matches:
            return "No matching draft found. Send 'reports' to list."
        p = matches[0]
        txt = self._read_text(p, max_bytes=40_000)
        if not txt:
            return f"Empty/unreadable: {p.name}"
        # Keep SMS manageable; the sender will split but avoid huge payloads.
        if len(txt) > 35_000:
            txt = txt[:35_000] + "\n\n[truncated]"
        return f"=== {p.name} ===\n" + txt

    def _handle_power_command(self, sender_handle: str, normalized: str) -> str:
        action = "shutdown" if normalized.startswith("shutdown") else "reboot"
        self._pending_confirm["power"] = {
            "action": action,
            "sender": _normalize_handle(sender_handle),
            "expires_epoch": time.time() + 300,
        }
        return f"Approve {action}? Reply 'ACCEPT' or 'DENY' within 5 minutes."

    def _handle_accept_deny(self, sender_handle: str, normalized: str) -> Optional[str]:
        pending = self._pending_confirm.get("power")
        if not pending:
            return None
        expected_sender = _normalize_handle(str(pending.get("sender") or ""))
        if expected_sender and _normalize_handle(sender_handle) != expected_sender:
            return None
        if time.time() > float(pending.get("expires_epoch", 0)):
            self._pending_confirm.pop("power", None)
            return "No pending approval (expired)."
        action = str(pending.get("action") or "")
        if not action:
            self._pending_confirm.pop("power", None)
            return None

        if normalized == "deny":
            self._pending_confirm.pop("power", None)
            return f"Denied. {action} cancelled."

        if normalized == "accept":
            self._pending_confirm.pop("power", None)
            if not self._power_preflight_ok(action):
                return f"{action.capitalize()} blocked: sudo needs a password. Configure passwordless shutdown/reboot for Sentinel."
            self.send_message(
                "[Iron Dome] Rebooting now. I’ll message when Sentinel is back online."
                if action == "reboot"
                else "[Iron Dome] Shutting down now. Sentinel will be offline until this Mac starts again."
            )
            ok, err = self._attempt_power(action)
            if not ok:
                return f"{action.capitalize()} failed: {err}" if err else f"{action.capitalize()} failed."
            return None

    def _power_preflight_ok(self, action: str | None = None) -> bool:
        """Return True if non-interactive sudo is permitted for the power action.

        Important: do NOT probe by running shutdown/reboot. Use `sudo -l` to check
        sudoers policy without side effects.
        """

        def can_list(cmd: list[str]) -> bool:
            try:
                p = subprocess.run(["/usr/bin/sudo", "-n", "-l", *cmd], capture_output=True, text=True)
                if p.returncode == 0:
                    return True
                err = (p.stderr or p.stdout or "").strip()
                if err:
                    err = err[:400]
                self._log(
                    "warn",
                    "power preflight failed",
                    action=str(action or ""),
                    rc=p.returncode,
                    stderr=err,
                    cmd=" ".join(cmd),
                )
                return False
            except Exception:
                return False

        if action == "shutdown":
            return can_list(["/sbin/shutdown", "-h", "now"])
        if action == "reboot":
            return can_list(["/sbin/shutdown", "-r", "now"])

        # Unknown action: accept either capability.
        return can_list(["/sbin/shutdown", "-r", "now"]) or can_list(["/sbin/shutdown", "-h", "now"])

    def _attempt_power(self, action: str) -> tuple[bool, str]:
        # Defensive-safe: do not escalate privileges automatically.
        # If user wants this to work unattended, configure sudoers for shutdown/reboot.
        if action == "shutdown":
            cmd = ["/usr/bin/sudo", "-n", "/sbin/shutdown", "-h", "now"]
        else:
            cmd = ["/usr/bin/sudo", "-n", "/sbin/shutdown", "-r", "now"]

        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            self._log("error", "power command failed", action=action, rc=p.returncode, stderr=(p.stderr or "")[:2000])
            err = (p.stderr or p.stdout or "").strip()
            if not err:
                err = "sudo is not configured for passwordless shutdown/reboot"
            return False, err[:300]
        return True, ""

    def _run_cmd(self, cmd: list[str], timeout: int = 10) -> str:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
            return out.strip()
        except Exception as e:
            return f"error: {e}"

    # --------- scheduling/loop ---------

    def _maybe_send_alerts(self) -> None:
        h = self._alerts_hash()
        last = self._state.get("last_alert_hash") or self._state.get("last_alert_fingerprint") or ""
        if not h or h == last:
            return

        # Decide whether to notify: medium/high, or any change if you want.
        alerts_txt = self.workdir / "alerts-latest.txt"
        overall = "none"
        if alerts_txt.exists():
            m = re.search(r"^overall_severity:\s*(\w+)\s*$", self._read_text(alerts_txt), re.M)
            if m:
                overall = m.group(1).strip().lower()

        self._state["last_alert_hash"] = h
        self._state["last_alert_fingerprint"] = h
        self._save_state()

        if overall in ("medium", "high"):
            if self._alert_rl.allow():
                self.send_message("[Iron Dome] threat update\n" + self._alerts_summary())

    def _daily_summary_due(self) -> bool:
        ymd = time.strftime("%Y-%m-%d", time.gmtime())
        return ymd != (self._state.get("last_daily_summary_ymd") or "")

    def _send_daily_summary(self) -> None:
        ymd = time.strftime("%Y-%m-%d", time.gmtime())
        self._state["last_daily_summary_ymd"] = ymd
        self._save_state()
        self.send_message("[Iron Dome] daily summary\n" + self._status_text())

    def run_forever(self) -> None:
        self._log("info", "sentinel start", workdir=str(self.workdir), interval_s=self.interval_seconds, poll_s=self.poll_seconds)

        # Announce online once per boot.
        try:
            self._maybe_send_online()
        except Exception as e:
            self._log("warn", "online_announce_failed", error=str(e))

        next_scan = time.time() + 2
        next_poll = time.time() + 1
        next_housekeeping = time.time() + 15

        while not self._stop:
            now = time.time()

            if now >= next_scan:
                try:
                    self._maybe_prompt_ollama_start()
                except Exception as e:
                    self._log("warn", "ollama_prompt_failed", error=str(e))
                ok = self.run_pipeline()
                self._state["last_scan_epoch"] = int(time.time())
                self._save_state()
                # Legal module: capture evidence snapshot and optionally create report drafts.
                if ok and maybe_generate_legal_artifacts is not None and os.environ.get("SENTINEL_LEGAL_ENABLE", "0").strip() == "1":
                    try:
                        res = maybe_generate_legal_artifacts(self.workdir, host=self._host_name())
                        if res.get("report_created") and self._alert_rl.allow():
                            self.send_message(f"[Iron Dome] legal draft created\n{res.get('report_eml')}")
                    except Exception as e:
                        self._log("error", "legal module error", error=str(e))
                if not ok and self._alert_rl.allow():
                    self.send_message("[Iron Dome] ERROR: pipeline failed\nSend 'log' for details.")
                next_scan = now + self.interval_seconds

            if now >= next_poll:
                self._poll_and_handle_commands()
                next_poll = now + self.poll_seconds

            if now >= next_housekeeping:
                try:
                    self._maybe_send_alerts()
                    if self.daily_summary_enabled and self._daily_summary_due() and self.to_handle:
                        self._send_daily_summary()
                except Exception as e:
                    self._log("error", "housekeeping error", error=str(e))
                next_housekeeping = now + 30

            time.sleep(0.5)

        self._log("info", "sentinel stop")

    def _poll_and_handle_commands(self) -> None:
        if not self.allowed_handles:
            return

        # Poll each allowed handle; process anything new.
        last_id = str(self._state.get("last_message_id") or "")

        newest_seen = last_id
        responses: list[str] = []

        for handle in sorted(self.allowed_handles):
            msgs = self.poll_messages(handle, limit=25)
            for m in msgs:
                if not m.message_id:
                    continue

                # Replay protection: if state is lost after reboot, ignore old messages.
                if self._boot_epoch and m.date_sent:
                    sent_epoch = self._iso_to_epoch(m.date_sent)
                    if sent_epoch and sent_epoch < (self._boot_epoch - 5):
                        continue

                # Simple monotonic check.
                if last_id and self._compare_message_ids(m.message_id, last_id) <= 0:
                    continue

                if not self._authorized_sender(m.sender_handle):
                    continue

                prompt_state = self._state.get("ollama_prompt")
                prompt_pending = isinstance(prompt_state, dict) and bool(prompt_state.get("pending"))

                # Ignore empty/noise unless we're waiting for an Ollama prompt response.
                raw_text = (m.text or "")
                text = raw_text.strip()
                if not text and not prompt_pending:
                    continue

                if prompt_pending:
                    consumed = self._handle_ollama_prompt_response(raw_text)
                    if consumed:
                        if self._compare_message_ids(m.message_id, newest_seen) > 0:
                            newest_seen = m.message_id
                        continue

                reply = self.handle_command(m.sender_handle, text)
                if reply:
                    responses.append(reply)

                if self._compare_message_ids(m.message_id, newest_seen) > 0:
                    newest_seen = m.message_id

        if newest_seen and newest_seen != last_id:
            self._state["last_message_id"] = newest_seen
            self._save_state()

        for r in responses[-3:]:
            # reply without flooding
            if self._reply_rl.allow():
                self.send_message(r)

    def _handle_ollama_prompt_response(self, raw_text: str) -> bool:
        prompt_state = self._state.get("ollama_prompt")
        if not isinstance(prompt_state, dict) or not prompt_state.get("pending"):
            return False

        reply = (raw_text or "")
        normalized = re.sub(r"\s+", " ", reply.strip()).lower()

        # Allow reset while pending.
        if normalized in {"ollama reset", "ollama reset-prompt", "ai reset"}:
            try:
                if self.ollama_prompt_dismissed_path.exists():
                    self.ollama_prompt_dismissed_path.unlink()
            except Exception:
                pass
            self._state["ollama_prompt"] = {}
            self._save_state()
            self.send_message("Ollama prompt reset.")
            return True

        yes = {"", "yes", "y", "start", "ok", "okay"}
        no = {"no", "n"}

        if normalized in yes:
            ok, msg = self._attempt_start_ollama()
            u = str(prompt_state.get("url") or (os.environ.get("OLLAMA_URL") or "http://localhost:11434")).strip()
            if ok and self._ollama_reachable(u):
                self.send_message("[Iron Dome] Ollama started. AI is online.")
            else:
                self.send_message(f"[Iron Dome] Ollama start failed or still offline. ({msg})")
            self._state["ollama_prompt"] = {}
            self._save_state()
            return True

        # NO, or any unknown response => NO + dismiss prompt.
        try:
            self.ollama_prompt_dismissed_path.write_text(_now_iso() + "\n", encoding="utf-8")
        except Exception:
            pass

        if normalized in no:
            self.send_message("[Iron Dome] OK. AI will stay off (notify-only).")
        else:
            self.send_message("[Iron Dome] OK. Leaving AI off and dismissing this prompt. Send 'ollama reset' to ask again.")
        self._state["ollama_prompt"] = {}
        self._save_state()
        return True

    def _compare_message_ids(self, a: str, b: str) -> int:
        """Compare message IDs (best effort).

        If both parse as int, compare numerically; else lexicographically.
        """
        try:
            ai = int(re.sub(r"[^0-9]", "", a) or "0")
            bi = int(re.sub(r"[^0-9]", "", b) or "0")
            return (ai > bi) - (ai < bi)
        except Exception:
            return (a > b) - (a < b)


def _install_signal_handlers(s: Sentinel) -> None:
    def _handler(signum: int, _frame) -> None:  # type: ignore[override]
        s._stop = True

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def main(argv: list[str]) -> int:
    if "--help" in argv or "-h" in argv:
        # Show module doc + runtime commands help (help list is generated by Sentinel).
        try:
            s = Sentinel()
            help_text = s._help_text()
        except Exception:
            help_text = ""
        print((__doc__ or "") + ("\n\n" + help_text if help_text else ""))
        return 0

    s = Sentinel()
    _install_signal_handlers(s)

    if "--once" in argv:
        ok = s.run_pipeline()
        s._maybe_send_alerts()
        return 0 if ok else 2

    s.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
