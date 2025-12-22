#!/usr/bin/env python3
"""Iron Dome Legal Module (local evidence + report drafts).

What this module DOES:
- Builds a tamper-evident (hash-chained) JSONL log of threat evidence.
- Extracts basic IOCs (IPs/MACs/ports/domains) from existing Iron Dome artifacts.
- Produces *report drafts* (RFC 5322 .eml + JSON metadata) for manual submission.

What this module does NOT do:
- It does not "hack back" or interact with attacker systems.
- It does not auto-post to public forums/feeds.
- It does not provide identity-evasion guidance ("burner" relays) or harassment tooling.

All outputs are stored locally under <workdir>/legal/.
"""

from __future__ import annotations

import dataclasses
import email.utils
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    import whois as pywhois  # type: ignore
except Exception:  # pragma: no cover
    pywhois = None  # type: ignore


@dataclasses.dataclass(frozen=True)
class LegalConfig:
    enabled: bool
    min_confidence: float
    min_persistence_repeats: int
    max_reports_per_day: int
    allow_whois: bool
    allow_rdap: bool
    max_snapshot_bytes: int


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8", errors="replace"))


def _read_text(path: Path, max_bytes: int = 250_000) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    ips = sorted(set(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)))
    macs_raw = re.findall(r"\b((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b", text, re.I)
    macs = []
    for m in macs_raw:
        parts = m.lower().split(":")
        macs.append(":".join(p.zfill(2) for p in parts) if len(parts) == 6 else m.lower())
    macs = sorted(set(macs))

    # Domains (best-effort; avoid grabbing local hostnames too aggressively)
    domains = sorted(
        set(
            d.lower()
            for d in re.findall(r"\b([a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-zA-Z]{2,})\b", text)
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", d)
        )
    )

    # Ports from patterns like :443 or port 22
    ports = sorted(set(re.findall(r"(?::|\bport\s+)(\d{2,5})\b", text, re.I)))

    return {
        "ips": ips[:200],
        "macs": macs[:200],
        "domains": domains[:200],
        "ports": ports[:200],
    }


def _extract_user_agents(text: str) -> List[str]:
    uas = set()
    for m in re.findall(r"User-Agent\s*:\s*([^\r\n]{3,250})", text, re.I):
        uas.add(m.strip())
    for m in re.findall(r"useragent=([^\s\"]{3,250})", text, re.I):
        uas.add(m.strip())
    return sorted(uas)[:50]


def _extract_iocs(workdir: Path) -> Dict[str, List[str]]:
    candidates = [
        workdir / "alerts-latest.txt",
        workdir / "alerts-latest.jsonl",
        workdir / "irondome-latest.txt",
        workdir / "actions-latest.txt",
        workdir / "dossier-latest.json",
        workdir / "spectrum-playbook-latest.json",
    ]

    blob_parts: List[str] = []
    for p in candidates:
        if p.exists():
            blob_parts.append(f"== {p.name} ==\n" + _read_text(p))

    blob = "\n\n".join(blob_parts)
    out = _extract_iocs_from_text(blob)
    # Include user-agents if present in logs.
    out["user_agents"] = _extract_user_agents(blob)
    return out


def _overall_severity(workdir: Path) -> str:
    alerts = workdir / "alerts-latest.txt"
    if not alerts.exists():
        return "none"
    m = re.search(r"^overall_severity:\s*(\w+)\s*$", _read_text(alerts), re.M)
    sev = (m.group(1).strip().lower() if m else "none")
    return sev if sev in ("none", "low", "medium", "high") else "none"


def _persistence_repeats(workdir: Path) -> int:
    p = workdir / "persistence.json"
    obj = _load_json(p) if p.exists() else None
    if not isinstance(obj, dict):
        return 0
    by_id = obj.get("by_id")
    if not isinstance(by_id, dict):
        return 0
    mx = 0
    for rec in by_id.values():
        if not isinstance(rec, dict):
            continue
        try:
            mx = max(mx, int(rec.get("count") or 0))
        except Exception:
            continue
    return mx


def _ai_confidence(workdir: Path) -> float:
    # Prefer explicit model confidence if present; fall back to heuristic.
    p = workdir / "ai-decision-latest.json"
    obj = _load_json(p) if p.exists() else None
    if not isinstance(obj, dict):
        return 0.0

    conf = obj.get("confidence")
    val: Optional[float] = None
    if isinstance(conf, (int, float)):
        val = float(conf)
    elif isinstance(conf, str):
        try:
            val = float(conf.strip())
        except Exception:
            val = None
    if val is not None:
        if val != val or val in (float("inf"), float("-inf")):
            return 0.0
        if val < 0.0:
            return 0.0
        if val > 1.0:
            return 1.0
        return float(round(val, 3))

    sev = str(obj.get("overall_severity") or "none").lower()
    base = {"none": 0.1, "low": 0.3, "medium": 0.6, "high": 0.85}.get(sev, 0.1)
    ra = obj.get("recommended_actions")
    if isinstance(ra, list) and any(isinstance(x, dict) and x.get("action") for x in ra):
        base = min(0.99, base + 0.05)
    return float(base)


def load_legal_config_from_env() -> LegalConfig:
    enabled = os.environ.get("SENTINEL_LEGAL_ENABLE", "0").strip() == "1"
    min_conf = float(os.environ.get("SENTINEL_LEGAL_MIN_CONFIDENCE", "0.85") or "0.85")
    min_rep = int(re.sub(r"[^0-9]", "", os.environ.get("SENTINEL_LEGAL_MIN_PERSISTENCE", "3")) or "3")
    max_per_day = int(re.sub(r"[^0-9]", "", os.environ.get("SENTINEL_LEGAL_MAX_REPORTS_PER_DAY", "3")) or "3")
    allow_whois = os.environ.get("SENTINEL_LEGAL_WHOIS", "1").strip() != "0"
    allow_rdap = os.environ.get("SENTINEL_LEGAL_RDAP", "1").strip() != "0"
    max_snapshot_bytes = int(re.sub(r"[^0-9]", "", os.environ.get("SENTINEL_LEGAL_MAX_SNAPSHOT_BYTES", "200000")) or "200000")
    return LegalConfig(
        enabled=enabled,
        min_confidence=min_conf,
        min_persistence_repeats=max(1, min_rep),
        max_reports_per_day=max(0, max_per_day),
        allow_whois=allow_whois,
        allow_rdap=allow_rdap,
        max_snapshot_bytes=max(50_000, max_snapshot_bytes),
    )


class EvidenceChain:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.base_dir / "evidence-chain.jsonl"
        self.index_path = self.base_dir / "index.json"
        self._index = self._load_index()

    def _load_index(self) -> Dict[str, Any]:
        try:
            obj = json.loads(self.index_path.read_text(encoding="utf-8"))
        except Exception:
            obj = {}
        if not isinstance(obj, dict):
            obj = {}
        obj.setdefault("created_at", _now_iso())
        obj.setdefault("last_hash", "")
        obj.setdefault("reports_today", {})
        return obj

    def _save_index(self) -> None:
        tmp = self.index_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._index, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.index_path)

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        prev = str(self._index.get("last_hash") or "")
        record = dict(record)
        record["prev_hash"] = prev
        record["_canonical"] = _canonical_json({k: v for k, v in record.items() if k != "hash"})
        record_hash = _sha256_text(record["_canonical"])
        record["hash"] = record_hash

        # Write JSONL.
        with self.chain_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        self._index["last_hash"] = record_hash
        self._save_index()
        return record

    def can_emit_report_today(self, max_reports_per_day: int) -> bool:
        if max_reports_per_day <= 0:
            return False
        ymd = time.strftime("%Y-%m-%d", time.gmtime())
        rt = self._index.get("reports_today")
        if not isinstance(rt, dict):
            rt = {}
            self._index["reports_today"] = rt
        cnt = int(rt.get(ymd) or 0)
        return cnt < max_reports_per_day

    def mark_report_emitted(self) -> None:
        ymd = time.strftime("%Y-%m-%d", time.gmtime())
        rt = self._index.get("reports_today")
        if not isinstance(rt, dict):
            rt = {}
            self._index["reports_today"] = rt
        rt[ymd] = int(rt.get(ymd) or 0) + 1
        self._save_index()


def whois_lookup_ip(ip: str, *, timeout_s: int = 12) -> str:
    """Best-effort WHOIS for an IP.

    Tries:
    1) system `whois`
    2) (optional) python-whois for domains (not great for IPs, but keep as fallback)
    """

    whois_bin = "/usr/bin/whois" if Path("/usr/bin/whois").exists() else ("whois" if shutil_which("whois") else "")
    if whois_bin:
        try:
            p = subprocess.run([whois_bin, ip], capture_output=True, text=True, timeout=timeout_s)
            out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
            return out.strip()
        except Exception:
            pass

    if pywhois is not None:
        try:
            obj = pywhois.whois(ip)  # type: ignore[attr-defined]
            return str(obj)
        except Exception:
            return ""

    return ""


def rdap_lookup_ip(ip: str, *, timeout_s: int = 10) -> str:
    """Best-effort RDAP JSON for IP via public registries.

    This is a read-only lookup and does not publish data.
    """
    if requests is None:
        return ""
    # ARIN endpoint generally works globally (may redirect/referral).
    url = f"https://rdap.arin.net/registry/ip/{ip}"
    try:
        r = requests.get(url, timeout=timeout_s, headers={"Accept": "application/rdap+json"})
        if r.status_code >= 400:
            return ""
        # Keep as pretty JSON text for embedding.
        try:
            return json.dumps(r.json(), ensure_ascii=False, indent=2)[:50_000]
        except Exception:
            return (r.text or "")[:50_000]
    except Exception:
        return ""


def shutil_which(name: str) -> str:
    # Minimal which to avoid importing shutil in older environments (but it exists on 3.x).
    try:
        import shutil

        return shutil.which(name) or ""
    except Exception:
        return ""


def extract_abuse_emails(whois_text: str) -> List[str]:
    if not whois_text:
        return []
    emails = set(re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", whois_text, re.I))

    # Prefer abuse/security/noc.
    preferred = []
    other = []
    for e in sorted(emails):
        local = e.split("@", 1)[0].lower()
        if any(k in local for k in ("abuse", "security", "cert", "irt", "noc")):
            preferred.append(e)
        else:
            other.append(e)

    # Deduplicate, cap.
    out = []
    for e in preferred + other:
        if e not in out:
            out.append(e)
    return out[:10]


def build_incident_id(severity: str, iocs: Dict[str, List[str]], evidence_hash: str) -> str:
    core = {
        "severity": severity,
        "ips": iocs.get("ips", [])[:20],
        "macs": iocs.get("macs", [])[:20],
        "domains": iocs.get("domains", [])[:20],
        "ports": iocs.get("ports", [])[:20],
        "evidence_hash": evidence_hash,
    }
    return _sha256_text(_canonical_json(core))[:16]


def write_report_drafts(
    *,
    workdir: Path,
    chain: EvidenceChain,
    incident: Dict[str, Any],
    iocs: Dict[str, List[str]],
    whois_by_ip: Dict[str, str],
    abuse_emails_by_ip: Dict[str, List[str]],
) -> Tuple[List[Path], Path]:
    reports_dir = Path(str(incident.get("incident_dir") or (workdir / "legal" / "reports")))
    reports_dir.mkdir(parents=True, exist_ok=True)

    incident_id = str(incident.get("incident_id") or "")
    ts = int(time.time())
    date_hdr = email.utils.formatdate(timeval=None, localtime=False, usegmt=True)

    # Recipients for ISP abuse: union of abuse emails for all IPs.
    abuse_recipients: List[str] = []
    for emails in abuse_emails_by_ip.values():
        for e in emails:
            if e not in abuse_recipients:
                abuse_recipients.append(e)

    def base_body() -> List[str]:
        lines: List[str] = []
        lines.append("This is a draft incident report generated from local host evidence.")
        lines.append("Please review and edit before sending.")
        lines.append("")
        lines.append(f"Time (UTC): {incident.get('time')}")
        lines.append(f"Host: {incident.get('host')}")
        lines.append(f"Severity: {incident.get('severity')}")
        lines.append(f"Persistence repeats: {incident.get('persistence_repeats')}")
        lines.append(f"AI confidence (estimate): {incident.get('ai_confidence_est')}")
        lines.append(f"Incident ID: {incident_id}")
        lines.append("")
        lines.append("IOCs:")
        for k in ("ips", "macs", "domains", "ports", "user_agents"):
            vals = iocs.get(k) or []
            if vals:
                lines.append(f"- {k}: {', '.join(vals[:50])}")
        lines.append("")
        lines.append("Evidence artifacts (local file hashes):")
        for a in incident.get("artifacts", []) or []:
            if isinstance(a, dict):
                lines.append(f"- {a.get('path')} sha256={a.get('sha256')}")
        lines.append("")
        lines.append("Evidence chain:")
        lines.append(f"- chain_head_sha256: {chain._index.get('last_hash','')}")
        lines.append("")
        return lines

    drafts: List[Path] = []

    # 1) ISP abuse report (.eml)
    subj = f"Security incident report (draft) id={incident_id} severity={incident.get('severity','')}"
    body_lines = base_body()
    body_lines.append("WHOIS/RDAP (best effort):")
    for ip in (iocs.get("ips") or [])[:5]:
        if ip in whois_by_ip and whois_by_ip[ip]:
            body_lines.append(f"--- WHOIS {ip} ---")
            body_lines.append(whois_by_ip[ip][:3000])
        if ip in whois_by_ip and whois_by_ip[ip]:
            body_lines.append("")
    body = "\n".join(body_lines).strip() + "\n"

    isp_eml = reports_dir / f"isp-abuse-{ts}-{incident_id}.eml"
    headers = [
        f"Date: {date_hdr}",
        "From: (fill in before sending)",
        f"To: {', '.join(abuse_recipients) if abuse_recipients else '(abuse contact)'}",
        f"Subject: {subj}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 8bit",
        f"X-IronDome-Incident-ID: {incident_id}",
        f"X-IronDome-Evidence-Chain-Head: {chain._index.get('last_hash','')}",
    ]
    isp_eml.write_text("\r\n".join(headers) + "\r\n\r\n" + body, encoding="utf-8")
    drafts.append(isp_eml)

    # 2) IC3 template (text)
    ic3_txt = reports_dir / f"ic3-{ts}-{incident_id}.txt"
    ic3_lines = []
    ic3_lines.append("IC3 COMPLAINT DRAFT (manual submission)")
    ic3_lines.append("------------------------------------")
    ic3_lines.append("You can paste this into https://www.ic3.gov/ after review.")
    ic3_lines.append("")
    ic3_lines.append("Incident type(s): (select what applies)")
    ic3_lines.append("- Unauthorized access attempt / brute-force")
    ic3_lines.append("- Malware / suspicious process")
    ic3_lines.append("- Denial of service (if applicable)")
    ic3_lines.append("")
    ic3_lines.extend(base_body())
    ic3_lines.append("Narrative (fill in):")
    ic3_lines.append("- What happened, how you detected it, what you did to contain it.")
    ic3_lines.append("- Any financial loss? (if none, state 'none')")
    ic3_lines.append("")
    ic3_lines.append("Attachments (local references):")
    ic3_lines.append(f"- {incident.get('incident_dir')}")
    ic3_txt.write_text("\n".join(ic3_lines).strip() + "\n", encoding="utf-8")
    drafts.append(ic3_txt)

    # 3) CERT / CSIRT template (.eml) (recipient left blank)
    cert_eml = reports_dir / f"cert-{ts}-{incident_id}.eml"
    cert_headers = [
        f"Date: {date_hdr}",
        "From: (fill in before sending)",
        "To: (national CERT/CSIRT contact)",
        f"Subject: {subj}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 8bit",
        f"X-IronDome-Incident-ID: {incident_id}",
        f"X-IronDome-Evidence-Chain-Head: {chain._index.get('last_hash','')}",
    ]
    cert_body = "\n".join(base_body() + [
        "Requested assistance:",
        "- Triage/attribution guidance (if applicable)",
        "- Any known campaigns matching these IOCs",
        "",
        "Attachments (local references):",
        f"- {incident.get('incident_dir')}",
        "",
    ]).strip() + "\n"
    cert_eml.write_text("\r\n".join(cert_headers) + "\r\n\r\n" + cert_body, encoding="utf-8")
    drafts.append(cert_eml)

    meta_path = reports_dir / f"reports-{ts}-{incident_id}.json"
    meta = {
        "time": incident.get("time"),
        "incident_id": incident_id,
        "severity": incident.get("severity"),
        "persistence_repeats": incident.get("persistence_repeats"),
        "recipients_suggested": {"abuse": abuse_recipients},
        "whois_available": bool(whois_by_ip),
        "drafts": [str(p) for p in drafts],
        "incident_dir": str(incident.get("incident_dir") or ""),
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    chain.mark_report_emitted()
    return drafts, meta_path


def _run_snapshot(cmd: List[str], *, timeout_s: int = 15) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return out.strip()
    except Exception as e:
        return f"error: {e}"


def _write_snapshot_file(path: Path, content: str, *, max_bytes: int) -> Dict[str, Any]:
    data = content.encode("utf-8", errors="replace")[:max_bytes]
    path.write_bytes(data)
    return {"path": str(path), "sha256": _sha256_bytes(data), "bytes": len(data)}


def maybe_generate_legal_artifacts(workdir: Path, *, host: str) -> Dict[str, Any]:
    """Main entrypoint: append evidence record; maybe generate report drafts.

    Returns a dict summarizing what happened.
    """

    cfg = load_legal_config_from_env()
    if not cfg.enabled:
        return {"enabled": False}

    legal_root = workdir / "legal"
    chain = EvidenceChain(legal_root)

    severity = _overall_severity(workdir)
    repeats = _persistence_repeats(workdir)
    conf = _ai_confidence(workdir)
    iocs = _extract_iocs(workdir)

    # Create dated incident folder.
    ymd = time.strftime("%Y-%m-%d", time.gmtime())
    incident_dir = legal_root / ymd
    incident_dir.mkdir(parents=True, exist_ok=True)

    # Artifact hashes (local).
    artifacts: List[Dict[str, Any]] = []
    for p in [
        workdir / "alerts-latest.txt",
        workdir / "alerts-latest.jsonl",
        workdir / "irondome-latest.txt",
        workdir / "actions-latest.txt",
        workdir / "ai-decision-latest.json",
        workdir / "persistence.json",
        workdir / "spectrum-playbook-latest.json",
        workdir / "dossier-latest.json",
    ]:
        if not p.exists():
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        artifacts.append({"path": str(p), "sha256": _sha256_bytes(data), "bytes": len(data)})

    # Add extra snapshots (process/network/logs) into the incident directory.
    snapshots: List[Dict[str, Any]] = []
    ts = int(time.time())
    snap_dir = incident_dir / f"incident-{ts}"
    snap_dir.mkdir(parents=True, exist_ok=True)

    snapshots.append(_write_snapshot_file(snap_dir / "ps.txt", _run_snapshot(["/bin/ps", "auxww"]), max_bytes=cfg.max_snapshot_bytes))
    snapshots.append(_write_snapshot_file(snap_dir / "lsof-listen.txt", _run_snapshot(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]), max_bytes=cfg.max_snapshot_bytes))
    snapshots.append(_write_snapshot_file(snap_dir / "netstat.txt", _run_snapshot(["/usr/sbin/netstat", "-anv"]), max_bytes=cfg.max_snapshot_bytes))
    snapshots.append(_write_snapshot_file(snap_dir / "arp.txt", _run_snapshot(["/usr/sbin/arp", "-a"]), max_bytes=cfg.max_snapshot_bytes))

    # Prefer a small unified log slice (best effort).
    snapshots.append(
        _write_snapshot_file(
            snap_dir / "unified-log-15m.txt",
            _run_snapshot([
                "/usr/bin/log",
                "show",
                "--style",
                "syslog",
                "--last",
                "15m",
                "--predicate",
                'eventMessage CONTAINS[c] "deny" OR eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "invalid" OR eventMessage CONTAINS[c] "blocked" OR eventMessage CONTAINS[c] "ssh"',
            ], timeout_s=25),
            max_bytes=cfg.max_snapshot_bytes,
        )
    )

    # Copy (by reference) existing artifacts into dossier, but keep hashes only.
    dossier_path = snap_dir / "dossier.json"

    evidence_hash = _sha256_text(
        _canonical_json({"severity": severity, "repeats": repeats, "iocs": iocs, "artifacts": artifacts, "snapshots": snapshots})
    )
    incident_id = build_incident_id(severity, iocs, evidence_hash)

    record = {
        "time": _now_iso(),
        "type": "evidence_snapshot",
        "host": host,
        "severity": severity,
        "persistence_repeats": repeats,
        "ai_confidence_est": conf,
        "incident_id": incident_id,
        "incident_dir": str(snap_dir),
        "iocs": iocs,
        "artifacts": artifacts,
        "snapshots": snapshots,
        "evidence_sha256": evidence_hash,
    }

    # Write a per-incident dossier (tamper-evident via evidence_sha256 + chain).
    dossier_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

    chain.append(record)

    should_report = (
        severity == "high" or (severity == "medium" and repeats >= cfg.min_persistence_repeats)
    ) and conf >= cfg.min_confidence

    # Rate limit reports per day.
    if should_report and not chain.can_emit_report_today(cfg.max_reports_per_day):
        should_report = False

    whois_by_ip: Dict[str, str] = {}
    abuse_emails_by_ip: Dict[str, List[str]] = {}

    if should_report and cfg.allow_whois:
        for ip in (iocs.get("ips") or [])[:10]:
            text_parts = []
            if cfg.allow_rdap:
                rd = rdap_lookup_ip(ip)
                if rd:
                    text_parts.append("[RDAP]\n" + rd)
            wt = whois_lookup_ip(ip)
            if wt:
                text_parts.append("[WHOIS]\n" + wt)
            merged = "\n\n".join(text_parts).strip()
            if merged:
                whois_by_ip[ip] = merged
                abuse_emails_by_ip[ip] = extract_abuse_emails(merged)

    drafts: List[Path] = []
    meta_path: Optional[Path] = None
    if should_report:
        drafts, meta_path = write_report_drafts(
            workdir=workdir,
            chain=chain,
            incident=record,
            iocs=iocs,
            whois_by_ip=whois_by_ip,
            abuse_emails_by_ip=abuse_emails_by_ip,
        )

    return {
        "enabled": True,
        "severity": severity,
        "persistence_repeats": repeats,
        "ai_confidence_est": conf,
        "incident_id": incident_id,
        "evidence_chain": str(chain.chain_path),
        "incident_dir": str(snap_dir),
        "dossier": str(dossier_path),
        "report_created": bool(drafts),
        "report_drafts": [str(p) for p in drafts],
        "report_meta": str(meta_path) if meta_path else "",
        "abuse_recipients_found": sum(len(v) for v in abuse_emails_by_ip.values()),
    }
