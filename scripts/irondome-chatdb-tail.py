#!/usr/bin/env python3
"""Print recent inbound Messages from chat.db for a given handle.

Usage:
  /Users/mirelacertan/.continue/.venv/bin/python scripts/irondome-chatdb-tail.py +14135550676 --limit 10

Notes:
- Requires Full Disk Access for the python binary running it.
- Reads `~/Library/Messages/chat.db` in read-only mode.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sqlite3
from pathlib import Path


def normalize_handle(handle: str) -> str:
    h = (handle or "").strip()
    if "@" in h:
        return h.lower()
    digits = re.sub(r"[^0-9+]", "", h)
    if digits.startswith("+"):
        return "+" + re.sub(r"[^0-9]", "", digits)
    only = re.sub(r"\D+", "", digits)
    if len(only) == 10:
        return "+1" + only
    if len(only) == 11 and only.startswith("1"):
        return "+" + only
    return h


def msg_date_to_iso(raw: int | None) -> str:
    if raw is None:
        return ""
    v = int(raw)
    apple_epoch_unix = 978307200
    if v > 1_000_000_000_000:
        ts = (v / 1_000_000_000.0) + apple_epoch_unix
    else:
        ts = float(v) + apple_epoch_unix
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).replace(microsecond=0)
    return dt.isoformat().replace("+00:00", "Z")


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
    filtered = []
    for r in runs:
        if r in junk_exact:
            continue
        if r.startswith(("__", "NS")):
            continue
        if "kIM" in r or "AttributeName" in r:
            continue
        filtered.append(r)
    pool = filtered or runs
    pool.sort(key=len, reverse=True)
    return pool[0].strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("handle", help="Phone number in +E.164 or Apple ID email")
    ap.add_argument("--limit", type=int, default=10)
    args = ap.parse_args()

    buddy = normalize_handle(args.handle)
    candidates = {buddy}
    if buddy.startswith("+"):
        candidates.add(buddy[1:])
    digits_only = re.sub(r"\D+", "", buddy)
    if digits_only:
        candidates.add(digits_only)

    db_path = Path("~/Library/Messages/chat.db").expanduser()
    if not db_path.exists():
        raise SystemExit(f"chat.db not found: {db_path}")

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

    uri = f"file:{db_path.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=1.0)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(sql, [*sorted(candidates), max(1, min(args.limit, 200))]).fetchall()
    finally:
        con.close()

    rows = list(rows)
    rows.reverse()
    for r in rows:
        text = (r["mtext"] or "").strip()
        if not text and r["abody"] is not None:
            try:
                text = _extract_text_from_attributed_body(bytes(r["abody"]))
            except Exception:
                text = ""
        print(f"{msg_date_to_iso(r['mdate'])}\t{normalize_handle(str(r['sender'] or ''))}\t{text}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
