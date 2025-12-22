#!/usr/bin/env python3
"""Print recent inbound Messages from chat.db (all senders).

Usage:
  /Users/mirelacertan/.continue/.venv/bin/python scripts/irondome-chatdb-recent.py --limit 25

This is a debugging helper to discover the exact `handle.id` values present in your
Messages database (e.g. +E.164, digits-only, or an email).
"""

from __future__ import annotations

import argparse
import datetime
import sqlite3
from pathlib import Path

import re


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
    ap.add_argument("--limit", type=int, default=25)
    args = ap.parse_args()

    db_path = Path("~/Library/Messages/chat.db").expanduser()
    if not db_path.exists():
        raise SystemExit(f"chat.db not found: {db_path}")

        sql = """
    SELECT
      m.ROWID AS mid,
      COALESCE(h.id, '') AS sender,
      m.date AS mdate,
            COALESCE(m.text, '') AS mtext,
            m.attributedBody AS abody
    FROM message m
    LEFT JOIN handle h ON h.ROWID = m.handle_id
    WHERE m.is_from_me = 0
    ORDER BY m.date DESC
    LIMIT ?
    """.strip()

    uri = f"file:{db_path.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=1.0)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(sql, [max(1, min(args.limit, 200))]).fetchall()
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
        sender = str(r["sender"] or "")
        print(f"{msg_date_to_iso(r['mdate'])}\t{sender}\t{text}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
