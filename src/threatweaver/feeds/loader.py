"""Store feed records as enrichment ("intel") with provenance.

A feed snapshot is a source (kind="feed", identified by content hash), so
loading the same snapshot twice is a no-op and every intel row can be traced
to the exact snapshot and the original record text.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from ..models import IocType
from ..normalize import normalize_value
from ..store import upsert_ioc
from .common import FeedSpec


@dataclass(frozen=True)
class LoadResult:
    source_id: int
    already_loaded: bool = False
    records: int = 0
    rejected: int = 0
    skipped_rows: int = 0
    new_iocs: int = 0


def load_feed(
    conn: sqlite3.Connection, spec: FeedSpec, text: str, collected_at: str | None = None
) -> LoadResult:
    collected_at = collected_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    parsed = spec.parse(text)
    name = f"feed:{spec.name}"

    with conn:
        existing = conn.execute(
            "SELECT id FROM sources WHERE name = ? AND content_sha256 = ?", (name, digest)
        ).fetchone()
        if existing:
            return LoadResult(existing["id"], already_loaded=True)
        source_id = conn.execute(
            "INSERT INTO sources (name, kind, content_sha256, ingested_at) VALUES (?, 'feed', ?, ?)",
            (name, digest, collected_at),
        ).lastrowid

        rejected = new_iocs = 0
        for rec in parsed.records:
            try:
                norm = normalize_value(rec.type, rec.value, trusted=True)
            except ValueError:
                rejected += 1
                continue
            ioc_id, created = upsert_ioc(conn, norm.type.value, norm.value, norm.attrs, collected_at)
            new_iocs += created
            conn.execute(
                "INSERT OR IGNORE INTO intel (ioc_id, source_id, feed, record_key, attrs, raw, collected_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ioc_id, source_id, rec.feed, rec.key, json.dumps(rec.fields, sort_keys=True), rec.raw, collected_at),
            )
            if norm.type == IocType.URL:
                host = norm.attrs["host"]
                kind = IocType.IPV6 if _is_v6(host) else IocType.IPV4 if _is_v4(host) else IocType.DOMAIN
                host_ioc = normalize_value(kind, host, trusted=True)
                host_id, created = upsert_ioc(conn, host_ioc.type.value, host_ioc.value, host_ioc.attrs, collected_at)
                new_iocs += created
                conn.execute(
                    "INSERT OR IGNORE INTO relations (parent_id, child_id, kind, source_id) VALUES (?, ?, 'url_host', ?)",
                    (ioc_id, host_id, source_id),
                )
    return LoadResult(source_id, False, len(parsed.records), rejected, parsed.skipped, new_iocs)


def _is_v4(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


def _is_v6(host: str) -> bool:
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        return False
