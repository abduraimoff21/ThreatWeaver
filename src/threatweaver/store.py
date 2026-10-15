"""Module B (part 2): SQLite store with de-duplication and provenance.

One row per unique (type, value) in `iocs`; every place that indicator was
seen is a row in `observations` pointing at the source, the exact original
text, its offsets and line number. Nothing is ever merged away without a trail:
deleting duplicates would lose the provenance, so duplicates are collapsed by
construction and the evidence is kept in `observations`.

Ingesting the same source content twice is a no-op.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .extract import extract
from .normalize import normalize

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id             INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    ingested_at    TEXT NOT NULL,
    UNIQUE (name, content_sha256)
);
CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY,
    type       TEXT NOT NULL,
    value      TEXT NOT NULL,
    attrs      TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE (type, value)
);
CREATE TABLE IF NOT EXISTS observations (
    id                    INTEGER PRIMARY KEY,
    ioc_id                INTEGER NOT NULL REFERENCES iocs(id),
    source_id             INTEGER NOT NULL REFERENCES sources(id),
    raw                   TEXT NOT NULL,
    span_start            INTEGER NOT NULL,
    span_end              INTEGER NOT NULL,
    line_no               INTEGER NOT NULL,
    defanged              INTEGER NOT NULL,
    parent_observation_id INTEGER REFERENCES observations(id),
    context               TEXT,
    UNIQUE (source_id, ioc_id, span_start, span_end)
);
CREATE TABLE IF NOT EXISTS relations (
    id        INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES iocs(id),
    child_id  INTEGER NOT NULL REFERENCES iocs(id),
    kind      TEXT NOT NULL,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    UNIQUE (parent_id, child_id, kind, source_id)
);
CREATE TABLE IF NOT EXISTS intel (
    id           INTEGER PRIMARY KEY,
    ioc_id       INTEGER NOT NULL REFERENCES iocs(id),
    source_id    INTEGER NOT NULL REFERENCES sources(id),
    feed         TEXT NOT NULL,
    record_key   TEXT NOT NULL,
    attrs        TEXT NOT NULL,
    raw          TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    UNIQUE (source_id, ioc_id, record_key)
);
CREATE TABLE IF NOT EXISTS links (
    id          INTEGER PRIMARY KEY,
    rule        TEXT NOT NULL,
    ioc_a       INTEGER NOT NULL REFERENCES iocs(id),
    ioc_b       INTEGER NOT NULL REFERENCES iocs(id),
    explanation TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    weight      INTEGER NOT NULL,
    UNIQUE (rule, ioc_a, ioc_b)
);
CREATE TABLE IF NOT EXISTS advisories (
    id              INTEGER PRIMARY KEY,
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    content_sha256  TEXT NOT NULL,
    status          TEXT NOT NULL,
    author          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    reviewer        TEXT,
    reviewed_at     TEXT,
    review_note     TEXT,
    approved_sha256 TEXT,
    published_at    TEXT,
    published_path  TEXT
);
CREATE TABLE IF NOT EXISTS advisory_events (
    id             INTEGER PRIMARY KEY,
    advisory_id    INTEGER NOT NULL REFERENCES advisories(id),
    action         TEXT NOT NULL,
    actor          TEXT NOT NULL,
    at             TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    note           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_intel_ioc ON intel(ioc_id);
CREATE INDEX IF NOT EXISTS idx_rel_parent ON relations(parent_id);
CREATE INDEX IF NOT EXISTS idx_rel_child ON relations(child_id);
CREATE INDEX IF NOT EXISTS idx_obs_ioc ON observations(ioc_id);
CREATE INDEX IF NOT EXISTS idx_obs_source ON observations(source_id);
"""


@dataclass(frozen=True)
class IngestResult:
    source_id: int
    already_ingested: bool = False
    candidates: int = 0
    rejected: int = 0
    new_iocs: int = 0
    new_observations: int = 0


def connect(path: str | Path = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases created by older versions up to the current schema."""
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(observations)")}
    if "context" not in columns:
        with conn:
            conn.execute("ALTER TABLE observations ADD COLUMN context TEXT")


CONTEXT_CHARS = 200
NEWLINE = chr(10)
CARRIAGE_RETURN = chr(13)


def _context(text: str, start: int, end: int) -> str:
    """The log line around a sighting (at most ~400 characters), for display only."""
    line_start = text.rfind(NEWLINE, 0, start) + 1
    line_end = text.find(NEWLINE, end)
    line_end = len(text) if line_end == -1 else line_end
    a, b = max(line_start, start - CONTEXT_CHARS), min(line_end, end + CONTEXT_CHARS)
    return text[a:b].strip(CARRIAGE_RETURN)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ingest_text(
    conn: sqlite3.Connection,
    text: str,
    source_name: str,
    source_kind: str = "file",
    observed_at: str | None = None,
) -> IngestResult:
    """Extract, normalize and store every IOC in `text`, recording provenance."""
    observed_at = observed_at or _now()
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    with conn:  # one transaction: either the whole source lands or none of it
        existing = conn.execute(
            "SELECT id FROM sources WHERE name = ? AND content_sha256 = ?", (source_name, digest)
        ).fetchone()
        if existing:
            return IngestResult(source_id=existing["id"], already_ingested=True)

        source_id = conn.execute(
            "INSERT INTO sources (name, kind, content_sha256, ingested_at) VALUES (?, ?, ?, ?)",
            (source_name, source_kind, digest, observed_at),
        ).lastrowid

        newlines = [i for i, ch in enumerate(text) if ch == "\n"]
        candidates = extract(text)
        obs_ids: dict[int, int] = {}  # id(candidate) -> observation row id
        ioc_ids: dict[int, int] = {}  # id(candidate) -> ioc row id
        rejected = new_iocs = new_obs = 0

        # extract() lists a URL before its derived host, so parents are stored first.
        for cand in candidates:
            norm = normalize(cand)
            if norm is None:
                rejected += 1
                continue
            ioc_id, created = upsert_ioc(conn, norm.type.value, norm.value, norm.attrs, observed_at)
            new_iocs += created
            ioc_ids[id(cand)] = ioc_id
            parent = obs_ids.get(id(cand.derived_from)) if cand.derived_from else None
            cur = conn.execute(
                "INSERT OR IGNORE INTO observations "
                "(ioc_id, source_id, raw, span_start, span_end, line_no, defanged, parent_observation_id, context) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ioc_id, source_id, cand.raw, cand.start, cand.end,
                 bisect_right(newlines, cand.start - 1) + 1, int(cand.defanged), parent,
                 _context(text, cand.start, cand.end)),
            )
            if cur.rowcount:
                new_obs += 1
                obs_ids[id(cand)] = cur.lastrowid
            if cand.derived_from is not None and id(cand.derived_from) in ioc_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO relations (parent_id, child_id, kind, source_id) VALUES (?, ?, 'url_host', ?)",
                    (ioc_ids[id(cand.derived_from)], ioc_id, source_id),
                )

    return IngestResult(source_id, False, len(candidates), rejected, new_iocs, new_obs)


def upsert_ioc(conn: sqlite3.Connection, kind: str, value: str, attrs: dict[str, str], seen: str) -> tuple[int, int]:
    row = conn.execute("SELECT id FROM iocs WHERE type = ? AND value = ?", (kind, value)).fetchone()
    if row:
        conn.execute("UPDATE iocs SET last_seen = MAX(last_seen, ?) WHERE id = ?", (seen, row["id"]))
        return row["id"], 0
    cur = conn.execute(
        "INSERT INTO iocs (type, value, attrs, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (kind, value, json.dumps(attrs, sort_keys=True), seen, seen),
    )
    return cur.lastrowid, 1


def ingest_file(conn: sqlite3.Connection, path: str | Path, source_kind: str = "file") -> IngestResult:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return ingest_text(conn, text, source_name=p.name, source_kind=source_kind)


def list_iocs(conn: sqlite3.Connection, ioc_type: str | None = None, min_sources: int = 1) -> list[sqlite3.Row]:
    sql = (
        "SELECT i.id, i.type, i.value, i.attrs, i.first_seen, i.last_seen, "
        "COUNT(o.id) AS observations, COUNT(DISTINCT o.source_id) AS sources "
        "FROM iocs i JOIN observations o ON o.ioc_id = i.id "
        "WHERE (? IS NULL OR i.type = ?) GROUP BY i.id HAVING sources >= ? "
        "ORDER BY observations DESC, i.type, i.value"
    )
    return conn.execute(sql, (ioc_type, ioc_type, min_sources)).fetchall()


def provenance(conn: sqlite3.Connection, ioc_type: str, value: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT o.id, s.name AS source, s.kind, o.line_no, o.span_start, o.span_end, o.raw, "
        "o.defanged, o.parent_observation_id "
        "FROM observations o JOIN iocs i ON i.id = o.ioc_id JOIN sources s ON s.id = o.source_id "
        "WHERE i.type = ? AND i.value = ? ORDER BY s.name, o.span_start",
        (ioc_type, value),
    ).fetchall()
