"""Module B (part 2): SQLite store with de-duplication and provenance.

One row per unique (type, value) in `iocs`; every place that indicator was
seen is a row in `observations` pointing at the source, the exact original
text, its offsets and line number. Nothing is ever merged away without a trail:
deleting duplicates would lose the provenance, so duplicates are collapsed by
construction and the evidence is kept in `observations`.

Ingesting the same source content twice is a no-op.

`ioc_source_stats` keeps, for every indicator and source, how many times it was seen and how many of those
were written defanged on their own. It is filled while a file is ingested, so the analysis never has to count
millions of sightings again; databases made by older versions get it filled in once (`ensure_stats`).
"""

from __future__ import annotations

import codecs
import hashlib
import json
import sqlite3
from bisect import bisect_right
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .extract import extract
from .models import IocType
from .normalize import normalize

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id             INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    ingested_at    TEXT NOT NULL,
    stats_done     INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS ioc_source_stats (
    ioc_id          INTEGER NOT NULL,
    source_id       INTEGER NOT NULL,
    sightings       INTEGER NOT NULL,
    direct_defanged INTEGER NOT NULL,
    PRIMARY KEY (ioc_id, source_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if str(path) != ":memory:":
        # WAL lets the dashboard keep reading while a large file is being ingested in one transaction.
        if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
            conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases created by older versions up to the current schema."""
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(observations)")}
    if "context" not in columns:
        with conn:
            conn.execute("ALTER TABLE observations ADD COLUMN context TEXT")
    if "stats_done" not in {r["name"] for r in conn.execute("PRAGMA table_info(sources)")}:
        with conn:  # instant: only the table definition changes. The summary itself is built by ensure_stats.
            conn.execute("ALTER TABLE sources ADD COLUMN stats_done INTEGER NOT NULL DEFAULT 0")


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


CHUNK_BYTES = 4 * 1024 * 1024  # text is processed this much at a time, always ending on a line boundary
MAX_LINE_BYTES = 64 * 1024 * 1024  # a "line" longer than this is split at whitespace instead of growing without limit
IOC_CACHE_LIMIT = 400_000
_LONG_LINE_BREAKS = (b" ", b"\t", b",", b";")


@dataclass
class _Totals:
    candidates: int = 0
    rejected: int = 0
    new_iocs: int = 0
    new_observations: int = 0


def _newline_positions(text: str) -> list[int]:
    out: list[int] = []
    i = text.find(NEWLINE)
    while i != -1:
        out.append(i)
        i = text.find(NEWLINE, i + 1)
    return out


def _store_chunk(
    conn: sqlite3.Connection,
    text: str,
    source_id: int,
    observed_at: str,
    char_offset: int,
    line_base: int,
    totals: _Totals,
    ioc_cache: dict[tuple[str, str], int],
) -> None:
    """Extract and store one chunk. `char_offset` / `line_base` make spans and line numbers absolute."""
    newlines = _newline_positions(text)
    candidates = extract(text)
    totals.candidates += len(candidates)
    obs_ids: dict[int, int] = {}  # id(candidate) -> observation row id (parents are listed before their hosts)
    ioc_ids: dict[int, int] = {}  # id(candidate) -> ioc row id
    seen: dict[int, list[int]] = {}  # ioc id -> [sightings stored, of which written defanged on their own]

    for cand in candidates:
        norm = normalize(cand)
        if norm is None:
            totals.rejected += 1
            continue
        key = (norm.type.value, norm.value)
        ioc_id = ioc_cache.get(key)
        if ioc_id is None:
            ioc_id, created = upsert_ioc(conn, norm.type.value, norm.value, norm.attrs, observed_at)
            totals.new_iocs += created
            if len(ioc_cache) >= IOC_CACHE_LIMIT:
                ioc_cache.clear()
            ioc_cache[key] = ioc_id
        ioc_ids[id(cand)] = ioc_id
        parent = obs_ids.get(id(cand.derived_from)) if cand.derived_from else None
        cur = conn.execute(
            "INSERT OR IGNORE INTO observations "
            "(ioc_id, source_id, raw, span_start, span_end, line_no, defanged, parent_observation_id, context) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ioc_id, source_id, cand.raw, char_offset + cand.start, char_offset + cand.end,
             line_base + bisect_right(newlines, cand.start - 1) + 1, int(cand.defanged), parent,
             _context(text, cand.start, cand.end)),
        )
        if cur.rowcount:
            totals.new_observations += 1
            obs_ids[id(cand)] = cur.lastrowid
            counts = seen.setdefault(ioc_id, [0, 0])
            counts[0] += 1
            counts[1] += 1 if (cand.defanged and parent is None) else 0
        if cand.derived_from is not None and id(cand.derived_from) in ioc_ids:
            kind = "email_domain" if cand.derived_from.type == IocType.EMAIL else "url_host"
            conn.execute(
                "INSERT OR IGNORE INTO relations (parent_id, child_id, kind, source_id) VALUES (?, ?, ?, ?)",
                (ioc_ids[id(cand.derived_from)], ioc_id, kind, source_id),
            )
    if seen:
        conn.executemany(
            "INSERT INTO ioc_source_stats (ioc_id, source_id, sightings, direct_defanged) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (ioc_id, source_id) DO UPDATE SET sightings = sightings + excluded.sightings, "
            "direct_defanged = direct_defanged + excluded.direct_defanged",
            [(i, source_id, n, d) for i, (n, d) in seen.items()],
        )


def _existing_source(conn: sqlite3.Connection, name: str, digest: str) -> int | None:
    row = conn.execute("SELECT id FROM sources WHERE name = ? AND content_sha256 = ?", (name, digest)).fetchone()
    return row["id"] if row else None


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
        existing = _existing_source(conn, source_name, digest)
        if existing:
            return IngestResult(source_id=existing, already_ingested=True)
        source_id = conn.execute(
            "INSERT INTO sources (name, kind, content_sha256, ingested_at, stats_done) VALUES (?, ?, ?, ?, 1)",
            (source_name, source_kind, digest, observed_at),
        ).lastrowid
        totals = _Totals()
        _store_chunk(conn, text, source_id, observed_at, 0, 0, totals, {})
    return IngestResult(source_id, False, totals.candidates, totals.rejected, totals.new_iocs, totals.new_observations)


def _sha256_file(path: Path, block: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(block)
            if not data:
                return h.hexdigest()
            h.update(data)


def _read_chunks(path: Path, chunk_bytes: int, max_line_bytes: int) -> Iterator[tuple[str, int]]:
    """Yield (text, bytes consumed). Chunks end on a newline, so no indicator is ever cut in half.

    Only a line longer than `max_line_bytes` is split (at whitespace, comma or semicolon when
    possible). An incremental decoder makes multi-byte characters safe at any cut, and gives the
    same text as decoding the whole file at once.
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    pending = b""
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk_bytes)
            if not block:
                tail = decoder.decode(pending, final=True)
                if tail:
                    yield tail, len(pending)
                return
            pending += block
            cut = pending.rfind(b"\n") + 1  # bytes to emit: everything up to and including the last newline
            if cut == 0:
                if len(pending) < max_line_bytes:
                    continue  # still inside one long line; keep reading
                cut = max(pending.rfind(b) for b in _LONG_LINE_BREAKS) + 1 or len(pending)
            text = decoder.decode(pending[:cut])
            consumed = cut
            pending = pending[cut:]
            if text:
                yield text, consumed
            elif consumed:
                yield "", consumed


def ingest_path(
    conn: sqlite3.Connection,
    path: str | Path,
    source_name: str | None = None,
    source_kind: str = "file",
    observed_at: str | None = None,
    chunk_bytes: int = CHUNK_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
    progress: Callable[[int, int], None] | None = None,
) -> IngestResult:
    """Ingest a text file of any size with bounded memory.

    The file is hashed first (its SHA-256 is the file's own, so `Get-FileHash` agrees), then read in
    chunks inside a single transaction: either the whole file lands or none of it. `progress` is
    called with (bytes done, total bytes) after each chunk.
    """
    p = Path(path)
    name = source_name or p.name
    observed_at = observed_at or _now()
    total = p.stat().st_size
    digest = _sha256_file(p)

    with conn:
        existing = _existing_source(conn, name, digest)
        if existing:
            return IngestResult(source_id=existing, already_ingested=True)
        source_id = conn.execute(
            "INSERT INTO sources (name, kind, content_sha256, ingested_at, stats_done) VALUES (?, ?, ?, ?, 1)",
            (name, source_kind, digest, observed_at),
        ).lastrowid
        totals, cache = _Totals(), {}
        char_offset = line_base = done = 0
        for text, consumed in _read_chunks(p, chunk_bytes, max_line_bytes):
            if text:
                _store_chunk(conn, text, source_id, observed_at, char_offset, line_base, totals, cache)
                char_offset += len(text)
                line_base += text.count(NEWLINE)
            done += consumed
            if progress:
                progress(done, total)
    return IngestResult(source_id, False, totals.candidates, totals.rejected, totals.new_iocs, totals.new_observations)


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
    return ingest_path(conn, path, source_kind=source_kind)


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


def ensure_stats(conn: sqlite3.Connection) -> int:
    """Fill in the per-indicator summary for sources that do not have it yet (databases made by an older
    version). One pass over that source's sightings, in its own transaction, so it can be repeated if
    interrupted. Does nothing, and writes nothing, once every source is done. Returns how many it filled in."""
    todo = [r["id"] for r in conn.execute("SELECT id FROM sources WHERE stats_done = 0 ORDER BY id")]
    for source_id in todo:
        with conn:
            conn.execute("DELETE FROM ioc_source_stats WHERE source_id = ?", (source_id,))
            conn.execute(
                "INSERT INTO ioc_source_stats (ioc_id, source_id, sightings, direct_defanged) "
                "SELECT ioc_id, source_id, COUNT(*), COALESCE(SUM(defanged = 1 AND parent_observation_id IS NULL), 0) "
                "FROM observations WHERE source_id = ? GROUP BY ioc_id", (source_id,))
            conn.execute("UPDATE sources SET stats_done = 1 WHERE id = ?", (source_id,))
    return len(todo)


def first_observation_ids(conn: sqlite3.Connection, ioc_ids: Iterable[int], limit: int, direct_defanged_only: bool = False) -> dict[int, list[int]]:
    """The first `limit` sighting ids of each indicator, oldest first. One short index lookup per indicator,
    instead of numbering every sighting in the database."""
    extra = " AND defanged = 1 AND parent_observation_id IS NULL" if direct_defanged_only else ""
    sql = f"SELECT id FROM observations WHERE ioc_id = ?{extra} ORDER BY id LIMIT ?"
    return {i: [r[0] for r in conn.execute(sql, (i, limit))] for i in ioc_ids}


def bump_epoch(conn: sqlite3.Connection) -> None:
    """Called when something is deleted: a saved analysis made before this point must not be trusted."""
    with conn:
        conn.execute("INSERT INTO meta (key, value) VALUES ('epoch', '1') "
                     "ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1")


def epoch(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key = 'epoch'").fetchone()
    return int(row[0]) if row else 0


# ------------------------------------------------------------------ removing an upload
REMOVE_BATCH = 100_000  # sightings deleted per transaction; keeps the write-ahead log small on a huge source


@dataclass(frozen=True)
class RemovalResult:
    source_id: int
    name: str
    sightings: int  # sightings of that source that were deleted
    relations: int  # url_host / email_domain relations recorded by that source
    indicators: int  # indicators seen nowhere else, which were deleted too


def remove_source(
    conn: sqlite3.Connection,
    source_id: int,
    progress: Callable[[int, int], None] | None = None,
    batch: int = REMOVE_BATCH,
) -> RemovalResult:
    """Delete one uploaded file or pasted text: its sightings, its relations, and every indicator that was
    seen nowhere else. Indicators that other sources or a feed still refer to are kept.

    Feed snapshots are not uploads and are refused. The correlation cache (`links`) is cleared because it
    was computed from data that has changed. Sightings go in batches, each its own transaction, so a source
    with millions of them does not build a giant write-ahead log; `progress` is called with (done, total)
    after each one. If the process dies half way the source is still listed: remove it again to finish
    (indicators that only that part of the source mentioned can then be left behind, unused and harmless).
    """
    row = conn.execute("SELECT id, name, kind FROM sources WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        raise LookupError("no such source")
    if row["kind"] == "feed":
        raise ValueError("a feed snapshot is not an upload; download the feed again to replace it")
    total = conn.execute("SELECT COUNT(*) FROM observations WHERE source_id = ?", (source_id,)).fetchone()[0]
    done = 0
    bump_epoch(conn)  # from here until it finishes, a half-removed source must not be taken for the finished one
    # Every sighting of this source goes, children (the host of a URL) and parents together, so the references
    # between them hold once it is finished. SQLite checks them row by row, which would stop a batch that
    # deletes a parent first, so checking is paused on this connection while the batches run.
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        with conn:
            conn.execute("CREATE TEMP TABLE IF NOT EXISTS removing_iocs (ioc_id INTEGER PRIMARY KEY)")
            conn.execute("DELETE FROM removing_iocs")
        lo, hi = conn.execute("SELECT MIN(id), MAX(id) FROM observations WHERE source_id = ?", (source_id,)).fetchone()
        start = lo
        while lo is not None and start <= hi:
            end = start + max(1, batch) - 1
            with conn:
                conn.execute("INSERT OR IGNORE INTO removing_iocs SELECT ioc_id FROM observations "
                             "WHERE source_id = ? AND id BETWEEN ? AND ?", (source_id, start, end))
                done += conn.execute("DELETE FROM observations WHERE source_id = ? AND id BETWEEN ? AND ?",
                                     (source_id, start, end)).rowcount
            if progress:
                progress(done, total)
            start = end + 1
        with conn:
            conn.execute("INSERT OR IGNORE INTO removing_iocs SELECT parent_id FROM relations WHERE source_id = ?", (source_id,))
            conn.execute("INSERT OR IGNORE INTO removing_iocs SELECT child_id FROM relations WHERE source_id = ?", (source_id,))
            relations = conn.execute("DELETE FROM relations WHERE source_id = ?", (source_id,)).rowcount
            conn.execute("DELETE FROM ioc_source_stats WHERE source_id = ?", (source_id,))
            conn.execute("DELETE FROM links")
            removed = conn.execute(
                "DELETE FROM iocs WHERE id IN (SELECT ioc_id FROM removing_iocs) "
                "AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.ioc_id = iocs.id) "
                "AND NOT EXISTS (SELECT 1 FROM intel t WHERE t.ioc_id = iocs.id) "
                "AND NOT EXISTS (SELECT 1 FROM relations r WHERE r.parent_id = iocs.id) "
                "AND NOT EXISTS (SELECT 1 FROM relations r WHERE r.child_id = iocs.id)").rowcount
            conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
            conn.execute("DROP TABLE IF EXISTS temp.removing_iocs")
            conn.execute("INSERT INTO meta (key, value) VALUES ('epoch', '1') "
                         "ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1")
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
    try:  # give the space in the log back; a reader that is busy just means it happens later
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.DatabaseError:
        pass
    return RemovalResult(source_id, row["name"], done, relations, removed)
