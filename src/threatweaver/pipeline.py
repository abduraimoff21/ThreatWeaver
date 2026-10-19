"""Run the whole offline pipeline on a directory: ingest -> load feeds -> correlate -> triage -> report."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import store
from .correlate import CorrelationResult, correlate, save_links
from .feeds import FEODO, URLHAUS, load_feed
from .report import build_report
from .triage import Verdict, triage

FEED_FILES = {"feodo.json": FEODO, "urlhaus.csv": URLHAUS}
FIXED_TIME = "2026-10-14T12:00:00+00:00"  # deterministic timestamps for reproducible synthetic runs


@dataclass
class PipelineRun:
    conn: sqlite3.Connection
    result: CorrelationResult
    verdicts: dict[int, Verdict]
    report: dict[str, Any]
    seconds: dict[str, float] = field(default_factory=dict)


def load_scenario(conn: sqlite3.Connection, scenario_dir: str | Path, timestamp: str | None = FIXED_TIME) -> None:
    """Ingest `<dir>/docs/*` as sources and any known feed snapshots in `<dir>/feeds/`."""
    root = Path(scenario_dir)
    for doc in sorted((root / "docs").glob("*")):
        if doc.is_file():
            store.ingest_text(conn, doc.read_text(encoding="utf-8", errors="replace"), doc.name, observed_at=timestamp)
    for name, spec in FEED_FILES.items():
        path = root / "feeds" / name
        if path.exists():
            load_feed(conn, spec, path.read_text(encoding="utf-8"), collected_at=timestamp)


def run(conn: sqlite3.Connection, generated_at: str | None = FIXED_TIME, persist: bool = True) -> PipelineRun:
    import time

    timings: dict[str, float] = {}
    t = time.perf_counter()
    result = correlate(conn)
    if persist:  # the links table is only a cache; read-only callers (the dashboard) skip it
        save_links(conn, result.links)
    timings["correlate"] = time.perf_counter() - t
    t = time.perf_counter()
    verdicts = triage(conn, result)
    timings["triage"] = time.perf_counter() - t
    t = time.perf_counter()
    report = build_report(conn, generated_at, result, verdicts)
    timings["report"] = time.perf_counter() - t
    return PipelineRun(conn, result, verdicts, report, timings)


def run_scenario(scenario_dir: str | Path, db_path: str | Path = ":memory:") -> PipelineRun:
    import time

    conn = store.connect(db_path)
    t = time.perf_counter()
    load_scenario(conn, scenario_dir)
    load_time = time.perf_counter() - t
    pr = run(conn)
    pr.seconds["ingest_and_feeds"] = load_time
    return pr
