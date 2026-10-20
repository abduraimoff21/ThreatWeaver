"""Dashboard API: plain functions from a database to JSON-able dicts. No HTTP in here.

Every function takes a `Context` and returns data, or raises `ApiError(status, message)`.
Anything that came from a log or a feed is data, not markup: it is returned as JSON
strings and the front end only ever renders it with textContent. Indicator values are
returned both exact (`value`) and defanged (`display`); the UI shows `display` unless
the analyst asks for exact values.
"""

from __future__ import annotations

import heapq
import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .. import advisory, store
from ..correlate import RULES
from ..defang import defang
from ..extract import extract
from ..feeds import FEEDS, FeedError, fetch_text, load_feed
from ..pipeline import run
from ..report import _safe_field, render_markdown, verify_traceability
from ..triage import RULE_DESCRIPTIONS
from .jobs import JobManager

MAX_UPLOAD_BYTES = 1024 * 1024 * 1024  # files streamed to disk and processed in the background
MAX_PASTE_BYTES = 20 * 1024 * 1024  # pasted text travels as JSON, so it stays small
MAX_SIGHTINGS = 50
CASE_INDICATORS_MAX = 500  # a case page lists this many indicators; the Indicators page searches all of them
CASE_LINKS_MAX = 2000
DETAIL_LINKS_MAX = 100  # strongest links listed in an indicator's detail panel
PAGE_SIZE_MAX = 200
LEVELS = ("high", "medium", "low", "info")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Context:
    db_path: str
    out_dir: Path = Path("out/advisories")
    cache_dir: str = ".threatweaver-cache"
    fetcher: Callable[..., Any] = fetch_text  # injectable so tests never touch the network
    env: dict[str, str] | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)
    _cache: tuple[tuple, Any] | None = None
    _jobs: JobManager | None = None

    def connect(self) -> sqlite3.Connection:
        return store.connect(self.db_path)

    def jobs(self) -> JobManager:
        with self.lock:
            if self._jobs is None:
                self._jobs = JobManager(self.db_path)
            return self._jobs

    def require_idle(self) -> None:
        """Writes would queue behind (and time out against) a large file being ingested."""
        if self._jobs is not None and self._jobs.busy():
            raise ApiError(409, "a large file is still being processed; wait until it finishes, then try again")

    def close(self) -> None:
        if self._jobs is not None:
            self._jobs.close()

    def environ(self) -> dict[str, str]:
        return dict(os.environ) if self.env is None else self.env


# ------------------------------------------------------------------ helpers
def safe_line(text: str | None) -> str:
    """A log line made safe to show: control characters dropped, every indicator in it defanged."""
    if not text:
        return ""
    text = _CONTROL.sub("", text)
    spans = []
    for cand in extract(text):
        if cand.derived_from is None and not cand.defanged:
            spans.append((cand.start, cand.end, defang(cand.raw)))
    for start, end, replacement in sorted(spans, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


class Analysis:
    """One consistent snapshot: correlation, triage and the report, built from the database."""

    def __init__(self, conn: sqlite3.Connection):
        pr = run(conn, generated_at=None, persist=False)
        self.result, self.verdicts, self.report = pr.result, pr.verdicts, pr.report
        self.indicators: dict[int, dict[str, Any]] = {}
        self.case_of: dict[int, str] = {}
        for case in self.report["cases"]:
            for ind in case["indicators"]:
                self.indicators[ind["id"]] = ind
                self.case_of[ind["id"]] = case["case_id"]
        self.cases = {c["case_id"]: c for c in self.report["cases"]}
        self.graphs: dict[tuple, dict[str, Any]] = {}  # small cache of built graphs, dropped with this snapshot
        self.adjacencies: dict[tuple, dict[int, list]] = {}  # link index per (case, link types); see _adjacency
        self._link_index: dict[str, dict[int, list[dict[str, Any]]]] = {}

    def links_of(self, ioc_id: int) -> list[dict[str, Any]]:
        """The links touching one indicator. Indexed once per case the first time it is asked for, so opening an
        indicator costs its own links, not every link in a case that may hold millions."""
        case_id = self.case_of[ioc_id]
        index = self._link_index.get(case_id)
        if index is None:
            index = {}
            for l in self.cases[case_id]["links"]:
                index.setdefault(l["a"]["id"], []).append(l)
                index.setdefault(l["b"]["id"], []).append(l)
            self._link_index[case_id] = index
        return index.get(ioc_id, [])


def analysis(ctx: Context, conn: sqlite3.Connection) -> Analysis:
    # Rows are only ever added, so the newest id says whether anything changed. (Counting 14 million
    # sightings on every request would make every page wait for it.)
    row = conn.execute(
        "SELECT (SELECT COALESCE(MAX(id), 0) FROM observations), "
        "(SELECT COALESCE(MAX(id), 0) FROM intel), (SELECT COUNT(*) FROM sources), "
        "(SELECT COALESCE(MAX(id), 0) FROM relations)"
    ).fetchone()
    version = tuple(row)
    with ctx.lock:
        if ctx._cache and ctx._cache[0] == version:
            return ctx._cache[1]
        fresh = Analysis(conn)
        ctx._cache = (version, fresh)
        return fresh


def _row(ind: dict[str, Any], case_id: str | None = None) -> dict[str, Any]:
    return {
        "id": ind["id"], "type": ind["type"], "value": ind["value"], "display": defang(ind["value"]),
        "level": ind["level"], "score": ind["score"], "scope": ind["scope"], "case_id": case_id,
    }


def _int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ read API
def overview(ctx: Context) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        env = ctx.environ()
        sources = [dict(r) for r in conn.execute(
            "SELECT s.id, s.name, s.kind, s.content_sha256 AS sha256, s.ingested_at, "
            "(SELECT COUNT(DISTINCT ioc_id) FROM observations o WHERE o.source_id = s.id) AS indicators, "
            "(SELECT COUNT(*) FROM intel t WHERE t.source_id = s.id) AS records "
            "FROM sources s ORDER BY s.id DESC")]
        feeds = []
        for name, spec in FEEDS.items():
            latest = next((s for s in sources if s["name"] == f"feed:{name}"), None)
            feeds.append({
                "feed": name, "loaded": latest is not None,
                "collected_at": latest["ingested_at"] if latest else None,
                "records": latest["records"] if latest else 0,
                "needs_key": bool(spec.needs_env), "key_set": bool(spec.needs_env and env.get(spec.needs_env)),
                "key_variable": spec.needs_env, "min_interval_seconds": spec.min_interval_seconds,
                "terms_url": spec.terms_url,
            })
        rule_counts: dict[str, int] = {}
        for link in a.result.links:
            rule_counts[link.rule] = rule_counts.get(link.rule, 0) + 1
        return {
            "database": Path(ctx.db_path).name if ctx.db_path != ":memory:" else ":memory:",
            "summary": a.report["summary"], "link_rules": rule_counts,
            "sources": [s for s in sources if s["kind"] != "feed"], "feeds": feeds,
            "generated_at": a.report["generated_at"],
            "empty": a.report["summary"]["indicators"] == 0,
            "limits": {"upload_bytes": MAX_UPLOAD_BYTES, "paste_bytes": MAX_PASTE_BYTES},
        }
    finally:
        conn.close()


CASES_PAGE = 200


def _is_quiet(case: dict[str, Any]) -> bool:
    return not case["links"] and case["max_level"] == "info"


def cases(ctx: Context, query: dict[str, str] | None = None) -> dict[str, Any]:
    """One page of cases, highest priority first. Quiet ones (a lone, unremarkable indicator) are hidden
    unless asked for: with hundreds of thousands of indicators the full list would be enormous."""
    query = query or {}
    include_quiet = query.get("quiet") == "1"
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        everything = a.report["cases"]
        quiet_total = sum(1 for c in everything if _is_quiet(c))
        chosen = everything if include_quiet else [c for c in everything if not _is_quiet(c)]
        limit = _int(query.get("limit"), CASES_PAGE, 1, 500)
        offset = _int(query.get("offset"), 0, 0, 10**9)
        page = chosen[offset:offset + limit]
        return {
            "cases": [{
                "case_id": case["case_id"], "max_level": case["max_level"], "max_score": case["max_score"],
                "size": len(case["indicators"]), "links": len(case["links"]),
                "indicators": [_row(i, case["case_id"]) for i in case["indicators"][:6]],
            } for case in page],
            "total": len(chosen), "all_cases": len(everything), "quiet_cases": quiet_total,
            "offset": offset, "limit": limit,
        }
    finally:
        conn.close()


def case_detail(ctx: Context, case_id: str) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        case = a.cases.get(case_id)
        if case is None:
            raise ApiError(404, "case not found")
        # a case built from a big log can hold hundreds of thousands of indicators: send the strongest page of it
        shown = case["indicators"][:CASE_INDICATORS_MAX]
        return {
            "case_id": case_id, "max_level": case["max_level"], "max_score": case["max_score"],
            "indicators": [_row(i, case_id) for i in shown], "indicators_total": len(case["indicators"]),
            "links": [_link_row(l) for l in case["links"][:CASE_LINKS_MAX]], "links_total": len(case["links"]),
        }
    finally:
        conn.close()


def _link_row(link: dict[str, Any]) -> dict[str, Any]:
    return {"rule": link["rule"], "a": link["a"]["id"], "b": link["b"]["id"],
            "evidence": link["evidence_total"]}


def indicators(ctx: Context, query: dict[str, str]) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        kind, level = query.get("type", ""), query.get("level", "")
        needle = query.get("q", "").strip().lower()
        source = query.get("source", "").strip().lower()
        matches = []
        for ind in a.indicators.values():
            if kind and ind["type"] != kind:
                continue
            if level and ind["level"] != level:
                continue
            if source and not any(source in s.lower() for s in ind["sources"]):
                continue
            if needle and needle not in ind["value"].lower() and needle not in defang(ind["value"]).lower():
                continue
            matches.append(ind)
        matches.sort(key=lambda i: (-i["score"], -i["sightings_total"], i["type"], i["value"]))
        limit = _int(query.get("limit"), 50, 1, PAGE_SIZE_MAX)
        offset = _int(query.get("offset"), 0, 0, 10**9)
        rows = []
        for ind in matches[offset:offset + limit]:  # rows are built for the visible page only
            row = _row(ind, a.case_of[ind["id"]])
            row.update(sightings=ind["sightings_total"], sources=ind["sources"],
                       feed_matches=ind["feed_matches_total"], rules=[r["rule"] for r in ind["rules"]])
            rows.append(row)
        return {"total": len(matches), "offset": offset, "limit": limit, "rows": rows}
    finally:
        conn.close()


def indicator_detail(ctx: Context, ioc_id: int) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        ind = a.indicators.get(ioc_id)
        if ind is None:
            raise ApiError(404, "indicator not found")
        total = conn.execute("SELECT COUNT(*) FROM observations WHERE ioc_id = ?", (ioc_id,)).fetchone()[0]
        sightings = [{
            "observation_id": r["id"], "source": r["source"], "line": r["line_no"],
            "raw": safe_line(r["raw"]) if not r["defanged"] else _CONTROL.sub("", r["raw"]),
            "defanged": bool(r["defanged"]), "from_url": r["parent_observation_id"] is not None,
            "context": safe_line(r["context"]), "has_context": r["context"] is not None,
        } for r in conn.execute(
            "SELECT o.id, o.raw, o.line_no, o.defanged, o.parent_observation_id, o.context, s.name AS source "
            "FROM observations o JOIN sources s ON s.id = o.source_id WHERE o.ioc_id = ? ORDER BY o.id LIMIT ?",
            (ioc_id, MAX_SIGHTINGS))]
        mine = a.links_of(ioc_id)
        strongest = sorted(mine, key=lambda l: (-RULES[l["rule"]][0], -l["evidence_total"], l["a"]["id"], l["b"]["id"]))[:DETAIL_LINKS_MAX]
        links = []
        for l in strongest:
            other = l["b"] if l["a"]["id"] == ioc_id else l["a"]
            links.append({"rule": l["rule"], "other_id": other["id"], "other_type": other["type"],
                          "other": defang(other["value"]), "evidence": l["evidence_total"]})
        matches = []
        for m in ind["feed_matches"]:
            fields = {k: _safe_field(k, v) for k, v in m["fields"].items() if v not in ("", None, [])}
            matches.append({
                "feed": m["feed"], "via": m["via"], "listed_url": defang(m["listed_url"]) if m.get("listed_url") else None,
                "fields": fields, "snapshot": m["snapshot"], "collected_at": m["collected_at"],
                "intel_id": m["intel_id"],
            })
        row = _row(ind, a.case_of[ioc_id])
        row.update(
            suggested_action=ind["suggested_action"],
            rules=[{"rule": r["rule"], "points": r["points"], "reason": _defang_ioc_text(r["reason"]),
                    "description": RULE_DESCRIPTIONS.get(r["rule"], ""), "evidence_total": r["evidence_total"]} for r in ind["rules"]],
            sightings=sightings, sightings_total=total, feed_matches=matches, links=links, links_total=len(mine),
        )
        return row
    finally:
        conn.close()


def _defang_ioc_text(text: str) -> str:
    return safe_line(text)


GRAPH_LIMIT_DEFAULT = 150
GRAPH_LIMIT_MAX = 500
GRAPH_NEIGHBOURS = 6  # for each top indicator, how many of its strongest neighbours come with it
GRAPH_LINKS_PER_NODE = 3  # each indicator keeps its strongest few links in the picture
GRAPH_EDGE_CAP = 2500  # and the picture never draws more lines than this
GRAPH_CACHE_SIZE = 16
GRAPH_ADJACENCY_CACHE = 2
LEVEL_RANK = {level: n for n, level in enumerate(reversed(LEVELS))}  # info 0 ... high 3


def graph(ctx: Context, query: dict[str, str]) -> dict[str, Any]:
    """A picture a person can read. A big log yields far more links than a screen can show, so this picks the
    highest-priority indicators and the ones they connect to (not just the top scores, which are often not
    linked to each other), within `limit`. Filters: case, min_level, rules (comma list), limit."""
    case_id = query.get("case", "")
    level = query.get("min_level", "info")
    if level not in LEVEL_RANK:
        raise ApiError(400, "unknown priority level")
    rules = set(filter(None, query.get("rules", "").split(","))) or set(RULES)
    if not rules <= set(RULES):
        raise ApiError(400, "unknown link type")
    limit = _int(query.get("limit"), GRAPH_LIMIT_DEFAULT, 10, GRAPH_LIMIT_MAX)
    per_node = _int(query.get("per_node"), GRAPH_LINKS_PER_NODE, 1, 20)
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        if case_id and case_id not in a.cases:
            raise ApiError(404, "case not found")
        key = (case_id, level, tuple(sorted(rules)), limit, per_node)
        scope_key = (case_id, tuple(sorted(rules)))
        with ctx.lock:
            cached = a.graphs.get(key)
            adj = a.adjacencies.get(scope_key)
        if cached is not None:
            return cached
        if adj is None:
            adj = _adjacency(a, case_id, rules)
            with ctx.lock:
                if len(a.adjacencies) >= GRAPH_ADJACENCY_CACHE:
                    a.adjacencies.pop(next(iter(a.adjacencies)))
                a.adjacencies[scope_key] = adj
        built = _build_graph(a, case_id, LEVEL_RANK[level], limit, per_node, adj)
        with ctx.lock:
            if len(a.graphs) >= GRAPH_CACHE_SIZE:
                a.graphs.pop(next(iter(a.graphs)))
            a.graphs[key] = built
        return built
    finally:
        conn.close()


def _adjacency(a: Analysis, case_id: str, rules: set[str]) -> dict[int, list[tuple[str, int, int, int]]]:
    """indicator id -> the links touching it, as (rule, a_id, b_id, evidence count). Each link is one tuple shared
    by both ends. Built once per snapshot and link-type choice, so changing the level or size is quick."""
    ind = a.indicators
    if case_id:
        case = a.cases[case_id]
        scope: set[int] | None = {i["id"] for i in case["indicators"]}
        raw = ((l["rule"], l["a"]["id"], l["b"]["id"], l["evidence_total"]) for l in case["links"])
    else:
        scope = None
        raw = ((l.rule, l.a, l.b, len(l.evidence) if l.evidence_total is None else l.evidence_total) for l in a.result.links)
    adj: dict[int, list[tuple[str, int, int, int]]] = {}
    for link in raw:
        rule, x, y, _ = link
        if rule in rules and x != y and x in ind and y in ind and (scope is None or (x in scope and y in scope)):
            adj.setdefault(x, []).append(link)
            adj.setdefault(y, []).append(link)
    return adj


def _build_graph(a: Analysis, case_id: str, min_rank: int, limit: int, per_node: int,
                 adj: dict[int, list[tuple[str, int, int, int]]]) -> dict[str, Any]:
    ind = a.indicators

    def other(link: tuple[str, int, int, int], me: int) -> int:
        return link[2] if link[1] == me else link[1]

    # The priority level picks where to start; whatever those indicators connect to comes along at any level,
    # because "a medium host linked to a dozen quiet addresses" is exactly what an analyst wants to see.
    seeds = [i for i in adj if LEVEL_RANK[ind[i]["level"]] >= min_rank]
    chosen: dict[int, None] = {}
    for seed in sorted(seeds, key=lambda i: (-ind[i]["score"], -len(adj[i]), i)):
        if len(chosen) >= limit:
            break
        chosen.setdefault(seed)
        near = {other(link, seed) for link in adj[seed]}
        for o in heapq.nsmallest(GRAPH_NEIGHBOURS, near, key=lambda i: (-ind[i]["score"], i)):
            if len(chosen) >= limit:
                break
            chosen.setdefault(o)
    case = a.cases[case_id] if case_id else None
    if case is not None:  # a case page should show the whole case first, linked or not
        rest = sorted((i for i in case["indicators"] if i["id"] not in chosen and LEVEL_RANK[i["level"]] >= min_rank), key=lambda i: -i["score"])
        for i in rest[:max(0, limit - len(chosen))]:
            chosen[i["id"]] = None

    capped = len(chosen) >= limit
    seen: set[int] = set()
    every: list[dict[str, Any]] = []
    for x in chosen:  # only the chosen indicators' own links are looked at, never the whole link list
        for link in adj.get(x, ()):
            if id(link) not in seen and link[1] in chosen and link[2] in chosen:
                seen.add(id(link))
                every.append({"rule": link[0], "a": link[1], "b": link[2], "evidence": link[3]})
    edges = _strongest_links(every, per_node)
    if case is None:  # a node whose neighbours did not fit in the budget is just a dot; leave it out
        touched = {e["a"] for e in edges} | {e["b"] for e in edges}
        chosen = {i: None for i in chosen if i in touched}
    matching = len(seeds) if case is None else sum(1 for i in case["indicators"] if LEVEL_RANK[i["level"]] >= min_rank)
    nodes = []
    for i in chosen:
        row = _row(ind[i], a.case_of[i])
        row["degree"] = len({other(link, i) for link in adj.get(i, ())})  # how many it is linked to in all, drawn or not
        nodes.append(row)
    return {"nodes": nodes, "edges": edges, "edges_total": len(every), "matching": matching, "truncated": capped,
            "limit": limit, "per_node": per_node}


def _strongest_links(every: list[dict[str, Any]], per_node: int) -> list[dict[str, Any]]:
    """Keep each indicator's strongest links (rule weight, then how often the link was seen). Among a few hundred
    indicators from a big log nearly every pair is linked, and drawing them all is a solid black disc: this keeps
    the structure and drops the repetition. An indicator's full list of links is still in its detail panel."""
    def strength(e: dict[str, Any]) -> tuple[int, int]:
        return (RULES[e["rule"]][0], e["evidence"])

    touching: dict[int, list[int]] = {}
    for n, e in enumerate(every):
        touching.setdefault(e["a"], []).append(n)
        touching.setdefault(e["b"], []).append(n)
    keep: set[int] = set()
    for indexes in touching.values():
        keep.update(sorted(indexes, key=lambda n: strength(every[n]), reverse=True)[:per_node])
    kept = sorted(keep, key=lambda n: strength(every[n]), reverse=True)[:GRAPH_EDGE_CAP]
    return [every[n] for n in sorted(kept)]


def sources(ctx: Context) -> dict[str, Any]:
    return {"sources": overview(ctx)["sources"]}


PREVIEW_LINES = 600


def report(ctx: Context) -> dict[str, Any]:
    """A bounded preview for the page; the full files come from report_download."""
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        lines = render_markdown(a.report).split(chr(10))
        return {"preview": chr(10).join(lines[:PREVIEW_LINES]), "lines": len(lines), "truncated": len(lines) > PREVIEW_LINES,
                "summary": a.report["summary"], "traceability": verify_traceability(conn, a.report)}
    finally:
        conn.close()


def report_download(ctx: Context, fmt: str) -> tuple[bytes, str, str]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
    finally:
        conn.close()
    if fmt == "md":
        return render_markdown(a.report).encode("utf-8"), "text/markdown; charset=utf-8", "threatweaver-report.md"
    if fmt == "json":
        return json.dumps(a.report, indent=2).encode("utf-8"), "application/json; charset=utf-8", "threatweaver-report.json"
    raise ApiError(404, "unknown report format")


# ------------------------------------------------------------------ actions
def clean_name(raw: Any) -> str:
    """A display name for a source: no folders, no control characters, at most 120 characters."""
    name = str(raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    return _CONTROL.sub("", name).strip()[:120]


def ingest(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
    ctx.require_idle()
    name = clean_name(body.get("name"))
    text = body.get("text")
    if not name:
        raise ApiError(400, "a file name is required")
    if not isinstance(text, str):
        raise ApiError(400, "text content is required")
    if len(text.encode("utf-8")) > MAX_PASTE_BYTES:
        raise ApiError(413, f"pasted text is larger than {MAX_PASTE_BYTES // (1024 * 1024)} MB; upload it as a file instead")
    with ctx.lock:
        conn = ctx.connect()
        try:
            res = store.ingest_text(conn, text, name)
        finally:
            conn.close()
    return {"name": name, "already_ingested": res.already_ingested, "candidates": res.candidates,
            "new_indicators": res.new_iocs, "sightings": res.new_observations, "rejected": res.rejected}


def start_upload(ctx: Context, name: str, path: Path, size: int) -> dict[str, Any]:
    """Register a file the server has already streamed to disk; it is processed in the background."""
    job = ctx.jobs().submit(name, path, size)
    return {"job": job.to_dict()}


def jobs_status(ctx: Context) -> dict[str, Any]:
    return ctx.jobs().listing() if ctx._jobs is not None else {"jobs": [], "active": 0}


def remove_source(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
    """Delete a file or pasted text that was added earlier, with everything extracted from it. This cannot be undone
    (adding the file again brings it back), so the request must say it was confirmed; the page asks the person first.
    The work runs in the background like an upload."""
    ctx.require_idle()
    source_id = body.get("source_id")
    if not isinstance(source_id, int) or isinstance(source_id, bool):
        raise ApiError(400, "source_id must be a whole number")
    if body.get("confirmed") is not True:
        raise ApiError(400, "removing a source must be confirmed")
    conn = ctx.connect()
    try:
        row = conn.execute("SELECT id, name, kind FROM sources WHERE id = ?", (source_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ApiError(404, "no such source; it may already have been removed")
    if row["kind"] == "feed":
        raise ApiError(400, "a feed snapshot is not an upload; download the feed again to replace it")
    jobs = ctx.jobs()
    if not jobs.has_room():
        raise ApiError(429, "too many jobs are waiting; try again shortly")
    return {"job": jobs.submit_removal(source_id, row["name"]).to_dict()}


def fetch_feed(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
    ctx.require_idle()
    name = body.get("feed")
    spec = FEEDS.get(name) if isinstance(name, str) else None
    if spec is None:
        raise ApiError(400, "unknown feed")
    with ctx.lock:
        try:
            text, cached = ctx.fetcher(spec, ctx.cache_dir, force=bool(body.get("force")), env=ctx.environ())
        except FeedError as exc:
            raise ApiError(502, str(exc)) from None
        conn = ctx.connect()
        try:
            res = load_feed(conn, spec, text)
        finally:
            conn.close()
    return {"feed": name, "from_cache": cached, "already_loaded": res.already_loaded, "records": res.records,
            "new_indicators": res.new_iocs, "rejected": res.rejected, "skipped_rows": res.skipped_rows}


# ------------------------------------------------------------------ advisories
def _adv_dict(conn: sqlite3.Connection, adv_id: int, full: bool) -> dict[str, Any]:
    try:
        row = advisory.get(conn, adv_id)
    except advisory.AdvisoryError:
        raise ApiError(404, "advisory not found") from None
    out = {k: row[k] for k in ("id", "title", "status", "author", "reviewer", "reviewed_at", "review_note",
                               "created_at", "updated_at", "published_path", "content_sha256")}
    if full:
        out["body"] = row["body"]
        out["events"] = [{k: e[k] for k in ("action", "actor", "at", "content_sha256", "note")}
                         for e in advisory.events(conn, adv_id)]
        out["findings"] = _findings(row["title"] + "\n" + row["body"])
    return out


def _findings(text: str) -> list[dict[str, Any]]:
    return [{"kind": f.kind, "excerpt": safe_line(f.excerpt), "blocking": f.blocking}
            for f in advisory.check_confidentiality(text)]


def advisories(ctx: Context) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        return {"advisories": [_adv_dict(conn, r["id"], False) for r in advisory.list_advisories(conn)]}
    finally:
        conn.close()


def advisory_detail(ctx: Context, adv_id: int) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        return _adv_dict(conn, adv_id, True)
    finally:
        conn.close()


def advisory_check(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
    text = body.get("text")
    if not isinstance(text, str) or len(text) > 500_000:
        raise ApiError(400, "text is required (max 500 000 characters)")
    return {"findings": _findings(text)}


def _advisory_action(ctx: Context, adv_id: int | None, fn: Callable[[sqlite3.Connection], Any]) -> dict[str, Any]:
    ctx.require_idle()
    with ctx.lock:
        conn = ctx.connect()
        try:
            try:
                result = fn(conn)
            except advisory.AdvisoryError as exc:
                raise ApiError(404 if "does not exist" in str(exc) else 409, str(exc)) from None
            except ValueError as exc:
                raise ApiError(400, str(exc)) from None
            return _adv_dict(conn, adv_id if adv_id is not None else result, True)
        finally:
            conn.close()


def _text(body: dict[str, Any], key: str) -> str:
    value = body.get(key, "")
    return value if isinstance(value, str) else ""


def advisory_draft(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
    author = _text(body, "author")

    def go(conn: sqlite3.Connection) -> int:
        a = analysis(ctx, conn)
        title, text = advisory.draft_from_report(a.report)
        return advisory.create_draft(conn, title, text, author)

    return _advisory_action(ctx, None, go)


def advisory_edit(ctx: Context, adv_id: int, body: dict[str, Any]) -> dict[str, Any]:
    return _advisory_action(ctx, adv_id, lambda c: advisory.edit_draft(
        c, adv_id, _text(body, "title"), _text(body, "body"), _text(body, "actor")))


def advisory_submit(ctx: Context, adv_id: int, body: dict[str, Any]) -> dict[str, Any]:
    return _advisory_action(ctx, adv_id, lambda c: advisory.submit_for_review(c, adv_id, _text(body, "actor")))


def advisory_approve(ctx: Context, adv_id: int, body: dict[str, Any]) -> dict[str, Any]:
    return _advisory_action(ctx, adv_id, lambda c: advisory.approve(
        c, adv_id, _text(body, "reviewer"), _text(body, "seen_sha256"), _text(body, "confirmation")))


def advisory_reject(ctx: Context, adv_id: int, body: dict[str, Any]) -> dict[str, Any]:
    return _advisory_action(ctx, adv_id, lambda c: advisory.reject(c, adv_id, _text(body, "reviewer"), _text(body, "note")))


def advisory_publish(ctx: Context, adv_id: int, body: dict[str, Any]) -> dict[str, Any]:
    return _advisory_action(ctx, adv_id, lambda c: advisory.publish(c, adv_id, _text(body, "actor"), ctx.out_dir))
