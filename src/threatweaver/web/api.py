"""Dashboard API: plain functions from a database to JSON-able dicts. No HTTP in here.

Every function takes a `Context` and returns data, or raises `ApiError(status, message)`.
Anything that came from a log or a feed is data, not markup: it is returned as JSON
strings and the front end only ever renders it with textContent. Indicator values are
returned both exact (`value`) and defanged (`display`); the UI shows `display` unless
the analyst asks for exact values.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .. import advisory, store
from ..defang import defang
from ..extract import extract
from ..feeds import FEEDS, FeedError, fetch_text, load_feed
from ..pipeline import run
from ..report import _safe_field, render_markdown, verify_traceability
from ..triage import RULE_DESCRIPTIONS

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_SIGHTINGS = 50
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

    def connect(self) -> sqlite3.Connection:
        return store.connect(self.db_path)

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
        pr = run(conn, generated_at=None)
        self.result, self.verdicts, self.report = pr.result, pr.verdicts, pr.report
        self.indicators: dict[int, dict[str, Any]] = {}
        self.case_of: dict[int, str] = {}
        for case in self.report["cases"]:
            for ind in case["indicators"]:
                self.indicators[ind["id"]] = ind
                self.case_of[ind["id"]] = case["case_id"]
        self.cases = {c["case_id"]: c for c in self.report["cases"]}


def analysis(ctx: Context, conn: sqlite3.Connection) -> Analysis:
    row = conn.execute(
        "SELECT (SELECT COALESCE(MAX(id), 0) FROM observations), (SELECT COUNT(*) FROM observations), "
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
        }
    finally:
        conn.close()


def cases(ctx: Context) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        out = []
        for case in a.report["cases"]:
            out.append({
                "case_id": case["case_id"], "max_level": case["max_level"], "max_score": case["max_score"],
                "size": len(case["indicators"]), "links": len(case["links"]),
                "indicators": [_row(i, case["case_id"]) for i in case["indicators"]],
            })
        return {"cases": out}
    finally:
        conn.close()


def case_detail(ctx: Context, case_id: str) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        case = a.cases.get(case_id)
        if case is None:
            raise ApiError(404, "case not found")
        return {
            "case_id": case_id, "max_level": case["max_level"], "max_score": case["max_score"],
            "indicators": [_row(i, case_id) for i in case["indicators"]],
            "links": [_link_row(l) for l in case["links"]],
        }
    finally:
        conn.close()


def _link_row(link: dict[str, Any]) -> dict[str, Any]:
    return {"rule": link["rule"], "a": link["a"]["id"], "b": link["b"]["id"],
            "evidence": len(link["evidence"])}


def indicators(ctx: Context, query: dict[str, str]) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        kind, level = query.get("type", ""), query.get("level", "")
        needle = query.get("q", "").strip().lower()
        source = query.get("source", "").strip().lower()
        rows = []
        for ind in a.indicators.values():
            if kind and ind["type"] != kind:
                continue
            if level and ind["level"] != level:
                continue
            sources = sorted({s["source"] for s in ind["sightings"]})
            if source and not any(source in s.lower() for s in sources):
                continue
            if needle and needle not in ind["value"].lower() and needle not in defang(ind["value"]).lower():
                continue
            row = _row(ind, a.case_of[ind["id"]])
            row.update(sightings=len(ind["sightings"]), sources=sources,
                       feed_matches=len(ind["feed_matches"]), rules=[r["rule"] for r in ind["rules"]])
            rows.append(row)
        rows.sort(key=lambda r: (-r["score"], -r["sightings"], r["type"], r["value"]))
        limit = _int(query.get("limit"), 50, 1, PAGE_SIZE_MAX)
        offset = _int(query.get("offset"), 0, 0, 10**9)
        return {"total": len(rows), "offset": offset, "limit": limit, "rows": rows[offset:offset + limit]}
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
        links = []
        for case in [a.cases[a.case_of[ioc_id]]]:
            for l in case["links"]:
                if ioc_id in (l["a"]["id"], l["b"]["id"]):
                    other = l["b"] if l["a"]["id"] == ioc_id else l["a"]
                    links.append({"rule": l["rule"], "other_id": other["id"], "other_type": other["type"],
                                  "other": defang(other["value"]), "evidence": len(l["evidence"])})
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
                    "description": RULE_DESCRIPTIONS.get(r["rule"], ""), "evidence": r["evidence"]} for r in ind["rules"]],
            sightings=sightings, sightings_total=total, feed_matches=matches, links=links,
        )
        return row
    finally:
        conn.close()


def _defang_ioc_text(text: str) -> str:
    return safe_line(text)


def graph(ctx: Context, query: dict[str, str]) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        case_id = query.get("case", "")
        if case_id:
            case = a.cases.get(case_id)
            if case is None:
                raise ApiError(404, "case not found")
            members, links = case["indicators"], case["links"]
        else:  # everything that has at least one link
            links = [l for c in a.report["cases"] for l in c["links"]]
            linked = {l["a"]["id"] for l in links} | {l["b"]["id"] for l in links}
            members = [i for i in a.indicators.values() if i["id"] in linked]
            members.sort(key=lambda i: -i["score"])
            members = members[:300]
        keep = {i["id"] for i in members}
        seen, edges = set(), []
        for l in links:
            key = (l["rule"], l["a"]["id"], l["b"]["id"])
            if l["a"]["id"] in keep and l["b"]["id"] in keep and key not in seen:
                seen.add(key)
                edges.append({"rule": l["rule"], "a": l["a"]["id"], "b": l["b"]["id"]})
        return {"nodes": [_row(i, a.case_of[i["id"]]) for i in members], "edges": edges,
                "truncated": not case_id and len(members) == 300}
    finally:
        conn.close()


def sources(ctx: Context) -> dict[str, Any]:
    return {"sources": overview(ctx)["sources"]}


def report(ctx: Context) -> dict[str, Any]:
    conn = ctx.connect()
    try:
        a = analysis(ctx, conn)
        return {"markdown": render_markdown(a.report), "json": a.report,
                "traceability": verify_traceability(conn, a.report)}
    finally:
        conn.close()


# ------------------------------------------------------------------ actions
def ingest(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
    name = str(body.get("name", "")).replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL.sub("", name).strip()[:120]
    text = body.get("text")
    if not name:
        raise ApiError(400, "a file name is required")
    if not isinstance(text, str):
        raise ApiError(400, "text content is required")
    if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ApiError(413, f"file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    with ctx.lock:
        conn = ctx.connect()
        try:
            res = store.ingest_text(conn, text, name)
        finally:
            conn.close()
    return {"name": name, "already_ingested": res.already_ingested, "candidates": res.candidates,
            "new_indicators": res.new_iocs, "sightings": res.new_observations, "rejected": res.rejected}


def fetch_feed(ctx: Context, body: dict[str, Any]) -> dict[str, Any]:
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
