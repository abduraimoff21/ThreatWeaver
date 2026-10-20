"""The intelligence cycle, as ThreatWeaver works it.

    1 Plan      decide what you need to know (direction)            plan table, below
    2 Collect   gather logs, reports and public feeds                store.py, feeds/
    3 Process   extract, normalize, de-duplicate                     extract.py, normalize.py, store.py
    4 Analyse   correlate, rate, group into cases                    correlate.py, triage.py, report.py
    5 Share     report; advisories a different person approves       report.py, advisory.py
    6 Feedback  record what was right or wrong, then plan again      feedback table, below

Only stages 1 and 6 need data of their own, and that is all this module stores: a plan (the question being
answered, who it is for, how it may be shared) and analyst feedback (a verdict on an indicator). Feedback never
changes a score by itself. Scores stay the sum of named, readable rules, so a person decides whether a rule needs
changing; feedback shows where to look (how often "high" turned out to be a false alarm, for example) and keeps
indicators a person judged to be a false alarm out of advisory drafts.

Nothing here contacts a network, blocks anything or publishes anything.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .defang import defang
from .extract import extract

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

MAX_REQUIREMENT = 500
MAX_AUDIENCE = 200
MAX_NOTE = 500
MAX_NAME = 80

# How far a finding may travel (FIRST's Traffic Light Protocol 2.0), in plain words.
MARKINGS = {
    "TLP:CLEAR": "Can be shared publicly.",
    "TLP:GREEN": "Share with partners and the wider community, but not publicly.",
    "TLP:AMBER": "Share only inside your own organisation and with those who need it.",
    "TLP:RED": "Named recipients only. Do not pass it on.",
}
DEFAULT_MARKING = "TLP:GREEN"

VERDICTS = {
    "confirmed": "Real threat",
    "false_positive": "False alarm",
    "watch": "Keep watching",
    "expected": "Expected / normal",
}
# Verdicts that keep an indicator out of an advisory draft.
LEFT_OUT_OF_ADVISORIES = frozenset({"false_positive", "expected"})

PLAN_EXAMPLES = (
    "Which addresses and domains in these logs need an analyst's attention first?",
    "Do any of our logs touch infrastructure that public feeds list as malicious?",
    "What does this reported phishing email tell us: who sent it, where does it point, what was attached?",
)


class NotFound(ValueError):
    """The thing a request names does not exist."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value: Any, label: str, maximum: int, required: bool = True) -> str:
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    value = " ".join(_CONTROL.sub("", value).split())  # one line, no control characters
    if required and not value:
        raise ValueError(f"{label} is required")
    if len(value) > maximum:
        raise ValueError(f"{label} is longer than {maximum} characters")
    return value


def defang_text(text: str) -> str:
    """Free text made safe to paste: every indicator in it defanged (used for notes in reports)."""
    spans = [(c.start, c.end, defang(c.raw)) for c in extract(text) if c.derived_from is None and not c.defanged]
    for start, end, replacement in sorted(spans, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


# ------------------------------------------------------------------ 1 Plan
def save_plan(conn: sqlite3.Connection, requirement: Any, audience: Any, marking: Any, author: Any) -> dict[str, Any]:
    """Record the question this cycle answers. Each save is a new row, so the history of questions is kept."""
    requirement = _text(requirement, "the question", MAX_REQUIREMENT)
    if len(requirement) < 5:
        raise ValueError("the question is too short to mean anything")
    audience = _text(audience, "the audience", MAX_AUDIENCE, required=False)
    marking = marking if isinstance(marking, str) and marking in MARKINGS else None
    if marking is None:
        raise ValueError("choose a sharing level: " + ", ".join(MARKINGS))
    author = _text(author, "your name", MAX_NAME)
    with conn:
        conn.execute("INSERT INTO plan (requirement, audience, marking, author, created_at) VALUES (?, ?, ?, ?, ?)",
                     (requirement, audience, marking, author, _now()))
    return current_plan(conn) or {}


def current_plan(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT id, requirement, audience, marking, author, created_at FROM plan ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    out = {k: row[k] for k in ("id", "requirement", "audience", "marking", "author", "created_at")}
    out["marking_meaning"] = MARKINGS[row["marking"]]
    out["revisions"] = conn.execute("SELECT COUNT(*) FROM plan").fetchone()[0]
    return out


# ------------------------------------------------------------------ 6 Feedback
def add_feedback(conn: sqlite3.Connection, ioc_id: int, verdict: Any, note: Any, reviewer: Any) -> dict[str, Any]:
    """Record a person's verdict on an indicator. Append-only: a new verdict supersedes the old one but both are kept."""
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        raise ValueError("verdict must be one of: " + ", ".join(VERDICTS))
    note = _text(note, "the note", MAX_NOTE, required=False)
    reviewer = _text(reviewer, "your name", MAX_NAME)
    if conn.execute("SELECT 1 FROM iocs WHERE id = ?", (ioc_id,)).fetchone() is None:
        raise NotFound("indicator not found")
    with conn:
        cur = conn.execute("INSERT INTO feedback (ioc_id, verdict, note, reviewer, at) VALUES (?, ?, ?, ?, ?)",
                           (ioc_id, verdict, note, reviewer, _now()))
    return _feedback_row(conn.execute("SELECT * FROM feedback WHERE id = ?", (cur.lastrowid,)).fetchone())


def _feedback_row(r: sqlite3.Row) -> dict[str, Any]:
    return {"id": r["id"], "ioc_id": r["ioc_id"], "verdict": r["verdict"], "label": VERDICTS[r["verdict"]],
            "note": r["note"], "reviewer": r["reviewer"], "at": r["at"]}


def latest_verdicts(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    """ioc id -> its most recent verdict. The table holds one row per judgement, so it stays small."""
    rows = conn.execute("SELECT * FROM feedback WHERE id IN (SELECT MAX(id) FROM feedback GROUP BY ioc_id)")
    return {r["ioc_id"]: _feedback_row(r) for r in rows}


def history(conn: sqlite3.Connection, ioc_id: int) -> list[dict[str, Any]]:
    return [_feedback_row(r) for r in conn.execute("SELECT * FROM feedback WHERE ioc_id = ? ORDER BY id DESC", (ioc_id,))]


def left_out_of_advisories(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    """(type, value) of indicators whose latest verdict says they should not be advised on."""
    latest = latest_verdicts(conn)
    ids = [i for i, v in latest.items() if v["verdict"] in LEFT_OUT_OF_ADVISORIES]
    out: set[tuple[str, str]] = set()
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        out.update((r["type"], r["value"]) for r in conn.execute(
            f"SELECT type, value FROM iocs WHERE id IN ({','.join('?' * len(chunk))})", chunk))
    return out


def accuracy_by_level(latest: dict[int, dict[str, Any]], level_of: dict[int, str]) -> list[dict[str, Any]]:
    """For each suggested level: how the people who reviewed those indicators judged them."""
    order = ("high", "medium", "low", "info")
    table = {lvl: {"level": lvl, "reviewed": 0, **{v: 0 for v in VERDICTS}} for lvl in order}
    for ioc_id, fb in latest.items():
        lvl = level_of.get(ioc_id)
        if lvl in table:
            table[lvl]["reviewed"] += 1
            table[lvl][fb["verdict"]] += 1
    return [table[lvl] for lvl in order]


def feedback_counts(conn: sqlite3.Connection) -> dict[str, Any]:
    by = {v: 0 for v in VERDICTS}
    for fb in latest_verdicts(conn).values():
        by[fb["verdict"]] += 1
    return {"reviewed": sum(by.values()), "by_verdict": by}


# ------------------------------------------------------------------ where the cycle stands
STAGES = (
    ("plan", 1, "Plan"), ("collect", 2, "Collect"), ("process", 3, "Process"),
    ("analyse", 4, "Analyse"), ("share", 5, "Share"), ("feedback", 6, "Feedback"),
)


def data_version(conn: sqlite3.Connection) -> tuple[int, int]:
    """Changes whenever sightings or indicators are added (rows are only ever added), without counting them."""
    return (conn.execute("SELECT COALESCE(MAX(id), 0) FROM observations").fetchone()[0],
            conn.execute("SELECT COALESCE(MAX(id), 0) FROM iocs").fetchone()[0])


def process_counts(conn: sqlite3.Connection) -> dict[str, Any]:
    """What processing produced: sightings, and the distinct local indicators by type."""
    by_type = {r["type"]: r["n"] for r in conn.execute(
        "SELECT type, COUNT(*) AS n FROM iocs i WHERE EXISTS (SELECT 1 FROM observations o WHERE o.ioc_id = i.id) "
        "GROUP BY type ORDER BY n DESC")}
    return {"sightings": data_version(conn)[0], "indicators": sum(by_type.values()), "by_type": by_type}


def cycle_status(conn: sqlite3.Connection, busy: bool = False, feeds_loaded: int = 0,
                 analysis_summary: dict[str, Any] | None = None, process: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cheap facts about each stage (no analysis is run) and the one thing to do next."""
    plan = current_plan(conn)
    local_sources = conn.execute("SELECT COUNT(*) FROM sources WHERE kind != 'feed'").fetchone()[0]
    process = process or process_counts(conn)
    sightings, indicators, by_type = process["sightings"], process["indicators"], process["by_type"]
    advisories = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) AS n FROM advisories GROUP BY status")}
    fb = feedback_counts(conn)

    def stage(key: str, state: str, line: str) -> dict[str, Any]:
        n, name = next((n, name) for k, n, name in STAGES if k == key)
        return {"key": key, "n": n, "name": name, "state": state, "line": line}

    if analysis_summary is not None:
        analyse_line = f"{analysis_summary['cases']:,} cases; {analysis_summary['by_level']['high']:,} high, {analysis_summary['by_level']['medium']:,} medium"
    else:
        analyse_line = "Open it to see what matters most" if indicators else "Waiting for data"
    stages = [
        stage("plan", "done" if plan else "todo", plan["requirement"] if plan else "No question written yet"),
        stage("collect", "working" if busy else "done" if local_sources else "todo",
              "A file is being processed" if busy else
              (f"{local_sources} source{'s' if local_sources != 1 else ''}, {feeds_loaded} public feed{'s' if feeds_loaded != 1 else ''}" if local_sources
               else "Nothing added yet")),
        stage("process", "done" if indicators else "waiting",
              f"{indicators:,} indicators from {sightings:,} sightings" if indicators else "Happens automatically once data is added"),
        stage("analyse", "ready" if indicators else "waiting", analyse_line),
        stage("share", "done" if advisories.get("published") else "ready" if indicators else "waiting",
              (f"{sum(advisories.values())} advisor{'y' if sum(advisories.values()) == 1 else 'ies'}" if advisories else "Report ready to download") if indicators else "Waiting for data"),
        stage("feedback", "done" if fb["reviewed"] else "ready" if indicators else "waiting",
              f"{fb['reviewed']} reviewed" if fb["reviewed"] else ("Nothing reviewed yet" if indicators else "Waiting for data")),
    ]
    if plan is None:
        nxt = {"stage": "plan", "headline": "Start by writing down your question",
               "text": "A cycle starts with what you need to know. It keeps the rest of the work pointed at something.", "href": "#/plan", "button": "Write the question"}
    elif busy:
        nxt = {"stage": "collect", "headline": "Your file is being processed",
               "text": "Extraction, clean-up and de-duplication run on their own. Results appear when it finishes.", "href": "#/collect", "button": "See progress"}
    elif not local_sources:
        nxt = {"stage": "collect", "headline": "Add something to look at",
               "text": "Drop in a log file or paste a report or email. Downloading the public feeds is optional.", "href": "#/collect", "button": "Add data"}
    elif not fb["reviewed"]:
        nxt = {"stage": "analyse", "headline": "Look at what matters most",
               "text": "ThreatWeaver has grouped and rated what it found. Start with the highest priority, then tell it what was right or wrong.", "href": "#/analyse", "button": "Open priorities"}
    else:
        nxt = {"stage": "plan", "headline": "Start the next cycle",
               "text": "You have given feedback. Refine your question or add more data, and go round again.", "href": "#/plan", "button": "Review the question"}
    return {"plan": plan, "stages": stages, "next": nxt,
            "collect": {"sources": local_sources, "feeds_loaded": feeds_loaded, "busy": busy},
            "process": {"sightings": sightings, "indicators": indicators, "by_type": by_type},
            "share": {"advisories": advisories}, "feedback": fb}
