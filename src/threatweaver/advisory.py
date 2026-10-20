"""Module H: human-approved advisory publishing.

Lifecycle:  draft -> submitted -> approved -> published        (or rejected -> draft)

What the code enforces
  * An advisory cannot be submitted while the confidentiality check has blocking
    findings (private addresses, internal host names, personal e-mail addresses,
    confidentiality / TLP:AMBER / TLP:RED markers, and any caller-supplied terms).
    There is no override flag: change the text.
  * Approval needs a reviewer who is not the author, who names the exact content
    hash they reviewed, and who supplies the typed confirmation "APPROVE <id>".
  * Any edit after approval returns the advisory to draft and voids the approval.
    Publishing re-checks that the text still matches the approved hash and re-runs
    the confidentiality check.
  * Every transition is appended to an event log with the content hash.
  * "Publishing" writes local files (Markdown + JSON). It never touches a network.

What it cannot enforce: names are self-asserted (no authentication), and a program
could pass the confirmation string itself. The command line makes the approval
step interactive-only (a terminal prompt); treat anything beyond that as process,
not code.

Drafts built from a report contain only public feed evidence. Local sightings,
source file names and internal hosts are deliberately left out.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .defang import defang, refang
from .extract import extract
from .normalize import normalize
from .triage import NON_ROUTABLE

STATUSES = ("draft", "submitted", "approved", "rejected", "published")
_INTERNAL_HOST = re.compile(r"\b[\w.-]+\.(?:local|internal|corp|lan|intranet|localdomain|home\.arpa)\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_MARKERS = re.compile(
    r"\b(?:confidential|internal use only|do not distribute|proprietary|privileged|"
    r"TLP\s*:?\s*(?:AMBER|RED)(?:\+STRICT)?)\b", re.I)
_PLACEHOLDER_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")


class AdvisoryError(Exception):
    """A workflow rule was violated (wrong state, same reviewer, hash mismatch, ...)."""


@dataclass(frozen=True)
class Finding:
    kind: str
    excerpt: str
    blocking: bool = True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def content_hash(title: str, body: str) -> str:
    return hashlib.sha256(f"{title}\n{body}".encode("utf-8")).hexdigest()


# ----------------------------------------------------------- confidentiality
def check_confidentiality(text: str, extra_terms: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    for cand in extract(text):
        norm = normalize(cand)
        if norm is None or cand.derived_from is not None:
            continue
        if norm.type.value in ("ipv4", "ipv6") and norm.attrs.get("scope") in NON_ROUTABLE:
            findings.append(Finding("non_routable_address", f"{norm.attrs['scope']} address {defang(norm.value)}"))
        if not cand.defanged and norm.type.value in ("url", "domain", "ipv4", "ipv6", "email", "filename"):
            findings.append(Finding("indicator_not_defanged", cand.raw, blocking=False))
    refanged = refang(text).text
    for m in _INTERNAL_HOST.finditer(refanged):
        findings.append(Finding("internal_hostname", defang(m.group())))
    for m in _EMAIL.finditer(refanged):
        if not m.group(1).lower().endswith(_PLACEHOLDER_EMAIL_DOMAINS):
            findings.append(Finding("email_address", "<redacted>@" + defang(m.group(1))))
    for m in _MARKERS.finditer(text):
        findings.append(Finding("confidentiality_marker", m.group()))
    lowered = text.lower()
    for term in extra_terms:
        if term and term.lower() in lowered:
            findings.append(Finding("denylisted_term", term))
    return findings


def blocking_findings(text: str, extra_terms: tuple[str, ...] = ()) -> list[Finding]:
    return [f for f in check_confidentiality(text, extra_terms) if f.blocking]


# ---------------------------------------------------------------- workflow
def _row(conn: sqlite3.Connection, advisory_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM advisories WHERE id = ?", (advisory_id,)).fetchone()
    if row is None:
        raise AdvisoryError(f"advisory {advisory_id} does not exist")
    return row


def _event(conn: sqlite3.Connection, advisory_id: int, action: str, actor: str, sha: str, at: str, note: str = "") -> None:
    conn.execute(
        "INSERT INTO advisory_events (advisory_id, action, actor, at, content_sha256, note) VALUES (?, ?, ?, ?, ?, ?)",
        (advisory_id, action, actor, at, sha, note),
    )


def _require_name(name: str, what: str) -> str:
    name = (name or "").strip()
    if not name:
        raise AdvisoryError(f"{what} name is required")
    return name


def create_draft(conn: sqlite3.Connection, title: str, body: str, author: str, now: str | None = None) -> int:
    author = _require_name(author, "author")
    now = now or _now()
    sha = content_hash(title, body)
    with conn:
        cur = conn.execute(
            "INSERT INTO advisories (title, body, content_sha256, status, author, created_at, updated_at) "
            "VALUES (?, ?, ?, 'draft', ?, ?, ?)", (title, body, sha, author, now, now))
        _event(conn, cur.lastrowid, "create", author, sha, now)
    return cur.lastrowid


def edit_draft(conn: sqlite3.Connection, advisory_id: int, title: str, body: str, actor: str, now: str | None = None) -> None:
    actor = _require_name(actor, "editor")
    now = now or _now()
    row = _row(conn, advisory_id)
    if row["status"] == "published":
        raise AdvisoryError("a published advisory is immutable; create a new advisory instead")
    sha = content_hash(title, body)
    voided = row["status"] in ("approved", "submitted")
    with conn:
        conn.execute(
            "UPDATE advisories SET title=?, body=?, content_sha256=?, status='draft', updated_at=?, reviewer=NULL, "
            "reviewed_at=NULL, review_note=NULL, approved_sha256=NULL WHERE id=?", (title, body, sha, now, advisory_id))
        _event(conn, advisory_id, "edit", actor, sha, now, "approval/submission voided" if voided else "")


def submit_for_review(conn: sqlite3.Connection, advisory_id: int, actor: str, extra_terms: tuple[str, ...] = (),
                      now: str | None = None) -> None:
    actor = _require_name(actor, "submitter")
    now = now or _now()
    row = _row(conn, advisory_id)
    if row["status"] != "draft":
        raise AdvisoryError(f"only drafts can be submitted (status is {row['status']})")
    found = blocking_findings(row["title"] + "\n" + row["body"], extra_terms)
    if found:
        listing = "; ".join(f"{f.kind}: {f.excerpt}" for f in found)
        raise AdvisoryError(f"confidentiality check failed, fix the text first: {listing}")
    with conn:
        conn.execute("UPDATE advisories SET status='submitted', updated_at=? WHERE id=?", (now, advisory_id))
        _event(conn, advisory_id, "submit", actor, row["content_sha256"], now)


def approve(conn: sqlite3.Connection, advisory_id: int, reviewer: str, seen_sha256: str, confirmation: str,
            now: str | None = None) -> None:
    reviewer = _require_name(reviewer, "reviewer")
    now = now or _now()
    row = _row(conn, advisory_id)
    if row["status"] != "submitted":
        raise AdvisoryError(f"only submitted advisories can be approved (status is {row['status']})")
    if reviewer.casefold() == row["author"].strip().casefold():
        raise AdvisoryError("the reviewer must be a different person from the author")
    if seen_sha256 != row["content_sha256"]:
        raise AdvisoryError("the content changed since you reviewed it; review the current text")
    if confirmation != f"APPROVE {advisory_id}":
        raise AdvisoryError(f'confirmation must be exactly "APPROVE {advisory_id}"')
    with conn:
        conn.execute(
            "UPDATE advisories SET status='approved', reviewer=?, reviewed_at=?, approved_sha256=?, updated_at=? WHERE id=?",
            (reviewer, now, row["content_sha256"], now, advisory_id))
        _event(conn, advisory_id, "approve", reviewer, row["content_sha256"], now)


def reject(conn: sqlite3.Connection, advisory_id: int, reviewer: str, note: str, now: str | None = None) -> None:
    reviewer = _require_name(reviewer, "reviewer")
    now = now or _now()
    row = _row(conn, advisory_id)
    if row["status"] != "submitted":
        raise AdvisoryError(f"only submitted advisories can be rejected (status is {row['status']})")
    with conn:
        conn.execute("UPDATE advisories SET status='rejected', reviewer=?, reviewed_at=?, review_note=?, updated_at=? WHERE id=?",
                     (reviewer, now, note, now, advisory_id))
        _event(conn, advisory_id, "reject", reviewer, row["content_sha256"], now, note)


def publish(conn: sqlite3.Connection, advisory_id: int, actor: str, out_dir: str | Path,
            extra_terms: tuple[str, ...] = (), now: str | None = None) -> Path:
    """Write the approved advisory to `out_dir` as local files. Never sends anything anywhere."""
    actor = _require_name(actor, "publisher")
    now = now or _now()
    row = _row(conn, advisory_id)
    if row["status"] != "approved":
        raise AdvisoryError(f"only approved advisories can be published (status is {row['status']})")
    if content_hash(row["title"], row["body"]) != row["approved_sha256"]:
        raise AdvisoryError("the text no longer matches what was approved")
    found = blocking_findings(row["title"] + "\n" + row["body"], extra_terms)
    if found:
        raise AdvisoryError("confidentiality check failed at publish time: " + "; ".join(f.kind for f in found))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"advisory-{advisory_id:04d}"
    header = (f"<!-- Approved by {row['reviewer']} at {row['reviewed_at']}; author {row['author']}; "
              f"content sha256 {row['approved_sha256']} -->\n\n")
    (out / f"{stem}.md").write_text(header + row["body"], encoding="utf-8")
    events = [dict(e) for e in conn.execute(
        "SELECT action, actor, at, content_sha256, note FROM advisory_events WHERE advisory_id = ? ORDER BY id", (advisory_id,))]
    meta = {"id": advisory_id, "title": row["title"], "author": row["author"], "reviewer": row["reviewer"],
            "approved_at": row["reviewed_at"], "published_at": now, "content_sha256": row["approved_sha256"], "events": events}
    (out / f"{stem}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    with conn:
        conn.execute("UPDATE advisories SET status='published', published_at=?, published_path=?, updated_at=? WHERE id=?",
                     (now, str(out / f"{stem}.md"), now, advisory_id))
        _event(conn, advisory_id, "publish", actor, row["approved_sha256"], now, str(out / f"{stem}.md"))
    return out / f"{stem}.md"


def get(conn: sqlite3.Connection, advisory_id: int) -> sqlite3.Row:
    return _row(conn, advisory_id)


def list_advisories(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT id, title, status, author, reviewer, updated_at FROM advisories ORDER BY id").fetchall()


def events(conn: sqlite3.Connection, advisory_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM advisory_events WHERE advisory_id = ? ORDER BY id", (advisory_id,)).fetchall()


# ------------------------------------------------------------ report -> draft
def draft_from_report(report: dict[str, Any], leave_out: frozenset[tuple[str, str]] | set[tuple[str, str]] = frozenset()) -> tuple[str, str]:
    """Build a public-evidence-only advisory draft (title, Markdown body) from a report dict.

    Included: indicators rated medium or high that have a public feed record and a
    routable address. Excluded on purpose: local sightings, source names, internal
    hosts, and indicators with no public evidence. `leave_out` holds (type, value)
    pairs an analyst judged to be a false alarm or expected activity (see lifecycle.py).
    """
    rows: list[tuple[str, str, str, str]] = []
    families: set[str] = set()
    snapshots: dict[str, tuple[str, str]] = {}
    for case in report["cases"]:
        for ind in case["indicators"]:
            if ind["level"] not in ("high", "medium") or ind["scope"] in NON_ROUTABLE or not ind["feed_matches"]:
                continue
            if (ind["type"], ind["value"]) in leave_out:
                continue
            listed = []
            for fm in ind["feed_matches"]:
                f = fm["fields"]
                fam = f.get("malware") or ""
                if fam:
                    families.add(fam)
                role = "listed" if fm["via"] == "exact" else f"hosts listed URL {defang(fm['listed_url'])}"
                listed.append(f"{fm['feed']} ({role}{', ' + fam if fam else ''}, status {f.get('status') or 'unknown'})")
                snapshots[fm["feed"]] = (fm["collected_at"], fm["snapshot_sha256"])
            rows.append((ind["level"], ind["type"], defang(ind["value"]), "; ".join(dict.fromkeys(listed))))
    if not rows:
        raise ValueError("no indicators with public feed evidence at medium or high level; nothing to advise on"
                         + (" (indicators marked as false alarms or expected were left out)" if leave_out else ""))
    rows.sort(key=lambda r: (r[0] != "high", r[1], r[2]))

    date = report["generated_at"][:10]
    label = ", ".join(sorted(families)) or "malware infrastructure"
    title = f"Advisory draft: {label} indicators ({date})"
    lines = [
        f"# {title}", "",
        "TLP:CLEAR. Prepared from public threat intelligence. DRAFT pending human review.", "",
        "## Summary", "",
        f"{len(rows)} indicator(s) are listed by public abuse.ch feeds (as of the snapshots below). "
        "Indicators are defanged.", "",
        "## Indicators", "",
        "| Level | Type | Indicator | Public listing |", "|---|---|---|---|",
    ]
    lines += [f"| {lvl} | {typ} | `{val}` | {why} |" for lvl, typ, val, why in rows]
    lines += ["", "## Basis", ""]
    for feed, (at, sha) in sorted(snapshots.items()):
        note = "CC0" if feed == "feodotracker" else "see abuse.ch terms of use"
        lines.append(f"- {feed}: snapshot collected {at}, sha256 `{sha[:12]}` ({note})")
    lines += [
        "", "## Recommended handling", "",
        "Check these indicators against your own telemetry before acting. Any blocking or containment is "
        "a decision for the receiving organisation under its own change process.", "",
        "## Caveats", "",
        "Feed listings are point-in-time, can be stale or wrong, and absence from a feed is not evidence of safety.", "",
    ]
    return title, "\n".join(lines)
