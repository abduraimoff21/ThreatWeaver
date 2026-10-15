"""Module F: investigation reports (JSON + Markdown) with end-to-end traceability.

`build_report` returns a plain dict; the Markdown is rendered from that same
dict, so the two cannot disagree. Every claim in it (a triage rule hit, a
sighting, a feed record, a link) carries ids that point at stored rows, and
`verify_traceability` re-reads those rows to prove each one still exists and
says what the report says it does.

Indicators are defanged in Markdown so the report is safe to paste anywhere.
The JSON keeps exact values for machine use.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .correlate import CorrelationResult, Evidence, clusters, correlate
from .defang import defang
from .triage import LEVELS, RULE_DESCRIPTIONS, Verdict, triage

NOTICE = (
    "DRAFT FOR ANALYST REVIEW. Triage levels are suggestions from simple rules, not findings. "
    "ThreatWeaver does not block, quarantine or publish anything. Indicators are defanged."
)
LEVEL_ORDER = [name for name, _ in LEVELS]


def _ev(evidence: tuple[Evidence, ...]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, int], dict[str, Any]] = {}
    for e in evidence:
        seen[(e.kind, e.id)] = e.to_dict()
    return [seen[k] for k in sorted(seen)]


def build_report(
    conn: sqlite3.Connection,
    generated_at: str | None = None,
    result: CorrelationResult | None = None,
    verdicts: dict[int, Verdict] | None = None,
) -> dict[str, Any]:
    result = result or correlate(conn)
    verdicts = verdicts or triage(conn, result)
    iocs = {r["id"]: r for r in conn.execute("SELECT id, type, value, attrs FROM iocs")}
    sources = {r["id"]: r for r in conn.execute("SELECT id, name, kind, content_sha256, ingested_at FROM sources")}

    def ioc_ref(i: int) -> dict[str, Any]:
        return {"id": i, "type": iocs[i]["type"], "value": iocs[i]["value"]}

    sightings: dict[int, list[dict[str, Any]]] = {}
    for o in conn.execute("SELECT * FROM observations ORDER BY id"):
        sightings.setdefault(o["ioc_id"], []).append({
            "observation_id": o["id"], "source": sources[o["source_id"]]["name"], "line": o["line_no"],
            "raw": o["raw"], "defanged": bool(o["defanged"]), "derived_from_url": o["parent_observation_id"] is not None,
        })
    intel: dict[int, dict[int, dict[str, Any]]] = {}
    for t in conn.execute("SELECT * FROM intel ORDER BY id"):
        intel.setdefault(t["ioc_id"], {})[t["id"]] = {
            "intel_id": t["id"], "feed": t["feed"], "record_key": t["record_key"], "fields": json.loads(t["attrs"]),
            "raw": t["raw"], "snapshot": sources[t["source_id"]]["name"],
            "snapshot_sha256": sources[t["source_id"]]["content_sha256"], "collected_at": t["collected_at"],
        }

    matches_for: dict[int, list[dict[str, Any]]] = {}
    for m in result.matches:
        rec = dict(intel[m.ioc_id][m.intel_id]) if m.via == "exact" else dict(intel[m.related_ioc_id][m.intel_id])
        rec["via"] = m.via
        if m.related_ioc_id is not None:
            rec["listed_url"] = iocs[m.related_ioc_id]["value"]
        matches_for.setdefault(m.ioc_id, []).append(rec)

    local = sorted(verdicts)
    cases = []
    for members in clusters(local, result.links):
        member_set = set(members)
        ordered = sorted(members, key=lambda i: (-verdicts[i].score, iocs[i]["type"], iocs[i]["value"]))
        case_id = "TW-" + hashlib.sha256(
            "\n".join(sorted(f"{iocs[i]['type']} {iocs[i]['value']}" for i in members)).encode()
        ).hexdigest()[:8]
        cases.append({
            "case_id": case_id,
            "max_score": max(verdicts[i].score for i in members),
            "max_level": min((verdicts[i].level for i in members), key=LEVEL_ORDER.index),  # LEVEL_ORDER is high -> info
            "indicators": [{
                **ioc_ref(i),
                "scope": json.loads(iocs[i]["attrs"]).get("scope"),
                "score": verdicts[i].score,
                "level": verdicts[i].level,
                "suggested_action": verdicts[i].suggested_action,
                "rules": [{"rule": h.rule, "points": h.points, "reason": h.reason, "evidence": _ev(h.evidence)}
                          for h in verdicts[i].hits],
                "sightings": sightings.get(i, []),
                "feed_matches": matches_for.get(i, []),
            } for i in ordered],
            "links": [{
                "rule": l.rule, "a": ioc_ref(l.a), "b": ioc_ref(l.b),
                "explanation": l.explanation, "evidence": _ev(l.evidence),
            } for l in result.links if l.a in member_set or l.b in member_set],
        })
    cases.sort(key=lambda c: (-c["max_score"], c["case_id"]))

    counts = Counter(v.level for v in verdicts.values())
    return {
        "report": "ThreatWeaver investigation report",
        "tool_version": __version__,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "notice": NOTICE,
        "summary": {
            "indicators": len(verdicts), "cases": len(cases),
            "by_level": {lvl: counts.get(lvl, 0) for lvl in LEVEL_ORDER},
            "links": len(result.links), "feed_matches": len(result.matches),
            "skipped_noisy_lines": result.skipped_lines,
        },
        "sources": [{"id": s["id"], "name": s["name"], "kind": s["kind"], "sha256": s["content_sha256"],
                     "ingested_at": s["ingested_at"]} for s in sources.values()],
        "rule_catalog": RULE_DESCRIPTIONS,
        "cases": cases,
    }


def _safe_field(key: str, value: Any) -> Any:
    """Defang feed field values that are (or may be) hostnames or URLs."""
    if isinstance(value, str) and (key == "hostname" or "://" in value):
        return defang(value)
    return value


def render_markdown(report: dict[str, Any]) -> str:
    def d(_kind: str, value: str) -> str:
        return defang(value)

    def refs(evidence: list[dict[str, Any]]) -> str:
        short = {"observation": "obs", "intel": "intel", "relation": "rel"}
        return " ".join(f"`{short[e['kind']]}#{e['id']}`" for e in evidence)

    s = report["summary"]
    out = [
        f"# {report['report']}",
        "",
        f"Generated {report['generated_at']} by ThreatWeaver {report['tool_version']}",
        "",
        f"> {report['notice']}",
        "",
        "## Summary",
        "",
        f"{s['indicators']} indicators in {s['cases']} case(s); {s['links']} correlation links; {s['feed_matches']} feed matches.",
        "",
        "| " + " | ".join(LEVEL_ORDER) + " |",
        "|" + "---|" * len(LEVEL_ORDER),
        "| " + " | ".join(str(s["by_level"][l]) for l in LEVEL_ORDER) + " |",
        "",
        "Sources (SHA-256 prefix pins the exact content analysed):",
        "",
    ]
    out += [f"- `{x['name']}` ({x['kind']}) `{x['sha256'][:12]}`" for x in report["sources"]]
    if s["skipped_noisy_lines"]:
        out += ["", f"{s['skipped_noisy_lines']} line(s) with too many indicators were not used for correlation."]

    for case in report["cases"]:
        out += ["", f"## Case {case['case_id']}: {len(case['indicators'])} indicator(s), highest level **{case['max_level']}**", "",
                "| Level | Score | Type | Indicator |", "|---|---|---|---|"]
        out += [f"| {i['level']} | {i['score']} | {i['type']} | `{d(i['type'], i['value'])}` |" for i in case["indicators"]]
        out += ["", "### Why"]
        for i in case["indicators"]:
            out += ["", f"**`{d(i['type'], i['value'])}`**: {i['level']} ({i['score']}). {i['suggested_action']}", ""]
            if i["rules"]:
                for r in i["rules"]:
                    out.append(f"- `{r['rule']}` {r['points']:+d}: {r['reason']} {refs(r['evidence'])}".rstrip())
            else:
                out.append("- No triage rule fired.")
            for sg in i["sightings"]:
                raw = sg["raw"] if sg["defanged"] else defang(sg["raw"])
                note = " (host of a URL)" if sg["derived_from_url"] else ""
                out.append(f"- Seen in `{sg['source']}` line {sg['line']}: `{raw}`{note} `obs#{sg['observation_id']}`")
            for fm in i["feed_matches"]:
                f = fm["fields"]
                detail = ", ".join(f"{k}={_safe_field(k, v)}" for k, v in f.items() if v not in ("", None, []))
                via = "listed" if fm["via"] == "exact" else f"hosts listed URL `{defang(fm['listed_url'])}`"
                out.append(f"- Feed `{fm['feed']}` {via}: {detail} (snapshot `{fm['snapshot']}` `{fm['snapshot_sha256'][:12]}`, `intel#{fm['intel_id']}`)")
        if case["links"]:
            out += ["", "### Links", "", "| Rule | A | B | Evidence |", "|---|---|---|---|"]
            out += [f"| `{l['rule']}` | `{d(l['a']['type'], l['a']['value'])}` | `{d(l['b']['type'], l['b']['value'])}` | {refs(l['evidence'])} |"
                    for l in case["links"]]
    out += ["", "## Method and limitations", "",
            "Triage rules:", ""]
    out += [f"- `{k}` {v}" for k, v in report["rule_catalog"].items()]
    out += ["",
            "Links come from four rules only (url_host, same_line, hostname_ip, shared_family); same_line means the same line of the same source and is evidence of co-occurrence, not of causation; hostname_ip relies on the naming convention of the host name and is a strong hint, not proof, that both refer to the same machine.",
            "Feed data is a point-in-time snapshot of public lists and can be stale or wrong. Absence from a feed is not evidence of safety.",
            ""]
    return "\n".join(out)


def verify_traceability(conn: sqlite3.Connection, report: dict[str, Any]) -> dict[str, Any]:
    """Re-read every row the report cites and check it exists and says the same thing."""
    claims = 0
    problems: list[str] = []
    tables = {"observation": "observations", "intel": "intel", "relation": "relations"}

    def check_ref(ref: dict[str, Any], where: str) -> None:
        nonlocal claims
        claims += 1
        row = conn.execute(f"SELECT 1 FROM {tables[ref['kind']]} WHERE id = ?", (ref["id"],)).fetchone()
        if row is None:
            problems.append(f"{where}: {ref['kind']}#{ref['id']} does not exist")

    for case in report["cases"]:
        for ind in case["indicators"]:
            name = f"{ind['type']} {ind['value']}"
            claims += 1
            if sum(r["points"] for r in ind["rules"]) != ind["score"]:
                problems.append(f"{name}: rule points do not add up to score")
            for r in ind["rules"]:
                for ref in r["evidence"]:
                    check_ref(ref, f"{name} {r['rule']}")
            for sg in ind["sightings"]:
                claims += 1
                row = conn.execute(
                    "SELECT o.raw, o.line_no, s.name FROM observations o JOIN sources s ON s.id = o.source_id "
                    "JOIN iocs i ON i.id = o.ioc_id WHERE o.id = ? AND i.type = ? AND i.value = ?",
                    (sg["observation_id"], ind["type"], ind["value"]),
                ).fetchone()
                if row is None or (row["raw"], row["line_no"], row["name"]) != (sg["raw"], sg["line"], sg["source"]):
                    problems.append(f"{name}: sighting obs#{sg['observation_id']} does not match the database")
            for fm in ind["feed_matches"]:
                claims += 1
                row = conn.execute("SELECT raw, feed FROM intel WHERE id = ?", (fm["intel_id"],)).fetchone()
                if row is None or (row["raw"], row["feed"]) != (fm["raw"], fm["feed"]):
                    problems.append(f"{name}: feed record intel#{fm['intel_id']} does not match the database")
        for link in case["links"]:
            for ref in link["evidence"]:
                check_ref(ref, f"link {link['rule']}")
    return {"claims": claims, "unresolved": len(problems), "problems": problems,
            "traceable_fraction": 1.0 if claims == 0 else (claims - len(problems)) / claims}
