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
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from . import __version__, attack, store
from .correlate import CorrelationResult, Evidence, clusters, correlate
from .defang import defang
from .triage import LEVELS, NON_ROUTABLE, RULE_DESCRIPTIONS, Verdict, triage

NOTICE = (
    "DRAFT FOR ANALYST REVIEW. Triage levels are suggestions from simple rules, not findings. "
    "ThreatWeaver does not block, quarantine or publish anything. Indicators are defanged."
)
LEVEL_ORDER = [name for name, _ in LEVELS]

# Big inputs would otherwise produce reports nobody can open (one IP seen 867 times, 600k sightings).
# Detail is capped per indicator; the true totals are always stated, and the database keeps everything.
MAX_SIGHTINGS = 20
MAX_EVIDENCE = 20
MAX_FEED_MATCHES = 20
MAX_QUIET_ROWS = 100


def _ev(evidence: tuple[Evidence, ...], total: int | None = None) -> tuple[list[dict[str, Any]], int]:
    """Distinct evidence refs in a stable order: (the first MAX_EVIDENCE of them, the true total).

    `total` is the producer's own count when it only handed over a sample of its evidence.
    """
    seen: dict[tuple[str, int], dict[str, Any]] = {}
    for e in evidence:
        seen[(e.kind, e.id)] = e.to_dict()
    ordered = [seen[k] for k in sorted(seen)]
    return ordered[:MAX_EVIDENCE], max(len(ordered), total or 0)


def _rule_dict(hit) -> dict[str, Any]:
    shown, total = _ev(hit.evidence, hit.evidence_total)
    return {"rule": hit.rule, "points": hit.points, "reason": hit.reason, "evidence": shown, "evidence_total": total}


def _link_dict(l, ioc_ref) -> dict[str, Any]:
    shown, total = _ev(l.evidence, l.evidence_total)
    return {"rule": l.rule, "a": ioc_ref(l.a), "b": ioc_ref(l.b), "explanation": l.explanation,
            "evidence": shown, "evidence_total": total}


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

    # Sightings are summarised, never listed in full: the totals and source names come from the summary kept at
    # upload time, and only the first MAX_SIGHTINGS rows per indicator are read, each by a short index lookup.
    # Memory and time grow with the number of indicators, not with the size of the log.
    store.ensure_stats(conn)
    sight_total: dict[int, int] = {}
    sight_sources: dict[int, list[str]] = {}
    for r in conn.execute("SELECT ioc_id, source_id, sightings FROM ioc_source_stats"):
        sight_total[r["ioc_id"]] = sight_total.get(r["ioc_id"], 0) + r["sightings"]
        sight_sources.setdefault(r["ioc_id"], []).append(sources[r["source_id"]]["name"])
    sightings: dict[int, list[dict[str, Any]]] = {}
    log_lines: dict[int, list[str]] = {}  # stored log lines, read only to suggest ATT&CK hints; never put in the report
    for ioc_id in sorted(sight_total):
        wants_lines = iocs[ioc_id]["type"] not in attack.HASH_TYPES
        rows = conn.execute(
            "SELECT id, source_id, line_no, raw, defanged, parent_observation_id" + (", context" if wants_lines else "") +
            " FROM observations WHERE ioc_id = ? ORDER BY id LIMIT ?", (ioc_id, MAX_SIGHTINGS)).fetchall()
        if wants_lines:
            log_lines[ioc_id] = [o["context"] for o in rows[:attack.MAX_LINES] if o["context"]]
        sightings[ioc_id] = [{
            "observation_id": o["id"], "source": sources[o["source_id"]]["name"], "line": o["line_no"],
            "raw": o["raw"], "defanged": bool(o["defanged"]), "derived_from_url": o["parent_observation_id"] is not None,
        } for o in rows]
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

    # Links are attached to cases through an index by indicator: scanning every link for every case
    # is quadratic (800,000 single-indicator cases x hundreds of thousands of links never finishes).
    link_position = {id(l): n for n, l in enumerate(result.links)}
    links_by_ioc: dict[int, list] = defaultdict(list)
    for l in result.links:
        links_by_ioc[l.a].append(l)
        links_by_ioc[l.b].append(l)

    def attack_hints(i: int) -> list[dict[str, Any]]:
        """MITRE ATT&CK possibilities for one indicator (see attack.py); empty for most."""
        v, ioc_type = verdicts[i], iocs[i]["type"]
        email = disguised_file = risky_domain = False
        if ioc_type in ("email", "filename"):  # only these read their neighbours
            for l in links_by_ioc.get(i, ()):
                other = l.b if l.a == i else l.a
                if l.rule == "same_line":
                    email = email or iocs[other]["type"] == "email"
                    disguised_file = disguised_file or (iocs[other]["type"] == "filename" and "disguised" in json.loads(iocs[other]["attrs"]))
                elif l.rule == "email_domain" and other in verdicts and verdicts[other].level == "high":
                    risky_domain = True
        return attack.assess(attack.Facts(
            type=ioc_type, value=iocs[i]["value"], disguised=ioc_type == "filename" and "disguised" in json.loads(iocs[i]["attrs"]),
            rules={h.rule: h.points for h in v.hits}, matches=matches_for.get(i, ()), sightings=sight_total.get(i, 0),
            lines=log_lines.get(i, ()), linked_email=email, linked_disguised_file=disguised_file, linked_risky_domain=risky_domain,
            internal=ioc_type in ("ipv4", "ipv6") and json.loads(iocs[i]["attrs"]).get("scope", "") in NON_ROUTABLE))

    local = sorted(verdicts)
    cases = []
    hints_everywhere: list[list[dict[str, Any]]] = []
    for members in clusters(local, result.links):
        member_set = set(members)
        ordered = sorted(members, key=lambda i: (-verdicts[i].score, iocs[i]["type"], iocs[i]["value"]))
        hints = {i: attack_hints(i) for i in ordered}
        hints_everywhere.extend(h for h in hints.values() if h)
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
                "rules": [_rule_dict(h) for h in verdicts[i].hits],
                "sources": sorted(set(sight_sources.get(i, []))),
                "sightings_total": sight_total.get(i, 0),
                "sightings": sightings.get(i, []),
                "feed_matches_total": len(matches_for.get(i, [])),
                "feed_matches": matches_for.get(i, [])[:MAX_FEED_MATCHES],
                **({"attack": hints[i]} if hints[i] else {}),  # only where there is something to say
            } for i in ordered],
            "links": [_link_dict(l, ioc_ref) for l in sorted(
                {id(l): l for i in members for l in links_by_ioc.get(i, ())}.values(), key=lambda l: link_position[id(l)])],
        })
        if any(hints.values()):
            cases[-1]["attack"] = attack.rollup(h for h in hints.values() if h)
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
        "attack": attack.summary(attack.rollup(hints_everywhere)),
        "cases": cases,
    }


def _safe_field(key: str, value: Any) -> Any:
    """Defang feed field values that are (or may be) hostnames or URLs."""
    if isinstance(value, str) and (key == "hostname" or "://" in value):
        return defang(value)
    return value


def _is_quiet(case: dict[str, Any]) -> bool:
    """A single indicator, nothing linked to it, no triage rule fired and no ATT&CK hint to show."""
    return (not case["links"] and case["max_level"] == "info" and len(case["indicators"]) == 1
            and not case["indicators"][0]["rules"] and not case.get("attack"))


def render_markdown(report: dict[str, Any]) -> str:
    def d(_kind: str, value: str) -> str:
        return defang(value)

    def refs(evidence: list[dict[str, Any]], total: int | None = None) -> str:
        short = {"observation": "obs", "intel": "intel", "relation": "rel"}
        text = " ".join(f"`{short[e['kind']]}#{e['id']}`" for e in evidence)
        more = (total or len(evidence)) - len(evidence)
        return text + (f" (+{more} more)" if more > 0 else "")

    s = report["summary"]
    out = [
        f"# {report['report']}",
        "",
        f"Generated {report['generated_at']} by ThreatWeaver {report['tool_version']}",
        "",
        f"> {report['notice']}",
        "",
    ]
    out += [
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

    att = report.get("attack") or {}
    used = [(pid, p) for pid, p in att.get("patterns", {}).items() if p["indicators"]]
    if used:
        rank = {"feed": 0, "shape": 1, "log": 2, "volume": 3}
        out += ["", "## MITRE ATT&CK view", "", att["notice"], "",
                "| Could be | Based on | Indicators |", "|---|---|---|"]
        out += [f"| {p['title']} (`{pid}`) | {p['basis_label'].lower()} | {p['indicators']} |"
                for pid, p in sorted(used, key=lambda x: (rank[x[1]["basis"]], -x[1]["indicators"], x[0]))]
        out += ["", "| Tactic | Techniques (indicators it was suggested for) |", "|---|---|"]
        out += [f"| {g['tactic']} | " + "; ".join(f"`{t['id']}` {t['name']} ({t['indicators']})" for t in g["techniques"]) + " |"
                for g in att["by_tactic"]]
        out += ["", "Each technique's page, with how it works and how to detect it, is at " + defang(att["source"]) +
                "/techniques/<id>/ (shown defanged like every address in this report; a dot in a sub-technique id becomes a slash)."]

    detailed = [c for c in report["cases"] if not _is_quiet(c)]
    quiet = [c for c in report["cases"] if _is_quiet(c)]
    for case in detailed:
        out += ["", f"## Case {case['case_id']}: {len(case['indicators'])} indicator(s), highest level **{case['max_level']}**", "",
                "| Level | Score | Type | Indicator |", "|---|---|---|---|"]
        out += [f"| {i['level']} | {i['score']} | {i['type']} | `{d(i['type'], i['value'])}` |" for i in case["indicators"]]
        out += ["", "### Why"]
        for i in case["indicators"]:
            out += ["", f"**`{d(i['type'], i['value'])}`**: {i['level']} ({i['score']}). {i['suggested_action']}", ""]
            if i["rules"]:
                for r in i["rules"]:
                    out.append(f"- `{r['rule']}` {r['points']:+d}: {r['reason']} {refs(r['evidence'], r.get('evidence_total'))}".rstrip())
            else:
                out.append("- No triage rule fired.")
            for hint in i.get("attack", ()):
                pat, techs = att["patterns"][hint["pattern"]], att["techniques"]
                out.append(f"- ATT&CK `{hint['pattern']}` {pat['title']} ({pat['basis_label'].lower()}): {hint['why']} "
                           "Techniques to consider: " + ", ".join(f"`{t}` {techs[t]['name']}" for t in hint["techniques"]) + ".")
            for sg in i["sightings"]:
                raw = sg["raw"] if sg["defanged"] else defang(sg["raw"])
                note = " (host of a URL)" if sg["derived_from_url"] else ""
                out.append(f"- Seen in `{sg['source']}` line {sg['line']}: `{raw}`{note} `obs#{sg['observation_id']}`")
            if i["sightings_total"] > len(i["sightings"]):
                out.append(f"- ...and {i['sightings_total'] - len(i['sightings'])} more sightings (all are in the database and the JSON totals).")
            for fm in i["feed_matches"]:
                f = fm["fields"]
                detail = ", ".join(f"{k}={_safe_field(k, v)}" for k, v in f.items() if v not in ("", None, []))
                via = "listed" if fm["via"] == "exact" else f"hosts listed URL `{defang(fm['listed_url'])}`"
                out.append(f"- Feed `{fm['feed']}` {via}: {detail} (snapshot `{fm['snapshot']}` `{fm['snapshot_sha256'][:12]}`, `intel#{fm['intel_id']}`)")
        if case["links"]:
            out += ["", "### Links", "", "| Rule | A | B | Evidence |", "|---|---|---|---|"]
            out += [f"| `{l['rule']}` | `{d(l['a']['type'], l['a']['value'])}` | `{d(l['b']['type'], l['b']['value'])}` | {refs(l['evidence'], l.get('evidence_total'))} |"
                    for l in case["links"]]
    if quiet:
        rows = sorted((i for c in quiet for i in c["indicators"]), key=lambda i: (-i["sightings_total"], i["type"], i["value"]))
        out += ["", f"## Quiet indicators ({len(rows)})", "",
                "Single indicators with no links and no triage rule fired. Listed compactly; full detail is in the JSON report.", "",
                "| Type | Indicator | Seen |", "|---|---|---|"]
        out += [f"| {i['type']} | `{d(i['type'], i['value'])}` | {i['sightings_total']} |" for i in rows[:MAX_QUIET_ROWS]]
        if len(rows) > MAX_QUIET_ROWS:
            out.append(f"\n...and {len(rows) - MAX_QUIET_ROWS} more quiet indicators (most-seen first are shown above).")
    out += ["", "## Method and limitations", "",
            "Triage rules:", ""]
    out += [f"- `{k}` {v}" for k, v in report["rule_catalog"].items()]
    out += ["",
            "Links come from five rules only (url_host, email_domain, same_line, hostname_ip, shared_family); same_line means the same line of the same source and is evidence of co-occurrence, not of causation; hostname_ip relies on the naming convention of the host name and is a strong hint, not proof, that both refer to the same machine.",
            "Feed data is a point-in-time snapshot of public lists and can be stale or wrong. Absence from a feed is not evidence of safety.",
            ""]
    if att:
        out += [f"{att['framework']} names and identifiers. {att['notice']}", "", att["copyright"], ""]
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
            if ind["sightings_total"] < len(ind["sightings"]) or ind["feed_matches_total"] < len(ind["feed_matches"]):
                problems.append(f"{name}: totals are smaller than the detail shown")
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
