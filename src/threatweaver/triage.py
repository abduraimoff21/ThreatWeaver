"""Module E: simple, readable, rule-based triage.

A verdict is a sum of the points of the rules that fired, each with a reason and
evidence. Levels are thresholds on that sum. The output is a *suggestion for an
analyst*: ThreatWeaver has no code that blocks, quarantines or publishes
anything, and `suggested_action` never says to block without human review.

Rules (points)
  TW-T01  +50  exact match in Feodo Tracker listed online (active botnet C2)
  TW-T02  +45  exact match in URLhaus listed online (live malware URL)
  TW-T03  +25  exact match in a feed, but listed offline / unknown status
  TW-T04  +30  is the host of a URL a feed lists
  TW-T05  +10  ... and that URL is online
  TW-T06  +10  seen in 2+ different local sources
  TW-T07  +10  an analyst defanged it (they already judged it dangerous)
  TW-T08  +15  linked (url_host / same_line) to an indicator that scored "high"
               on its own merits (first pass; no cascading)
  TW-T09  floor  private / loopback / link-local / multicast address: never above "info"
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass

from .correlate import CorrelationResult, Evidence, correlate
from .defang import defang

LEVELS = (("high", 50), ("medium", 25), ("low", 10), ("info", 0))
NON_ROUTABLE = {"private", "loopback", "link_local", "multicast", "unspecified"}

RULE_DESCRIPTIONS = {
    "TW-T01": "Exact match in Feodo Tracker, listed online",
    "TW-T02": "Exact match in URLhaus, listed online",
    "TW-T03": "Exact match in a feed, not listed online",
    "TW-T04": "Host of a URL listed by a feed",
    "TW-T05": "Host of a feed URL that is listed online",
    "TW-T06": "Seen in two or more local sources",
    "TW-T07": "Defanged by an analyst in a source document",
    "TW-T08": "Linked to an indicator that is high risk on its own",
    "TW-T09": "Non-routable address: capped at info",
}


@dataclass(frozen=True)
class RuleHit:
    rule: str
    points: int
    reason: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class Verdict:
    ioc_id: int
    type: str
    value: str
    score: int
    level: str
    hits: tuple[RuleHit, ...]
    suggested_action: str


def level_for(score: int) -> str:
    return next(name for name, floor in LEVELS if score >= floor)


def _action(level: str) -> str:
    return {
        "high": "Escalate for analyst review now. Any containment (e.g. blocking) is a human decision through your normal change process.",
        "medium": "Review soon. Check the evidence and the feed record before deciding on any action.",
        "low": "Note for context; no action suggested on this evidence alone.",
        "info": "No action suggested.",
    }[level]


def triage(conn: sqlite3.Connection, result: CorrelationResult | None = None) -> dict[int, Verdict]:
    """Score every local indicator. Deterministic for a given database."""
    result = result or correlate(conn)
    iocs = {r["id"]: r for r in conn.execute("SELECT id, type, value, attrs FROM iocs")}
    local = [r["ioc_id"] for r in conn.execute("SELECT DISTINCT ioc_id FROM observations ORDER BY ioc_id")]

    obs = defaultdict(list)
    for o in conn.execute("SELECT id, ioc_id, source_id, defanged, parent_observation_id FROM observations ORDER BY id"):
        obs[o["ioc_id"]].append(o)
    matches = defaultdict(list)
    for m in result.matches:
        matches[m.ioc_id].append(m)

    def first_pass(ioc_id: int) -> list[RuleHit]:
        hits: list[RuleHit] = []
        exact = [m for m in matches[ioc_id] if m.via == "exact"]
        hosted = [m for m in matches[ioc_id] if m.via == "hosts_feed_url"]

        online = [m for m in exact if m.status == "online"]
        feodo = [m for m in online if m.feed == "feodotracker"]
        urlhaus = [m for m in online if m.feed == "urlhaus"]
        if feodo:
            hits.append(RuleHit("TW-T01", 50, "listed online by Feodo Tracker as a botnet C2 (" +
                                ", ".join(sorted({m.malware for m in feodo if m.malware}) or {"family unknown"}) + ")",
                                tuple(Evidence("intel", m.intel_id) for m in feodo)))
        if urlhaus:
            hits.append(RuleHit("TW-T02", 45, "listed online by URLhaus as a malware URL",
                                tuple(Evidence("intel", m.intel_id) for m in urlhaus)))
        offline = [m for m in exact if m.status != "online"]
        if offline:
            hits.append(RuleHit("TW-T03", 25, "listed by " + ", ".join(sorted({m.feed for m in offline})) +
                                " but not online in the snapshot",
                                tuple(Evidence("intel", m.intel_id) for m in offline)))
        if hosted:
            hits.append(RuleHit("TW-T04", 30, f"hosts {len({m.related_ioc_id for m in hosted})} URL(s) listed by a feed",
                                tuple(Evidence("intel", m.intel_id) for m in hosted)))
            hosted_online = [m for m in hosted if m.status == "online"]
            if hosted_online:
                hits.append(RuleHit("TW-T05", 10, "at least one of those URLs is listed online",
                                    tuple(Evidence("intel", m.intel_id) for m in hosted_online)))
        sources = {o["source_id"] for o in obs[ioc_id]}
        if len(sources) >= 2:
            hits.append(RuleHit("TW-T06", 10, f"seen in {len(sources)} different local sources",
                                tuple(Evidence("observation", o["id"]) for o in obs[ioc_id])))
        defanged = [o for o in obs[ioc_id] if o["defanged"] and o["parent_observation_id"] is None]
        if defanged:
            hits.append(RuleHit("TW-T07", 10, "written defanged in a source document",
                                tuple(Evidence("observation", o["id"]) for o in defanged)))
        return hits

    base = {i: first_pass(i) for i in local}
    base_level = {i: level_for(sum(h.points for h in hits)) for i, hits in base.items()}

    neighbours = defaultdict(list)
    for link in result.links:
        if link.rule in ("url_host", "same_line"):
            neighbours[link.a].append((link.b, link))
            neighbours[link.b].append((link.a, link))

    verdicts: dict[int, Verdict] = {}
    for i in local:
        hits = list(base[i])
        risky = [(n, l) for n, l in neighbours[i] if base_level.get(n) == "high"]
        if risky:
            label = ", ".join(sorted(f"{iocs[n]['type']} {defang(iocs[n]['value'])}" for n, _ in risky))
            hits.append(RuleHit("TW-T08", 15, f"linked to high-risk indicator(s): {label}",
                                tuple(e for _, l in risky for e in l.evidence)))
        score = sum(h.points for h in hits)
        scope = json.loads(iocs[i]["attrs"]).get("scope", "")
        if scope in NON_ROUTABLE:
            if score:
                hits.append(RuleHit("TW-T09", -score, f"{scope} address cannot be a public threat indicator", ()))
            score = 0
        level = level_for(score)
        verdicts[i] = Verdict(i, iocs[i]["type"], iocs[i]["value"], score, level, tuple(hits), _action(level))
    return verdicts
