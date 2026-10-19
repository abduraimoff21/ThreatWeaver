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
  TW-T08  +15  linked (url_host / same_line / hostname_ip) to an indicator that scored "high"
               on its own merits (first pass; no cascading)
  TW-T09  floor  private / loopback / link-local / multicast address: never above "info"
  TW-T10  +10/+25/+30  high-volume repeat activity: 100 / 1,000 / 10,000+ sightings of a
               network indicator (IP, domain, URL). Volume is a prompt to look, not evidence
               of malice (public DNS, CDNs and scanners you run all score high here), so the
               tiers top out below "high" and it only ever adds to other evidence.
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
# (minimum sightings, points), highest first. The top tier stays below the 50 points needed for "high".
VOLUME_TIERS = ((10_000, 30), (1_000, 25), (100, 10))
VOLUME_TYPES = {"ipv4", "ipv6", "domain", "url"}  # a hash seen often in logs says nothing by itself

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
    "TW-T10": "High-volume repeat activity (volume is a prompt to look, not proof)",
}


@dataclass(frozen=True)
class RuleHit:
    rule: str
    points: int
    reason: str
    evidence: tuple[Evidence, ...]  # may be only the first few items; see evidence_total
    evidence_total: int | None = None  # true number of evidence items when `evidence` is a sample


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


EVIDENCE_SAMPLE = 20  # evidence ids kept per rule hit; the true count travels in RuleHit.evidence_total


@dataclass(frozen=True)
class _Stats:
    count: int = 0
    sources: int = 0
    first_ids: tuple[int, ...] = ()
    defanged_count: int = 0
    first_defanged_ids: tuple[int, ...] = ()


def _observation_stats(conn: sqlite3.Connection) -> defaultdict:
    """Everything triage needs to know about sightings, gathered by SQL so memory does not grow with them."""
    n: dict[int, tuple[int, int]] = {
        r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT ioc_id, COUNT(*), COUNT(DISTINCT source_id) FROM observations GROUP BY ioc_id")}
    first: dict[int, list[int]] = defaultdict(list)
    for ioc_id, obs_id in conn.execute(
        "SELECT ioc_id, id FROM (SELECT ioc_id, id, ROW_NUMBER() OVER (PARTITION BY ioc_id ORDER BY id) AS rn "
        "FROM observations) WHERE rn <= ? ORDER BY ioc_id, id", (EVIDENCE_SAMPLE,)):
        first[ioc_id].append(obs_id)
    dcount: dict[int, int] = {r[0]: r[1] for r in conn.execute(
        "SELECT ioc_id, COUNT(*) FROM observations WHERE defanged = 1 AND parent_observation_id IS NULL GROUP BY ioc_id")}
    dfirst: dict[int, list[int]] = defaultdict(list)
    for ioc_id, obs_id in conn.execute(
        "SELECT ioc_id, id FROM (SELECT ioc_id, id, ROW_NUMBER() OVER (PARTITION BY ioc_id ORDER BY id) AS rn "
        "FROM observations WHERE defanged = 1 AND parent_observation_id IS NULL) WHERE rn <= ? ORDER BY ioc_id, id",
        (EVIDENCE_SAMPLE,)):
        dfirst[ioc_id].append(obs_id)
    stats: defaultdict = defaultdict(_Stats)
    for ioc_id, (count, sources) in n.items():
        stats[ioc_id] = _Stats(count, sources, tuple(first[ioc_id]), dcount.get(ioc_id, 0), tuple(dfirst[ioc_id]))
    return stats


def triage(conn: sqlite3.Connection, result: CorrelationResult | None = None) -> dict[int, Verdict]:
    """Score every local indicator. Deterministic for a given database."""
    result = result or correlate(conn)
    iocs = {r["id"]: r for r in conn.execute("SELECT id, type, value, attrs FROM iocs")}
    local = [r["ioc_id"] for r in conn.execute("SELECT DISTINCT ioc_id FROM observations ORDER BY ioc_id")]

    stats = _observation_stats(conn)  # per-indicator counts and the first few ids: O(indicators), not O(sightings)
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
        st = stats[ioc_id]
        spread = st.sources
        if spread >= 2:
            hits.append(RuleHit("TW-T06", 10, f"seen in {spread} different local sources",
                                tuple(Evidence("observation", i) for i in st.first_ids), st.count))
        if st.defanged_count:
            hits.append(RuleHit("TW-T07", 10, "written defanged in a source document",
                                tuple(Evidence("observation", i) for i in st.first_defanged_ids), st.defanged_count))
        if iocs[ioc_id]["type"] in VOLUME_TYPES:
            count = st.count
            tier = next((pts for floor, pts in VOLUME_TIERS if count >= floor), None)
            if tier:
                hits.append(RuleHit(
                    "TW-T10", tier,
                    f"seen {count:,} times across {spread} source{'s' if spread != 1 else ''}; heavy repeat activity is worth a look but is not proof of malice",
                    tuple(Evidence("observation", i) for i in st.first_ids), st.count))
        return hits

    base = {i: first_pass(i) for i in local}
    base_level = {i: level_for(sum(h.points for h in hits)) for i, hits in base.items()}

    neighbours = defaultdict(list)
    for link in result.links:
        if link.rule in ("url_host", "same_line", "hostname_ip"):
            neighbours[link.a].append((link.b, link))
            neighbours[link.b].append((link.a, link))

    verdicts: dict[int, Verdict] = {}
    for i in local:
        hits = list(base[i])
        risky = [(n, l) for n, l in neighbours[i] if base_level.get(n) == "high"]
        if risky:
            label = ", ".join(sorted(f"{iocs[n]['type']} {defang(iocs[n]['value'])}" for n, _ in risky))
            union = {e for _, l in risky for e in l.evidence}
            truncated = any(l.evidence_total not in (None, len(l.evidence)) for _, l in risky)
            total = sum(l.evidence_total or len(l.evidence) for _, l in risky) if truncated else len(union)
            hits.append(RuleHit("TW-T08", 15, f"linked to high-risk indicator(s): {label}",
                                tuple(sorted(union, key=lambda e: (e.kind, e.id))), total))
        score = sum(h.points for h in hits)
        scope = json.loads(iocs[i]["attrs"]).get("scope", "")
        if scope in NON_ROUTABLE:
            if score:
                hits.append(RuleHit("TW-T09", -score, f"{scope} address cannot be a public threat indicator", ()))
            score = 0
        level = level_for(score)
        verdicts[i] = Verdict(i, iocs[i]["type"], iocs[i]["value"], score, level, tuple(hits), _action(level))
    return verdicts
