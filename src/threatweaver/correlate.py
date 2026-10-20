"""Module D: transparent evidence correlation.

Every link says which rule created it, why, and which stored rows are the
evidence (observations, relations, intel). There is no hidden scoring model:
the rules below are the whole story, and weights only decide which links are
strong enough to group indicators into a case.

Rules
  url_host       a URL and its host (structural, weight 3)
  email_domain   an e-mail address and its domain (structural, weight 3). Not made for public
                 mailbox providers such as gmail.com: they are not recorded as domains at all
  same_line     two different indicators on the same line of the same source,
                 not overlapping each other (weight 2). Lines with many
                 indicators are skipped as too noisy to mean anything.
  hostname_ip    a host name that spells out an IPv4 address (192-0-2-7.isp.example.net,
                 7.2.0.192.in-addr..., n192000002007.example.net) and that address,
                 when both were seen locally (weight 2). Forward or reversed octets,
                 any number of leading zeros. Evidence cites up to 10 sightings of the
                 host name (the claim comes from its spelling) and the first of the IP.
  shared_family  two local indicators that exact-match feed records naming the
                 same malware family (weight 1; shown, but does not merge cases)

Feed matches (enrichment) are produced alongside, not as links, and use only the
newest snapshot of each feed:
  exact           the local indicator itself is listed by a feed
  hosts_feed_url  the local domain/IP is the host of a URL a feed lists
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations, groupby
from typing import Any

RULES: dict[str, tuple[int, str]] = {
    "url_host": (3, "URL and its host name or address"),
    "email_domain": (3, "e-mail address and its domain"),
    "same_line": (2, "different indicators on the same line of the same source"),
    "hostname_ip": (2, "host name spells out an IPv4 address that was also observed"),
    "shared_family": (1, "both indicators are listed by a feed under the same malware family"),
}
CLUSTER_MIN_WEIGHT = 2
MAX_IOCS_PER_LINE = 8
MAX_FAMILY_GROUP = 25
MAX_HOSTNAME_EVIDENCE = 10
LINK_EVIDENCE_CAP = 1000  # evidence ids kept per link; the real count is still recorded in evidence_total

_SEPARATED_OCTETS = re.compile(r"(?=(?<!\d)(\d{1,3})([-.])(\d{1,3})\2(\d{1,3})\2(\d{1,3})(?!\d))")
_PACKED_OCTETS = re.compile(r"(?<!\d)(\d{3})(\d{3})(\d{3})(\d{3})(?!\d)")


@dataclass(frozen=True)
class Evidence:
    kind: str  # "observation" | "relation" | "intel"
    id: int

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "id": self.id}


@dataclass(frozen=True)
class Link:
    rule: str
    a: int  # ioc id, a < b
    b: int
    explanation: str
    evidence: tuple[Evidence, ...]
    evidence_total: int | None = None  # true number of evidence items when `evidence` was capped

    @property
    def weight(self) -> int:
        return RULES[self.rule][0]


@dataclass(frozen=True)
class FeedMatch:
    ioc_id: int
    intel_id: int
    feed: str
    via: str  # "exact" | "hosts_feed_url"
    related_ioc_id: int | None  # the listed URL, for hosts_feed_url
    status: str
    malware: str


@dataclass
class CorrelationResult:
    links: list[Link] = field(default_factory=list)
    matches: list[FeedMatch] = field(default_factory=list)
    skipped_lines: int = 0
    skipped_families: int = 0


def encoded_ipv4_candidates(hostname: str) -> set[str]:
    """Every IPv4 address a host name could be spelling out (forward and reversed octets)."""
    found: set[str] = set()
    groups: list[tuple[str, ...]] = [m.group(1, 3, 4, 5) for m in _SEPARATED_OCTETS.finditer(hostname)]
    groups += [m.groups() for m in _PACKED_OCTETS.finditer(hostname)]
    for g in groups:
        octets = [int(x) for x in g]
        if all(o <= 255 for o in octets):
            found.add(".".join(map(str, octets)))
            found.add(".".join(map(str, reversed(octets))))
    return found


def _pair(x: int, y: int) -> tuple[int, int]:
    return (x, y) if x < y else (y, x)


def correlate(
    conn: sqlite3.Connection,
    max_per_line: int = MAX_IOCS_PER_LINE,
    max_family_group: int = MAX_FAMILY_GROUP,
) -> CorrelationResult:
    out = CorrelationResult()
    local = {r[0] for r in conn.execute("SELECT DISTINCT ioc_id FROM observations")}
    label = {r["id"]: f"{r['type']} {r['value']}" for r in conn.execute("SELECT id, type, value FROM iocs")}

    # --- url_host and email_domain (structural: one was written inside the other) ----------------------
    by_kind: dict[str, dict[tuple[int, int], list[int]]] = {"url_host": defaultdict(list), "email_domain": defaultdict(list)}
    for r in conn.execute(
        "SELECT r.id, r.parent_id, r.child_id, r.kind FROM relations r JOIN sources s ON s.id = r.source_id "
        "WHERE r.kind IN ('url_host', 'email_domain') AND s.kind != 'feed' ORDER BY r.id"
    ):
        if r["parent_id"] in local and r["child_id"] in local and r["parent_id"] != r["child_id"]:
            by_kind[r["kind"]][_pair(r["parent_id"], r["child_id"])].append(r["id"])
    host_pairs = {pair for pairs in by_kind.values() for pair in pairs}  # already explained structurally
    for rule, parts in (("url_host", "are a URL and its host"), ("email_domain", "are an e-mail address and its domain")):
        for (a, b), rel_ids in sorted(by_kind[rule].items()):
            out.links.append(Link(
                rule, a, b, f"{label[a]} and {label[b]} {parts}",
                tuple(Evidence("relation", i) for i in rel_ids),
            ))

    # --- same_line -------------------------------------------------------
    # Observations arrive ordered by (source, line), so each line's group is processed and dropped:
    # memory stays flat however large the input is.
    line_pairs: dict[tuple[int, int], dict[int, None]] = {}
    line_overflow: dict[tuple[int, int], int] = {}
    rows = conn.execute(
        "SELECT id, ioc_id, source_id, line_no, span_start, span_end FROM observations ORDER BY source_id, line_no, id"
    )
    for _, group in groupby(rows, key=lambda o: (o["source_id"], o["line_no"])):
        obs = list(group)
        if len(obs) < 2:
            continue
        if len({o["ioc_id"] for o in obs}) > max_per_line:
            out.skipped_lines += 1
            continue
        for o1, o2 in combinations(obs, 2):
            if o1["ioc_id"] == o2["ioc_id"]:
                continue
            if o1["span_start"] < o2["span_end"] and o2["span_start"] < o1["span_end"]:
                continue  # overlapping text, e.g. a hash inside a URL: structure, not co-occurrence
            pair = _pair(o1["ioc_id"], o2["ioc_id"])
            if pair in host_pairs:
                continue  # already explained by url_host
            kept = line_pairs.setdefault(pair, {})
            for obs_id in (o1["id"], o2["id"]):
                if obs_id in kept:
                    continue
                if len(kept) < LINK_EVIDENCE_CAP:
                    kept[obs_id] = None
                else:
                    line_overflow[pair] = line_overflow.get(pair, 0) + 1
    for (a, b), kept in sorted(line_pairs.items()):
        extra = line_overflow.get((a, b), 0)
        out.links.append(Link(
            "same_line", a, b, f"{label[a]} and {label[b]} appear on the same line",
            tuple(Evidence("observation", i) for i in sorted(kept)),
            evidence_total=len(kept) + extra if extra else None,
        ))

    # --- hostname_ip -----------------------------------------------------
    def first_sightings(ioc_id: int, limit: int) -> list[int]:
        return [r[0] for r in conn.execute("SELECT id FROM observations WHERE ioc_id = ? ORDER BY id LIMIT ?", (ioc_id, limit))]

    local_ips = {r["value"]: r["id"] for r in conn.execute("SELECT id, value FROM iocs WHERE type = 'ipv4'") if r["id"] in local}
    for r in conn.execute("SELECT id, value FROM iocs WHERE type = 'domain' ORDER BY id"):
        if r["id"] not in local:
            continue
        for ip in sorted(encoded_ipv4_candidates(r["value"]) & local_ips.keys()):
            a, b = _pair(r["id"], local_ips[ip])
            evidence = first_sightings(r["id"], MAX_HOSTNAME_EVIDENCE) + first_sightings(local_ips[ip], 1)
            out.links.append(Link(
                "hostname_ip", a, b, f"{label[r['id']]} spells out the address {ip}, which was also observed",
                tuple(Evidence("observation", i) for i in evidence),
            ))

    # --- feed matches ----------------------------------------------------
    intel_by_ioc: dict[int, list[sqlite3.Row]] = defaultdict(list)
    # Only the newest snapshot of each feed counts as current. Older snapshots stay in the
    # database as history, but a record that was "online" last week and "offline" now must
    # not keep raising alarms.
    for t in conn.execute(
        "SELECT t.id, t.ioc_id, t.feed, t.attrs FROM intel t WHERE t.source_id = ("
        "  SELECT s.id FROM intel t2 JOIN sources s ON s.id = t2.source_id WHERE t2.feed = t.feed "
        "  ORDER BY t2.collected_at DESC, s.id DESC LIMIT 1) ORDER BY t.id"
    ):
        intel_by_ioc[t["ioc_id"]].append(t)

    def make_match(ioc_id: int, t: sqlite3.Row, via: str, related: int | None) -> FeedMatch:
        attrs = json.loads(t["attrs"])
        return FeedMatch(ioc_id, t["id"], t["feed"], via, related,
                         str(attrs.get("status", "")).lower(), str(attrs.get("malware", "")))

    for ioc_id in sorted(local):
        for t in intel_by_ioc.get(ioc_id, ()):
            out.matches.append(make_match(ioc_id, t, "exact", None))
    for r in conn.execute("SELECT DISTINCT parent_id, child_id FROM relations WHERE kind = 'url_host' ORDER BY 1, 2"):
        if r["child_id"] in local and r["parent_id"] != r["child_id"]:
            for t in intel_by_ioc.get(r["parent_id"], ()):
                out.matches.append(make_match(r["child_id"], t, "hosts_feed_url", r["parent_id"]))

    # --- shared_family ---------------------------------------------------
    families: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(list))
    for m in out.matches:
        if m.via == "exact" and m.malware:
            families[m.malware.casefold()][m.ioc_id].append(m.intel_id)
    for family, members in sorted(families.items()):
        if len(members) < 2:
            continue
        if len(members) > max_family_group:
            out.skipped_families += 1
            continue
        for a, b in combinations(sorted(members), 2):
            out.links.append(Link(
                "shared_family", a, b,
                f"{label[a]} and {label[b]} are both listed as '{family}' by a feed",
                tuple(Evidence("intel", i) for i in sorted(members[a] + members[b])),
            ))
    return out


def clusters(ioc_ids: list[int], links: list[Link], min_weight: int = CLUSTER_MIN_WEIGHT) -> list[list[int]]:
    """Group indicators connected by links of at least `min_weight` (union-find)."""
    parent = {i: i for i in ioc_ids}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for link in links:
        if link.weight >= min_weight and link.a in parent and link.b in parent:
            parent[find(link.a)] = find(link.b)
    groups: dict[int, list[int]] = defaultdict(list)
    for i in sorted(ioc_ids):
        groups[find(i)].append(i)
    return sorted(groups.values(), key=lambda g: g[0])


def save_links(conn: sqlite3.Connection, links: list[Link]) -> None:
    """Replace the stored links with `links` (the table is a cache of a pure function)."""
    with conn:
        conn.execute("DELETE FROM links")
        conn.executemany(
            "INSERT INTO links (rule, ioc_a, ioc_b, explanation, evidence, weight) VALUES (?, ?, ?, ?, ?, ?)",
            [(l.rule, l.a, l.b, l.explanation, json.dumps([e.to_dict() for e in l.evidence]), l.weight) for l in links],
        )


def to_networkx(links: list[Link], labels: dict[int, str]):
    """Optional: build a NetworkX graph (pip install networkx). Edges carry rule and weight."""
    try:
        import networkx as nx
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError("networkx is optional; install it with: pip install networkx") from exc
    g = nx.MultiGraph()
    for node_id, text in labels.items():
        g.add_node(node_id, label=text)
    for l in links:
        g.add_edge(l.a, l.b, rule=l.rule, weight=l.weight, explanation=l.explanation)
    return g
