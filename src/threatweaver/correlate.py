"""Module D: transparent evidence correlation.

Every link says which rule created it, why, and which stored rows are the
evidence (observations, relations, intel). There is no hidden scoring model:
the rules below are the whole story, and weights only decide which links are
strong enough to group indicators into a case.

Rules
  url_host       a URL and its host (structural, weight 3)
  same_line      two different indicators on the same line of the same source,
                 not overlapping each other (weight 2). Lines with many
                 indicators are skipped as too noisy to mean anything.
  shared_family  two local indicators that exact-match feed records naming the
                 same malware family (weight 1; shown, but does not merge cases)

Feed matches (enrichment) are produced alongside, not as links, and use only the
newest snapshot of each feed:
  exact           the local indicator itself is listed by a feed
  hosts_feed_url  the local domain/IP is the host of a URL a feed lists
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

RULES: dict[str, tuple[int, str]] = {
    "url_host": (3, "URL and its host name or address"),
    "same_line": (2, "different indicators on the same line of the same source"),
    "shared_family": (1, "both indicators are listed by a feed under the same malware family"),
}
CLUSTER_MIN_WEIGHT = 2
MAX_IOCS_PER_LINE = 8
MAX_FAMILY_GROUP = 25


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

    # --- url_host --------------------------------------------------------
    host_pairs: dict[tuple[int, int], list[int]] = defaultdict(list)
    for r in conn.execute(
        "SELECT r.id, r.parent_id, r.child_id FROM relations r JOIN sources s ON s.id = r.source_id "
        "WHERE r.kind = 'url_host' AND s.kind != 'feed' ORDER BY r.id"
    ):
        if r["parent_id"] in local and r["child_id"] in local and r["parent_id"] != r["child_id"]:
            host_pairs[_pair(r["parent_id"], r["child_id"])].append(r["id"])
    for (a, b), rel_ids in sorted(host_pairs.items()):
        out.links.append(Link(
            "url_host", a, b, f"{label[a]} and {label[b]} are a URL and its host",
            tuple(Evidence("relation", i) for i in rel_ids),
        ))

    # --- same_line -------------------------------------------------------
    by_line: dict[tuple[int, int], list[sqlite3.Row]] = defaultdict(list)
    for o in conn.execute(
        "SELECT id, ioc_id, source_id, line_no, span_start, span_end FROM observations ORDER BY id"
    ):
        by_line[(o["source_id"], o["line_no"])].append(o)
    line_pairs: dict[tuple[int, int], list[int]] = defaultdict(list)
    for (_, _), obs in sorted(by_line.items()):
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
            line_pairs[pair].extend([o1["id"], o2["id"]])
    for (a, b), obs_ids in sorted(line_pairs.items()):
        out.links.append(Link(
            "same_line", a, b, f"{label[a]} and {label[b]} appear on the same line",
            tuple(Evidence("observation", i) for i in sorted(set(obs_ids))),
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
