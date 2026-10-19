"""Correlation, triage and the report must use memory proportional to the number of indicators,
not the number of sightings, and give the same answers as the straightforward algorithm."""

import json
import random
import tracemalloc
from collections import defaultdict
from itertools import combinations

import pytest

from threatweaver import store
from threatweaver import correlate as correlate_module
from threatweaver.correlate import correlate
from threatweaver.pipeline import run
from threatweaver.report import MAX_EVIDENCE, build_report, render_markdown, verify_traceability
from threatweaver.triage import EVIDENCE_SAMPLE, triage


def reference_same_line(conn, max_per_line=8):
    """The original algorithm: load every observation, group by line, compare all pairs."""
    rows = conn.execute("SELECT id, ioc_id, source_id, line_no, span_start, span_end FROM observations ORDER BY id").fetchall()
    host_pairs = {tuple(sorted((r["parent_id"], r["child_id"]))) for r in conn.execute(
        "SELECT r.parent_id, r.child_id FROM relations r JOIN sources s ON s.id = r.source_id WHERE r.kind='url_host' AND s.kind != 'feed'")}
    by_line = defaultdict(list)
    for o in rows:
        by_line[(o["source_id"], o["line_no"])].append(o)
    pairs, skipped = defaultdict(set), 0
    for _, obs in sorted(by_line.items()):
        if len({o["ioc_id"] for o in obs}) > max_per_line:
            skipped += 1
            continue
        for o1, o2 in combinations(obs, 2):
            if o1["ioc_id"] == o2["ioc_id"] or (o1["span_start"] < o2["span_end"] and o2["span_start"] < o1["span_end"]):
                continue
            pair = tuple(sorted((o1["ioc_id"], o2["ioc_id"])))
            if pair in host_pairs:
                continue
            pairs[pair].update([o1["id"], o2["id"]])
    return {pair: sorted(ids) for pair, ids in pairs.items()}, skipped


def random_log(rng, lines):
    pool = ([f"192.0.2.{i}" for i in range(1, 30)] + [f"host{i}.example.com" for i in range(15)] + [f"10.0.0.{i}" for i in range(1, 8)]
            + [f"http://u{i}.example.net/p{i}" for i in range(10)] + ["0123456789abcdef0123456789abcdef", "hxxp://bad[.]example[.]org/x", "198[.]51[.]100[.]7"])
    out = []
    for _ in range(lines):
        out.append("event " + " ".join(rng.choice(pool) for _ in range(rng.randint(0, 5))) + f" tail{rng.randint(0, 9)}")
    return "\n".join(out) + "\n"


def test_streaming_same_line_matches_the_original_algorithm_on_random_logs():
    rng = random.Random(7)
    for trial in range(15):
        conn = store.connect(":memory:")
        for n in range(3):
            store.ingest_text(conn, random_log(rng, rng.randint(1, 120)), f"src{n}.log")
        want, want_skipped = reference_same_line(conn)
        got = correlate(conn)
        links = {(l.a, l.b): [e.id for e in l.evidence] for l in got.links if l.rule == "same_line"}
        assert links == want, f"trial {trial}"
        assert got.skipped_lines == want_skipped


def test_link_evidence_is_capped_but_the_true_count_is_kept(monkeypatch):
    monkeypatch.setattr(correlate_module, "LINK_EVIDENCE_CAP", 10)
    conn = store.connect(":memory:")
    store.ingest_text(conn, "".join(f"line {i} 192.0.2.1 evil.example.com\n" for i in range(100)), "a.log")
    (link,) = [l for l in correlate(conn).links if l.rule == "same_line"]
    assert len(link.evidence) == 10 and link.evidence_total == 200  # 100 lines x 2 sightings
    report = build_report(conn, "2026-10-14T00:00:00+00:00")
    rep_link = next(l for c in report["cases"] for l in c["links"] if l["rule"] == "same_line")
    assert rep_link["evidence_total"] == 200 and len(rep_link["evidence"]) == 10  # what was kept (cap 10 < report cap 20)
    assert "(+190 more)" in render_markdown(report)
    assert verify_traceability(conn, report)["unresolved"] == 0


def test_triage_keeps_a_small_evidence_sample_with_the_true_total():
    conn = store.connect(":memory:")
    for n in range(3):
        store.ingest_text(conn, "".join(f"seen {i} 192.0.2.9\n" for i in range(400)), f"s{n}.log")
    (v,) = triage(conn).values()
    by_rule = {h.rule: h for h in v.hits}
    assert by_rule["TW-T06"].evidence_total == 1200 and len(by_rule["TW-T06"].evidence) == EVIDENCE_SAMPLE
    assert by_rule["TW-T10"].evidence_total == 1200
    ids = [e.id for e in by_rule["TW-T06"].evidence]
    assert ids == sorted(ids) and ids == [r[0] for r in conn.execute("SELECT id FROM observations ORDER BY id LIMIT 20")]


def test_defanged_evidence_sample_counts_only_direct_defanged_sightings():
    conn = store.connect(":memory:")
    store.ingest_text(conn, "".join(f"c2 hxxp://bad[.]example[.]org/{i} and 198[.]51[.]100[.]7\n" for i in range(50)), "x.log")
    verdicts = {v.value: v for v in triage(conn).values()}
    hit = next(h for h in verdicts["198.51.100.7"].hits if h.rule == "TW-T07")
    assert hit.evidence_total == 50 and len(hit.evidence) == EVIDENCE_SAMPLE
    host = verdicts["bad.example.org"]  # derived from the URL, not written by the analyst: no "written defanged" hit
    assert all(h.rule != "TW-T07" for h in host.hits)


def peak_kb(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1] / 1024
    finally:
        tracemalloc.stop()


def test_analysis_memory_does_not_grow_with_the_number_of_sightings():
    """Same 40 indicators, 10x more sightings: peak memory of correlate + triage + report must stay bounded."""
    def build(lines):
        conn = store.connect(":memory:")
        text = "".join(f"event {i} 192.0.2.{i % 20 + 1} host{i % 20}.example.com\n" for i in range(lines))
        store.ingest_text(conn, text, "a.log")
        return conn

    small, big = build(2_000), build(20_000)
    run(small, None, persist=False)  # warm-up (imports, caches)
    small_kb = peak_kb(lambda: run(small, None, persist=False))
    big_kb = peak_kb(lambda: run(big, None, persist=False))
    # Measured: the old implementation grew 8.6x here (26.6 MB at only 40,000 sightings, ~4.4 GB at 7.7 million);
    # the bounded one grows ~2.8x to 3.4 MB because each link keeps up to LINK_EVIDENCE_CAP evidence ids.
    assert big_kb < small_kb * 4, (small_kb, big_kb)
    assert big_kb < 8_000, big_kb


def test_report_and_analysis_results_are_unchanged_for_the_scenario():
    from pathlib import Path

    from threatweaver.pipeline import run_scenario
    from threatweaver.scenario_eval import evaluate_scenario

    scenario = Path(__file__).resolve().parents[1] / "data" / "synthetic" / "scenario"
    scores = evaluate_scenario(scenario, run_scenario(scenario))
    assert scores.errors == [] and scores.links.recall == 1.0 and scores.links.precision == 1.0


def test_attaching_links_to_cases_is_not_quadratic():
    """The old code scanned every link once per case (cases x links: minutes at 800,000 cases). Count how often
    the links list is walked: it must not grow with the number of cases. Deterministic, so it does not depend on speed."""
    class CountingList(list):
        walks = 0

        def __iter__(self):
            CountingList.walks += 1
            return super().__iter__()

    conn = store.connect(":memory:")
    singles = "".join(f"seen from 11.0.{i // 255}.{i % 255 + 1}" + chr(10) for i in range(3_000))
    pairs = "".join(f"pair 12.0.{i // 255}.{i % 255 + 1} h{i}.example.net" + chr(10) for i in range(200))
    store.ingest_text(conn, singles + pairs, "big.log")
    result = correlate(conn)
    result.links = CountingList(result.links)
    report = build_report(conn, "2026-10-14T00:00:00+00:00", result, triage(conn, result))
    assert len(report["cases"]) == 3_000 + 200
    assert CountingList.walks <= 5, f"the links list was walked {CountingList.walks} times for {len(report['cases'])} cases"


def test_links_are_attached_to_the_right_cases_in_the_original_order():
    conn = store.connect(":memory:")
    store.ingest_text(conn, "a 192.0.2.1 x1.example.com\nb 192.0.2.2 x2.example.com\nc 192.0.2.3 x3.example.com\nd 192.0.2.9\n", "s.log")
    report = build_report(conn, "2026-10-14T00:00:00+00:00")
    by_ind = {i["value"]: c for c in report["cases"] for i in c["indicators"]}
    for n in (1, 2, 3):
        case = by_ind[f"192.0.2.{n}"]
        assert {i["value"] for i in case["indicators"]} == {f"192.0.2.{n}", f"x{n}.example.com"}
        assert len(case["links"]) == 1 and {case["links"][0]["a"]["value"], case["links"][0]["b"]["value"]} == {f"192.0.2.{n}", f"x{n}.example.com"}
    assert by_ind["192.0.2.9"]["links"] == []
    ids = [l["a"]["id"] for c in report["cases"] for l in c["links"]]
    assert len(ids) == 3
