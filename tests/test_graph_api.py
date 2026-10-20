"""The link-graph API must give a picture a person can read, however big the log is."""

import pytest

from threatweaver import store
from threatweaver.web import api
from threatweaver.web.api import ApiError, Context, GRAPH_EDGE_CAP, LEVEL_RANK

HUB = "198.51.100.9"


def make(tmp_path, text, name="a.log"):
    ctx = Context(db_path=str(tmp_path / "g.db"), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = store.connect(ctx.db_path)
    store.ingest_text(conn, text, name)
    conn.close()
    return ctx


def hub_log(peers=40, lines=1100):
    """One busy address seen with 40 quiet ones: the shape of a scanner in a large log."""
    return "".join(f"hit {HUB} peer 192.0.2.{1 + i % peers}\n" for i in range(lines))


def clique_log(size=12, repeat=3):
    ips = [f"203.0.113.{i}" for i in range(1, size + 1)]
    return "".join(f"mesh {a} {b}\n" for _ in range(repeat) for n, a in enumerate(ips) for b in ips[n + 1:])


def levels(ctx):
    conn = ctx.connect()
    try:
        return {i["value"]: i["level"] for i in api.analysis(ctx, conn).indicators.values()}
    finally:
        conn.close()


def test_the_level_picks_where_to_start_and_neighbours_come_along_at_any_level(tmp_path):
    ctx = make(tmp_path, hub_log())
    lv = levels(ctx)
    assert LEVEL_RANK[lv[HUB]] > max(LEVEL_RANK[v] for k, v in lv.items() if k != HUB), "fixture drifted: the hub must outrank its peers"
    g = api.graph(ctx, {"min_level": lv[HUB], "limit": "100"})
    values = {n["value"]: n for n in g["nodes"]}
    assert HUB in values and len(values) > 1
    assert any(LEVEL_RANK[n["level"]] < LEVEL_RANK[lv[HUB]] for n in g["nodes"]), "neighbours of any level must be drawn"
    assert g["matching"] == 1  # only the hub is at that level; the rest are what it connects to
    assert values[HUB]["degree"] == 40  # the full number of links, drawn or not


def test_a_level_nothing_reaches_gives_an_empty_graph_not_an_error(tmp_path):
    ctx = make(tmp_path, hub_log(lines=30))
    g = api.graph(ctx, {"min_level": "high"})
    assert g["nodes"] == [] and g["edges"] == []


def test_dense_links_are_thinned_to_each_indicators_strongest_and_the_total_is_reported(tmp_path):
    ctx = make(tmp_path, clique_log())
    g = api.graph(ctx, {"per_node": "2"})
    assert len(g["nodes"]) == 12
    assert g["edges_total"] == 66 and len(g["edges"]) < g["edges_total"]
    assert len(g["edges"]) <= 2 * len(g["nodes"])
    degree = {}
    for e in g["edges"]:
        degree[e["a"]] = degree.get(e["a"], 0) + 1
        degree[e["b"]] = degree.get(e["b"], 0) + 1
    assert set(degree) == {n["id"] for n in g["nodes"]}  # nobody was thinned into a dot
    more = api.graph(ctx, {"per_node": "20"})
    assert len(more["edges"]) == 66


def test_limit_caps_the_nodes_and_says_so(tmp_path):
    ctx = make(tmp_path, hub_log())
    g = api.graph(ctx, {"limit": "10"})
    assert len(g["nodes"]) <= 10 and g["truncated"] is True
    ids = {n["id"] for n in g["nodes"]}
    assert g["edges"] and all(e["a"] in ids and e["b"] in ids and e["a"] != e["b"] for e in g["edges"])
    assert {e["a"] for e in g["edges"]} | {e["b"] for e in g["edges"]} == ids  # the all-indicators view never draws a lone dot


def test_an_indicator_whose_neighbours_did_not_fit_is_left_out_not_drawn_as_a_dot(tmp_path):
    ctx = make(tmp_path, "".join(f"pair 192.0.2.{i} 198.51.100.{i}\n" for i in range(1, 21)))
    g = api.graph(ctx, {"limit": "11"})  # five whole pairs fit; the sixth pair's first member would be a lone dot
    assert len(g["nodes"]) == 10 and g["truncated"] is True
    assert {e["a"] for e in g["edges"]} | {e["b"] for e in g["edges"]} == {n["id"] for n in g["nodes"]}


def test_edges_never_exceed_the_hard_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "GRAPH_EDGE_CAP", 20)
    ctx = make(tmp_path, clique_log(size=15))
    g = api.graph(ctx, {"per_node": "20"})
    assert len(g["edges"]) == 20 and g["edges_total"] == 105
    assert GRAPH_EDGE_CAP == 2500  # the real limit stays generous enough for a full-screen graph


def test_link_types_can_be_switched_off(tmp_path):
    ctx = make(tmp_path, hub_log(lines=60))
    assert api.graph(ctx, {"rules": "same_line"})["edges"]
    only_urls = api.graph(ctx, {"rules": "url_host"})
    assert only_urls["nodes"] == [] and only_urls["edges"] == []


def test_bad_parameters_are_refused_and_odd_numbers_are_clamped(tmp_path):
    ctx = make(tmp_path, hub_log(lines=60))
    for query in ({"min_level": "urgent"}, {"rules": "same_line,telepathy"}):
        with pytest.raises(ApiError) as e:
            api.graph(ctx, query)
        assert e.value.status == 400
    with pytest.raises(ApiError) as e:
        api.graph(ctx, {"case": "TW-nope"})
    assert e.value.status == 404
    assert api.graph(ctx, {"limit": "99999"})["limit"] == api.GRAPH_LIMIT_MAX
    assert api.graph(ctx, {"limit": "-5"})["limit"] == 10
    assert api.graph(ctx, {"limit": "banana"})["limit"] == api.GRAPH_LIMIT_DEFAULT


def test_a_case_page_shows_its_own_indicators_and_is_also_capped(tmp_path):
    ctx = make(tmp_path, hub_log(lines=200) + "lonely 192.0.2.200\n")
    conn = ctx.connect()
    try:
        a = api.analysis(ctx, conn)
        big = max(a.cases.values(), key=lambda c: len(c["indicators"]))
    finally:
        conn.close()
    g = api.graph(ctx, {"case": big["case_id"], "limit": "10"})
    assert len(g["nodes"]) == 10 and g["truncated"] is True
    assert {n["case_id"] for n in g["nodes"]} == {big["case_id"]}
    full = api.graph(ctx, {"case": big["case_id"], "limit": "500"})
    assert len(full["nodes"]) == len(big["indicators"]) and not full["truncated"]


def test_case_and_indicator_pages_send_a_bounded_page_of_a_huge_case(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "CASE_INDICATORS_MAX", 8)
    monkeypatch.setattr(api, "CASE_LINKS_MAX", 5)
    monkeypatch.setattr(api, "DETAIL_LINKS_MAX", 6)
    ctx = make(tmp_path, hub_log(lines=300))
    conn = ctx.connect()
    try:
        a = api.analysis(ctx, conn)
        case = max(a.cases.values(), key=lambda c: len(c["indicators"]))
        hub_id = next(i["id"] for i in a.indicators.values() if i["value"] == HUB)
    finally:
        conn.close()
    detail = api.case_detail(ctx, case["case_id"])
    assert len(detail["indicators"]) == 8 and detail["indicators_total"] == len(case["indicators"]) > 8
    assert len(detail["links"]) == 5 and detail["links_total"] == len(case["links"])
    ind = api.indicator_detail(ctx, hub_id)
    assert len(ind["links"]) == 6 and ind["links_total"] == 40  # the hub is linked to all 40 peers
    other_ids = {l["other_id"] for l in ind["links"]}
    assert hub_id not in other_ids and len(other_ids) == 6


def test_an_indicators_links_come_from_an_index_not_a_scan_of_the_whole_case(tmp_path):
    ctx = make(tmp_path, hub_log(lines=300))
    conn = ctx.connect()
    try:
        a = api.analysis(ctx, conn)
        peer = next(i for i in a.indicators.values() if i["value"] == "192.0.2.3")
        hub = next(i for i in a.indicators.values() if i["value"] == HUB)
        mine = a.links_of(peer["id"])
        assert len(mine) == 1 and {mine[0]["a"]["id"], mine[0]["b"]["id"]} == {peer["id"], hub["id"]}
        assert a.links_of(peer["id"]) is mine  # built once, then reused
        assert len(a.links_of(hub["id"])) == 40
    finally:
        conn.close()


def test_graphs_are_cached_per_snapshot_and_rebuilt_after_new_data(tmp_path):
    ctx = make(tmp_path, hub_log(lines=60))
    first = api.graph(ctx, {"limit": "50"})
    assert api.graph(ctx, {"limit": "50"}) is first
    conn = ctx.connect()
    store.ingest_text(conn, "later 198.51.100.77 192.0.2.5\n", "b.log")
    conn.close()
    second = api.graph(ctx, {"limit": "50"})
    assert second is not first and "198.51.100.77" in {n["value"] for n in second["nodes"]}


def test_the_same_data_always_draws_the_same_graph(tmp_path):
    ctx = make(tmp_path, hub_log(lines=400) + clique_log())
    one = api.graph(ctx, {"limit": "60", "min_level": "info"})
    ctx._cache = None  # force a fresh analysis
    two = api.graph(ctx, {"limit": "60", "min_level": "info"})
    assert one == two
