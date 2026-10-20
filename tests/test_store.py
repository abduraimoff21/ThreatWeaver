from pathlib import Path

import pytest

from threatweaver import store
from threatweaver.evaluate import evaluate

CORPUS = Path(__file__).resolve().parents[1] / "data" / "synthetic"


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_spelling_variants_dedup_to_one_ioc_with_all_observations(conn):
    text = "EVIL.example.com\nevil[.]example[.]com\nevil.example.com.\n"
    res = store.ingest_text(conn, text, "feed-a")
    assert res.new_iocs == 1
    assert res.new_observations == 3
    assert count(conn, "iocs") == 1
    (row,) = store.list_iocs(conn)
    assert row["observations"] == 3 and row["sources"] == 1


def test_provenance_records_source_line_and_original_text(conn):
    store.ingest_text(conn, "nothing here\nC2 at 203[.]0[.]113[.]9 today\n", "report.txt")
    (obs,) = store.provenance(conn, "ipv4", "203.0.113.9")
    assert obs["source"] == "report.txt"
    assert obs["line_no"] == 2
    assert obs["raw"] == "203[.]0[.]113[.]9"
    assert obs["defanged"] == 1


def test_same_ioc_in_two_sources_is_one_row_two_sources(conn):
    store.ingest_text(conn, "192.0.2.1", "feed-a")
    store.ingest_text(conn, "seen 192.0.2.1 again", "feed-b")
    assert count(conn, "iocs") == 1
    (row,) = store.list_iocs(conn)
    assert row["sources"] == 2
    assert store.list_iocs(conn, min_sources=3) == []


def test_reingesting_same_source_is_a_noop(conn):
    first = store.ingest_text(conn, "192.0.2.1 evil.example.com", "feed-a")
    second = store.ingest_text(conn, "192.0.2.1 evil.example.com", "feed-a")
    assert not first.already_ingested and second.already_ingested
    assert count(conn, "observations") == 2
    assert count(conn, "sources") == 1


def test_changed_content_under_same_name_is_a_new_source(conn):
    store.ingest_text(conn, "192.0.2.1", "feed-a")
    res = store.ingest_text(conn, "192.0.2.1 192.0.2.2", "feed-a")
    assert not res.already_ingested
    assert res.new_iocs == 1
    assert count(conn, "sources") == 2


def test_url_host_is_linked_to_its_url_observation(conn):
    store.ingest_text(conn, "go to http://bad.example.com/x now", "feed-a")
    (host_obs,) = store.provenance(conn, "domain", "bad.example.com")
    (url_obs,) = store.provenance(conn, "url", "http://bad.example.com/x")
    assert host_obs["parent_observation_id"] == url_obs["id"]
    assert url_obs["parent_observation_id"] is None


def test_ip_scope_is_stored(conn):
    store.ingest_text(conn, "10.0.0.5", "feed-a")
    row = conn.execute("SELECT attrs FROM iocs").fetchone()
    assert '"scope": "private"' in row["attrs"]


def test_synthetic_corpus_ingest_matches_labels(conn):
    import json

    labels = json.loads((CORPUS / "labels.json").read_text(encoding="utf-8"))
    for name in labels:
        store.ingest_file(conn, CORPUS / name)
    stored = {(r["type"], r["value"]) for r in store.list_iocs(conn)}
    expected = {(e["type"], e["value"]) for entries in labels.values() for e in entries}
    assert stored == expected
    # No two rows share a (type, value): dedup invariant.
    assert count(conn, "iocs") == len(stored)


def test_extraction_quality_on_synthetic_corpus():
    report = evaluate(CORPUS)
    assert report.errors == []
    assert report.overall.precision == 1.0
    assert report.overall.recall == 1.0
