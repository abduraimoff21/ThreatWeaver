"""Removing an earlier upload: what goes, what must stay, and that it cannot corrupt the database."""

import json
import math

import pytest

from threatweaver import lifecycle, store
from threatweaver.correlate import correlate, save_links
from threatweaver.feeds import FEODO, load_feed
from threatweaver.pipeline import run
from threatweaver.report import build_report, render_markdown
from threatweaver.web import api
from threatweaver.web.api import Context
from threatweaver.web.jobs import JobManager
from test_web import Client, start  # noqa: F401  (the HTTP helpers the dashboard tests use)


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def sources(conn):
    return {r["name"]: r["id"] for r in conn.execute("SELECT id, name FROM sources")}


def values(conn):
    return {f"{r['type']} {r['value']}" for r in conn.execute("SELECT type, value FROM iocs")}


def counts(conn):
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("observations", "relations", "iocs", "sources", "links")}


def integrity(conn):
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1, "checking of references must be switched back on"


# ------------------------------------------------------------------ what goes and what stays
def test_removing_a_source_deletes_its_sightings_and_only_the_indicators_seen_nowhere_else(conn):
    store.ingest_text(conn, "198.51.100.7 shared.example.com only-a.example.org\n", "a.log")
    store.ingest_text(conn, "198.51.100.7 only-b.example.net\n", "b.log")
    before_b = conn.execute("SELECT COUNT(*) FROM observations WHERE source_id = ?", (sources(conn)["b.log"],)).fetchone()[0]

    gone = store.remove_source(conn, sources(conn)["a.log"])

    assert (gone.name, gone.sightings, gone.indicators) == ("a.log", 3, 2)  # shared.example.com and only-a.example.org
    assert values(conn) == {"ipv4 198.51.100.7", "domain only-b.example.net"}
    assert sources(conn).keys() == {"b.log"}
    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == before_b  # the other source is untouched
    integrity(conn)


def test_the_host_of_a_url_and_the_domain_of_an_address_go_with_their_parent(conn):
    store.ingest_text(conn, "see http://bad.example.com/x and write to bob@evil.example.org\n", "a.log")
    assert counts(conn)["relations"] == 2
    store.remove_source(conn, sources(conn)["a.log"])
    assert counts(conn) == {"observations": 0, "relations": 0, "iocs": 0, "sources": 0, "links": 0}
    integrity(conn)


def test_a_parent_is_never_deleted_before_its_child_within_a_batch_boundary(conn):
    # URL + host pairs make every other sighting a child of the one before; tiny batches cut between them
    store.ingest_text(conn, "".join(f"http://h{i}.example.com/p{i}\n" for i in range(40)), "a.log")
    store.remove_source(conn, sources(conn)["a.log"], batch=3)
    assert counts(conn)["observations"] == 0
    integrity(conn)


def test_big_sources_are_removed_in_batches_with_progress(conn):
    store.ingest_text(conn, "".join(f"line {i} 192.0.2.{i % 250 + 1} h{i}.example.com\n" for i in range(60)), "a.log")
    total = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    seen = []
    store.remove_source(conn, sources(conn)["a.log"], progress=lambda done, all_: seen.append((done, all_)), batch=7)
    assert seen[-1] == (total, total)
    assert [d for d, _ in seen] == sorted(d for d, _ in seen) and len(seen) >= math.ceil(total / 7) - 1
    assert all(a == total for _, a in seen)
    integrity(conn)


def test_a_source_with_nothing_extracted_can_still_be_removed(conn):
    store.ingest_text(conn, "nothing to see here\n", "empty.txt")
    gone = store.remove_source(conn, sources(conn)["empty.txt"])
    assert (gone.sightings, gone.indicators) == (0, 0) and counts(conn)["sources"] == 0


# ------------------------------------------------------------------ what must never be removed
def test_a_feed_snapshot_is_not_an_upload_and_an_unknown_source_is_refused(conn):
    store.ingest_text(conn, "beacon 203.0.113.9\n", "a.log")
    load_feed(conn, FEODO, json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "Emotet"}]))
    feed_id = conn.execute("SELECT id FROM sources WHERE kind = 'feed'").fetchone()["id"]
    before = counts(conn)
    with pytest.raises(ValueError, match="feed snapshot"):
        store.remove_source(conn, feed_id)
    with pytest.raises(LookupError):
        store.remove_source(conn, 9999)
    assert counts(conn) == before


def test_an_indicator_a_feed_lists_stays_after_its_log_is_removed_and_still_matches(conn):
    store.ingest_text(conn, "beacon 203.0.113.9 and local-only 198.51.100.7\n", "a.log")
    load_feed(conn, FEODO, json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "Emotet"}]))
    store.remove_source(conn, sources(conn)["a.log"])
    assert "ipv4 203.0.113.9" in values(conn) and "ipv4 198.51.100.7" not in values(conn)
    assert conn.execute("SELECT COUNT(*) FROM intel").fetchone()[0] == 1
    integrity(conn)
    store.ingest_text(conn, "beacon 203.0.113.9\n", "again.log")  # the feed record is still there to match it
    assert [m.feed for m in correlate(conn).matches] == ["feodotracker"]


def test_an_analysts_verdict_keeps_its_indicator_so_the_verdict_is_not_lost(conn):
    store.ingest_text(conn, "hit 198.51.100.7\n", "a.log")
    ioc = conn.execute("SELECT id FROM iocs").fetchone()["id"]
    lifecycle.add_feedback(conn, ioc, "confirmed", "seen beaconing", "dana")
    store.remove_source(conn, sources(conn)["a.log"])
    assert values(conn) == {"ipv4 198.51.100.7"}
    assert lifecycle.latest_verdicts(conn)[ioc]["verdict"] == "confirmed"
    integrity(conn)


# ------------------------------------------------------------------ everything downstream agrees
def test_cases_triage_and_reports_stop_mentioning_what_was_removed(conn):
    store.ingest_text(conn, "198.51.100.7 evil.example.com\n", "a.log")
    store.ingest_text(conn, "203.0.113.9 other.example.net\n", "b.log")
    run(conn)  # fills the links cache
    assert counts(conn)["links"] == 2
    store.remove_source(conn, sources(conn)["a.log"])
    assert counts(conn)["links"] == 0  # a cache of data that has changed
    md = render_markdown(build_report(conn, "2026-10-20T00:00:00+00:00"))
    assert "203[.]0[.]113[.]9" in md and "198[.]51[.]100[.]7" not in md and "evil[.]example[.]com" not in md
    assert {l.rule for l in correlate(conn).links} == {"same_line"}


def test_the_same_text_can_be_added_again_afterwards_and_comes_back_the_same(conn):
    text = "198.51.100.7 evil.example.com bob@example.org\n"
    store.ingest_text(conn, text, "a.log")
    first = values(conn)
    store.remove_source(conn, sources(conn)["a.log"])
    again = store.ingest_text(conn, text, "a.log")
    assert not again.already_ingested and values(conn) == first


# ------------------------------------------------------------------ interruption
def test_a_removal_that_is_interrupted_can_be_run_again_and_leaves_the_checks_switched_on(tmp_path):
    db = tmp_path / "x.db"
    c = store.connect(db)
    store.ingest_text(c, "".join(f"line {i} 192.0.2.{i % 250 + 1}\n" for i in range(40)), "a.log")
    store.ingest_text(c, "198.51.100.7\n", "keep.log")
    sid = sources(c)["a.log"]
    calls = []

    def die_on_the_second_batch(done, total):
        calls.append(done)
        if len(calls) == 2:
            raise RuntimeError("power cut")

    with pytest.raises(RuntimeError):
        store.remove_source(c, sid, progress=die_on_the_second_batch, batch=5)
    assert "a.log" in sources(c)  # still listed, so it can be finished
    assert 0 < c.execute("SELECT COUNT(*) FROM observations WHERE source_id = ?", (sid,)).fetchone()[0] < 40
    assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    store.remove_source(c, sid, batch=5)
    assert sources(c).keys() == {"keep.log"}
    assert c.execute("SELECT COUNT(*) FROM observations WHERE source_id = ?", (sid,)).fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1  # the other source survived both attempts
    integrity(c)
    c.close()


def test_the_log_file_is_shrunk_back_after_a_removal_on_disk(tmp_path):
    c = store.connect(tmp_path / "x.db")
    store.ingest_text(c, "".join(f"line {i} 10.1.{i % 200}.{i % 250 + 1} h{i}.example.com\n" for i in range(3_000)), "big.log")
    store.remove_source(c, sources(c)["big.log"], batch=500)
    wal = tmp_path / "x.db-wal"
    assert not wal.exists() or wal.stat().st_size < 200_000  # checkpointed, not left to grow
    c.close()


# ------------------------------------------------------------------ in the dashboard
@pytest.fixture
def web(tmp_path):
    ctx = Context(db_path=str(tmp_path / "w.db"), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    c = store.connect(ctx.db_path)
    store.ingest_text(c, "198.51.100.7 evil.example.com\n", "a.log")
    store.ingest_text(c, "203.0.113.9 other.example.net\n", "b.log")
    load_feed(c, FEODO, json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "Emotet"}]))
    c.close()
    server, client = start(ctx)
    yield client, ctx
    server.shutdown()
    server.server_close()
    ctx.close()


def source_id(ctx, name):
    c = ctx.connect()
    try:
        return c.execute("SELECT id FROM sources WHERE name = ?", (name,)).fetchone()["id"]
    finally:
        c.close()


def test_removing_an_upload_through_the_dashboard_runs_in_the_background_and_updates_everything(web):
    client, ctx = web
    sid = source_id(ctx, "a.log")
    # warm the caches the removal has to invalidate
    assert client.get("/api/status")[1]["process"]["indicators"] == 4
    assert client.get("/api/cases")[1]["all_cases"] == 2

    status, out = client.post("/api/sources/remove", {"source_id": sid, "confirmed": True})
    assert status == 200 and out["job"]["kind"] == "remove" and out["job"]["name"] == "a.log"
    assert ctx.jobs().wait(30)

    job = client.get("/api/jobs")[1]["jobs"][0]
    assert job["state"] == "done" and job["kind"] == "remove" and job["result"] == {"name": "a.log", "removed": True, "sightings": 2, "indicators": 2}
    s = client.get("/api/status")[1]
    assert [x["name"] for x in s["sources"]] == ["b.log"]
    assert s["process"]["indicators"] == 2 and s["process"]["sightings"] == 2  # not stale
    assert client.get("/api/cases")[1]["all_cases"] == 1  # the analysis was redone
    assert client.post("/api/sources/remove", {"source_id": sid, "confirmed": True})[0] == 404  # already gone


@pytest.mark.parametrize(
    "body, status",
    [
        ({"confirmed": True}, 400),
        ({"source_id": "1", "confirmed": True}, 400),
        ({"source_id": True, "confirmed": True}, 400),
        ({"source_id": 1}, 400),  # not confirmed
        ({"source_id": 1, "confirmed": False}, 400),
        ({"source_id": 1, "confirmed": "true"}, 400),
        ({"source_id": 9999, "confirmed": True}, 404),
    ],
)
def test_a_bad_or_unconfirmed_removal_is_refused_and_removes_nothing(web, body, status):
    client, ctx = web
    assert client.post("/api/sources/remove", body)[0] == status
    assert len(client.get("/api/status")[1]["sources"]) == 2


def test_a_feed_snapshot_cannot_be_removed_from_the_dashboard(web):
    client, ctx = web
    c = ctx.connect()
    feed = c.execute("SELECT id FROM sources WHERE kind = 'feed'").fetchone()["id"]
    c.close()
    status, err = client.post("/api/sources/remove", {"source_id": feed, "confirmed": True})
    assert status == 400 and "feed snapshot" in err["error"]


def test_the_removal_route_needs_the_token_and_the_right_origin_and_waits_for_other_work(web):
    client, ctx = web
    sid = source_id(ctx, "a.log")
    body = {"source_id": sid, "confirmed": True}
    assert client.post("/api/sources/remove", body, token=False)[0] == 403
    assert client.post("/api/sources/remove", body, token="nope")[0] == 403
    assert client.post("/api/sources/remove", body, headers={"Origin": "http://evil.example"})[0] == 403
    assert client.get("/api/sources/remove")[0] == 404  # not a GET action
    assert len(client.get("/api/status")[1]["sources"]) == 2

    class Busy:
        def busy(self):
            return True

    ctx._jobs = Busy()
    status, err = client.post("/api/sources/remove", body)
    assert status == 409 and "still being processed" in err["error"]
    ctx._jobs = None
    assert len(client.get("/api/status")[1]["sources"]) == 2


def test_while_a_removal_runs_other_writes_are_refused_and_afterwards_allowed(web, tmp_path):
    import threading

    client, ctx = web
    release = threading.Event()
    started = threading.Event()
    real = store.remove_source

    def held_open(conn, sid, progress=None):
        started.set()
        release.wait(20)
        return real(conn, sid, progress=progress)

    ctx._jobs = JobManager(ctx.db_path, work_dir=tmp_path / "work", remove=held_open)
    job = ctx._jobs.submit_removal(source_id(ctx, "a.log"), "a.log")
    assert started.wait(10) and job.state == "processing" and ctx._jobs.busy()
    assert client.post("/api/plan", {"requirement": "What matters?", "marking": "TLP:GREEN", "author": "d"})[0] == 409
    assert client.post("/api/ingest", {"name": "x.txt", "text": "1.2.3.4"})[0] == 409
    assert client.post("/api/sources/remove", {"source_id": source_id(ctx, "b.log"), "confirmed": True})[0] == 409
    assert client.get("/api/status")[0] == 200  # reading keeps working while it runs
    release.set()
    assert ctx._jobs.wait(30) and job.state == "done"
    assert client.post("/api/plan", {"requirement": "What matters?", "marking": "TLP:GREEN", "author": "d"})[0] == 200


def test_a_failing_removal_is_reported_as_a_failed_job_and_the_worker_carries_on(tmp_path):
    db = str(tmp_path / "j.db")
    c = store.connect(db)
    store.ingest_text(c, "198.51.100.7\n", "a.log")
    c.close()

    def boom(conn, source_id, progress=None):
        raise RuntimeError("disk full")

    mgr = JobManager(db, work_dir=tmp_path / "work", remove=boom)
    job = mgr.submit_removal(1, "a.log")
    assert mgr.wait(10)
    assert job.state == "error" and "disk full" in job.error
    assert job.to_dict()["kind"] == "remove"
    ok = JobManager(db, work_dir=tmp_path / "work2")
    real = ok.submit_removal(1, "a.log")
    assert ok.wait(10) and real.state == "done" and real.result["sightings"] == 1
    mgr.close()
    ok.close()


def test_the_page_asks_first_and_never_builds_html_from_data():
    import pathlib

    js = (pathlib.Path(__file__).resolve().parents[1] / "src" / "threatweaver" / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "confirm(`Remove" in js and "confirmed: true" in js and "/api/sources/remove" in js
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js
