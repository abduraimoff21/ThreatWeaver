"""The analysis must not re-read every sighting, and a finished one must survive a restart."""

import gzip
import json
import random
import re
import sqlite3
import threading
import time

import pytest

from threatweaver import analysis_cache, store
from threatweaver.correlate import correlate
from threatweaver.pipeline import run
from threatweaver.triage import EVIDENCE_SAMPLE, _observation_stats, triage
from threatweaver.web import api
from threatweaver.web.api import Context
from threatweaver.web.jobs import JobManager


def random_log(rng, lines):
    ips = [f"192.0.2.{i}" for i in range(1, 30)] + [f"198.51.100.{i}" for i in range(1, 30)]
    hosts = [f"h{i}.example.com" for i in range(12)]
    out = []
    for n in range(lines):
        parts = [rng.choice(ips) for _ in range(rng.randint(0, 3))]
        if rng.random() < 0.3:
            parts.append(rng.choice(hosts))
        if rng.random() < 0.2:
            parts.append("http://" + rng.choice(hosts) + f"/p{rng.randint(1, 4)}")
        if rng.random() < 0.15:
            parts.append(rng.choice(ips).replace(".", "[.]"))
        if rng.random() < 0.1:
            parts.append(f"hxxp://{rng.choice(hosts).replace('.', '[.]')}/x")
        if rng.random() < 0.1:
            parts.append(f"user{rng.randint(1, 5)}@{rng.choice(hosts)}")
        out.append(f"line {n} " + " ".join(parts))
    return "\n".join(out) + "\n"


def make_db(tmp_path, seed=1, sources=3, lines=150, name="c.db"):
    rng = random.Random(seed)
    path = tmp_path / name
    conn = store.connect(path)
    for i in range(sources):
        store.ingest_text(conn, random_log(rng, lines), f"src{i}.log")
    conn.close()
    return path


def recount(conn):
    """What the summary must equal, worked out the slow way from the sightings themselves."""
    rows = conn.execute(
        "SELECT ioc_id, source_id, COUNT(*) AS n, SUM(defanged = 1 AND parent_observation_id IS NULL) AS d "
        "FROM observations GROUP BY ioc_id, source_id").fetchall()
    return {(r["ioc_id"], r["source_id"]): (r["n"], r["d"] or 0) for r in rows}


def same(a, b):
    """Two reports are the same analysis if they match once the time they were made is set aside."""
    return json.dumps({**a, "generated_at": ""}, sort_keys=True) == json.dumps({**b, "generated_at": ""}, sort_keys=True)


def summary(conn):
    return {(r["ioc_id"], r["source_id"]): (r["sightings"], r["direct_defanged"])
            for r in conn.execute("SELECT * FROM ioc_source_stats")}


# ------------------------------------------------------------------ the per-indicator summary
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_the_summary_kept_while_ingesting_equals_a_recount_of_the_sightings(tmp_path, seed):
    conn = store.connect(make_db(tmp_path, seed))
    assert summary(conn) == recount(conn) and summary(conn)
    assert any(d for _, d in summary(conn).values()), "the data must include indicators written defanged on their own"
    assert conn.execute("SELECT COUNT(*) FROM sources WHERE stats_done = 0").fetchone()[0] == 0


def test_the_summary_is_right_for_a_file_ingested_in_many_chunks(tmp_path):
    p = tmp_path / "big.log"
    p.write_text(random_log(random.Random(9), 600), encoding="utf-8")
    conn = store.connect(":memory:")
    store.ingest_path(conn, p, chunk_bytes=2_000)
    assert summary(conn) == recount(conn)


def test_a_sighting_that_is_ignored_as_a_duplicate_is_not_counted(conn=None):
    conn = store.connect(":memory:")
    store.ingest_text(conn, "198.51.100.7 hxxp://a[.]example[.]com/x\n", "a.log")
    store.ingest_text(conn, "198.51.100.7 hxxp://a[.]example[.]com/x\n", "a.log")  # the same content again: a no-op
    assert summary(conn) == recount(conn) and sum(n for n, _ in summary(conn).values()) == 3


def test_databases_from_before_the_summary_are_filled_in_once_and_give_the_same_analysis(tmp_path):
    path = make_db(tmp_path)
    conn = store.connect(path)
    before = json.dumps(run(conn, generated_at="x", persist=False).report, sort_keys=True)
    # make it look like a database made by an older version: no summary, and no marker column
    conn.execute("DROP TABLE ioc_source_stats")
    conn.execute("DROP TABLE meta")
    conn.execute("ALTER TABLE sources DROP COLUMN stats_done")
    conn.commit()
    conn.close()

    conn = store.connect(path)  # opening it migrates it: instant, nothing is counted yet
    assert conn.execute("SELECT COUNT(*) FROM ioc_source_stats").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sources WHERE stats_done = 0").fetchone()[0] == 3
    assert store.ensure_stats(conn) == 3
    assert summary(conn) == recount(conn)
    after = json.dumps(run(conn, generated_at="x", persist=False).report, sort_keys=True)
    assert after == before
    changes = conn.total_changes
    assert store.ensure_stats(conn) == 0 and conn.total_changes == changes, "once done, it must not write anything"


def test_removing_a_source_removes_its_part_of_the_summary(tmp_path):
    conn = store.connect(make_db(tmp_path))
    first = conn.execute("SELECT id FROM sources ORDER BY id").fetchone()["id"]
    store.remove_source(conn, first)
    assert summary(conn) == recount(conn)
    assert first not in {s for _, s in summary(conn)}


# ------------------------------------------------------------------ triage and the report agree with the slow way
def old_observation_stats(conn):
    """The window-function version this replaced, kept here as the reference."""
    n = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT ioc_id, COUNT(*), COUNT(DISTINCT source_id) FROM observations GROUP BY ioc_id")}
    first = {}
    for ioc_id, obs_id in conn.execute(
        "SELECT ioc_id, id FROM (SELECT ioc_id, id, ROW_NUMBER() OVER (PARTITION BY ioc_id ORDER BY id) AS rn FROM observations) "
        "WHERE rn <= ? ORDER BY ioc_id, id", (EVIDENCE_SAMPLE,)):
        first.setdefault(ioc_id, []).append(obs_id)
    dcount = {r[0]: r[1] for r in conn.execute(
        "SELECT ioc_id, COUNT(*) FROM observations WHERE defanged = 1 AND parent_observation_id IS NULL GROUP BY ioc_id")}
    dfirst = {}
    for ioc_id, obs_id in conn.execute(
        "SELECT ioc_id, id FROM (SELECT ioc_id, id, ROW_NUMBER() OVER (PARTITION BY ioc_id ORDER BY id) AS rn "
        "FROM observations WHERE defanged = 1 AND parent_observation_id IS NULL) WHERE rn <= ? ORDER BY ioc_id, id", (EVIDENCE_SAMPLE,)):
        dfirst.setdefault(ioc_id, []).append(obs_id)
    return {i: (c, s, tuple(first[i]), dcount.get(i, 0), tuple(dfirst.get(i, ()))) for i, (c, s) in n.items()}


@pytest.mark.parametrize("seed", [4, 5])
def test_triage_statistics_equal_the_window_function_reference(tmp_path, seed):
    conn = store.connect(make_db(tmp_path, seed, lines=250))
    new = {i: (s.count, s.sources, s.first_ids, s.defanged_count, s.first_defanged_ids) for i, s in _observation_stats(conn).items()}
    assert new == old_observation_stats(conn)


def test_the_report_totals_sources_and_first_sightings_equal_the_reference(tmp_path):
    conn = store.connect(make_db(tmp_path, 6, lines=250))
    report = run(conn, generated_at="x", persist=False).report
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM sources")}
    for case in report["cases"]:
        for ind in case["indicators"]:
            rows = conn.execute("SELECT id, source_id, line_no, raw FROM observations WHERE ioc_id = ? ORDER BY id", (ind["id"],)).fetchall()
            assert ind["sightings_total"] == len(rows)
            assert ind["sources"] == sorted({names[r["source_id"]] for r in rows})
            assert [(s["observation_id"], s["line"], s["raw"]) for s in ind["sightings"]] == [(r["id"], r["line_no"], r["raw"]) for r in rows[:20]]


def test_a_first_sightings_lookup_is_one_short_index_range_not_a_sort(tmp_path):
    conn = store.connect(make_db(tmp_path))
    plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN SELECT id FROM observations WHERE ioc_id = ? ORDER BY id LIMIT ?", (1, 20)))
    assert "idx_obs_ioc" in plan and "TEMP B-TREE" not in plan


def test_the_analysis_never_reads_all_the_sightings_except_to_find_what_shares_a_line(tmp_path):
    """The scale guard: with the summary in place, the only statement that reads every sighting is the one
    that lines them up by source and line to find indicators sharing a line. Anything else that does is the
    slow version coming back (counting, numbering or listing all of them)."""
    conn = store.connect(make_db(tmp_path, 7, lines=300))
    store.ensure_stats(conn)
    statements = []
    conn.set_trace_callback(statements.append)
    run(conn, generated_at="x", persist=False)
    conn.set_trace_callback(None)
    broad = [s for s in statements if re.search(r"FROM observations", s) and not re.search(r"WHERE\s+(ioc_id|o\.ioc_id|source_id)", s)]
    assert len(broad) == 1 and "ORDER BY source_id, line_no" in broad[0], broad


# ------------------------------------------------------------------ the saved analysis
def computed(tmp_path, **kw):
    path = make_db(tmp_path, **kw)
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = ctx.connect()
    a = api.analysis(ctx, conn)
    conn.close()
    return ctx, a


def test_a_saved_analysis_loads_back_identical(tmp_path):
    ctx, a = computed(tmp_path)
    saved = analysis_cache.path_for(ctx.db_path)
    assert saved.exists() and saved.name.endswith(".analysis.gz")
    conn = ctx.connect()
    parts = analysis_cache.load(saved, analysis_cache.fingerprint(conn))
    conn.close()
    result, verdicts, report = parts
    assert same(report, a.report)
    assert result.links == a.result.links and result.matches == a.result.matches
    assert (result.skipped_lines, result.skipped_families) == (a.result.skipped_lines, a.result.skipped_families)
    assert verdicts == a.verdicts and len(verdicts) > 20


def test_a_restart_uses_the_saved_analysis_and_does_not_recompute(tmp_path, monkeypatch):
    ctx, first = computed(tmp_path)
    monkeypatch.setattr(api, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("the analysis was recomputed")))
    restarted = Context(db_path=ctx.db_path, out_dir=ctx.out_dir, cache_dir=ctx.cache_dir, env={})
    conn = restarted.connect()
    again = api.analysis(restarted, conn)
    conn.close()
    assert again is not first and same(again.report, first.report)
    assert again.cases.keys() == first.cases.keys() and again.indicators.keys() == first.indicators.keys()


def test_adding_a_source_makes_the_saved_analysis_stale(tmp_path):
    ctx, a = computed(tmp_path)
    conn = ctx.connect()
    store.ingest_text(conn, "later 203.0.113.9 and fresh.example.net\n", "new.log")
    b = api.analysis(ctx, conn)
    conn.close()
    assert b is not a and "203.0.113.9" in {i["value"] for i in b.indicators.values()}
    assert "203.0.113.9" not in {i["value"] for i in a.indicators.values()}


def test_removing_then_adding_different_content_with_the_same_number_of_sightings_is_not_mistaken_for_the_old_state(tmp_path):
    """The trap a counter-based check falls into: same number of sources, same newest id, different content."""
    path = tmp_path / "t.db"
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = ctx.connect()
    store.ingest_text(conn, "198.51.100.7 a.example.com\n", "a.log")
    store.ingest_text(conn, "203.0.113.1 b.example.com\n", "b.log")
    first = api.analysis(ctx, conn)
    assert "203.0.113.1" in {i["value"] for i in first.indicators.values()}
    store.remove_source(conn, conn.execute("SELECT id FROM sources WHERE name = 'b.log'").fetchone()["id"])
    store.ingest_text(conn, "203.0.113.2 c.example.com\n", "b.log")  # the same name and shape, different content
    second = api.analysis(ctx, conn)
    conn.close()
    values = {i["value"] for i in second.indicators.values()}
    assert "203.0.113.2" in values and "203.0.113.1" not in values

    # and a restart agrees, from the saved copy
    restarted = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = restarted.connect()
    third = api.analysis(restarted, conn)
    conn.close()
    assert {i["value"] for i in third.indicators.values()} == values


def test_something_deleted_since_the_copy_was_made_invalidates_it_even_with_the_same_sources(tmp_path):
    ctx, a = computed(tmp_path)
    conn = ctx.connect()
    fp = analysis_cache.fingerprint(conn)
    store.bump_epoch(conn)  # what a removal does when it starts
    assert analysis_cache.fingerprint(conn) != fp
    assert analysis_cache.load(analysis_cache.path_for(ctx.db_path), analysis_cache.fingerprint(conn)) is None
    conn.close()


def test_new_code_does_not_trust_an_analysis_made_by_old_code(tmp_path, monkeypatch):
    ctx, a = computed(tmp_path)
    conn = ctx.connect()
    monkeypatch.setattr(analysis_cache, "_signature", "a-different-version-of-the-rules")
    assert analysis_cache.load(analysis_cache.path_for(ctx.db_path), analysis_cache.fingerprint(conn)) is None
    conn.close()


@pytest.mark.parametrize("damage", ["empty", "garbage", "truncated", "not-json", "wrong-format", "wrong-fingerprint", "missing-keys"])
def test_a_damaged_or_foreign_saved_file_is_ignored_and_replaced(tmp_path, damage):
    ctx, a = computed(tmp_path)
    saved = analysis_cache.path_for(ctx.db_path)
    good = saved.read_bytes()
    conn = ctx.connect()
    fp = analysis_cache.fingerprint(conn)
    conn.close()
    if damage == "empty":
        saved.write_bytes(b"")
    elif damage == "garbage":
        saved.write_bytes(b"\x00\x01 this is not a gzip file")
    elif damage == "truncated":
        saved.write_bytes(good[: len(good) // 2])
    elif damage == "not-json":
        saved.write_bytes(gzip.compress(b"not json at all"))
    elif damage == "wrong-format":
        saved.write_bytes(gzip.compress(json.dumps({"format": 999, "fingerprint": fp}).encode()))
    elif damage == "wrong-fingerprint":
        saved.write_bytes(gzip.compress(json.dumps({"format": analysis_cache.FORMAT, "fingerprint": "0" * 64}).encode()))
    else:
        saved.write_bytes(gzip.compress(json.dumps({"format": analysis_cache.FORMAT, "fingerprint": fp}).encode()))
    assert analysis_cache.load(saved, fp) is None
    restarted = Context(db_path=ctx.db_path, out_dir=ctx.out_dir, cache_dir=ctx.cache_dir, env={})
    conn = restarted.connect()
    b = api.analysis(restarted, conn)
    conn.close()
    assert same(b.report, a.report)
    conn = ctx.connect()
    assert analysis_cache.load(saved, fp) is not None, "the damaged file should have been replaced by a good one"
    conn.close()


def test_the_saved_file_is_plain_gzipped_json_written_atomically(tmp_path):
    ctx, a = computed(tmp_path)
    saved = analysis_cache.path_for(ctx.db_path)
    assert saved.read_bytes()[:2] == b"\x1f\x8b"
    data = json.loads(gzip.decompress(saved.read_bytes()))
    assert {"format", "fingerprint", "links", "matches", "verdicts", "report"} <= data.keys()
    assert not list(tmp_path.glob("*.tmp"))
    assert "pickle" not in (analysis_cache.__doc__ or "").replace("never pickle", "")
    source = open(analysis_cache.__file__, encoding="utf-8").read()
    assert not re.search(r"^\s*(import|from)\s+(pickle|marshal|shelve)", source, re.M)


def test_a_failed_save_leaves_the_older_file_untouched_and_the_analysis_still_works(tmp_path):
    ctx, a = computed(tmp_path)
    saved = analysis_cache.path_for(ctx.db_path)
    before = saved.read_bytes()
    conn = ctx.connect()
    fp = analysis_cache.fingerprint(conn)
    conn.close()
    assert analysis_cache.save(saved, fp, a.result, a.verdicts, {"cannot": {1, 2, 3}}) is False  # a set is not JSON
    assert saved.read_bytes() == before and not list(tmp_path.glob("*.tmp"))


def test_an_unwritable_place_costs_a_message_not_the_analysis(tmp_path, monkeypatch, capsys):
    path = make_db(tmp_path)
    monkeypatch.setattr(analysis_cache, "save", lambda *a, **k: False)
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = ctx.connect()
    assert api.analysis(ctx, conn).indicators
    conn.close()
    assert "could not save the analysis" in capsys.readouterr().err


def test_an_in_memory_database_has_no_file(tmp_path):
    assert analysis_cache.path_for(":memory:") is None and analysis_cache.path_for("") is None
    assert analysis_cache.load(None, "x") is None


def test_the_saved_files_are_kept_out_of_version_control():
    import pathlib

    ignore = (pathlib.Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8")
    assert "*.analysis.gz" in ignore


def test_a_failed_analysis_leaves_the_connection_clean(tmp_path, monkeypatch):
    path = make_db(tmp_path)
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = ctx.connect()
    monkeypatch.setattr(api, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        api.analysis(ctx, conn)
    assert not conn.in_transaction and ctx._cache is None
    conn.close()


# ------------------------------------------------------------------ waiting, and preparing ahead
def test_two_requests_at_once_make_the_analysis_once(tmp_path, monkeypatch):
    path = make_db(tmp_path, lines=60)
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    calls = []
    real = api.run

    def slow(conn, **kw):
        calls.append(1)
        time.sleep(0.4)
        return real(conn, **kw)

    monkeypatch.setattr(api, "run", slow)
    results = []

    def ask():
        c = ctx.connect()
        results.append(api.analysis(ctx, c))
        c.close()

    threads = [threading.Thread(target=ask) for _ in range(4)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert len(calls) == 1 and len({id(r) for r in results}) == 1 and len(results) == 4


def test_the_rest_of_the_dashboard_is_not_held_up_while_the_analysis_is_made(tmp_path, monkeypatch):
    path = make_db(tmp_path, lines=60)
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    started, release = threading.Event(), threading.Event()
    real = api.run

    def held(conn, **kw):
        started.set()
        release.wait(20)
        return real(conn, **kw)

    monkeypatch.setattr(api, "run", held)
    t = threading.Thread(target=lambda: api.warm(ctx))
    t.start()
    assert started.wait(10)
    t0 = time.time()
    ctx.jobs()  # polling for progress takes the same lock; it must not wait for the analysis
    assert api.jobs_status(ctx) == {"jobs": [], "active": 0} and time.time() - t0 < 1.0
    release.set()
    t.join(30)
    assert ctx._cache is not None


def test_warming_up_loads_or_makes_the_analysis_and_never_raises(tmp_path, capsys):
    path = make_db(tmp_path, lines=40)
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    api.warm(ctx)
    assert ctx._cache is not None and analysis_cache.path_for(ctx.db_path).exists()
    broken = Context(db_path=str(tmp_path / "missing-folder" / "x.db"), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    api.warm(broken)  # cannot even open the database: reported, not raised
    assert "preparing the analysis failed" in capsys.readouterr().err


def test_the_analysis_is_prepared_when_an_upload_finishes_only_if_asked_to(tmp_path):
    path = make_db(tmp_path, sources=1, lines=40)
    extra = tmp_path / "more.log"
    extra.write_text("203.0.113.9 later.example.net\n", encoding="utf-8")

    quiet = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    quiet.jobs().submit("more.log", extra, extra.stat().st_size)
    assert quiet.jobs().wait(20)
    time.sleep(0.3)
    assert quiet._cache is None, "tests and scripts must not start background work unasked"

    extra2 = tmp_path / "more2.log"
    extra2.write_text("203.0.113.10 later2.example.net\n", encoding="utf-8")
    eager = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={}, warm_after_jobs=True)
    eager.jobs().submit("more2.log", extra2, extra2.stat().st_size)
    assert eager.jobs().wait(20)
    for _ in range(100):
        if eager._cache is not None:
            break
        time.sleep(0.1)
    assert eager._cache is not None
    assert "203.0.113.10" in {i["value"] for i in eager._cache[1].indicators.values()}


def test_a_failing_background_preparation_cannot_stop_the_worker(tmp_path):
    path = make_db(tmp_path, sources=1, lines=20)
    extra = tmp_path / "more.log"
    extra.write_text("203.0.113.9\n", encoding="utf-8")

    def boom():
        raise RuntimeError("no")

    mgr = JobManager(str(path), work_dir=tmp_path / "w", on_idle=boom)
    job = mgr.submit("more.log", extra, extra.stat().st_size)
    assert mgr.wait(20) and job.state == "done"
    mgr.close()


# ------------------------------------------------------------------ each part of the identity matters on its own
def test_a_removal_that_dies_half_way_still_changes_the_identity_of_the_database(tmp_path):
    conn = store.connect(make_db(tmp_path, sources=2, lines=60))
    before = analysis_cache.fingerprint(conn)
    target = conn.execute("SELECT id FROM sources ORDER BY id LIMIT 1").fetchone()["id"]

    def die(done, total):
        raise RuntimeError("power cut")

    with pytest.raises(RuntimeError):
        store.remove_source(conn, target, progress=die, batch=5)
    assert conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 2  # same sources as before...
    assert analysis_cache.fingerprint(conn) != before  # ...but not the same data, and the identity says so


def test_the_content_hash_of_a_source_is_part_of_the_identity(tmp_path):
    conn = store.connect(make_db(tmp_path, sources=1, lines=30))
    before = analysis_cache.fingerprint(conn)
    conn.execute("UPDATE sources SET content_sha256 = ?", ("f" * 64,))
    assert analysis_cache.fingerprint(conn) != before


def test_the_name_and_kind_of_a_source_are_part_of_the_identity(tmp_path):
    conn = store.connect(make_db(tmp_path, sources=1, lines=30))
    before = analysis_cache.fingerprint(conn)
    conn.execute("UPDATE sources SET name = 'renamed.log'")
    assert analysis_cache.fingerprint(conn) != before


def test_preparing_ahead_waits_until_the_whole_queue_is_done(tmp_path):
    path = make_db(tmp_path, sources=1, lines=20)
    release = threading.Event()
    calls = []
    real = store.ingest_path

    def slow_first(conn, p, **kw):
        if not release.is_set():
            release.wait(10)
        return real(conn, p, **kw)

    one, two = tmp_path / "one.log", tmp_path / "two.log"
    one.write_text("203.0.113.1\n", encoding="utf-8")
    two.write_text("203.0.113.2\n", encoding="utf-8")
    mgr = JobManager(str(path), work_dir=tmp_path / "w", ingest=slow_first, on_idle=lambda: calls.append(1))
    mgr.submit("one.log", one, one.stat().st_size)
    mgr.submit("two.log", two, two.stat().st_size)  # queued behind the first
    release.set()
    assert mgr.wait(20)
    time.sleep(0.2)
    assert calls == [1], "one preparation, after the last job, not one per job"
    mgr.close()


def test_filling_in_the_summary_of_an_old_database_is_done_by_one_caller_while_the_other_waits(tmp_path, monkeypatch):
    """Both the start-up preparation and the first page can arrive together on an old database. The fill writes
    to the database, so a second writer would wait on the database lock and time out: it must wait for the first."""
    path = make_db(tmp_path, sources=2, lines=60)
    conn = store.connect(path)
    conn.execute("DROP TABLE ioc_source_stats")
    conn.execute("DROP TABLE meta")
    conn.execute("ALTER TABLE sources DROP COLUMN stats_done")
    conn.commit()
    conn.close()
    ctx = Context(db_path=str(path), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})

    entered, release, fills = [], threading.Event(), []
    real = store.ensure_stats

    def watched(c):
        entered.append(threading.current_thread().name)
        if len(entered) == 1:
            release.wait(10)
        n = real(c)
        fills.append(n)
        return n

    monkeypatch.setattr(store, "ensure_stats", watched)
    results = []

    def ask(name):
        c = ctx.connect()
        results.append(api.analysis(ctx, c))
        c.close()

    first = threading.Thread(target=ask, args=("first",), name="first")
    first.start()
    for _ in range(100):
        if entered:
            break
        time.sleep(0.02)
    second = threading.Thread(target=ask, args=("second",), name="second")
    second.start()
    time.sleep(0.4)
    assert entered == ["first"], "the second caller must wait, not start filling in the same tables"
    release.set()
    first.join(30)
    second.join(30)
    assert len(results) == 2 and results[0] is results[1]
    assert sum(fills) == 2  # both sources were filled in exactly once


# ------------------------------------------------------------------ links keep their counts, not their evidence lists
def test_compacting_keeps_every_link_and_its_true_evidence_count(tmp_path, monkeypatch):
    from threatweaver import correlate as correlate_module

    monkeypatch.setattr(correlate_module, "LINK_EVIDENCE_CAP", 10)  # so some links have a capped list
    conn = store.connect(":memory:")
    store.ingest_text(conn, "".join(f"line {i} 192.0.2.1 evil.example.com\n" for i in range(100)), "a.log")
    store.ingest_text(conn, "198.51.100.7 http://bad.example.org/x\n", "b.log")
    raw = correlate(conn)
    assert any(l.evidence_total and l.evidence_total > len(l.evidence) for l in raw.links), "the data must include a capped link"
    packed = analysis_cache.compact(raw)
    assert len(packed.links) == len(raw.links)
    for before, after in zip(raw.links, packed.links):
        assert (after.rule, after.a, after.b, after.explanation) == (before.rule, before.a, before.b, before.explanation)
        assert after.evidence == () and after.evidence_total == analysis_cache.evidence_count(before)
    assert packed.matches == raw.matches and packed.skipped_lines == raw.skipped_lines


def test_an_analysis_looks_the_same_whether_it_was_made_or_loaded(tmp_path):
    ctx, made = computed(tmp_path)
    assert all(l.evidence == () and l.evidence_total is not None for l in made.result.links) and made.result.links
    restarted = Context(db_path=ctx.db_path, out_dir=ctx.out_dir, cache_dir=ctx.cache_dir, env={})
    conn = restarted.connect()
    loaded = api.analysis(restarted, conn)
    conn.close()
    assert loaded.result.links == made.result.links
    for query in ({"min_level": "info"}, {"min_level": "info", "per_node": "1", "limit": "30"}, {"rules": "same_line", "limit": "20"}):
        assert api.graph(restarted, query) == api.graph(ctx, query)  # the picture does not depend on where the analysis came from


def test_the_saved_file_does_not_carry_evidence_lists_for_links(tmp_path):
    ctx, made = computed(tmp_path, sources=3, lines=200)
    data = json.loads(gzip.decompress(analysis_cache.path_for(ctx.db_path).read_bytes()))
    assert all(len(link) == 5 and isinstance(link[4], int) for link in data["links"])
