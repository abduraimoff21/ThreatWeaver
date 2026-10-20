"""The intelligence cycle: plan (stage 1), the status of every stage, and feedback (stage 6)."""

import pytest

from threatweaver import lifecycle, store
from threatweaver.report import render_markdown
from threatweaver.web import api
from threatweaver.web.api import ApiError, Context
from test_web import SCENARIO, Client, start  # noqa: F401  (the HTTP helpers the dashboard tests use)
from threatweaver.pipeline import load_scenario


def make(tmp_path, text=None, name="a.log"):
    ctx = Context(db_path=str(tmp_path / "c.db"), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = store.connect(ctx.db_path)
    if text is not None:
        store.ingest_text(conn, text, name)
    conn.close()
    return ctx


def ioc_id(ctx, value):
    conn = ctx.connect()
    try:
        return conn.execute("SELECT id FROM iocs WHERE value = ?", (value,)).fetchone()["id"]
    finally:
        conn.close()


# ------------------------------------------------------------------ 1 Plan
def test_a_plan_records_the_question_audience_and_sharing_level_and_keeps_every_revision(tmp_path):
    ctx = make(tmp_path)
    assert api.status(ctx)["plan"] is None
    first = api.plan_save(ctx, {"requirement": "Which hosts in these logs need attention?", "audience": "SOC shift lead",
                                "marking": "TLP:AMBER", "author": "dana"})["plan"]
    assert first["marking"] == "TLP:AMBER" and "organisation" in first["marking_meaning"] and first["revisions"] == 1
    second = api.plan_save(ctx, {"requirement": "Is the phishing wave linked to the botnet list?", "audience": "", "marking": "TLP:GREEN", "author": "dana"})["plan"]
    assert second["revisions"] == 2 and api.status(ctx)["plan"]["requirement"].startswith("Is the phishing")


@pytest.mark.parametrize(
    "body",
    [
        {"requirement": "", "marking": "TLP:GREEN", "author": "d"},
        {"requirement": "abc", "marking": "TLP:GREEN", "author": "d"},  # too short to mean anything
        {"requirement": "x" * 501, "marking": "TLP:GREEN", "author": "d"},
        {"requirement": "A real question", "marking": "TLP:PURPLE", "author": "d"},
        {"requirement": "A real question", "marking": "TLP:GREEN", "author": ""},
        {"requirement": "A real question", "marking": "TLP:GREEN", "author": "d", "audience": "y" * 201},
        {"requirement": 5, "marking": "TLP:GREEN", "author": "d"},
        {"requirement": "A real question", "author": "d"},
    ],
)
def test_a_bad_plan_is_refused(tmp_path, body):
    ctx = make(tmp_path)
    with pytest.raises(ApiError) as e:
        api.plan_save(ctx, body)
    assert e.value.status == 400 and api.status(ctx)["plan"] is None


def test_control_characters_and_line_breaks_are_stripped_from_the_plan(tmp_path):
    ctx = make(tmp_path)
    plan = api.plan_save(ctx, {"requirement": "Line one\n\x1b[31mline two  with   gaps", "marking": "TLP:CLEAR", "author": "d\x00ana"})["plan"]
    assert plan["requirement"] == "Line one [31mline two with gaps" and plan["author"] == "dana"


# ------------------------------------------------------------------ where the cycle stands
def test_the_next_step_follows_the_cycle(tmp_path):
    ctx = make(tmp_path)
    assert api.status(ctx)["next"]["stage"] == "plan"
    api.plan_save(ctx, {"requirement": "What should we look at first?", "marking": "TLP:GREEN", "author": "dana"})
    s = api.status(ctx)
    assert s["next"]["stage"] == "collect" and s["next"]["href"] == "#/collect"
    assert [(x["key"], x["state"]) for x in s["stages"]] == [("plan", "done"), ("collect", "todo"), ("process", "waiting"),
                                                             ("analyse", "waiting"), ("share", "waiting"), ("feedback", "waiting")]

    conn = ctx.connect()
    store.ingest_text(conn, "hit 198.51.100.7 and bad.example.com and bob@example.org\n", "a.log")
    conn.close()
    s = api.status(ctx)
    assert s["next"]["stage"] == "analyse"
    assert {x["key"]: x["state"] for x in s["stages"]} == {"plan": "done", "collect": "done", "process": "done",
                                                           "analyse": "ready", "share": "ready", "feedback": "ready"}
    assert s["process"]["by_type"] == {"domain": 2, "ipv4": 1, "email": 1} and s["process"]["indicators"] == 4
    assert "4 indicators from 4 sightings" in next(x["line"] for x in s["stages"] if x["key"] == "process")

    api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "198.51.100.7"), "verdict": "confirmed", "reviewer": "dana"})
    s = api.status(ctx)
    assert s["next"]["stage"] == "plan" and "next cycle" in s["next"]["headline"].lower()  # the loop closes
    assert next(x for x in s["stages"] if x["key"] == "feedback")["state"] == "done"


def test_status_never_runs_the_analysis_so_early_pages_load_at_once(tmp_path, monkeypatch):
    ctx = make(tmp_path, "hit 198.51.100.7\n")

    def refuse(*a, **k):
        raise AssertionError("status must not start an analysis")

    monkeypatch.setattr(api, "analysis", refuse)
    s = api.status(ctx)
    assert s["process"]["indicators"] == 1 and s["sources"][0]["name"] == "a.log" and len(s["feeds"]) == 2
    assert {f["feed"] for f in s["feeds"]} == {"feodotracker", "urlhaus"} and all(not f["loaded"] for f in s["feeds"])


def test_status_reports_a_finished_analysis_only_when_it_is_still_current(tmp_path):
    ctx = make(tmp_path, "hit 198.51.100.7 and bad.example.com\n")
    assert next(x for x in api.status(ctx)["stages"] if x["key"] == "analyse")["line"].startswith("Open it")
    conn = ctx.connect()
    api.analysis(ctx, conn)
    conn.close()
    line = next(x for x in api.status(ctx)["stages"] if x["key"] == "analyse")["line"]
    assert "cases" in line and "high" in line
    conn = ctx.connect()
    store.ingest_text(conn, "later 203.0.113.9\n", "b.log")
    conn.close()
    assert next(x for x in api.status(ctx)["stages"] if x["key"] == "analyse")["line"].startswith("Open it")  # stale: not shown


def test_the_process_counts_are_cached_until_something_is_added(tmp_path, monkeypatch):
    ctx = make(tmp_path, "hit 198.51.100.7\n")
    calls = []
    real = lifecycle.process_counts
    monkeypatch.setattr(lifecycle, "process_counts", lambda conn: calls.append(1) or real(conn))
    api.status(ctx)
    api.status(ctx)
    assert len(calls) == 1
    conn = ctx.connect()
    store.ingest_text(conn, "again 203.0.113.9\n", "b.log")
    conn.close()
    assert api.status(ctx)["process"]["indicators"] == 2 and len(calls) == 2


def test_writing_a_plan_or_feedback_does_not_throw_away_a_finished_analysis(tmp_path):
    ctx = make(tmp_path, "hit 198.51.100.7 and bad.example.com\n")
    conn = ctx.connect()
    before = api.analysis(ctx, conn)
    conn.close()
    api.plan_save(ctx, {"requirement": "What matters most here?", "marking": "TLP:GREEN", "author": "dana"})
    api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "198.51.100.7"), "verdict": "watch", "reviewer": "dana"})
    conn = ctx.connect()
    assert api.analysis(ctx, conn) is before
    conn.close()


# ------------------------------------------------------------------ 6 Feedback
def test_a_verdict_is_recorded_superseded_and_kept_in_the_history(tmp_path):
    ctx = make(tmp_path, "hit 198.51.100.7\n")
    i = ioc_id(ctx, "198.51.100.7")
    api.feedback_add(ctx, {"ioc_id": i, "verdict": "watch", "note": "odd hours", "reviewer": "dana"})
    api.feedback_add(ctx, {"ioc_id": i, "verdict": "false_positive", "note": "our scanner", "reviewer": "eli"})
    detail = api.indicator_detail(ctx, i)
    assert [f["verdict"] for f in detail["feedback"]] == ["false_positive", "watch"]  # newest first, nothing lost
    assert detail["feedback"][0]["label"] == "False alarm" and detail["feedback"][0]["reviewer"] == "eli"
    overview = api.feedback_overview(ctx)
    assert overview["summary"] == {"reviewed": 1, "by_verdict": {"confirmed": 0, "false_positive": 1, "watch": 0, "expected": 0}}
    assert overview["items"][0]["note"] == "our scanner"
    row = api.indicators(ctx, {})["rows"][0]
    assert row["verdict"] == "False alarm"


@pytest.mark.parametrize(
    "body, status",
    [
        ({"ioc_id": 1, "verdict": "great", "reviewer": "d"}, 400),
        ({"ioc_id": 1, "verdict": "watch", "reviewer": ""}, 400),
        ({"ioc_id": 1, "verdict": "watch", "reviewer": "d", "note": "n" * 501}, 400),
        ({"ioc_id": "1", "verdict": "watch", "reviewer": "d"}, 400),
        ({"ioc_id": True, "verdict": "watch", "reviewer": "d"}, 400),
        ({"verdict": "watch", "reviewer": "d"}, 400),
        ({"ioc_id": 99999, "verdict": "watch", "reviewer": "d"}, 404),
    ],
)
def test_bad_feedback_is_refused(tmp_path, body, status):
    ctx = make(tmp_path, "hit 198.51.100.7\n")
    with pytest.raises(ApiError) as e:
        api.feedback_add(ctx, body)
    assert e.value.status == status
    assert api.status(ctx)["feedback"]["reviewed"] == 0


def test_the_review_queue_offers_the_strongest_unreviewed_indicators_first(tmp_path):
    ctx = make(tmp_path, "".join(f"hit 198.51.100.7 {i}\n" for i in range(1_200)) + "once 203.0.113.9\n")
    queue = api.feedback_overview(ctx)["queue"]
    assert queue[0]["value"] == "198.51.100.7" and queue[0]["level"] != "info"
    api.feedback_add(ctx, {"ioc_id": queue[0]["id"], "verdict": "confirmed", "reviewer": "dana"})
    assert "198.51.100.7" not in {q["value"] for q in api.feedback_overview(ctx)["queue"]}  # reviewed ones leave the queue


def test_a_quiet_data_set_still_offers_something_to_review_and_says_so(tmp_path):
    ctx = make(tmp_path, "once 203.0.113.9 and 198.51.100.7\n")
    o = api.feedback_overview(ctx)
    assert len(o["queue"]) == 2 and o["queue_is_quiet"]


def test_the_accuracy_table_shows_how_each_suggested_level_was_judged(tmp_path):
    ctx = make(tmp_path, "".join(f"hit 198.51.100.7 {i}\n" for i in range(1_200)) + "once 203.0.113.9\n")
    api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "198.51.100.7"), "verdict": "false_positive", "reviewer": "dana"})
    api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "203.0.113.9"), "verdict": "confirmed", "reviewer": "dana"})
    table = {row["level"]: row for row in api.feedback_overview(ctx)["accuracy"]}
    assert table["medium"]["reviewed"] == 1 and table["medium"]["false_positive"] == 1 and table["medium"]["confirmed"] == 0
    assert table["info"]["reviewed"] == 1 and table["info"]["confirmed"] == 1
    assert table["high"]["reviewed"] == 0


# ------------------------------------------------------------------ share: the report and the advisory carry the cycle
def test_the_report_states_the_question_and_the_feedback_and_defangs_what_people_typed(tmp_path):
    ctx = make(tmp_path, "hit 198.51.100.7 from bad.example.com\n")
    api.plan_save(ctx, {"requirement": "Is bad.example.com talking to us?", "audience": "IT security", "marking": "TLP:AMBER", "author": "dana"})
    api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "198.51.100.7"), "verdict": "confirmed",
                           "note": "seen beaconing to evil.example.net | twice", "reviewer": "dana"})
    md = api.report_download(ctx, "md")[0].decode()
    assert "## Question this report answers" in md and "TLP:AMBER" in md and "IT security" in md
    assert "## Analyst feedback" in md and "Real threat" in md
    assert "evil[.]example[.]net" in md and "evil.example.net" not in md  # a note may mention an indicator; it is defanged
    assert md.count("| Real threat |") == 1 and "/ twice" in md  # a pipe in a note cannot break the table
    json_report = api.report_download(ctx, "json")[0].decode()
    assert '"plan"' in json_report and '"feedback"' in json_report
    preview = api.report(ctx)
    assert preview["plan"]["marking"] == "TLP:AMBER" and "Analyst feedback" in preview["preview"]


def test_a_report_without_a_plan_or_feedback_is_unchanged(tmp_path):
    ctx = make(tmp_path, "hit 198.51.100.7\n")
    md = api.report_download(ctx, "md")[0].decode()
    assert "Question this report answers" not in md and "Analyst feedback" not in md
    conn = ctx.connect()
    assert render_markdown(api.analysis(ctx, conn).report) == md  # the stored analysis and the download agree
    conn.close()


def test_advisory_drafts_leave_out_indicators_a_person_called_a_false_alarm_or_expected():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        ctx = Context(db_path=str(Path(d) / "s.db"), out_dir=Path(d) / "adv", cache_dir=str(Path(d) / "cache"), env={})
        conn = store.connect(ctx.db_path)
        load_scenario(conn, SCENARIO)
        conn.close()
        body = api.advisory_draft(ctx, {"author": "alice"})["body"]
        assert "203[.]0[.]113[.]45" in body
        api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "203.0.113.45"), "verdict": "expected", "note": "our own test host", "reviewer": "bob"})
        redone = api.advisory_draft(ctx, {"author": "alice"})["body"]
        assert "203[.]0[.]113[.]45" not in redone
        # "keep watching" and "real threat" do not remove it
        api.feedback_add(ctx, {"ioc_id": ioc_id(ctx, "203.0.113.45"), "verdict": "confirmed", "reviewer": "bob"})
        assert "203[.]0[.]113[.]45" in api.advisory_draft(ctx, {"author": "alice"})["body"]


# ------------------------------------------------------------------ over HTTP
@pytest.fixture
def web(tmp_path):
    ctx = make(tmp_path, "hit 198.51.100.7\n")
    server, client = start(ctx)
    yield client, ctx
    server.shutdown()
    server.server_close()
    ctx.close()


def test_the_new_routes_need_the_token_and_validate_their_input(web):
    client, ctx = web
    for path in ("/api/status", "/api/feedback"):
        assert client.get(path, token=False)[0] == 403 and client.get(path, token="nope")[0] == 403
    for path in ("/api/plan", "/api/feedback"):
        assert client.post(path, {}, token=False)[0] == 403
        assert client.post(path, {}, headers={"Origin": "http://evil.example"})[0] == 403
    assert client.post("/api/plan", {"requirement": "ok?"})[0] == 400
    status, saved = client.post("/api/plan", {"requirement": "What should we look at first?", "marking": "TLP:GREEN", "author": "dana"})
    assert status == 200 and saved["plan"]["marking"] == "TLP:GREEN"
    status, s = client.get("/api/status")
    assert status == 200 and s["plan"]["requirement"].startswith("What should") and s["next"]["stage"] == "analyse"
    assert client.post("/api/feedback", {"ioc_id": 99999, "verdict": "watch", "reviewer": "d"})[0] == 404
    i = ioc_id(ctx, "198.51.100.7")
    assert client.post("/api/feedback", {"ioc_id": i, "verdict": "confirmed", "reviewer": "dana", "note": "yes"})[0] == 200
    status, fb = client.get("/api/feedback")
    assert status == 200 and fb["summary"]["reviewed"] == 1 and fb["items"][0]["value"] == "198.51.100.7"
    assert client.request("PUT", "/api/plan", {})[0] == 405


def test_plan_and_feedback_writes_wait_while_a_big_file_is_processing(web):
    client, ctx = web

    class Busy:
        def busy(self):
            return True

    ctx._jobs = Busy()
    assert client.post("/api/plan", {"requirement": "What should we look at first?", "marking": "TLP:GREEN", "author": "d"})[0] == 409
    assert client.post("/api/feedback", {"ioc_id": 1, "verdict": "watch", "reviewer": "d"})[0] == 409
    ctx._jobs = None


def test_free_text_is_returned_as_data_never_as_markup(web):
    client, ctx = web
    payload = "<img src=x onerror=alert(1)> <script>alert(2)</script>"
    client.post("/api/plan", {"requirement": payload + " why", "audience": payload, "marking": "TLP:GREEN", "author": "d"})
    client.post("/api/feedback", {"ioc_id": ioc_id(ctx, "198.51.100.7"), "verdict": "watch", "reviewer": "d", "note": payload})
    status, headers, body = client.request("GET", "/api/status")
    assert headers["Content-Type"].startswith("application/json") and b"<script>" in body  # stored and returned verbatim, as JSON
    js = (api.Path(__file__).resolve().parents[1] / "src" / "threatweaver" / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js and "document.write" not in js
