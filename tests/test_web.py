import http.client
import json
import re
import threading
from pathlib import Path

import pytest

from threatweaver import store
from threatweaver.cli import main
from threatweaver.feeds import FeedError
from threatweaver.pipeline import load_scenario
from threatweaver.web import api
from threatweaver.web.api import Context, safe_line
from threatweaver.web.server import STATIC_DIR, create_server

SCENARIO = Path(__file__).resolve().parents[1] / "data" / "synthetic" / "scenario"
FEEDS = SCENARIO / "feeds"


class Client:
    def __init__(self, server, token):
        self.port, self.token = server.server_address[1], token

    def request(self, method, path, body=None, headers=None, token=True, host=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host or f"127.0.0.1:{self.port}")
        h = dict(headers or {})
        if token:
            h.setdefault("X-TW-Token", self.token if token is True else token)
        payload = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        if payload is not None:
            h.setdefault("Content-Type", "application/json")
            h["Content-Length"] = str(len(payload))
        for k, v in h.items():
            conn.putheader(k, v)
        conn.endheaders(payload)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def get(self, path, **kw):
        status, headers, data = self.request("GET", path, **kw)
        return status, (json.loads(data) if headers.get("Content-Type", "").startswith("application/json") else data)

    def post(self, path, body, **kw):
        status, headers, data = self.request("POST", path, body, **kw)
        return status, json.loads(data)


def start(ctx):
    server, token = create_server(ctx, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, Client(server, token)


@pytest.fixture
def ctx(tmp_path):
    return Context(db_path=str(tmp_path / "t.db"), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})


@pytest.fixture
def web(ctx):
    store.connect(ctx.db_path).close()
    server, client = start(ctx)
    yield client
    server.shutdown()
    server.server_close()


@pytest.fixture
def scenario_web(ctx):
    conn = store.connect(ctx.db_path)
    load_scenario(conn, SCENARIO)
    conn.close()
    server, client = start(ctx)
    yield client
    server.shutdown()
    server.server_close()


# ------------------------------------------------------------- access control
def test_refuses_to_listen_on_anything_but_loopback(ctx):
    for host in ("0.0.0.0", "192.168.1.5", ""):
        with pytest.raises(ValueError, match="loopback"):
            create_server(ctx, host=host, port=0)


def test_page_needs_the_token_and_ships_security_headers(web):
    assert web.request("GET", "/", token=False)[0] == 403
    assert web.request("GET", "/?token=wrong", token=False)[0] == 403
    status, headers, body = web.request("GET", f"/?token={web.token}", token=False)
    assert status == 200 and f'content="{web.token}"'.encode() in body
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store" and headers["Referrer-Policy"] == "no-referrer"


def test_every_api_route_rejects_missing_or_wrong_token(web):
    for path in ("/api/overview", "/api/cases", "/api/indicators", "/api/graph", "/api/sources", "/api/report", "/api/advisories"):
        assert web.get(path, token=False)[0] == 403, path
        assert web.get(path, token="nope")[0] == 403, path
    for path in ("/api/ingest", "/api/feeds/fetch", "/api/advisory/draft", "/api/advisory/1/approve"):
        assert web.post(path, {}, token=False)[0] == 403, path


def test_dns_rebinding_host_header_is_refused(web):
    assert web.request("GET", "/api/overview", host="evil.example")[0] == 403
    assert web.request("GET", f"/?token={web.token}", token=False, host="evil.example")[0] == 403
    assert web.request("GET", "/static/app.js", host="evil.example")[0] == 404
    assert web.request("GET", "/api/overview", host=f"localhost:{web.port}")[0] == 200


def test_cross_site_requests_are_refused(web):
    assert web.post("/api/ingest", {"name": "a.txt", "text": "x"}, headers={"Origin": "http://evil.example"})[0] == 403
    assert web.post("/api/ingest", {"name": "a.txt", "text": "x"}, headers={"Origin": f"http://127.0.0.1:{web.port}"})[0] == 200
    # a "simple" cross-site form post cannot set JSON content type or the token header
    status, _, _ = web.request("POST", "/api/ingest", raw_body=b"name=a&text=b", headers={"Content-Type": "text/plain"})
    assert status == 415


def test_no_cors_headers_and_no_preflight_approval(web):
    status, headers, _ = web.request("GET", "/api/overview", headers={"Origin": "http://evil.example"})
    assert status == 403 and not any(k.lower().startswith("access-control") for k in headers)
    status, headers, _ = web.request("OPTIONS", "/api/overview", headers={"Origin": "http://evil.example"})
    assert status >= 400 and not any(k.lower().startswith("access-control") for k in headers)
    for method in ("PUT", "DELETE", "PATCH"):
        assert web.request(method, "/api/ingest")[0] == 405


def test_static_files_are_whitelisted(web):
    assert web.request("GET", "/static/app.js", token=False)[0] == 200
    assert web.request("GET", "/static/style.css", token=False)[0] == 200
    for path in ("/static/index.html", "/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/api.py", "/static/", "/etc/passwd"):
        assert web.request("GET", path, token=False)[0] == 404, path


def test_oversized_and_malformed_bodies(web, monkeypatch):
    assert web.request("POST", "/api/ingest", raw_body=b"{not json")[0] == 400
    assert web.request("POST", "/api/ingest", raw_body=b"[1,2]")[0] == 400
    status, _, _ = web.request("POST", "/api/ingest", headers={"Content-Length": str(10 ** 9), "Content-Type": "application/json"})
    assert status == 413
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 100)
    assert web.post("/api/ingest", {"name": "big.txt", "text": "x" * 500})[0] == 413


def test_the_token_is_never_written_to_the_server_log(web, capfd):
    web.request("GET", f"/?token={web.token}", token=False)
    web.get("/api/overview")
    err = capfd.readouterr().err
    assert web.token not in err and "[ui]" in err


def test_front_end_never_builds_html_from_data():
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "srcdoc", "javascript:"):
        assert forbidden not in js, forbidden
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and "onclick=" not in html and "style=" not in html
    # the only URL in the script is the SVG namespace identifier; nothing is fetched from elsewhere
    assert re.findall(r"https?://[^\s'\"]+", js) == ["http://www.w3.org/2000/svg"]


# ------------------------------------------------------------- data endpoints
def test_ingest_then_read_back_with_context_and_defanging(web):
    text = "line one\n2026-10-15 proxy user=eve GET http://203.0.113.9/<script>alert(1)</script>.bin dst=203.0.113.9\n"
    status, res = web.post("/api/ingest", {"name": "../../etc/proxy.log", "text": text})
    assert status == 200 and res["name"] == "proxy.log" and res["new_indicators"] >= 2
    assert web.post("/api/ingest", {"name": "../../etc/proxy.log", "text": text})[1]["already_ingested"] is True

    _, rows = web.get("/api/indicators?q=203.0.113.9&type=ipv4")
    (ind,) = rows["rows"]
    assert ind["value"] == "203.0.113.9" and ind["display"] == "203[.]0[.]113[.]9"
    _, detail = web.get(f"/api/indicator/{ind['id']}")
    assert detail["sightings_total"] == 2
    assert all("203.0.113.9" not in s["context"] and "203[.]0[.]113[.]9" in s["context"] for s in detail["sightings"])
    assert any("<script>" in s["context"] for s in detail["sightings"])  # kept as inert text; the UI uses textContent


def test_upload_validation(web):
    assert web.post("/api/ingest", {"name": "", "text": "x"})[0] == 400
    assert web.post("/api/ingest", {"name": "a.txt"})[0] == 400
    assert web.post("/api/ingest", {"name": "a.txt", "text": 5})[0] == 400


def test_overview_cases_graph_and_report(scenario_web):
    _, o = scenario_web.get("/api/overview")
    assert o["summary"]["indicators"] == 10 and o["summary"]["by_level"]["high"] == 4 and not o["empty"]
    assert {f["feed"] for f in o["feeds"]} == {"feodotracker", "urlhaus"} and all(f["loaded"] for f in o["feeds"])
    assert o["database"] == "t.db" and "/" not in o["database"] and "\\" not in o["database"]

    _, c = scenario_web.get("/api/cases")
    assert len(c["cases"]) == 3 and c["cases"][0]["max_level"] == "high"
    case_id = c["cases"][0]["case_id"]
    _, detail = scenario_web.get(f"/api/case/{case_id}")
    assert detail["indicators"] and detail["links"]
    assert scenario_web.get("/api/case/TW-nope")[0] == 404

    _, g = scenario_web.get(f"/api/graph?case={case_id}")
    ids = {n["id"] for n in g["nodes"]}
    assert g["edges"] and all(e["a"] in ids and e["b"] in ids for e in g["edges"])
    _, everything = scenario_web.get("/api/graph")
    assert len(everything["nodes"]) >= len(g["nodes"])

    _, r = scenario_web.get("/api/report")
    assert r["traceability"]["unresolved"] == 0 and "DRAFT FOR ANALYST REVIEW" in r["markdown"]


def test_indicator_detail_explains_the_rules(scenario_web):
    _, rows = scenario_web.get("/api/indicators?q=203.0.113.45&type=ipv4")
    (ind,) = rows["rows"]
    _, d = scenario_web.get(f"/api/indicator/{ind['id']}")
    assert d["level"] == "high" and {r["rule"] for r in d["rules"]} >= {"TW-T01", "TW-T06"}
    assert all(r["description"] for r in d["rules"]) and "blocking" in d["suggested_action"]
    assert d["feed_matches"][0]["feed"] == "feodotracker" and d["feed_matches"][0]["fields"]["malware"] == "Emotet"
    assert all("203.0.113.45" not in json.dumps(r) for r in d["rules"])  # reasons are defanged too
    assert d["sightings"][0]["has_context"] and scenario_web.get("/api/indicator/999999")[0] == 404
    assert scenario_web.get("/api/indicator/abc")[0] == 404


def test_filters_and_paging(scenario_web):
    assert scenario_web.get("/api/indicators?level=high")[1]["total"] == 4
    assert scenario_web.get("/api/indicators?source=a-proxy")[1]["total"] == 8
    assert scenario_web.get("/api/indicators?q=nothing-like-this")[1]["total"] == 0
    page = scenario_web.get("/api/indicators?limit=3&offset=3")[1]
    assert len(page["rows"]) == 3 and page["total"] == 10
    assert scenario_web.get("/api/indicators?limit=-5&offset=abc")[0] == 200


def test_analysis_refreshes_after_new_data(web):
    assert web.get("/api/overview")[1]["empty"] is True
    web.post("/api/ingest", {"name": "n.txt", "text": "seen 198.51.100.4 and 198.51.100.5"})
    assert web.get("/api/overview")[1]["summary"]["indicators"] == 2


# ------------------------------------------------------------- feeds and secrets
def test_feed_fetch_uses_the_cache_layer_and_reports_errors(ctx):
    calls = []

    def fake(spec, cache_dir, force=False, env=None, **kw):
        calls.append((spec.name, force, dict(env or {})))
        if spec.name == "urlhaus":
            raise FeedError("urlhaus needs a free abuse.ch Auth-Key in the URLHAUS_AUTH_KEY environment variable")
        return (FEEDS / "feodo.json").read_text(encoding="utf-8"), False

    ctx.fetcher = fake
    server, web = start(ctx)
    try:
        status, res = web.post("/api/feeds/fetch", {"feed": "feodotracker"})
        assert status == 200 and res["records"] == 3 and res["from_cache"] is False
        assert web.post("/api/feeds/fetch", {"feed": "feodotracker"})[1]["already_loaded"] is True
        status, err = web.post("/api/feeds/fetch", {"feed": "urlhaus"})
        assert status == 502 and "URLHAUS_AUTH_KEY" in err["error"]
        assert web.post("/api/feeds/fetch", {"feed": "somewhere-else"})[0] == 400
        assert web.post("/api/feeds/fetch", {"feed": ["x"]})[0] == 400
        assert web.post("/api/feeds/fetch", {"feed": "feodotracker", "force": True})[0] == 200 and calls[-1][1] is True
    finally:
        server.shutdown()


def test_the_feed_key_never_reaches_the_browser(ctx):
    secret = "tw-secret-key-0123456789"
    ctx.env = {"URLHAUS_AUTH_KEY": secret}
    store.connect(ctx.db_path).close()
    server, web = start(ctx)
    try:
        _, o = web.get("/api/overview")
        urlhaus = next(f for f in o["feeds"] if f["feed"] == "urlhaus")
        assert urlhaus["key_set"] is True and urlhaus["key_variable"] == "URLHAUS_AUTH_KEY"
        for path in ("/api/overview", "/api/cases", "/api/indicators", "/api/graph", "/api/sources", "/api/report", "/api/advisories"):
            assert secret.encode() not in web.request("GET", path)[2], path
        assert secret.encode() not in web.request("GET", f"/?token={web.token}", token=False)[2]
    finally:
        server.shutdown()


# ------------------------------------------------------------- advisories in the UI
def test_advisory_workflow_through_the_api(scenario_web, ctx):
    status, adv = scenario_web.post("/api/advisory/draft", {"author": "alice"})
    assert status == 200 and adv["status"] == "draft" and "203[.]0[.]113[.]45" in adv["body"]
    assert not any(f["blocking"] for f in adv["findings"])
    for private in ("a-proxy.log", "a-fw.log", "10[.]0[.]0[.]15", "alice"):
        assert private not in adv["body"], private
    adv_id = adv["id"]
    base = f"/api/advisory/{adv_id}"

    assert scenario_web.post(f"{base}/publish", {"actor": "alice"})[0] == 409  # cannot skip review
    assert scenario_web.post(f"{base}/submit", {"actor": "alice"})[1]["status"] == "submitted"
    sha = scenario_web.get(base)[1]["content_sha256"]

    approve = lambda **kw: scenario_web.post(f"{base}/approve", {"reviewer": "bob", "seen_sha256": sha, "confirmation": f"APPROVE {adv_id}", **kw})
    assert approve(reviewer="alice")[0] == 409
    assert approve(confirmation="yes")[0] == 409
    assert approve(confirmation="approve " + str(adv_id))[0] == 409
    assert approve(seen_sha256="0" * 64)[0] == 409
    assert scenario_web.get(base)[1]["status"] == "submitted"

    status, done = approve()
    assert status == 200 and done["status"] == "approved" and done["reviewer"] == "bob"
    status, pub = scenario_web.post(f"{base}/publish", {"actor": "carol"})
    assert status == 200 and pub["status"] == "published"
    files = sorted(p.name for p in ctx.out_dir.iterdir())
    assert files == [f"advisory-{adv_id:04d}.json", f"advisory-{adv_id:04d}.md"]
    assert [e["action"] for e in scenario_web.get(base)[1]["events"]] == ["create", "submit", "approve", "publish"]
    assert scenario_web.post(f"{base}/edit", {"title": "t", "body": "b", "actor": "alice"})[0] == 409  # immutable


def test_advisory_edit_check_and_blocking(scenario_web):
    _, adv = scenario_web.post("/api/advisory/draft", {"author": "alice"})
    base = f"/api/advisory/{adv['id']}"
    status, chk = scenario_web.post("/api/advisory/check", {"text": "see 10.0.0.5 and jane@realco.com, TLP:AMBER"})
    assert status == 200 and {f["kind"] for f in chk["findings"]} >= {"non_routable_address", "email_address", "confidentiality_marker"}
    scenario_web.post(f"{base}/edit", {"title": adv["title"], "body": adv["body"] + "\nInternal host 10.0.0.5\n", "actor": "alice"})
    status, err = scenario_web.post(f"{base}/submit", {"actor": "alice"})
    assert status == 409 and "confidentiality" in err["error"]
    assert scenario_web.post("/api/advisory/check", {"text": 5})[0] == 400
    assert scenario_web.get("/api/advisory/999")[0] == 404
    assert scenario_web.post("/api/advisory/999/submit", {"actor": "a"})[0] == 404


def test_advisory_draft_needs_public_evidence_and_an_author(web):
    assert web.post("/api/advisory/draft", {"author": "alice"})[0] == 400  # empty database: nothing to advise on
    assert web.get("/api/advisories")[1]["advisories"] == []


# ------------------------------------------------------------- helpers and CLI
def test_safe_line_defangs_and_strips_control_characters():
    out = safe_line("a\x00b\x1b[31m GET http://bad.example.com/x from 203.0.113.9 and hxxp://ok[.]example[.]org")
    assert "\x00" not in out and "\x1b" not in out
    assert "hxxp://bad[.]example[.]com/x" in out and "203[.]0[.]113[.]9" in out and "hxxp://ok[.]example[.]org" in out
    assert safe_line(None) == "" and safe_line("") == ""


def test_old_databases_are_migrated_in_place(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("CREATE TABLE observations (id INTEGER PRIMARY KEY, ioc_id INT, source_id INT, raw TEXT, span_start INT, span_end INT, line_no INT, defanged INT, parent_observation_id INT);")
    conn.close()
    new = store.connect(path)
    assert "context" in {r["name"] for r in new.execute("PRAGMA table_info(observations)")}


def test_ui_command_exists(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["ui", "--help"])
    assert exc.value.code == 0 and "--no-browser" in capsys.readouterr().out
