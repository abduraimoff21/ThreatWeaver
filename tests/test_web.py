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
    ctx.close()


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
    monkeypatch.setattr(api, "MAX_PASTE_BYTES", 100)
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
    assert r["traceability"]["unresolved"] == 0 and "DRAFT FOR ANALYST REVIEW" in r["preview"] and r["truncated"] is False
    status, headers, md = scenario_web.request("GET", "/api/report.md")
    assert status == 200 and headers["Content-Type"].startswith("text/markdown") and "attachment" in headers["Content-Disposition"]
    assert b"DRAFT FOR ANALYST REVIEW" in md
    status, headers, raw = scenario_web.request("GET", "/api/report.json")
    assert status == 200 and json.loads(raw)["summary"]["indicators"] == 10
    assert scenario_web.request("GET", "/api/report.md", token=False)[0] == 403
    assert scenario_web.request("GET", "/api/report.json", host="evil.example")[0] == 403
    assert scenario_web.request("GET", "/api/report.xml")[0] == 404


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


def test_a_huge_report_is_previewed_not_dumped(ctx):
    store.connect(ctx.db_path).close()
    server, web = start(ctx)
    try:
        text = "".join(f"line {i} host 192.0.2.{i % 250 + 1}.isp{i}.example.com seen 198.51.100.{i % 200 + 1}\n" for i in range(1500))
        web.post("/api/ingest", {"name": "big.log", "text": text})
        _, r = web.get("/api/report")
        assert r["lines"] > api.PREVIEW_LINES and r["truncated"] is True
        assert len(r["preview"].split(chr(10))) == api.PREVIEW_LINES
        assert len(json.dumps(r)) < 2_000_000
        assert len(web.request("GET", "/api/report.md")[2]) > len(r["preview"])
    finally:
        server.shutdown()


# ------------------------------------------------------------- large uploads: streamed to disk, ingested in the background
import socket
import time
from types import SimpleNamespace

OCTET = {"Content-Type": "application/octet-stream"}


def upload(web, name, data, **kw):
    status, headers, body = web.request("POST", f"/api/upload?name={name}", raw_body=data, headers=dict(OCTET, **kw.pop("headers", {})), **kw)
    return status, (json.loads(body) if body else None)


def wait_idle(web, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        _, jobs = web.get("/api/jobs")
        if jobs["active"] == 0:
            return jobs
        time.sleep(0.05)
    raise AssertionError("jobs did not finish")


def log_bytes(lines=2000):
    return "".join(f"2026-10-14 proxy GET http://198.51.100.{i % 200 + 1}/p{i}.bin dst=203.0.113.{i % 250 + 1}\n" for i in range(lines)).encode()


def upload_dir_files(ctx):
    return sorted(ctx.jobs().work_dir.iterdir())


def test_the_upload_limit_is_one_gigabyte_and_pasted_text_stays_small():
    assert api.MAX_UPLOAD_BYTES == 1024 ** 3 and api.MAX_PASTE_BYTES == 20 * 1024 * 1024


def test_overview_tells_the_page_the_limits(web):
    assert web.get("/api/overview")[1]["limits"] == {"upload_bytes": 1024 ** 3, "paste_bytes": 20 * 1024 * 1024}


def test_a_file_is_streamed_to_disk_ingested_in_the_background_and_the_temp_copy_removed(web, ctx):
    data = log_bytes(2000)
    status, res = upload(web, "proxy.log", data)
    assert status == 202 and res["job"]["name"] == "proxy.log" and res["job"]["size"] == len(data)
    jobs = wait_idle(web)
    (job,) = jobs["jobs"]
    assert job["state"] == "done" and job["percent"] == 100.0 and job["result"]["new_indicators"] > 400 and job["error"] is None
    _, o = web.get("/api/overview")
    assert o["summary"]["indicators"] == job["result"]["new_indicators"] and o["sources"][0]["name"] == "proxy.log"
    assert upload_dir_files(ctx) == []  # nothing left behind
    assert upload(web, "proxy.log", data)[0] == 202 and wait_idle(web)["jobs"][0]["result"]["already_ingested"] is True


def test_upload_sha256_is_the_files_own_hash(web):
    import hashlib

    data = log_bytes(50).replace(b"\n", b"\r\n")  # Windows line endings preserved
    upload(web, "crlf.log", data)
    wait_idle(web)
    assert web.get("/api/overview")[1]["sources"][0]["sha256"] == hashlib.sha256(data).hexdigest()


def test_upload_validation_and_name_sanitising(web, monkeypatch):
    assert upload(web, "", b"x")[0] == 400
    assert upload(web, "a.log", b"")[0] == 400
    assert web.request("POST", "/api/upload?name=a.log", headers=OCTET)[0] in (400, 411)  # no length / no body
    status, _ = upload(web, "..%2F..%2Fetc%2Fevil.log", b"seen 203.0.113.9\n")
    assert status == 202
    wait_idle(web)
    assert web.get("/api/overview")[1]["sources"][0]["name"] == "evil.log"
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 1000)
    assert upload(web, "big.log", b"x" * 1001)[0] == 413
    assert upload(web, "ok.log", b"seen 203.0.113.10 " + b" " * 900)[0] == 202


def test_upload_needs_token_host_origin_and_the_right_content_type(web, ctx):
    data = log_bytes(5)
    assert upload(web, "a.log", data, token=False)[0] == 403
    assert upload(web, "a.log", data, token="wrong")[0] == 403
    assert upload(web, "a.log", data, host="evil.example")[0] == 403
    assert upload(web, "a.log", data, headers={"Origin": "http://evil.example"})[0] == 403
    status, _, _ = web.request("POST", "/api/upload?name=a.log", raw_body=data, headers={"Content-Type": "application/json"})
    assert status == 415
    status, _, _ = web.request("POST", "/api/upload?name=a.log", raw_body=data, headers={"Content-Type": "text/plain"})
    assert status == 415
    assert web.get("/api/jobs", token=False)[0] == 403
    assert web.get("/api/jobs", host="evil.example")[0] == 403
    assert web.get("/api/jobs")[1] == {"jobs": [], "active": 0}
    assert not (ctx._jobs and upload_dir_files(ctx))  # rejected requests never touched the disk


def test_not_enough_disk_space_is_refused_before_anything_is_written(web, ctx, monkeypatch):
    from threatweaver.web import server

    monkeypatch.setattr(server.shutil, "disk_usage", lambda p: SimpleNamespace(total=10 ** 9, used=0, free=1000))
    status, res = upload(web, "a.log", log_bytes(10))
    assert status == 507 and "disk space" in res["error"] and upload_dir_files(ctx) == []


def test_a_cut_short_upload_is_discarded_and_the_server_keeps_working(web, ctx):
    sock = socket.create_connection(("127.0.0.1", web.port), timeout=5)
    sock.sendall((f"POST /api/upload?name=cut.log HTTP/1.1\r\nHost: 127.0.0.1:{web.port}\r\nX-TW-Token: {web.token}\r\n"
                  "Content-Type: application/octet-stream\r\nContent-Length: 100000\r\n\r\n").encode() + b"only a little data")
    sock.close()  # the browser tab was closed mid-upload
    time.sleep(0.5)
    assert upload_dir_files(ctx) == [] and web.get("/api/jobs")[1]["jobs"] == []
    assert upload(web, "after.log", b"seen 203.0.113.9\n")[0] == 202


def slow_ingest(started, release):
    """Stands in for a long ingest that holds the database write lock, like the real one does."""
    def run(conn, path, source_name=None, progress=None, **kw):
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO sources (name, kind, content_sha256, ingested_at) VALUES (?, 'file', 'h', 't')", (source_name,))
        size = path.stat().st_size
        progress(size // 2, size)
        started.set()
        release.wait(20)
        conn.rollback()
        return SimpleNamespace(already_ingested=False, candidates=1, new_iocs=1, new_observations=1, rejected=0)
    return run


def test_while_a_big_file_is_processed_reads_work_writes_are_politely_refused_and_progress_is_reported(ctx):
    import threading

    from threatweaver.web.jobs import JobManager

    store.connect(ctx.db_path).close()
    load = store.connect(ctx.db_path)
    store.ingest_text(load, "already here 198.51.100.7", "old.log")
    load.close()
    started, release = threading.Event(), threading.Event()
    ctx._jobs = JobManager(ctx.db_path, ingest=slow_ingest(started, release))
    server, web = start(ctx)
    try:
        assert upload(web, "huge.log", b"x" * 4000)[0] == 202
        assert started.wait(10)
        _, jobs = web.get("/api/jobs")
        (job,) = jobs["jobs"]
        assert jobs["active"] == 1 and job["state"] == "processing" and job["percent"] == 50.0 and job["result"] is None

        # reads keep working on the last committed data
        assert web.get("/api/overview")[1]["summary"]["indicators"] == 1
        assert web.get("/api/indicators")[0] == 200 and web.get("/api/cases")[0] == 200 and web.get("/api/report")[0] == 200
        # writes are refused with a clear message instead of timing out against the lock
        for status, body in (web.post("/api/ingest", {"name": "p.txt", "text": "x 203.0.113.9"}),
                             web.post("/api/feeds/fetch", {"feed": "feodotracker"}),
                             web.post("/api/advisory/draft", {"author": "alice"}),
                             web.post("/api/advisory/1/submit", {"actor": "alice"})):
            assert status == 409 and "still being processed" in body["error"]
        release.set()
        assert wait_idle(web)["jobs"][0]["state"] == "done"
        assert web.post("/api/ingest", {"name": "p.txt", "text": "x 203.0.113.9"})[0] == 200  # writes work again
    finally:
        release.set()
        server.shutdown()
        ctx.close()


def test_a_failing_job_reports_why_cleans_up_and_does_not_block_the_next_one(ctx):
    from threatweaver.web.jobs import JobManager

    store.connect(ctx.db_path).close()
    calls = []

    def flaky(conn, path, source_name=None, progress=None, **kw):
        calls.append(source_name)
        if len(calls) == 1:
            raise OSError("disk exploded (simulated)")
        return SimpleNamespace(already_ingested=False, candidates=0, new_iocs=0, new_observations=0, rejected=0)

    ctx._jobs = JobManager(ctx.db_path, ingest=flaky)
    server, web = start(ctx)
    try:
        upload(web, "bad.log", b"x" * 10)
        upload(web, "good.log", b"y" * 10)
        jobs = {j["name"]: j for j in wait_idle(web)["jobs"]}
        assert jobs["bad.log"]["state"] == "error" and "disk exploded" in jobs["bad.log"]["error"]
        assert jobs["good.log"]["state"] == "done"
        assert upload_dir_files(ctx) == []
    finally:
        server.shutdown()
        ctx.close()


def test_jobs_run_one_at_a_time_in_order_and_the_queue_is_bounded(ctx):
    import threading

    from threatweaver.web import jobs as jobs_module
    from threatweaver.web.jobs import JobManager

    store.connect(ctx.db_path).close()
    order, gate = [], threading.Event()

    def ordered(conn, path, source_name=None, progress=None, **kw):
        order.append(source_name)
        gate.wait(10)
        return SimpleNamespace(already_ingested=False, candidates=0, new_iocs=0, new_observations=0, rejected=0)

    jm = JobManager(ctx.db_path, ingest=ordered)
    ctx._jobs = jm
    for n in range(3):
        path = jm.new_upload_path()
        path.write_bytes(b"x")
        jm.submit(f"f{n}.log", path, 1)
    time.sleep(0.3)
    assert order == ["f0.log"]  # the others wait their turn
    gate.set()
    assert jm.wait(10) and order == ["f0.log", "f1.log", "f2.log"]
    assert not jm.busy() and list(jm.work_dir.iterdir()) == []
    jm.close()


def test_the_page_shows_upload_progress_and_polls_jobs_without_building_html():
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "/api/upload" in js and "xhr.upload" in js and "/api/jobs" in js and "application/octet-stream" in js
    assert ".text()" not in js and "FileReader" not in js  # a big file is never read into the page


def test_an_early_refusal_with_a_big_body_still_delivers_its_message(web, ctx, monkeypatch):
    """Replying and closing with the upload unread makes the OS reset the connection; the browser then shows
    a network error instead of 'not enough disk space'. The server must swallow the rest of the body first."""
    from threatweaver.web import server

    monkeypatch.setattr(server.shutil, "disk_usage", lambda p: SimpleNamespace(total=10 ** 9, used=0, free=1000))
    big = b"x" * (6 * 1024 * 1024)
    for _ in range(5):
        status, res = upload(web, "huge.log", big)
        assert status == 507 and "disk space" in res["error"]
    monkeypatch.undo()
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 1000)
    for _ in range(5):
        status, res = upload(web, "huge.log", b"y" * 600_000)
        assert status == 413 and "larger" in res["error"]
    assert upload_dir_files(ctx) == []


def test_cases_are_paged_and_quiet_ones_hidden_by_the_server(web):
    text = "".join(f"seen 11.0.{i // 250}.{i % 250 + 1}\n" for i in range(450)) + "linked 198.51.100.1 evil.example.com\n"
    web.post("/api/ingest", {"name": "many.log", "text": text})
    _, first = web.get("/api/cases")
    assert first["all_cases"] == 451 and first["quiet_cases"] == 450 and first["total"] == 1  # only the linked case is shown
    assert first["cases"][0]["links"] == 1 and len(first["cases"]) == 1

    _, quiet = web.get("/api/cases?quiet=1")
    assert quiet["total"] == 451 and len(quiet["cases"]) == 200 and quiet["limit"] == 200 and quiet["offset"] == 0
    _, page2 = web.get("/api/cases?quiet=1&offset=200&limit=200")
    _, page3 = web.get("/api/cases?quiet=1&offset=400&limit=200")
    ids = [c["case_id"] for p in (quiet, page2, page3) for c in p["cases"]]
    assert len(ids) == 451 and len(set(ids)) == 451  # pages neither overlap nor skip
    clamped = web.get("/api/cases?quiet=1&limit=9999")[1]
    assert clamped["limit"] == 500 and len(clamped["cases"]) == 451  # the page size is capped at 500
    assert web.get("/api/cases?limit=abc&offset=-3")[0] == 200
    assert all(len(c["indicators"]) <= 6 for c in quiet["cases"])  # a card needs only a few; the full list is on the case page


def test_indicator_search_still_finds_quiet_indicators_that_the_cases_page_hides(web):
    web.post("/api/ingest", {"name": "q.log", "text": "seen 11.9.9.9\nlinked 198.51.100.1 evil.example.com\n"})
    assert web.get("/api/cases")[1]["total"] == 1
    _, found = web.get("/api/indicators?q=11.9.9.9")
    assert found["total"] == 1 and found["rows"][0]["value"] == "11.9.9.9"


def test_the_access_link_is_short_enough_not_to_wrap_in_a_narrow_terminal(ctx):
    """A link that wraps mid-token breaks when copied (it did, in a 66-column terminal panel)."""
    import re

    server, token = create_server(ctx, port=0)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/?token={token}"
        assert len(token) == 16 and re.fullmatch(r"[A-Za-z0-9_-]{16}", token)
        assert len(url) < 50
        assert create_server(ctx, port=0)[1] != token  # still random per run
    finally:
        server.server_close()


def test_a_second_dashboard_never_shares_a_port_with_a_running_one(ctx):
    """On Windows a second bind to a listening port used to succeed, and connections then went to either process,
    so a stale dashboard could answer with a different token than the new dashboard printed."""
    first, token1 = create_server(ctx, port=0)
    busy = first.server_address[1]
    threading.Thread(target=first.serve_forever, daemon=True).start()
    second = None
    try:
        second, token2 = create_server(ctx, port=busy)  # asks for the busy port
        assert second.server_address[1] != busy  # moved to the next free port instead of sharing it
        assert token1 != token2
        threading.Thread(target=second.serve_forever, daemon=True).start()
        for srv, token in ((first, token1), (second, token2)):
            port = srv.server_address[1]
            status, _, _ = Client(srv, token).request("GET", f"/?token={token}", token=False)
            assert status == 200, f"the dashboard on {port} must accept its own token"
        # and every request to the busy port reaches the first dashboard, never the second
        other = Client(first, token2).request("GET", f"/?token={token2}", token=False)[0]
        assert other == 403
    finally:
        first.shutdown(); first.server_close()
        if second:
            second.shutdown(); second.server_close()
