import io
import json
import urllib.error
from pathlib import Path

import pytest

from threatweaver import store
from threatweaver.feeds import FEEDS, FEODO, URLHAUS, FeedError, fetch_text, load_feed
from threatweaver.feeds import feodo, urlhaus
from threatweaver.models import IocType

FEEDS_DIR = Path(__file__).resolve().parents[1] / "data" / "synthetic" / "scenario" / "feeds"
URLHAUS_TEXT = (FEEDS_DIR / "urlhaus.csv").read_text(encoding="utf-8")
FEODO_TEXT = (FEEDS_DIR / "feodo.json").read_text(encoding="utf-8")


# ------------------------------------------------------------- parsers
def test_at_most_two_feeds():
    assert set(FEEDS) == {"feodotracker", "urlhaus"}


def test_urlhaus_parses_fixture():
    res = urlhaus.parse(URLHAUS_TEXT)
    assert len(res.records) == 4 and res.skipped == 0
    first = res.records[0]
    assert first.type == IocType.URL and first.key == "900001"
    assert first.value == "https://update-check.example.net/stage1.bin"
    assert first.fields["status"] == "online" and first.fields["tags"] == ["Emotet", "exe"]
    assert res.records[3].fields["tags"] == []  # URLhaus writes the string "None" for no tags


def test_urlhaus_follows_header_not_fixed_positions():
    text = '# id,url,url_status,extra,tags\n"1","http://a.example.com/x","offline","zzz","t1"\n'
    (rec,) = urlhaus.parse(text).records
    assert rec.value == "http://a.example.com/x" and rec.fields["status"] == "offline" and rec.fields["tags"] == ["t1"]


def test_urlhaus_uncommented_header_and_malformed_rows():
    text = 'id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n' \
           '"1","d","http://a.example.com/x","online","d","t","","l","r"\n' \
           '"2","too","short"\n' \
           '"3","d","","online","d","t","","l","r"\n'
    res = urlhaus.parse(text)
    assert [r.key for r in res.records] == ["1"]
    assert res.skipped == 2


def test_feodo_parses_fixture():
    res = feodo.parse(FEODO_TEXT)
    assert [r.value for r in res.records] == ["203.0.113.45", "198.51.100.60", "192.0.2.99"]
    assert res.records[0].fields["malware"] == "Emotet" and res.records[0].key == "203.0.113.45:8080"
    assert all(r.type == IocType.IPV4 for r in res.records)


def test_feodo_rejects_bad_documents_and_skips_bad_rows():
    with pytest.raises(FeedError):
        feodo.parse("<html>rate limited</html>")
    with pytest.raises(FeedError):
        feodo.parse('{"not": "a list"}')
    res = feodo.parse(json.dumps([{"ip_address": "not-an-ip"}, {"ip_address": "2001:db8::5", "port": 443, "status": "Online"}, 7]))
    assert [r.type for r in res.records] == [IocType.IPV6]
    assert res.records[0].fields["status"] == "online"
    assert res.skipped == 2


# ------------------------------------------------------------- fetching
class FakeResponse(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


class FakeOpener:
    def __init__(self, body=b"[]", error=None):
        self.body, self.error, self.calls = body, error, []

    def __call__(self, request, timeout=None):
        self.calls.append(request.full_url)
        if self.error:
            raise self.error
        return FakeResponse(self.body)


def test_fetch_caches_and_respects_min_interval(tmp_path):
    opener, clock = FakeOpener(b"[]"), [1000.0]
    fetch = lambda **kw: fetch_text(FEODO, tmp_path, opener=opener, now=lambda: clock[0], env={}, **kw)
    assert fetch() == ("[]", False)
    clock[0] += 60  # well inside the 15 minute interval
    assert fetch() == ("[]", True)
    assert len(opener.calls) == 1
    clock[0] += FEODO.min_interval_seconds
    assert fetch()[1] is False and len(opener.calls) == 2
    assert fetch(force=True)[1] is False and len(opener.calls) == 3


def test_urlhaus_needs_key_and_never_leaks_it(tmp_path):
    with pytest.raises(FeedError, match="URLHAUS_AUTH_KEY"):
        fetch_text(URLHAUS, tmp_path, env={}, opener=FakeOpener())

    secret = "s3cr3t-key-123"
    ok = FakeOpener(b"# id,url\n")
    fetch_text(URLHAUS, tmp_path, env={"URLHAUS_AUTH_KEY": secret}, opener=ok)
    assert secret in ok.calls[0] and ok.calls[0].startswith("https://")
    assert not any(secret in p.read_text(encoding="utf-8") for p in tmp_path.iterdir()), "key must not be cached"

    for error in (urllib.error.HTTPError(ok.calls[0], 401, f"denied {secret}", {}, None),
                  urllib.error.URLError(f"cannot reach {ok.calls[0]}")):
        with pytest.raises(FeedError) as exc:
            fetch_text(URLHAUS, tmp_path / "other", env={"URLHAUS_AUTH_KEY": secret}, opener=FakeOpener(error=error), force=True)
        assert secret not in str(exc.value)


def test_fetch_refuses_oversize_and_non_https(tmp_path, monkeypatch):
    monkeypatch.setattr("threatweaver.feeds.common.MAX_BYTES", 10)
    with pytest.raises(FeedError, match="larger"):
        fetch_text(FEODO, tmp_path, env={}, opener=FakeOpener(b"x" * 50))
    from dataclasses import replace
    insecure = replace(FEODO, build_url=lambda env: "http://example.com/feed")
    with pytest.raises(FeedError, match="HTTPS"):
        fetch_text(insecure, tmp_path / "b", env={}, opener=FakeOpener())


# ------------------------------------------------------------- loading
@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def test_load_is_idempotent_and_keeps_raw_record(conn):
    first = load_feed(conn, FEODO, FEODO_TEXT, "2026-10-14T00:00:00+00:00")
    again = load_feed(conn, FEODO, FEODO_TEXT, "2026-10-15T00:00:00+00:00")
    assert first.records == 3 and not first.already_loaded and again.already_loaded
    assert conn.execute("SELECT COUNT(*) FROM intel").fetchone()[0] == 3
    row = conn.execute("SELECT raw, feed FROM intel ORDER BY id LIMIT 1").fetchone()
    assert json.loads(row["raw"])["ip_address"] == "203.0.113.45" and row["feed"] == "feodotracker"


def test_url_records_create_host_relations(conn):
    load_feed(conn, URLHAUS, URLHAUS_TEXT)
    rows = conn.execute(
        "SELECT p.value AS url, c.type AS ctype, c.value AS host FROM relations r "
        "JOIN iocs p ON p.id = r.parent_id JOIN iocs c ON c.id = r.child_id ORDER BY p.value").fetchall()
    assert ("http://198.51.100.60/x.ps1", "ipv4", "198.51.100.60") in {tuple(r) for r in rows}
    assert ("https://update-check.example.net/other.bin", "domain", "update-check.example.net") in {tuple(r) for r in rows}


def test_feed_urls_on_newer_tlds_are_not_dropped(conn):
    text = '# id,dateadded,url,url_status\n"1","d","http://payload.newtld-not-in-list.bond/a","online"\n'
    res = load_feed(conn, URLHAUS, text)
    assert res.records == 1 and res.rejected == 0


def test_feed_snapshot_changes_are_new_sources_not_overwrites(conn):
    load_feed(conn, FEODO, FEODO_TEXT)
    changed = json.loads(FEODO_TEXT)
    changed[0]["status"] = "offline"
    load_feed(conn, FEODO, json.dumps(changed))
    assert conn.execute("SELECT COUNT(*) FROM sources WHERE kind = 'feed'").fetchone()[0] == 2
    # history is kept: both statuses are queryable, each tied to its own snapshot
    statuses = {json.loads(r["attrs"])["status"] for r in conn.execute(
        "SELECT i.attrs FROM intel i JOIN iocs c ON c.id = i.ioc_id WHERE c.value = '203.0.113.45'")}
    assert statuses == {"online", "offline"}
