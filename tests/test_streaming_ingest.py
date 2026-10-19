"""Chunked ingest must give exactly the same database as ingesting the whole text at once."""

import hashlib
import sqlite3

import pytest

from threatweaver import store


def tricky_text():
    lines = [
        "2026-10-14T10:00:01Z proxy user=alice GET https://update-check.example.net/stage1.bin dst=203.0.113.45",
        "defanged: hxxps://bad[.]example[.]org/a and 198[.]51[.]100[.]8 and bob[@]example[.]org",
        "unicode 漢字 café ☃ then 192.0.2.10 and host-192.0.2.9-static.example.net",
        "nested http://a.example.com/x?u=http://b.example.net/y end",
        "hash 0123456789abcdef0123456789abcdef01234567 and ipv6 2001:db8::1 and 2001:db8::2",
        "",
        "last line has no newline 203.0.113.45",
    ]
    return "\r\n".join(lines[:3]) + "\n" + "\n".join(lines[3:])  # mixed CRLF / LF on purpose


def dump(conn):
    """Everything that matters, independent of row ids."""
    def ioc(i):
        r = conn.execute("SELECT type, value FROM iocs WHERE id = ?", (i,)).fetchone()
        return (r["type"], r["value"]) if r else None

    iocs = sorted((r["type"], r["value"], r["attrs"]) for r in conn.execute("SELECT type, value, attrs FROM iocs"))
    obs = sorted(
        (ioc(r["ioc_id"]), r["raw"], r["span_start"], r["span_end"], r["line_no"], r["defanged"], r["context"],
         ioc(conn.execute("SELECT ioc_id FROM observations WHERE id = ?", (r["parent_observation_id"],)).fetchone()[0])
         if r["parent_observation_id"] else None)
        for r in conn.execute("SELECT * FROM observations")
    )
    rel = sorted((ioc(r["parent_id"]), ioc(r["child_id"]), r["kind"]) for r in conn.execute("SELECT * FROM relations"))
    return iocs, obs, rel


@pytest.mark.parametrize("chunk_bytes", [1, 7, 37, 100, 4096, 10 ** 9])
def test_chunked_ingest_equals_whole_text_ingest(tmp_path, chunk_bytes):
    text = tricky_text()
    path = tmp_path / "proxy.log"
    path.write_bytes(text.encode("utf-8"))

    whole = store.connect(":memory:")
    store.ingest_text(whole, text, "proxy.log", observed_at="2026-10-14T12:00:00+00:00")
    chunked = store.connect(":memory:")
    res = store.ingest_path(chunked, path, observed_at="2026-10-14T12:00:00+00:00", chunk_bytes=chunk_bytes)

    assert dump(chunked) == dump(whole)
    assert not res.already_ingested and res.new_observations == whole.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    assert chunked.execute("SELECT content_sha256 FROM sources").fetchone()[0] == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_line_numbers_and_offsets_are_absolute_not_per_chunk(tmp_path):
    text = "".join(f"line {i} 192.0.2.{i % 250 + 1}\n" for i in range(500))
    path = tmp_path / "many.log"
    path.write_bytes(text.encode())
    conn = store.connect(":memory:")
    store.ingest_path(conn, path, chunk_bytes=64)  # roughly 3 lines per chunk
    for r in conn.execute("SELECT raw, span_start, span_end, line_no FROM observations"):
        assert text[r["span_start"]:r["span_end"]] == r["raw"]  # offsets point at the real text
        assert r["raw"] in text.split("\n")[r["line_no"] - 1]  # reported on the right line
    last = conn.execute("SELECT MAX(line_no) FROM observations").fetchone()[0]
    assert last == 500


def test_the_sha256_is_the_files_own_sha256(tmp_path):
    path = tmp_path / "f.log"
    path.write_bytes(b"hello 203.0.113.9\r\nbye\r\n")  # CRLF preserved, so Get-FileHash agrees
    conn = store.connect(":memory:")
    store.ingest_path(conn, path)
    assert conn.execute("SELECT content_sha256 FROM sources").fetchone()[0] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_reingesting_the_same_file_is_a_noop_and_a_changed_file_is_a_new_source(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("203.0.113.9\n")
    conn = store.connect(":memory:")
    first = store.ingest_path(conn, path)
    again = store.ingest_path(conn, path)
    assert not first.already_ingested and again.already_ingested and again.source_id == first.source_id
    path.write_text("203.0.113.9\n203.0.113.10\n")
    third = store.ingest_path(conn, path)
    assert not third.already_ingested and third.new_iocs == 1
    assert conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 2


def test_failure_midway_leaves_nothing_behind_and_can_be_retried(tmp_path):
    path = tmp_path / "big.log"
    path.write_text("".join(f"line {i} 192.0.2.{i % 250 + 1}\n" for i in range(300)))
    conn = store.connect(":memory:")

    def explode(done, total):
        if done > 2000:
            raise RuntimeError("disk full (simulated)")

    with pytest.raises(RuntimeError):
        store.ingest_path(conn, path, chunk_bytes=256, progress=explode)
    assert conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0
    ok = store.ingest_path(conn, path, chunk_bytes=256)  # not wrongly reported as already ingested
    assert not ok.already_ingested and ok.new_observations == 300


def test_progress_reports_bytes_and_reaches_the_total(tmp_path):
    path = tmp_path / "p.log"
    path.write_text("".join(f"x 192.0.2.{i % 250 + 1}\n" for i in range(200)))
    seen = []
    store.ingest_path(store.connect(":memory:"), path, chunk_bytes=100, progress=lambda d, t: seen.append((d, t)))
    assert seen and seen == sorted(seen) and seen[-1] == (path.stat().st_size, path.stat().st_size)


def test_empty_and_invalid_utf8_files(tmp_path):
    conn = store.connect(":memory:")
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    assert store.ingest_path(conn, empty).candidates == 0
    bad = tmp_path / "bad.log"
    bad.write_bytes(b"ok 203.0.113.9 \xff\xfe broken bytes \xc3 then 203.0.113.10\n")
    res = store.ingest_path(conn, bad, chunk_bytes=8)
    assert res.new_iocs == 2


def test_a_very_long_line_is_split_at_whitespace_instead_of_exhausting_memory(tmp_path):
    line = " ".join(f"192.0.2.{i % 250 + 1}" for i in range(4000))  # one 50 KB line, no newline
    path = tmp_path / "long.log"
    path.write_text(line)
    conn = store.connect(":memory:")
    res = store.ingest_path(conn, path, chunk_bytes=512, max_line_bytes=2048)
    assert res.candidates == 4000  # split only at spaces, so no address was cut in half
    assert conn.execute("SELECT COUNT(DISTINCT ioc_id) FROM observations").fetchone()[0] == 250
    assert conn.execute("SELECT MAX(line_no) FROM observations").fetchone()[0] == 1  # still one logical line


def test_ingest_file_keeps_working_for_existing_callers(tmp_path):
    path = tmp_path / "old-api.log"
    path.write_text("seen 203.0.113.9\n")
    conn = store.connect(":memory:")
    assert store.ingest_file(conn, path).new_iocs == 1
    assert conn.execute("SELECT name FROM sources").fetchone()[0] == "old-api.log"


def test_file_databases_use_wal_so_readers_are_not_blocked_by_a_long_ingest(tmp_path):
    db = tmp_path / "t.db"
    writer = store.connect(db)
    assert writer.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT INTO sources (name, kind, content_sha256, ingested_at) VALUES ('x', 'file', 'h', 't')")
    reader = store.connect(db)  # opening and reading while a write transaction is open must not block
    assert reader.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0  # sees only committed data
    writer.rollback()


def test_command_line_ingest_prints_progress_only_for_big_files(tmp_path, capsys, monkeypatch):
    import io as _io

    from threatweaver import cli

    show_out = _io.StringIO()
    show = cli.progress_printer("big.log", 1000, out=show_out)
    for done in (10, 40, 60, 500, 999, 1000):
        show(done, 1000)
    lines = show_out.getvalue().splitlines()
    assert lines[0] == "  big.log: 1%" and lines[-1] == "  big.log: 100%" and 4 <= len(lines) <= 8  # steps of 5%, not every call

    small = tmp_path / "small.log"
    small.write_text("seen 203.0.113.9" + chr(10))
    db = str(tmp_path / "t.db")
    assert cli.main(["ingest", str(small), "--db", db]) == 0
    assert capsys.readouterr().err == ""  # small files stay quiet

    monkeypatch.setattr(cli, "PROGRESS_FROM_BYTES", 1)
    big = tmp_path / "bigger.log"
    big.write_text("".join(f"x 192.0.2.{i % 250 + 1}" + chr(10) for i in range(2000)))
    assert cli.main(["ingest", str(big), "--db", db]) == 0
    assert "bigger.log: 100%" in capsys.readouterr().err
