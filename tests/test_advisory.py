import json
from pathlib import Path

import pytest

from threatweaver import advisory, store
from threatweaver.advisory import AdvisoryError, check_confidentiality, content_hash
from threatweaver.cli import main
from threatweaver.pipeline import run_scenario

SCENARIO = Path(__file__).resolve().parents[1] / "data" / "synthetic" / "scenario"
CLEAN = "# Notice\n\nIndicator hxxp://bad[.]example[.]org/x is listed by a public feed.\n"


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def submitted(conn, body=CLEAN, author="alice"):
    adv_id = advisory.create_draft(conn, "Test advisory", body, author)
    advisory.submit_for_review(conn, adv_id, author)
    return adv_id


def approved(conn, reviewer="bob"):
    adv_id = submitted(conn)
    sha = advisory.get(conn, adv_id)["content_sha256"]
    advisory.approve(conn, adv_id, reviewer, sha, f"APPROVE {adv_id}")
    return adv_id


# ------------------------------------------------------------- confidentiality
@pytest.mark.parametrize(
    "text, kind",
    [
        ("seen on 10.1.2.3", "non_routable_address"),
        ("seen on 192.168.0.5", "non_routable_address"),
        ("host 127.0.0.1", "non_routable_address"),
        ("fileserver.corp and more", "internal_hostname"),
        ("db01.internal.", "internal_hostname"),
        ("printer[.]lan", "internal_hostname"),
        ("contact jane.doe@realcompany.com", "email_address"),
        ("contact jane[at]realcompany[.]com", "email_address"),
        ("INTERNAL USE ONLY", "confidentiality_marker"),
        ("TLP:AMBER+STRICT", "confidentiality_marker"),
        ("tlp: red", "confidentiality_marker"),
        ("Strictly Confidential", "confidentiality_marker"),
    ],
)
def test_confidentiality_blocks(text, kind):
    assert kind in {f.kind for f in check_confidentiality(text) if f.blocking}


def test_confidentiality_denylist():
    assert check_confidentiality("Project Bluebird is affected", ("bluebird",))[0].kind == "denylisted_term"


def test_confidentiality_allows_public_synthetic_content():
    text = "198[.]51[.]100[.]60 and hxxp://bad[.]example[.]org/x, contact cert@example.org, TLP:CLEAR"
    assert advisory.blocking_findings(text) == []


def test_undefanged_indicator_is_a_warning_not_a_block():
    findings = check_confidentiality("see http://bad.example.org/x")
    assert [f.blocking for f in findings if f.kind == "indicator_not_defanged"] == [False]
    assert advisory.blocking_findings("see http://bad.example.org/x") == []


# ------------------------------------------------------------- lifecycle
def test_full_happy_path_writes_local_files_and_logs_every_step(conn, tmp_path):
    adv_id = approved(conn)
    path = advisory.publish(conn, adv_id, "carol", tmp_path, now="2026-10-15T09:00:00+00:00")
    assert path.read_text(encoding="utf-8").startswith("<!-- Approved by bob")
    assert CLEAN in path.read_text(encoding="utf-8")
    meta = json.loads((tmp_path / f"advisory-{adv_id:04d}.json").read_text(encoding="utf-8"))
    assert [e["action"] for e in meta["events"]] == ["create", "submit", "approve"]
    assert meta["reviewer"] == "bob" and meta["author"] == "alice"
    assert advisory.get(conn, adv_id)["status"] == "published"
    assert [e["action"] for e in advisory.events(conn, adv_id)] == ["create", "submit", "approve", "publish"]


def test_cannot_skip_review(conn, tmp_path):
    adv_id = advisory.create_draft(conn, "t", CLEAN, "alice")
    with pytest.raises(AdvisoryError, match="submitted"):
        advisory.approve(conn, adv_id, "bob", content_hash("t", CLEAN), f"APPROVE {adv_id}")
    with pytest.raises(AdvisoryError, match="approved"):
        advisory.publish(conn, adv_id, "alice", tmp_path)
    advisory.submit_for_review(conn, adv_id, "alice")
    with pytest.raises(AdvisoryError, match="approved"):
        advisory.publish(conn, adv_id, "alice", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_author_cannot_approve_own_advisory(conn):
    adv_id = submitted(conn, author="Alice")
    sha = advisory.get(conn, adv_id)["content_sha256"]
    for name in ("Alice", " alice ", "ALICE"):
        with pytest.raises(AdvisoryError, match="different person"):
            advisory.approve(conn, adv_id, name, sha, f"APPROVE {adv_id}")
    assert advisory.get(conn, adv_id)["status"] == "submitted"


def test_approval_needs_current_hash_and_exact_confirmation(conn):
    adv_id = submitted(conn)
    sha = advisory.get(conn, adv_id)["content_sha256"]
    with pytest.raises(AdvisoryError, match="changed"):
        advisory.approve(conn, adv_id, "bob", "0" * 64, f"APPROVE {adv_id}")
    for wrong in ("", "approve 1", "yes", f"APPROVE {adv_id + 1}"):
        with pytest.raises(AdvisoryError, match="confirmation"):
            advisory.approve(conn, adv_id, "bob", sha, wrong)
    with pytest.raises(AdvisoryError, match="name is required"):
        advisory.approve(conn, adv_id, "  ", sha, f"APPROVE {adv_id}")
    assert advisory.get(conn, adv_id)["status"] == "submitted"


def test_editing_voids_approval_and_requires_new_review(conn, tmp_path):
    adv_id = approved(conn)
    advisory.edit_draft(conn, adv_id, "Test advisory", CLEAN + "\nExtra line.\n", "alice")
    row = advisory.get(conn, adv_id)
    assert row["status"] == "draft" and row["reviewer"] is None and row["approved_sha256"] is None
    with pytest.raises(AdvisoryError):
        advisory.publish(conn, adv_id, "alice", tmp_path)
    assert any(e["note"] == "approval/submission voided" for e in advisory.events(conn, adv_id))


def test_tampering_with_stored_text_after_approval_blocks_publish(conn, tmp_path):
    adv_id = approved(conn)
    with conn:
        conn.execute("UPDATE advisories SET body = body || 'sneaky addition' WHERE id = ?", (adv_id,))
    with pytest.raises(AdvisoryError, match="no longer matches"):
        advisory.publish(conn, adv_id, "carol", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_publish_rechecks_confidentiality(conn, tmp_path):
    adv_id = approved(conn)
    leaked = CLEAN + "internal host 10.0.0.5\n"
    with conn:  # simulate hash-consistent tampering: attacker also updates the approved hash
        sha = content_hash("Test advisory", leaked)
        conn.execute("UPDATE advisories SET body=?, content_sha256=?, approved_sha256=? WHERE id=?", (leaked, sha, sha, adv_id))
    with pytest.raises(AdvisoryError, match="confidentiality"):
        advisory.publish(conn, adv_id, "carol", tmp_path)


def test_submit_is_refused_while_confidential_content_remains(conn):
    adv_id = advisory.create_draft(conn, "t", "see 10.0.0.5 and TLP:AMBER", "alice")
    with pytest.raises(AdvisoryError, match="confidentiality check failed"):
        advisory.submit_for_review(conn, adv_id, "alice")
    assert advisory.get(conn, adv_id)["status"] == "draft"
    advisory.edit_draft(conn, adv_id, "t", CLEAN, "alice")
    advisory.submit_for_review(conn, adv_id, "alice")
    assert advisory.get(conn, adv_id)["status"] == "submitted"


def test_rejection_returns_to_draft_via_edit_and_needs_a_note_in_the_log(conn):
    adv_id = submitted(conn)
    advisory.reject(conn, adv_id, "bob", "needs more evidence")
    assert advisory.get(conn, adv_id)["status"] == "rejected"
    assert advisory.events(conn, adv_id)[-1]["note"] == "needs more evidence"
    advisory.edit_draft(conn, adv_id, "t2", CLEAN, "alice")
    assert advisory.get(conn, adv_id)["status"] == "draft"


def test_published_advisories_are_immutable(conn, tmp_path):
    adv_id = approved(conn)
    advisory.publish(conn, adv_id, "carol", tmp_path)
    with pytest.raises(AdvisoryError, match="immutable"):
        advisory.edit_draft(conn, adv_id, "t", "new", "alice")
    with pytest.raises(AdvisoryError, match="approved"):
        advisory.publish(conn, adv_id, "carol", tmp_path)


def test_unknown_advisory(conn):
    with pytest.raises(AdvisoryError, match="does not exist"):
        advisory.get(conn, 42)


# ------------------------------------------------------------- draft from report
@pytest.fixture(scope="module")
def scenario_report():
    return run_scenario(SCENARIO).report


def test_draft_uses_only_public_evidence(scenario_report):
    title, body = advisory.draft_from_report(scenario_report)
    assert "Emotet" in title
    assert "203[.]0[.]113[.]45" in body and "update-check[.]example[.]net" in body
    for private in ("10[.]0[.]0[.]15", "10.0.0.15", "192[.]0[.]2[.]80", "docs[.]example[.]org"):
        assert private not in body  # private and no-evidence indicators are left out
    for internal in ("a-proxy.log", "a-fw.log", "a-dns.log", "alice", "bob", "carol"):
        assert internal not in body  # local sources and user names never leak
    assert "TLP:CLEAR" in body and "pending human review" in body


def test_generated_draft_passes_the_confidentiality_check(scenario_report):
    title, body = advisory.draft_from_report(scenario_report)
    assert advisory.blocking_findings(title + "\n" + body) == []


def test_no_draft_without_public_evidence():
    report = run_scenario(SCENARIO).report
    for case in report["cases"]:
        for ind in case["indicators"]:
            ind["feed_matches"] = []
    with pytest.raises(ValueError, match="nothing to advise"):
        advisory.draft_from_report(report)


# ------------------------------------------------------------- CLI
def test_cli_approve_refuses_without_a_terminal(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    conn = store.connect(db)
    adv_id = submitted(conn)
    conn.close()
    assert main(["advisory", "approve", str(adv_id), "--reviewer", "bob", "--db", db]) == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert advisory.get(store.connect(db), adv_id)["status"] == "submitted"


def test_cli_end_to_end_run_and_draft(tmp_path, capsys):
    db, out = str(tmp_path / "t.db"), str(tmp_path / "out")
    assert main(["run", str(SCENARIO), "--db", db, "--out", out]) == 0
    assert (tmp_path / "out" / "report.md").exists() and (tmp_path / "out" / "report.json").exists()
    assert "0 unresolved" in capsys.readouterr().out
    assert main(["advisory", "draft", "--author", "alice", "--db", db]) == 0
    assert main(["advisory", "submit", "1", "--actor", "alice", "--db", db]) == 0
    assert main(["advisory", "publish", "1", "--actor", "alice", "--db", db, "--out", str(tmp_path / "pub")]) == 1
    assert "approved" in capsys.readouterr().err
    assert not (tmp_path / "pub").exists()


def test_cli_approve_at_a_terminal_requires_the_typed_phrase(tmp_path, monkeypatch, capsys):
    import builtins
    import sys

    db = str(tmp_path / "t.db")
    conn = store.connect(db)
    adv_id = submitted(conn)
    conn.close()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    monkeypatch.setattr(builtins, "input", lambda prompt="": "yes")
    assert main(["advisory", "approve", str(adv_id), "--reviewer", "bob", "--db", db]) == 1
    assert advisory.get(store.connect(db), adv_id)["status"] == "submitted"

    monkeypatch.setattr(builtins, "input", lambda prompt="": f"APPROVE {adv_id}")
    assert main(["advisory", "approve", str(adv_id), "--reviewer", "bob", "--db", db]) == 0
    assert advisory.get(store.connect(db), adv_id)["status"] == "approved"
