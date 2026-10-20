import json
from pathlib import Path

import pytest

from threatweaver import store
from threatweaver.correlate import correlate, clusters
from threatweaver.defang import defang, refang
from threatweaver.extract import extract
from threatweaver.feeds import FEODO, load_feed
from threatweaver.pipeline import run, run_scenario
from threatweaver.report import build_report, render_markdown, verify_traceability
from threatweaver.scenario_eval import evaluate_scenario
from threatweaver.triage import level_for, triage

DATA = Path(__file__).resolve().parents[1] / "data" / "synthetic"
SCENARIO = DATA / "scenario"


@pytest.fixture(scope="module")
def scenario_run():
    return run_scenario(SCENARIO)


def test_scenario_scores_against_hand_labels():
    scores = evaluate_scenario(SCENARIO)
    assert scores.errors == []
    assert scores.links.precision == 1.0 and scores.links.recall == 1.0
    assert scores.matches.precision == 1.0 and scores.matches.recall == 1.0
    assert scores.triage_correct == scores.triage_total == 10 and not scores.triage_unlabeled
    assert scores.cases_exact
    assert scores.traceable_fraction == 1.0 and scores.claims > 50


def test_pipeline_is_deterministic():
    a = json.dumps(run_scenario(SCENARIO).report, sort_keys=True)
    b = json.dumps(run_scenario(SCENARIO).report, sort_keys=True)
    assert a == b


# ------------------------------------------------------------- correlation
def make(text, source="s1"):
    conn = store.connect(":memory:")
    store.ingest_text(conn, text, source)
    return conn


def test_hash_inside_url_is_not_a_co_occurrence_link():
    h = "0123456789abcdef0123456789abcdef01234567"
    conn = make(f"https://sandbox.example.com/r/{h}/x\n")
    assert {l.rule for l in correlate(conn).links} == {"url_host"}


def test_same_line_requires_same_source_and_line():
    conn = store.connect(":memory:")
    store.ingest_text(conn, "192.0.2.1\n192.0.2.2\n", "a")
    store.ingest_text(conn, "192.0.2.1 192.0.2.3\n", "b")
    pairs = {(l.rule, l.explanation) for l in correlate(conn).links}
    assert len(pairs) == 1 and "192.0.2.1" in next(iter(pairs))[1] and "192.0.2.3" in next(iter(pairs))[1]


def test_noisy_lines_are_skipped_not_exploded():
    ips = " ".join(f"192.0.2.{i}" for i in range(1, 12))
    result = correlate(make(ips))
    assert result.links == [] and result.skipped_lines == 1


def test_shared_family_links_but_does_not_merge_cases(scenario_run):
    rules = {l.rule for l in scenario_run.result.links}
    assert "shared_family" in rules
    ids = [r["id"] for r in scenario_run.conn.execute("SELECT DISTINCT ioc_id AS id FROM observations")]
    merged = clusters(ids, scenario_run.result.links)
    assert len(merged) == 3  # the two Emotet IPs stay in separate cases
    assert len(clusters(ids, scenario_run.result.links, min_weight=1)) == 2


def test_every_link_has_resolvable_evidence(scenario_run):
    assert all(l.evidence for l in scenario_run.result.links)


# ------------------------------------------------------------- triage
def test_levels_thresholds():
    assert [level_for(s) for s in (0, 9, 10, 24, 25, 49, 50, 200)] == ["info", "info", "low", "low", "medium", "medium", "high", "high"]


def test_rule_points_always_sum_to_score(scenario_run):
    for v in scenario_run.verdicts.values():
        assert sum(h.points for h in v.hits) == v.score


def test_private_address_never_rises_above_info_even_if_a_feed_lists_it():
    conn = make("beacon from 10.0.0.9 seen\n")
    feed = json.dumps([{"ip_address": "10.0.0.9", "port": 443, "status": "online", "malware": "Emotet"}])
    load_feed(conn, FEODO, feed)
    (verdict,) = triage(conn).values()
    assert verdict.level == "info" and verdict.score == 0
    assert any(h.rule == "TW-T09" for h in verdict.hits)


def test_only_the_newest_feed_snapshot_counts_for_matching():
    conn = make("beacon 203.0.113.9")
    online = json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "Emotet"}])
    offline = json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "offline", "malware": "Emotet"}])
    load_feed(conn, FEODO, online, "2026-10-10T00:00:00+00:00")
    (before,) = triage(conn).values()
    assert [h.rule for h in before.hits] == ["TW-T01"] and before.level == "high"
    load_feed(conn, FEODO, offline, "2026-10-12T00:00:00+00:00")
    (v,) = triage(conn).values()
    assert [h.rule for h in v.hits] == ["TW-T03"] and v.level == "medium" and v.score == 25
    assert conn.execute("SELECT COUNT(*) FROM intel").fetchone()[0] == 2  # history kept


def test_no_intel_means_info_for_a_lone_indicator():
    (v,) = triage(make("203.0.113.9")).values()
    assert v.level == "info" and v.hits == ()


def test_nothing_in_the_package_can_block_anything():
    src = "\n".join(p.read_text(encoding="utf-8") for p in (Path(__file__).resolve().parents[1] / "src" / "threatweaver").rglob("*.py"))
    for forbidden in ("iptables", "netsh", "subprocess", "os.system", "firewall-cmd", "socket.socket", "smtplib", "requests."):
        assert forbidden not in src, forbidden


# ------------------------------------------------------------- report
def test_report_is_fully_traceable(scenario_run):
    trace = verify_traceability(scenario_run.conn, scenario_run.report)
    assert trace["unresolved"] == 0 and trace["traceable_fraction"] == 1.0


def test_traceability_check_detects_tampering():
    pr = run_scenario(SCENARIO)
    with pr.conn:
        pr.conn.execute("UPDATE intel SET raw = 'edited' WHERE id = 1")
        pr.conn.execute("UPDATE observations SET line_no = 99 WHERE id = 1")
    trace = verify_traceability(pr.conn, pr.report)
    assert trace["unresolved"] >= 2 and trace["traceable_fraction"] < 1.0

    pr2 = run_scenario(SCENARIO)
    with pr2.conn:
        pr2.conn.execute("DELETE FROM relations WHERE id = 1")
    assert verify_traceability(pr2.conn, pr2.report)["unresolved"] >= 1


def test_markdown_defangs_every_indicator(scenario_run):
    md = render_markdown(scenario_run.report)
    leaked = [c.raw for c in extract(md) if not c.defanged]
    assert leaked == []
    assert "203[.]0[.]113[.]45" in md and "hxxps://update-check[.]example[.]net/stage1[.]bin" in md


def test_markdown_states_it_is_a_draft_and_never_recommends_auto_blocking(scenario_run):
    md = render_markdown(scenario_run.report)
    assert "DRAFT FOR ANALYST REVIEW" in md and "does not block" in md
    assert "human decision" in md


def test_empty_database_still_produces_a_valid_report():
    conn = store.connect(":memory:")
    report = build_report(conn, "2026-10-14T00:00:00+00:00")
    assert report["cases"] == [] and verify_traceability(conn, report)["traceable_fraction"] == 1.0
    assert "0 indicators" in render_markdown(report)


# ------------------------------------------------------------- defang
def test_defang_refang_round_trip_for_all_labeled_values():
    labels = json.loads((DATA / "labels.json").read_text(encoding="utf-8"))
    values = [e["value"] for entries in labels.values() for e in entries]
    assert len(values) > 40
    for v in values:
        assert refang(defang(v)).text == v, v
    assert defang("https://a.example.com/x") == "hxxps://a[.]example[.]com/x"


# ------------------------------------------------------------- hostname_ip rule
def hostname_links(text, feed=None):
    conn = make(text)
    if feed:
        load_feed(conn, FEODO, json.dumps(feed), "2026-10-14T00:00:00+00:00")
    ident = {r["id"]: r["value"] for r in conn.execute("SELECT id, value FROM iocs")}
    links = [(ident[l.a], ident[l.b]) for l in correlate(conn).links if l.rule == "hostname_ip"]
    return conn, [tuple(sorted(p)) for p in links]


@pytest.mark.parametrize(
    "host, note",
    [
        ("192-0-2-7.static.example.com", "dashes"),
        ("host192.0.2.7.isp.example.net", "dots with a prefix"),
        ("lns-vlq-45-tou-192-0-2-7.adsl.example.net", "embedded mid-name"),
        ("dsl-192-000-002-007.example.net", "zero-padded groups"),
        ("n192000002007.example.net", "12 digit run"),
        ("7.2.0.192.in-addr.example.net", "reversed order"),
    ],
)
def test_hostname_encoding_an_observed_ip_is_linked(host, note):
    _, links = hostname_links(f"login from {host}\nlater, src 192.0.2.7\n")
    assert links == [tuple(sorted((host, "192.0.2.7")))], note


@pytest.mark.parametrize(
    "text, why",
    [
        ("from 192-0-2-8.static.example.com\nsrc 192.0.2.7\n", "encoded IP is not the observed IP"),
        ("from host-300-1-1-1.example.net\nsrc 300.1.1.1\n", "octet above 255 is not an address"),
        ("from 192-0-2-7.static.example.com\n", "the IP itself was never observed"),
        ("src 192.0.2.7 and static.example.com\n", "nothing is encoded in the name"),
        ("from 192-0.2-7.static.example.com\nsrc 192.0.2.7\n", "mixed separators"),
        ("from a1920027b.example.com\nsrc 192.0.2.7\n", "digits that are not four octets"),
    ],
)
def test_hostname_ip_does_not_link_without_real_encoding(text, why):
    assert hostname_links(text)[1] == [], why


def test_hostname_ip_links_every_hostname_for_the_same_ip():
    _, links = hostname_links("a 192-0-2-7.one.example.com\nb 192.0.2.7.two.example.net\nsrc 192.0.2.7\n")
    assert len(links) == 2


def test_hostname_ip_merges_cases_cites_evidence_and_feeds_triage():
    feed = [{"ip_address": "192.0.2.7", "port": 443, "status": "online", "malware": "Emotet"}]
    conn, links = hostname_links("login from 192-0-2-7.static.example.com\nlater, src 192.0.2.7\n", feed)
    result = correlate(conn)
    (link,) = [l for l in result.links if l.rule == "hostname_ip"]
    assert {e.kind for e in link.evidence} == {"observation"} and 2 <= len(link.evidence) <= 2
    ids = [r["id"] for r in conn.execute("SELECT DISTINCT ioc_id AS id FROM observations")]
    assert len(clusters(ids, result.links)) == 1
    by_value = {v.value: v for v in triage(conn, result).values()}
    host = by_value["192-0-2-7.static.example.com"]
    assert [h.rule for h in host.hits] == ["TW-T08"] and by_value["192.0.2.7"].level == "high"
    assert verify_traceability(conn, build_report(conn, "2026-10-14T00:00:00+00:00"))["unresolved"] == 0


def test_hostname_ip_evidence_is_capped_but_still_resolvable():
    lines = "".join(f"line {i} 192-0-2-7.static.example.com\n" for i in range(40)) + "src 192.0.2.7\n"
    conn, _ = hostname_links(lines)
    (link,) = [l for l in correlate(conn).links if l.rule == "hostname_ip"]
    assert len(link.evidence) == 11  # 10 hostname sightings + the first sighting of the IP
    assert verify_traceability(conn, build_report(conn, "2026-10-14T00:00:00+00:00"))["unresolved"] == 0


# ------------------------------------------------------------- report size caps
def test_report_caps_detail_but_states_true_totals():
    from threatweaver.report import MAX_SIGHTINGS

    lines = "".join(f"line {i} beacon 203.0.113.9\n" for i in range(150))
    conn = make(lines)
    load_feed(conn, FEODO, json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "Emotet"}]))
    report = build_report(conn, "2026-10-14T00:00:00+00:00")
    (ind,) = [i for c in report["cases"] for i in c["indicators"]]
    assert ind["sightings_total"] == 150 and len(ind["sightings"]) == MAX_SIGHTINGS
    md = render_markdown(report)
    assert "...and 130 more sightings" in md
    assert verify_traceability(conn, report)["unresolved"] == 0
    assert len(json.dumps(report)) < 60_000  # 150 sightings must not balloon the report


def test_evidence_cap_keeps_the_first_refs_and_the_real_total():
    conn = store.connect(":memory:")
    for n in range(3):
        store.ingest_text(conn, "".join(f"192.0.2.1 seen {i}\n" for i in range(40)), f"src{n}")
    report = build_report(conn, "2026-10-14T00:00:00+00:00")
    (ind,) = [i for c in report["cases"] for i in c["indicators"]]
    t06 = next(r for r in ind["rules"] if r["rule"] == "TW-T06")
    assert t06["evidence_total"] == 120 and len(t06["evidence"]) == 20
    assert "(+100 more)" in render_markdown(report)


def test_quiet_single_indicators_are_summarised_not_given_a_section_each():
    conn = make("".join(f"host 198.51.100.{i}\n" for i in range(1, 31)))
    md = render_markdown(build_report(conn, "2026-10-14T00:00:00+00:00"))
    assert "## Quiet indicators (30)" in md and md.count("## Case ") == 0
    assert md.count("198[.]51[.]100[.]") == 30  # all listed once, defanged, in the compact table


def test_a_case_with_something_to_say_still_gets_full_detail(scenario_run):
    md = render_markdown(scenario_run.report)
    assert md.count("## Case ") == 3 and "Quiet indicators" not in md


# ------------------------------------------------------------- TW-T10 high-volume repeat activity
# Expected boundaries, written before the rule existed:
#   99 sightings -> nothing; 100..999 -> +10 (low); 1,000..9,999 -> +25 (medium); 10,000+ -> +30 (medium).
# Volume alone never reaches "high" (50), only applies to network indicators, and non-routable
# addresses stay capped at info.
def volume_verdict(count, ip="203.0.113.9", extra=""):
    conn = make("".join(f"event {i} from {ip}\n" for i in range(count)) + extra)
    return conn, {v.value: v for v in triage(conn).values()}


@pytest.mark.parametrize(
    "count, points, level",
    [(99, None, "info"), (100, 10, "low"), (999, 10, "low"), (1000, 25, "medium"), (9999, 25, "medium"), (10000, 30, "medium")],
)
def test_volume_tiers_have_exact_boundaries(count, points, level):
    _, verdicts = volume_verdict(count)
    v = verdicts["203.0.113.9"]
    t10 = [h for h in v.hits if h.rule == "TW-T10"]
    assert (t10[0].points if t10 else None) == points and v.level == level
    if t10:
        assert f"{count:,}" in t10[0].reason and "not proof" in t10[0].reason


def test_volume_alone_can_never_reach_high():
    _, verdicts = volume_verdict(12000)
    v = verdicts["203.0.113.9"]
    assert v.level == "medium" and v.score == 30


def test_volume_stacks_with_feed_evidence_and_says_so():
    conn = make("".join(f"event {i} from 203.0.113.9\n" for i in range(1000)))
    load_feed(conn, FEODO, json.dumps([{"ip_address": "203.0.113.9", "port": 443, "status": "online", "malware": "Emotet"}]))
    (v,) = triage(conn).values()
    assert {h.rule for h in v.hits} == {"TW-T01", "TW-T10"} and v.score == 75 and v.level == "high"


def test_hashes_are_not_flagged_for_volume():
    h = "0123456789abcdef0123456789abcdef"
    conn = make("".join(f"scan {i} {h}\n" for i in range(5000)))
    (v,) = triage(conn).values()
    assert v.level == "info" and v.hits == ()


def test_private_addresses_stay_capped_even_with_huge_volume():
    _, verdicts = volume_verdict(5000, ip="10.0.0.5")
    v = verdicts["10.0.0.5"]
    assert v.level == "info" and v.score == 0 and [h.rule for h in v.hits] == ["TW-T10", "TW-T09"]


def test_a_volume_only_neighbour_does_not_trigger_the_linked_to_high_risk_rule():
    # the IP is "medium" on volume alone; the domain on its line must not inherit anything from it
    conn, verdicts = volume_verdict(12000, extra="203.0.113.9 evil.example.com\n")
    assert verdicts["203.0.113.9"].level == "medium"
    assert verdicts["evil.example.com"].level == "info" and verdicts["evil.example.com"].hits == ()


def test_volume_rule_is_described_and_traceable():
    from threatweaver.triage import RULE_DESCRIPTIONS

    assert "TW-T10" in RULE_DESCRIPTIONS and "volume" in RULE_DESCRIPTIONS["TW-T10"].lower()
    conn, _ = volume_verdict(1500)
    report = build_report(conn, "2026-10-14T00:00:00+00:00")
    (ind,) = [i for c in report["cases"] for i in c["indicators"]]
    rule = next(r for r in ind["rules"] if r["rule"] == "TW-T10")
    assert rule["evidence_total"] == 1500 and len(rule["evidence"]) == 20
    assert verify_traceability(conn, report)["unresolved"] == 0


# ------------------------------------------------------------- e-mail addresses and attachment names
MAIL = (
    "From: Billing <billing@invoice-update.example.org>\n"
    'Content-Disposition: attachment; filename="Invoice_4471.pdf.exe"\n'
    "Relay 198.51.100.77 delivered it\n"
)


def test_an_email_and_its_domain_are_linked_structurally_and_the_pair_is_not_also_a_co_occurrence():
    conn = make(MAIL)
    ident = {r["id"]: f"{r['type']} {r['value']}" for r in conn.execute("SELECT id, type, value FROM iocs")}
    links = {(l.rule, ident[l.a], ident[l.b]) for l in correlate(conn).links}
    assert ("email_domain", "domain invoice-update.example.org", "email billing@invoice-update.example.org") in links or \
           ("email_domain", "email billing@invoice-update.example.org", "domain invoice-update.example.org") in links
    pair = {"domain invoice-update.example.org", "email billing@invoice-update.example.org"}
    assert not [l for l in correlate(conn).links if l.rule == "same_line" and {ident[l.a], ident[l.b]} == pair]


def test_the_domain_of_an_email_groups_with_the_email_into_one_case():
    conn = make(MAIL + "later: other@invoice-update.example.org wrote again\n")
    cases = {tuple(sorted(c)) for c in clusters(*_ids_and_links(conn))}
    values = {r["id"]: f"{r['type']} {r['value']}" for r in conn.execute("SELECT id, type, value FROM iocs")}
    named = [{values[i] for i in case} for case in cases]
    assert {"email billing@invoice-update.example.org", "email other@invoice-update.example.org",
            "domain invoice-update.example.org"} in named


def _ids_and_links(conn):
    result = correlate(conn)
    return [r["id"] for r in conn.execute("SELECT id FROM iocs ORDER BY id")], result.links


def test_two_addresses_at_a_free_mail_provider_are_not_pulled_into_one_case():
    conn = make("sender scammer@gmail.com\nunrelated victim@gmail.com\n")
    assert {l.rule for l in correlate(conn).links} == set()  # no shared domain indicator, no shared line


def test_a_document_extension_followed_by_an_executable_one_scores_medium_and_says_why():
    conn = make(MAIL)
    verdicts = {v.value: v for v in triage(conn).values()}
    v = verdicts["Invoice_4471.pdf.exe"]
    assert [h.rule for h in v.hits] == ["TW-T11"] and v.score == 25 and v.level == "medium"
    assert "document extension" in v.hits[0].reason and v.hits[0].evidence
    assert verdicts["billing@invoice-update.example.org"].level == "info"  # an address alone says nothing


def test_an_ordinary_attachment_name_is_not_scored():
    conn = make('Content-Disposition: attachment; filename="Quarterly_report.pdf"\nAttachment: setup.exe\n')
    assert {v.value: (v.score, v.level) for v in triage(conn).values()} == {"Quarterly_report.pdf": (0, "info"), "setup.exe": (0, "info")}


def test_high_volume_scoring_does_not_apply_to_emails_or_file_names():
    conn = make("".join(f"{i} bob@example.org invoice.pdf.exe\n" for i in range(1_200)))
    by_value = {v.value: v for v in triage(conn).values()}
    assert "TW-T10" not in {h.rule for h in by_value["bob@example.org"].hits}
    assert "TW-T10" not in {h.rule for h in by_value["invoice.pdf.exe"].hits}


def test_the_report_defangs_emails_and_file_names_and_stays_traceable():
    conn = make(MAIL)
    report = build_report(conn, "2026-10-20T00:00:00+00:00")
    md = render_markdown(report)
    assert "billing[@]invoice-update[.]example[.]org" in md and "Invoice_4471[.]pdf[.]exe" in md
    assert "billing@invoice-update.example.org" not in md and "Invoice_4471.pdf.exe" not in md
    assert verify_traceability(conn, report)["traceable_fraction"] == 1.0


def test_defang_round_trip_for_email_and_file_name_shapes():
    for value in ["bob@example.org", "A.b+c@sub.example.co.uk", "Invoice 4471.pdf.exe", "logo@2x.png", "a(1).docm"]:
        assert refang(defang(value)).text == value
    assert defang("bob@example.org") == "bob[@]example[.]org"
    assert defang("http://user@host.example.com/x") == "hxxp://user@host[.]example[.]com/x"  # URLs keep their own form
