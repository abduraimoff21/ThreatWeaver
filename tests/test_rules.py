import json
import sys
import types
from pathlib import Path

import pytest

from threatweaver.rules import (
    BackendUnavailable, UnsupportedRule, load_rule_file, run_suite, sigma_matches, yara_matches,
)

RULES = Path(__file__).resolve().parents[1] / "data" / "synthetic" / "rules"


def rule(condition, **selections):
    return {"detection": {**selections, "condition": condition}}


# ------------------------------------------------------------- sigma semantics
@pytest.mark.parametrize(
    "selection, event, expected",
    [
        ({"Image": "C:\\Tools\\A.EXE"}, {"Image": "c:\\tools\\a.exe"}, True),  # case-insensitive equality
        ({"Image": "*\\a.exe"}, {"Image": "C:\\x\\a.exe"}, True),  # wildcard
        ({"Image": "a?.exe"}, {"Image": "ab.exe"}, True),
        ({"Image|contains": "evil"}, {"Image": "x/EVIL/y"}, True),
        ({"Image|startswith": "C:\\Temp"}, {"Image": "c:\\temp\\x"}, True),
        ({"Image|endswith": [".ps1", ".bat"]}, {"Image": "run.BAT"}, True),  # list = OR
        ({"Image|contains|all": ["a", "b"]}, {"Image": "xaxb"}, True),
        ({"Image|contains|all": ["a", "z"]}, {"Image": "xaxb"}, False),
        ({"Cmd|re": r"-enc\s+[A-Za-z0-9+/=]{20,}"}, {"Cmd": "powershell -enc " + "A" * 24}, True),
        ({"Cmd|re": "^abc$"}, {"Cmd": "ABC"}, False),  # re is case-sensitive
        ({"ip|cidr": "10.0.0.0/8"}, {"ip": "10.9.8.7"}, True),
        ({"ip|cidr": "10.0.0.0/8"}, {"ip": "11.0.0.1"}, False),
        ({"ip|cidr": "10.0.0.0/8"}, {"ip": "not-an-ip"}, False),
        ({"Missing": None}, {"Other": 1}, True),  # null matches an absent field
        ({"Present": None}, {"Present": "x"}, False),
        ({"EventID": 4625}, {"EventID": 4625}, True),
        ({"a": "1", "b": "2"}, {"a": "1", "b": "3"}, False),  # fields in one map are ANDed
        ({"proc.name": "x"}, {"proc": {"name": "x"}}, True),  # dotted path
        ([{"a": "1"}, {"b": "2"}], {"b": "2"}, True),  # list of maps = OR
        (["mimikatz", "sekurlsa"], {"CommandLine": "run SEKURLSA::logonpasswords"}, True),  # keywords
        (["mimikatz"], {"CommandLine": "notepad"}, False),
    ],
)
def test_selection_semantics(selection, event, expected):
    assert sigma_matches(rule("sel", sel=selection), event) is expected


def test_condition_grammar():
    r = rule("(a or b) and not c", a={"x": 1}, b={"y": 1}, c={"z": 1})
    assert sigma_matches(r, {"x": 1}) is True
    assert sigma_matches(r, {"y": 1}) is True
    assert sigma_matches(r, {"x": 1, "z": 1}) is False
    assert sigma_matches(r, {}) is False
    # precedence: and binds tighter than or
    r2 = rule("a or b and c", a={"x": 1}, b={"y": 1}, c={"z": 1})
    assert sigma_matches(r2, {"x": 1}) is True and sigma_matches(r2, {"y": 1}) is False


def test_quantifiers():
    r = rule("1 of sel_*", sel_a={"x": 1}, sel_b={"y": 1}, other={"z": 1})
    assert sigma_matches(r, {"y": 1}) and not sigma_matches(r, {"z": 1})
    r = rule("all of sel_*", sel_a={"x": 1}, sel_b={"y": 1}, other={"z": 1})
    assert sigma_matches(r, {"x": 1, "y": 1}) and not sigma_matches(r, {"x": 1})
    assert sigma_matches(rule("all of them", a={"x": 1}, b={"y": 1}), {"x": 1, "y": 1})
    assert sigma_matches(rule("1 of them", a={"x": 1}, b={"y": 1}), {"y": 1})
    assert sigma_matches(rule(["a", "b"], a={"x": 1}, b={"y": 1}), {"y": 1})  # list of conditions = OR


@pytest.mark.parametrize(
    "bad_rule",
    [
        rule("sel | count() > 5", sel={"x": 1}),
        rule("sel", sel={"x|base64offset|contains": "a"}),
        rule("missing_selection", sel={"x": 1}),
        rule("sel and", sel={"x": 1}),
        rule("(sel", sel={"x": 1}),
        rule("1 of nothing_*", sel={"x": 1}),
        {"detection": {"sel": {"x": 1}}},
        {"detection": {"sel": {"x": 1}, "timeframe": "5m", "condition": "sel"}},
    ],
)
def test_unsupported_features_are_refused_loudly(bad_rule):
    with pytest.raises(UnsupportedRule):
        sigma_matches(bad_rule, {"x": 1})


# ------------------------------------------------------------- files and suites
def test_json_rule_file_loads():
    assert load_rule_file(RULES / "proxy_raw_ip_download.json")["level"] == "high"


def test_yaml_and_json_versions_of_the_rule_are_identical():
    pytest.importorskip("yaml")
    assert load_rule_file(RULES / "proxy_raw_ip_download.yml") == load_rule_file(RULES / "proxy_raw_ip_download.json")


def test_yaml_without_pyyaml_is_reported_not_crashed(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(BackendUnavailable):
        load_rule_file(RULES / "proxy_raw_ip_download.yml")


def test_sigma_suite_passes_with_counts():
    r = run_suite(RULES / "proxy_raw_ip_download.suite.json")
    assert r.status == "pass" and r.ok
    assert (r.tp, r.fn, r.fp, r.tn) == (2, 0, 0, 5)
    assert r.warnings == []


def test_suite_detects_false_positive_and_false_negative(tmp_path):
    (tmp_path / "r.json").write_text(json.dumps(rule("sel", sel={"x": "bad"})), encoding="utf-8")
    suite = {"type": "sigma", "rule_file": "r.json", "cases": [
        {"id": "miss", "expect_match": True, "event": {"x": "other"}},
        {"id": "noise", "expect_match": False, "event": {"x": "bad"}},
    ]}
    (tmp_path / "s.suite.json").write_text(json.dumps(suite), encoding="utf-8")
    r = run_suite(tmp_path / "s.suite.json")
    assert r.status == "fail" and (r.tp, r.fn, r.fp, r.tn) == (0, 1, 1, 0)


def test_suite_warns_when_it_cannot_prove_much(tmp_path):
    (tmp_path / "r.json").write_text(json.dumps(rule("sel", sel={"x": 1})), encoding="utf-8")
    suite = {"type": "sigma", "rule_file": "r.json", "cases": [{"id": "only-pos", "expect_match": True, "event": {"x": 1}}]}
    (tmp_path / "s.suite.json").write_text(json.dumps(suite), encoding="utf-8")
    assert any("negative" in w for w in run_suite(tmp_path / "s.suite.json").warnings)


def test_unsupported_rule_is_never_a_pass():
    r = run_suite(RULES / "unsupported.suite.json")
    assert r.status == "unsupported" and not r.ok


def test_missing_or_broken_rule_file_is_a_failure_not_a_crash(tmp_path):
    suite = {"type": "sigma", "rule_file": "nope.json", "cases": [{"id": "c", "expect_match": True, "event": {}}]}
    (tmp_path / "s.suite.json").write_text(json.dumps(suite), encoding="utf-8")
    assert run_suite(tmp_path / "s.suite.json").status == "fail"


# ------------------------------------------------------------- yara
def test_yara_unavailable_is_skipped_never_pass(monkeypatch):
    monkeypatch.setitem(sys.modules, "yara", None)
    with pytest.raises(BackendUnavailable):
        yara_matches("rule a { condition: true }", b"x")
    r = run_suite(RULES / "marker.suite.json")
    assert r.status == "skipped" and not r.ok


def test_yara_adapter_passes_rule_source_and_bytes(monkeypatch):
    """Glue only: a stub stands in for yara-python, so this proves nothing about YARA semantics."""
    seen = {}

    class Rules:
        def match(self, data):
            seen["data"] = data
            return [object()] if b"MARK" in data else []

    stub = types.SimpleNamespace(compile=lambda source: (seen.update(source=source) or Rules()))
    monkeypatch.setitem(sys.modules, "yara", stub)
    assert yara_matches("rule x {}", b"..MARK..") is True
    assert yara_matches("rule x {}", b"nothing") is False
    assert seen["source"] == "rule x {}"


def test_yara_suite_with_real_backend_if_installed():
    pytest.importorskip("yara")
    assert run_suite(RULES / "marker.suite.json").status == "pass"
