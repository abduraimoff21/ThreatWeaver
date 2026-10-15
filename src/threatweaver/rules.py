"""Module G: a test harness for Sigma and YARA detection rules.

The harness answers one question an analyst has before deploying a rule: does it
fire on what it should and stay quiet on what it should not? A *suite* pairs a
rule with labeled sample events (Sigma) or sample data (YARA).

Sigma: a pure-Python evaluator for the commonly used subset, so no dependency is
needed to run it (YAML rule files need the optional `pyyaml`; the same rule as
JSON works without it).
  supported  named selections as maps / lists of maps / keyword lists;
             modifiers contains, startswith, endswith, re, cidr, all;
             `*` and `?` wildcards; conditions with and / or / not, parentheses,
             `1 of x*`, `all of x*`, `1 of them`, `all of them`
  refused    anything else (aggregations `| count`, `near`, timeframes, other
             modifiers). The case is reported as UNSUPPORTED, never as a pass.

YARA: delegated to the optional `yara-python`. If it is not installed the suite
is reported as SKIPPED, never as a pass. No YARA semantics are re-implemented.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MISSING = object()


class UnsupportedRule(Exception):
    """The rule uses a feature this harness does not implement."""


class BackendUnavailable(Exception):
    """An optional dependency needed for this rule type is not installed."""


# --------------------------------------------------------------------- Sigma
def load_rule_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml
    except ImportError as exc:
        raise BackendUnavailable("YAML rule files need pyyaml (pip install pyyaml); JSON rules work without it") from exc
    return yaml.safe_load(text)


def _get(event: dict[str, Any], name: str) -> Any:
    if name in event:
        return event[name]
    cur: Any = event
    for part in name.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return MISSING
        cur = cur[part]
    return cur


def _match_value(modifiers: list[str], actual: Any, expected: Any) -> bool:
    if expected is None:
        return actual is MISSING or actual is None or actual == ""
    if actual is MISSING or actual is None:
        return False
    a, e = str(actual), str(expected)
    if "re" in modifiers:
        return re.search(e, a) is not None
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(a) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    a, e = a.lower(), e.lower()
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    return fnmatch.fnmatchcase(a, e)


_KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "all"}


def _match_field(event: dict[str, Any], spec: str, expected: Any) -> bool:
    name, *modifiers = spec.split("|")
    unknown = set(modifiers) - _KNOWN_MODIFIERS
    if unknown:
        raise UnsupportedRule(f"modifier(s) not supported: {', '.join(sorted(unknown))}")
    actual = _get(event, name)
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(modifiers, actual, v) for v in values]
    return all(results) if "all" in modifiers else any(results)


def _match_selection(selection: Any, event: dict[str, Any]) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(item, dict) for item in selection):
            return any(_match_selection(item, event) for item in selection)
        if all(isinstance(item, (str, int, float)) for item in selection):  # keywords
            haystack = [str(v).lower() for v in _flatten(event)]
            return any(any(fnmatch.fnmatchcase(h, f"*{str(k).lower()}*") for h in haystack) for k in selection)
    raise UnsupportedRule("selection shape not supported")


def _flatten(value: Any):
    if isinstance(value, dict):
        for v in value.values():
            yield from _flatten(v)
    elif isinstance(value, list):
        for v in value:
            yield from _flatten(v)
    elif value is not None:
        yield value


class _Condition:
    """Recursive-descent evaluator for Sigma condition strings."""

    def __init__(self, text: str, names: list[str], truth: dict[str, Any]):
        if "|" in text:
            raise UnsupportedRule("aggregation / pipe conditions are not supported")
        self.tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos = 0
        self.names = names
        self.truth = truth

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> bool:
        value = self.or_expr()
        if self.peek() is not None:
            raise UnsupportedRule(f"unexpected token in condition: {self.peek()!r}")
        return value

    def or_expr(self) -> bool:
        value = self.and_expr()
        while self.peek() == "or":
            self.take()
            rhs = self.and_expr()
            value = value or rhs
        return value

    def and_expr(self) -> bool:
        value = self.not_expr()
        while self.peek() == "and":
            self.take()
            rhs = self.not_expr()
            value = value and rhs
        return value

    def not_expr(self) -> bool:
        if self.peek() == "not":
            self.take()
            return not self.not_expr()
        return self.atom()

    def atom(self) -> bool:
        tok = self.peek()
        if tok is None:
            raise UnsupportedRule("condition ended unexpectedly")
        if tok == "(":
            self.take()
            value = self.or_expr()
            if self.peek() != ")":
                raise UnsupportedRule("missing closing parenthesis")
            self.take()
            return value
        if tok in ("1", "all") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1] == "of":
            quant = self.take()
            self.take()  # "of"
            target = self.take()
            chosen = self.names if target == "them" else [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            if not chosen:
                raise UnsupportedRule(f"no selection matches {target!r}")
            results = [self.lookup(n) for n in chosen]
            return all(results) if quant == "all" else any(results)
        self.take()
        return self.lookup(tok)

    def lookup(self, name: str) -> bool:
        if name not in self.truth:
            raise UnsupportedRule(f"condition references unknown selection {name!r}")
        return self.truth[name]()


def sigma_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise UnsupportedRule("rule has no detection.condition")
    selections = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    if "timeframe" in detection:
        raise UnsupportedRule("timeframe is not supported")
    cache: dict[str, bool] = {}

    def make(name: str):
        def evaluate() -> bool:
            if name not in cache:
                cache[name] = _match_selection(selections[name], event)
            return cache[name]

        return evaluate

    truth = {name: make(name) for name in selections}
    conditions = detection["condition"]
    conditions = conditions if isinstance(conditions, list) else [conditions]
    return any(_Condition(str(c), list(selections), truth).parse() for c in conditions)


# ---------------------------------------------------------------------- YARA
def yara_matches(rule_source: str, data: bytes) -> bool:
    try:
        import yara
    except ImportError as exc:
        raise BackendUnavailable("YARA rules need yara-python (pip install yara-python)") from exc
    return bool(yara.compile(source=rule_source).match(data=data))


# --------------------------------------------------------------------- Suites
@dataclass
class CaseResult:
    id: str
    expect_match: bool
    outcome: str  # "pass" | "fail" | "unsupported" | "skipped"
    matched: bool | None = None
    detail: str = ""


@dataclass
class SuiteResult:
    name: str
    kind: str
    cases: list[CaseResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _count(self, expect: bool, matched: bool) -> int:
        return sum(1 for c in self.cases if c.matched is not None and c.expect_match == expect and c.matched == matched)

    @property
    def tp(self) -> int: return self._count(True, True)
    @property
    def fn(self) -> int: return self._count(True, False)
    @property
    def fp(self) -> int: return self._count(False, True)
    @property
    def tn(self) -> int: return self._count(False, False)

    @property
    def ok(self) -> bool:
        return bool(self.cases) and all(c.outcome == "pass" for c in self.cases)

    @property
    def status(self) -> str:
        outcomes = {c.outcome for c in self.cases}
        for state in ("fail", "unsupported", "skipped"):
            if state in outcomes:
                return state
        return "pass" if self.cases else "empty"


def run_suite(suite_path: str | Path) -> SuiteResult:
    path = Path(suite_path)
    suite = json.loads(path.read_text(encoding="utf-8"))
    kind = suite["type"]
    result = SuiteResult(suite.get("name", path.stem), kind)
    rule_path = path.parent / suite["rule_file"]
    cases = suite.get("cases", [])
    if not any(c["expect_match"] for c in cases):
        result.warnings.append("no positive cases: the rule is not shown to detect anything")
    if not any(not c["expect_match"] for c in cases):
        result.warnings.append("no negative cases: false positives are not tested")

    rule: Any = None
    source = ""
    setup_error: tuple[str, str] | None = None
    try:
        if kind == "sigma":
            rule = load_rule_file(rule_path)
        elif kind == "yara":
            source = rule_path.read_text(encoding="utf-8")
        else:
            raise UnsupportedRule(f"unknown suite type {kind!r}")
    except BackendUnavailable as exc:
        setup_error = ("skipped", str(exc))
    except UnsupportedRule as exc:
        setup_error = ("unsupported", str(exc))
    except (OSError, ValueError) as exc:  # unreadable file, bad JSON/YAML
        setup_error = ("fail", f"cannot load rule: {exc}")

    for case in cases:
        expect = bool(case["expect_match"])
        if setup_error:
            result.cases.append(CaseResult(case["id"], expect, setup_error[0], None, setup_error[1]))
            continue
        try:
            if kind == "sigma":
                matched = sigma_matches(rule, case["event"])
            else:
                matched = yara_matches(source, case["data"].encode("utf-8"))
        except UnsupportedRule as exc:
            result.cases.append(CaseResult(case["id"], expect, "unsupported", None, str(exc)))
            continue
        except BackendUnavailable as exc:
            result.cases.append(CaseResult(case["id"], expect, "skipped", None, str(exc)))
            continue
        result.cases.append(CaseResult(case["id"], expect, "pass" if matched == expect else "fail", matched))
    return result


def format_suite(r: SuiteResult) -> str:
    lines = [f"{r.name} [{r.kind}]: {r.status.upper()}  (TP {r.tp}, FN {r.fn}, FP {r.fp}, TN {r.tn})"]
    for c in r.cases:
        want = "match" if c.expect_match else "no match"
        extra = f" - {c.detail}" if c.detail else ""
        lines.append(f"  {c.outcome.upper():<11} {c.id}: expected {want}{extra}")
    lines.extend(f"  warning: {w}" for w in r.warnings)
    return "\n".join(lines)
