"""Correlation / triage / traceability scores against a hand-labeled synthetic scenario.

Scenario layout (data/synthetic/scenario/): docs/, feeds/, labels.json. The labels
were derived by hand from the rule definitions *before* running the code; where
the code and the labels disagreed, each case was decided on its merits (see git
history), not by editing whichever side was convenient.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .evaluate import Counts
from .pipeline import PipelineRun, run_scenario
from .report import verify_traceability


@dataclass
class ScenarioScores:
    links: Counts = field(default_factory=Counts)
    matches: Counts = field(default_factory=Counts)
    triage_correct: int = 0
    triage_total: int = 0
    triage_unlabeled: list[str] = field(default_factory=list)
    cases_exact: bool = False
    traceable_fraction: float = 0.0
    claims: int = 0
    errors: list[str] = field(default_factory=list)


def _score(counts: Counts, actual: set, expected: set, what: str, errors: list[str]) -> None:
    counts.tp += len(actual & expected)
    for x in sorted(actual - expected, key=str):
        counts.fp += 1
        errors.append(f"FP {what}: {x}")
    for x in sorted(expected - actual, key=str):
        counts.fn += 1
        errors.append(f"FN {what}: {x}")


def evaluate_scenario(scenario_dir: str | Path, run: PipelineRun | None = None) -> ScenarioScores:
    labels = json.loads((Path(scenario_dir) / "labels.json").read_text(encoding="utf-8"))
    run = run or run_scenario(scenario_dir)
    conn = run.conn
    ident = {r["id"]: (r["type"], r["value"]) for r in conn.execute("SELECT id, type, value FROM iocs")}
    scores = ScenarioScores()

    actual_links = {(l.rule, frozenset({ident[l.a], ident[l.b]})) for l in run.result.links}
    expected_links = {(l["rule"], frozenset({tuple(l["a"]), tuple(l["b"])})) for l in labels["links"]}
    _score(scores.links, actual_links, expected_links, "link", scores.errors)

    actual_matches = {(ident[m.ioc_id], m.feed, m.via) for m in run.result.matches}
    expected_matches = {(tuple(m["ioc"]), m["feed"], m["via"]) for m in labels["matches"]}
    _score(scores.matches, actual_matches, expected_matches, "match", scores.errors)

    expected_levels = {tuple(t["ioc"]): t["level"] for t in labels["triage"]}
    for v in run.verdicts.values():
        key = (v.type, v.value)
        if key not in expected_levels:
            scores.triage_unlabeled.append(f"{key[0]} {key[1]}")
            continue
        scores.triage_total += 1
        if v.level == expected_levels[key]:
            scores.triage_correct += 1
        else:
            scores.errors.append(f"triage {key}: got {v.level} ({v.score}), expected {expected_levels[key]}")

    actual_cases = {frozenset(ident[i["id"]] for i in c["indicators"]) for c in run.report["cases"]}
    expected_cases = {frozenset(tuple(x) for x in case) for case in labels["cases"]}
    scores.cases_exact = actual_cases == expected_cases
    if not scores.cases_exact:
        scores.errors.append(f"cases differ: extra={actual_cases - expected_cases} missing={expected_cases - actual_cases}")

    trace = verify_traceability(conn, run.report)
    scores.traceable_fraction = trace["traceable_fraction"]
    scores.claims = trace["claims"]
    scores.errors.extend(f"trace: {p}" for p in trace["problems"])
    return scores


def format_scenario(s: ScenarioScores) -> str:
    lines = [
        f"correlation links   precision {s.links.precision:.3f}  recall {s.links.recall:.3f}  (TP {s.links.tp} FP {s.links.fp} FN {s.links.fn})",
        f"feed matches        precision {s.matches.precision:.3f}  recall {s.matches.recall:.3f}  (TP {s.matches.tp} FP {s.matches.fp} FN {s.matches.fn})",
        f"triage levels       {s.triage_correct}/{s.triage_total} correct, {len(s.triage_unlabeled)} unlabeled",
        f"cases               {'exact match' if s.cases_exact else 'DIFFER'}",
        f"report traceability {s.traceable_fraction:.3f} of {s.claims} claims resolve to stored evidence",
    ]
    lines.extend(["", *s.errors] if s.errors else [])
    return "\n".join(lines)
