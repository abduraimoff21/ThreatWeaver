"""Extraction precision/recall against a labeled synthetic corpus.

Corpus layout (see data/synthetic/):
    labels.json  {"<filename>": [{"type": "...", "value": "<normalized>"}, ...], ...}
    <filename>   the text document

Comparison is on the set of normalized (type, value) pairs per document, so
duplicate mentions inside one document do not inflate or deflate the scores.
An empty label list means "nothing should be extracted" and any output counts
as false positives.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .extract import extract
from .normalize import normalize


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


@dataclass
class Report:
    overall: Counts = field(default_factory=Counts)
    by_type: dict[str, Counts] = field(default_factory=lambda: defaultdict(Counts))
    errors: list[str] = field(default_factory=list)  # human-readable FP/FN lines
    documents: int = 0
    characters: int = 0
    seconds: float = 0.0


def extract_normalized(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for cand in extract(text):
        norm = normalize(cand)
        if norm is not None:
            out.add((norm.type.value, norm.value))
    return out


def evaluate(corpus_dir: str | Path) -> Report:
    corpus = Path(corpus_dir)
    labels: dict[str, list[dict[str, str]]] = json.loads((corpus / "labels.json").read_text(encoding="utf-8"))
    report = Report()
    for name, expected_list in sorted(labels.items()):
        text = (corpus / name).read_text(encoding="utf-8")
        expected = {(e["type"], e["value"]) for e in expected_list}

        start = time.perf_counter()
        actual = extract_normalized(text)
        report.seconds += time.perf_counter() - start
        report.documents += 1
        report.characters += len(text)

        for kind, value in sorted(actual & expected):
            report.overall.tp += 1
            report.by_type[kind].tp += 1
        for kind, value in sorted(actual - expected):
            report.overall.fp += 1
            report.by_type[kind].fp += 1
            report.errors.append(f"FP {name}: {kind} {value}")
        for kind, value in sorted(expected - actual):
            report.overall.fn += 1
            report.by_type[kind].fn += 1
            report.errors.append(f"FN {name}: {kind} {value}")
    return report


def format_report(report: Report) -> str:
    lines = [f"{'type':<8} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}"]
    rows = sorted(report.by_type.items()) + [("OVERALL", report.overall)]
    for kind, c in rows:
        lines.append(f"{kind:<8} {c.tp:>4} {c.fp:>4} {c.fn:>4} {c.precision:>10.3f} {c.recall:>8.3f}")
    rate = report.characters / report.seconds / 1e6 if report.seconds else float("inf")
    lines.append(f"\n{report.documents} documents, {report.characters} chars, {report.seconds * 1000:.1f} ms ({rate:.1f} MB/s)")
    lines.extend(["", *report.errors] if report.errors else [])
    return "\n".join(lines)
