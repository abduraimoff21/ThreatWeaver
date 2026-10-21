"""A finished analysis, saved next to the database so it is not redone every time the dashboard starts.

The analysis (correlation, triage and the report) is a pure function of what is in the database and of the
code that computes it. A saved copy is only used when both are exactly what they were when it was made:

  * the database: every source (its id, name, kind and SHA-256), plus a counter that is bumped whenever
    anything is deleted, so a half-finished removal can never be mistaken for the finished one;
  * the code: a hash of the modules that produce the analysis, so a new version recomputes.

Anything else (a missing, unreadable or older file) just means the analysis is computed again and saved.
The file is JSON (never pickle), written to a temporary name and renamed, so a crash cannot leave half a file.
It holds the same data the dashboard keeps in memory (indicator values and the report), so treat it like the
database: it sits beside it and stays out of version control.

Links are kept without their lists of evidence ids, only the count (`compact`). The report already carries the
capped evidence it shows, and for millions of sightings the lists would be millions of objects that nothing in the
dashboard reads. A freshly made analysis is compacted too, so it looks the same whether it was made or loaded.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import zlib
from pathlib import Path
from typing import Any

from . import __version__, store
from .correlate import CorrelationResult, Evidence, FeedMatch, Link
from .triage import RuleHit, Verdict

FORMAT = 1
SUFFIX = ".analysis.gz"
_MODULES = ("extract", "normalize", "defang", "files", "tlds", "models", "correlate", "triage", "report", "store", "attack", "attack_data")
_signature: str | None = None


def code_signature() -> str:
    """Changes whenever the code that produces an analysis changes."""
    global _signature
    if _signature is None:
        h = hashlib.sha256(__version__.encode())
        here = Path(__file__).resolve().parent
        for name in _MODULES:
            path = here / f"{name}.py"
            if path.exists():
                h.update(name.encode())
                h.update(path.read_bytes().replace(b"\r\n", b"\n"))  # the same on Windows and elsewhere
        _signature = h.hexdigest()
    return _signature


def fingerprint(conn: sqlite3.Connection) -> str:
    """Identifies the state of the database as far as the analysis is concerned. Cheap: it reads only the
    list of sources, however many millions of sightings they hold."""
    h = hashlib.sha256(f"{FORMAT}|{code_signature()}|{store.epoch(conn)}".encode())
    for r in conn.execute("SELECT id, name, kind, content_sha256 FROM sources ORDER BY id"):
        h.update(f"|{r['id']}|{r['name']}|{r['kind']}|{r['content_sha256']}".encode())
    return h.hexdigest()


def path_for(db_path: str) -> Path | None:
    return None if db_path in ("", ":memory:") else Path(str(db_path) + SUFFIX)


# ------------------------------------------------------------------ encoding
def _enc_ev(evidence: tuple[Evidence, ...]) -> list[Any]:
    kinds = {e.kind for e in evidence}
    if len(kinds) == 1:  # nearly always: every item of one link or rule is the same kind, so write the ids only
        return [next(iter(kinds)), [e.id for e in evidence]]
    return [None, [[e.kind, e.id] for e in evidence]]


def _dec_ev(encoded: list[Any]) -> tuple[Evidence, ...]:
    kind, items = encoded
    if kind is None:
        return tuple(Evidence(k, i) for k, i in items)
    return tuple(Evidence(kind, i) for i in items)


def evidence_count(l: Link) -> int:
    """How many pieces of evidence a link rests on: the true total if its list was capped, else the list's length."""
    return len(l.evidence) if l.evidence_total is None else l.evidence_total


def compact(result: CorrelationResult) -> CorrelationResult:
    """The same links without their evidence lists (the counts stay, in `evidence_total`)."""
    return CorrelationResult(
        links=[Link(l.rule, l.a, l.b, l.explanation, (), evidence_count(l)) for l in result.links],
        matches=result.matches, skipped_lines=result.skipped_lines, skipped_families=result.skipped_families)


def _enc_link(l: Link) -> list[Any]:
    return [l.rule, l.a, l.b, l.explanation, evidence_count(l)]


def _enc_verdict(v: Verdict) -> list[Any]:
    return [v.ioc_id, v.type, v.value, v.score, v.level, v.suggested_action,
            [[h.rule, h.points, h.reason, _enc_ev(h.evidence), h.evidence_total] for h in v.hits]]


_BIG_LISTS = ("links", "verdicts", "cases")  # written one item at a time, so a huge analysis is never one huge string


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))  # the fast, compiled encoder


def _write_json(put, value: dict[str, Any]) -> None:
    """`value` as JSON through `put`. Dictionaries are written key by key and the long lists item by item, with the
    compiled encoder doing the work: several times faster than the encoder's streaming mode, and memory stays flat."""
    put("{")
    for n, (key, item) in enumerate(value.items()):
        put(("," if n else "") + _dumps(key) + ":")
        if key in _BIG_LISTS and isinstance(item, list):
            put("[")
            for start in range(0, len(item), 500):
                put(("," if start else "") + ",".join(_dumps(x) for x in item[start:start + 500]))
            put("]")
        elif key == "report" and isinstance(item, dict):
            _write_json(put, item)
        else:
            put(_dumps(item))
    put("}")


def save(path: Path, fp: str, result: CorrelationResult, verdicts: dict[int, Verdict], report: dict[str, Any]) -> bool:
    """Write the analysis. Returns False (and leaves any older file alone) if it could not be written."""
    payload = {
        "format": FORMAT, "fingerprint": fp,
        "links": [_enc_link(l) for l in result.links],
        "matches": [[m.ioc_id, m.intel_id, m.feed, m.via, m.related_ioc_id, m.status, m.malware] for m in result.matches],
        "skipped_lines": result.skipped_lines, "skipped_families": result.skipped_families,
        "verdicts": [_enc_verdict(v) for v in verdicts.values()],
        "report": report,
    }
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1, mtime=0) as out:
            _write_json(lambda text: out.write(text.encode("utf-8")), payload)
        os.replace(tmp, path)
        return True
    except (OSError, ValueError, TypeError):
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def load(path: Path | None, fp: str) -> tuple[CorrelationResult, dict[int, Verdict], dict[str, Any]] | None:
    """The saved analysis if it is for exactly this database and code; otherwise None."""
    if path is None or not path.exists():
        return None
    try:
        data = json.loads(gzip.decompress(path.read_bytes()))
        if data.get("format") != FORMAT or data.get("fingerprint") != fp:
            return None
        result = CorrelationResult(
            links=[Link(rule, a, b, explanation, (), count) for rule, a, b, explanation, count in data["links"]],
            matches=[FeedMatch(*m) for m in data["matches"]],
            skipped_lines=data["skipped_lines"], skipped_families=data["skipped_families"],
        )
        verdicts = {}
        for ioc_id, kind, value, score, level, action, hits in data["verdicts"]:
            verdicts[ioc_id] = Verdict(ioc_id, kind, value, score, level,
                                       tuple(RuleHit(rule, points, reason, _dec_ev(ev), total) for rule, points, reason, ev, total in hits), action)
        return result, verdicts, data["report"]
    except (OSError, EOFError, ValueError, KeyError, TypeError, AttributeError, zlib.error, gzip.BadGzipFile):
        return None  # damaged or from something else: compute again


def discard(path: Path | None) -> None:
    if path is not None:
        try:
            path.unlink()
        except OSError:
            pass
