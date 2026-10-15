"""Command line interface. Everything here is read/analyse only: no network, no blocking actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import store
from .evaluate import evaluate, format_report
from .extract import extract
from .normalize import normalize

DEFAULT_DB = "threatweaver.db"
DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "data" / "synthetic"


def _cmd_extract(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file != "-" else sys.stdin.read()
    rows = []
    for cand in extract(text):
        norm = normalize(cand)
        if norm is None:
            continue
        rows.append({
            "type": norm.type.value, "value": norm.value, "raw": cand.raw,
            "span": [cand.start, cand.end], "defanged": cand.defanged,
            "derived": cand.derived_from is not None, "attrs": norm.attrs,
        })
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            note = " (host of URL)" if r["derived"] else " (defanged)" if r["defanged"] else ""
            print(f"{r['type']:<7} {r['value']}{note}")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    conn = store.connect(args.db)
    for path in args.files:
        res = store.ingest_file(conn, path)
        if res.already_ingested:
            print(f"{path}: already ingested, skipped")
        else:
            print(f"{path}: {res.candidates} candidates, {res.new_iocs} new IOCs, "
                  f"{res.new_observations} observations, {res.rejected} rejected")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    conn = store.connect(args.db)
    for r in store.list_iocs(conn, args.type, args.min_sources):
        print(f"{r['type']:<7} {r['value']}  obs={r['observations']} sources={r['sources']}")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    conn = store.connect(args.db)
    rows = store.provenance(conn, args.type, args.value)
    if not rows:
        print("not found", file=sys.stderr)
        return 1
    for r in rows:
        flags = " [defanged]" if r["defanged"] else ""
        flags += " [derived from URL]" if r["parent_observation_id"] else ""
        print(f"{r['source']}:{r['line_no']} chars {r['span_start']}-{r['span_end']}: {r['raw']}{flags}")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    report = evaluate(args.corpus)
    print(format_report(report))
    return 0 if not report.errors else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threatweaver", description="IOC extraction and normalization (Milestone 1)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("extract", help="print normalized IOCs from a file (or - for stdin); no database")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_extract)

    p = sub.add_parser("ingest", help="extract, normalize and store IOCs with provenance")
    p.add_argument("files", nargs="+")
    p.add_argument("--db", default=DEFAULT_DB)
    p.set_defaults(func=_cmd_ingest)

    p = sub.add_parser("list", help="list unique IOCs")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--type")
    p.add_argument("--min-sources", type=int, default=1)
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("show", help="show every place an IOC was seen")
    p.add_argument("type")
    p.add_argument("value")
    p.add_argument("--db", default=DEFAULT_DB)
    p.set_defaults(func=_cmd_show)

    p = sub.add_parser("evaluate", help="precision/recall against the synthetic corpus")
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    p.set_defaults(func=_cmd_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
