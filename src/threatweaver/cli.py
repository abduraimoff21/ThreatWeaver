"""Command line interface.

Nothing here blocks, quarantines or sends anything. The only network access is
`feeds fetch`, which you run explicitly; the only "publish" is writing local
files after a person approves an advisory at a terminal.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import advisory, store
from .benchmark import benchmark, format_benchmark
from .correlate import correlate, save_links
from .evaluate import evaluate, format_report
from .extract import extract
from .feeds import FEEDS, FeedError, fetch_text, load_feed
from .normalize import normalize
from .pipeline import load_scenario, run, run_scenario
from .report import build_report, render_markdown, verify_traceability
from .rules import format_suite, run_suite
from .scenario_eval import evaluate_scenario, format_scenario
from .triage import triage

DEFAULT_DB = "threatweaver.db"
DEFAULT_CACHE = ".threatweaver-cache"
DATA = Path(__file__).resolve().parents[2] / "data" / "synthetic"


def _db(args: argparse.Namespace):
    return store.connect(args.db)


# ------------------------------------------------------------ Milestone 1
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


PROGRESS_FROM_BYTES = 32 * 1024 * 1024  # smaller files finish too quickly to need a progress line


def progress_printer(name: str, total: int, out=None):
    """A progress callback that prints a line each time another 5% of a large file is done."""
    out = out or sys.stderr
    last = [-1]

    def show(done: int, _total: int) -> None:
        pct = 100 if total == 0 else int(100 * done / total)
        if pct // 5 != last[0] // 5 or pct == 100 and last[0] != 100:
            last[0] = pct
            print(f"  {name}: {pct}%", file=out, flush=True)

    return show


def _cmd_ingest(args: argparse.Namespace) -> int:
    conn = _db(args)
    for path in args.files:
        size = Path(path).stat().st_size
        progress = progress_printer(Path(path).name, size) if size >= PROGRESS_FROM_BYTES else None
        res = store.ingest_path(conn, path, progress=progress)
        if res.already_ingested:
            print(f"{path}: already ingested, skipped")
        else:
            print(f"{path}: {res.candidates} candidates, {res.new_iocs} new IOCs, "
                  f"{res.new_observations} observations, {res.rejected} rejected")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    for r in store.list_iocs(_db(args), args.type, args.min_sources):
        print(f"{r['type']:<7} {r['value']}  obs={r['observations']} sources={r['sources']}")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    rows = store.provenance(_db(args), args.type, args.value)
    if not rows:
        print("not found", file=sys.stderr)
        return 1
    for r in rows:
        flags = " [defanged]" if r["defanged"] else ""
        flags += " [derived from URL]" if r["parent_observation_id"] else ""
        print(f"{r['source']}:{r['line_no']} chars {r['span_start']}-{r['span_end']}: {r['raw']}{flags}")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    if args.scenario:
        scores = evaluate_scenario(args.scenario)
        print(format_scenario(scores))
        return 0 if not scores.errors else 1
    report = evaluate(args.corpus)
    print(format_report(report))
    return 0 if not report.errors else 1


# ------------------------------------------------------------ Milestone 2: feeds
def _cmd_feeds_fetch(args: argparse.Namespace) -> int:
    spec = FEEDS[args.feed]
    try:
        text, cached = fetch_text(spec, args.cache_dir, force=args.force)
    except FeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    res = load_feed(_db(args), spec, text)
    origin = "cache (inside the feed's rate limit)" if cached else "network"
    if res.already_loaded:
        print(f"{spec.name}: snapshot from {origin} identical to one already loaded")
    else:
        print(f"{spec.name}: {res.records} records from {origin}, {res.new_iocs} new IOCs, "
              f"{res.rejected} rejected, {res.skipped_rows} malformed rows skipped")
    return 0


def _cmd_feeds_load(args: argparse.Namespace) -> int:
    spec = FEEDS[args.feed]
    try:
        res = load_feed(_db(args), spec, Path(args.file).read_text(encoding="utf-8", errors="replace"))
    except FeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if res.already_loaded:
        print(f"{args.file}: identical snapshot already loaded")
    else:
        print(f"{args.file}: {res.records} records, {res.new_iocs} new IOCs, {res.rejected} rejected, "
              f"{res.skipped_rows} malformed rows skipped")
    return 0


# ------------------------------------------------------------ analysis
def _cmd_correlate(args: argparse.Namespace) -> int:
    conn = _db(args)
    result = correlate(conn)
    save_links(conn, result.links)
    ident = {r["id"]: f"{r['type']} {r['value']}" for r in conn.execute("SELECT id, type, value FROM iocs")}
    for l in result.links:
        print(f"{l.rule:<13} {ident[l.a]}  <->  {ident[l.b]}  evidence={len(l.evidence)}")
    print(f"\n{len(result.links)} links, {len(result.matches)} feed matches, {result.skipped_lines} noisy lines skipped")
    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    verdicts = triage(_db(args))
    for v in sorted(verdicts.values(), key=lambda v: (-v.score, v.type, v.value)):
        rules = ",".join(h.rule for h in v.hits) or "-"
        print(f"{v.level:<7} {v.score:>4}  {v.type:<7} {v.value}  [{rules}]")
    return 0


def _write_report(conn, out: Path, generated_at: str | None = None) -> dict:
    report = build_report(conn, generated_at)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    trace = verify_traceability(conn, report)
    print(f"wrote {out / 'report.md'} and {out / 'report.json'}; "
          f"{trace['claims']} claims, {trace['unresolved']} unresolved")
    return report


def _cmd_report(args: argparse.Namespace) -> int:
    _write_report(_db(args), Path(args.out))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    conn = _db(args)
    load_scenario(conn, args.scenario)
    pr = run(conn)
    _write_report(conn, Path(args.out), pr.report["generated_at"])
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    print(format_benchmark(benchmark(args.scenario, args.manual_seconds, repeat=args.repeat)))
    return 0


# ------------------------------------------------------------ rules (module G)
def _cmd_rules_test(args: argparse.Namespace) -> int:
    worst = 0
    for suite in args.suites:
        result = run_suite(suite)
        print(format_suite(result))
        if result.status in ("fail", "unsupported", "empty"):
            worst = 1
    return worst


# ------------------------------------------------------------ advisories (module H)
def _cmd_adv_draft(args: argparse.Namespace) -> int:
    conn = _db(args)
    try:
        title, body = advisory.draft_from_report(build_report(conn))
    except ValueError as exc:
        print(f"nothing drafted: {exc}", file=sys.stderr)
        return 1
    adv_id = advisory.create_draft(conn, title, body, args.author)
    print(f"created draft advisory {adv_id}: {title}")
    return 0


def _cmd_adv_list(args: argparse.Namespace) -> int:
    for a in advisory.list_advisories(_db(args)):
        print(f"{a['id']:>3}  {a['status']:<10} {a['title']}  (author {a['author']}, reviewer {a['reviewer'] or '-'})")
    return 0


def _cmd_adv_show(args: argparse.Namespace) -> int:
    conn = _db(args)
    a = advisory.get(conn, args.id)
    print(f"# advisory {a['id']}  status={a['status']}  sha256={a['content_sha256']}\n")
    print(a["body"])
    print("\n-- events --")
    for e in advisory.events(conn, args.id):
        print(f"{e['at']}  {e['action']:<8} {e['actor']}  {e['content_sha256'][:12]}  {e['note']}")
    return 0


def _cmd_adv_edit(args: argparse.Namespace) -> int:
    conn = _db(args)
    current = advisory.get(conn, args.id)
    body = Path(args.file).read_text(encoding="utf-8")
    advisory.edit_draft(conn, args.id, args.title or current["title"], body, args.actor)
    print(f"advisory {args.id} is now a draft again (any approval was voided)")
    return 0


def _cmd_adv_submit(args: argparse.Namespace) -> int:
    advisory.submit_for_review(_db(args), args.id, args.actor, tuple(args.deny or ()))
    print(f"advisory {args.id} submitted for review")
    return 0


def _cmd_adv_approve(args: argparse.Namespace) -> int:
    conn = _db(args)
    a = advisory.get(conn, args.id)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("error: approval must be given by a person at an interactive terminal", file=sys.stderr)
        return 2
    print(f"--- advisory {a['id']} by {a['author']} (sha256 {a['content_sha256']}) ---\n")
    print(a["title"], "\n")
    print(a["body"])
    typed = input(f'\nReviewer {args.reviewer}: type "APPROVE {a["id"]}" to approve exactly this text: ').strip()
    advisory.approve(conn, args.id, args.reviewer, a["content_sha256"], typed)
    print(f"advisory {args.id} approved by {args.reviewer}")
    return 0


def _cmd_adv_reject(args: argparse.Namespace) -> int:
    advisory.reject(_db(args), args.id, args.reviewer, args.note)
    print(f"advisory {args.id} rejected")
    return 0


def _cmd_adv_publish(args: argparse.Namespace) -> int:
    path = advisory.publish(_db(args), args.id, args.actor, args.out, tuple(args.deny or ()))
    print(f"published to local file {path} (nothing was sent anywhere)")
    return 0


def _cmd_ui(args: argparse.Namespace) -> int:
    from .web.api import Context
    from .web.server import serve

    store.connect(args.db).close()  # create or migrate the database before serving it
    serve(Context(db_path=args.db, out_dir=Path(args.out), cache_dir=args.cache_dir), port=args.port,
          open_browser=not args.no_browser)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threatweaver", description="Helps CERT analysts with repetitive investigative work. Read-only suggestions; humans decide.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help: str, func, db: bool = True, parent=sub) -> argparse.ArgumentParser:
        p = parent.add_parser(name, help=help)
        if db:
            p.add_argument("--db", default=DEFAULT_DB)
        p.set_defaults(func=func)
        return p

    p = add("extract", "print normalized IOCs from a file (or - for stdin); no database", _cmd_extract, db=False)
    p.add_argument("file")
    p.add_argument("--json", action="store_true")

    p = add("ingest", "extract, normalize and store IOCs with provenance", _cmd_ingest)
    p.add_argument("files", nargs="+")

    p = add("list", "list unique IOCs", _cmd_list)
    p.add_argument("--type")
    p.add_argument("--min-sources", type=int, default=1)

    p = add("show", "show every place an IOC was seen", _cmd_show)
    p.add_argument("type")
    p.add_argument("value")

    p = add("evaluate", "precision/recall on the synthetic corpus, or --scenario for correlation/triage/traceability", _cmd_evaluate, db=False)
    p.add_argument("--corpus", default=str(DATA))
    p.add_argument("--scenario", nargs="?", const=str(DATA / "scenario"), default=None)

    feeds = add("feeds", "public threat intel feeds (URLhaus, Feodo Tracker)", None, db=False)
    fsub = feeds.add_subparsers(dest="feeds_command", required=True)
    p = add("fetch", "download a feed snapshot (explicit network access; cached and rate limited)", _cmd_feeds_fetch, parent=fsub)
    p.add_argument("feed", choices=sorted(FEEDS))
    p.add_argument("--cache-dir", default=DEFAULT_CACHE)
    p.add_argument("--force", action="store_true", help="ignore the cache and the feed's minimum interval (be polite)")
    p = add("load", "load a feed snapshot you already have as a local file", _cmd_feeds_load, parent=fsub)
    p.add_argument("feed", choices=sorted(FEEDS))
    p.add_argument("file")

    add("correlate", "print correlation links and feed matches", _cmd_correlate)
    add("triage", "print rule-based triage verdicts", _cmd_triage)
    p = add("report", "write report.md and report.json", _cmd_report)
    p.add_argument("--out", default="out")
    p = add("run", "ingest a scenario directory (docs/ + feeds/) and write the report", _cmd_run)
    p.add_argument("scenario")
    p.add_argument("--out", default="out")
    p = add("benchmark", "processing time vs an ASSUMED manual baseline", _cmd_benchmark, db=False)
    p.add_argument("scenario", nargs="?", default=str(DATA / "scenario"))
    p.add_argument("--manual-seconds", type=float, default=30.0, help="assumed manual seconds per indicator per feed")
    p.add_argument("--repeat", type=int, default=5)

    rules = add("rules", "Sigma / YARA rule test harness", None, db=False)
    rsub = rules.add_subparsers(dest="rules_command", required=True)
    p = add("test", "run rule test suites (*.suite.json)", _cmd_rules_test, db=False, parent=rsub)
    p.add_argument("suites", nargs="+")

    adv = add("advisory", "human-approved advisory workflow", None, db=False)
    asub = adv.add_subparsers(dest="advisory_command", required=True)
    p = add("draft", "draft an advisory from public feed evidence in the database", _cmd_adv_draft, parent=asub)
    p.add_argument("--author", required=True)
    add("list", "list advisories", _cmd_adv_list, parent=asub)
    p = add("show", "show an advisory and its event log", _cmd_adv_show, parent=asub)
    p.add_argument("id", type=int)
    p = add("edit", "replace the body from a file (voids any approval)", _cmd_adv_edit, parent=asub)
    p.add_argument("id", type=int)
    p.add_argument("--file", required=True)
    p.add_argument("--title")
    p.add_argument("--actor", required=True)
    p = add("submit", "submit a draft for review (runs the confidentiality check)", _cmd_adv_submit, parent=asub)
    p.add_argument("id", type=int)
    p.add_argument("--actor", required=True)
    p.add_argument("--deny", action="append", help="extra term that must not appear (repeatable)")
    p = add("approve", "approve (interactive terminal only; reviewer must differ from author)", _cmd_adv_approve, parent=asub)
    p.add_argument("id", type=int)
    p.add_argument("--reviewer", required=True)
    p = add("reject", "reject a submitted advisory", _cmd_adv_reject, parent=asub)
    p.add_argument("id", type=int)
    p.add_argument("--reviewer", required=True)
    p.add_argument("--note", required=True)
    p = add("publish", "write an approved advisory to local files", _cmd_adv_publish, parent=asub)
    p.add_argument("id", type=int)
    p.add_argument("--actor", required=True)
    p.add_argument("--out", default="out/advisories")
    p.add_argument("--deny", action="append")

    p = add("ui", "open the local dashboard in your browser (loopback only)", _cmd_ui)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help="print the URL instead of opening a browser")
    p.add_argument("--out", default="out/advisories", help="where approved advisories are written")
    p.add_argument("--cache-dir", default=DEFAULT_CACHE)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except advisory.AdvisoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
