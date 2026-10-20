# ThreatWeaver

Local prototype for CERT analysts. Spec: `docs/SPEC.md` (scope and decisions). README has the design, measurements and limitations.

## Status

Modules A-H are built, and the dashboard follows the six-stage intelligence cycle (Plan, Collect, Process, Analyse, Share, Feedback; `lifecycle.py`). Further work should be driven by real-data feedback, not new modules.

## Rules (non-negotiable)

- Public or synthetic data only. Fixtures use RFC 5737 / 3849 addresses and `example.*` domains.
- No automatic blocking, quarantining or outbound sending. Triage suggests; humans decide. `tests/test_pipeline.py::test_nothing_in_the_package_can_block_anything` greps for risky imports; keep it passing.
- Network access exists only in `feeds fetch` (`feeds/common.py`). Never add network calls elsewhere. Feeds are limited to two (URLhaus, Feodo Tracker); `feeds/__init__.py` asserts it.
- The URLhaus Auth-Key comes from `URLHAUS_AUTH_KEY` and must never be stored, logged or put in an error message.
- Advisories: no bypass of the confidentiality check, reviewer != author, hash-locked approval, a typed `APPROVE <id>` phrase entered by a person (terminal prompt or dashboard box). Do not add an "auto-approve" or `--yes` path, and never approve or publish an advisory on a user's behalf, including through the dashboard API.
- Dashboard (`web/`): loopback only, token on every API route, Host/Origin checks, strict CSP with no inline code or styles, and data rendered with textContent only (no innerHTML). Log text and feed fields are attacker-influenced. Never put the URLhaus key in any response.
- Scale: ingest reads files in chunks (never the whole file), and correlation, triage and the report must not hold every sighting in memory or do work proportional to cases x links. Memory may grow with distinct indicators, not with log size. `tests/test_analysis_scale.py` and `tests/test_streaming_ingest.py` enforce this; keep them passing and do not loosen their thresholds to make a change fit.
- The dashboard stays simple: stages in cycle order, plain words, one obvious next step (`/api/status`). Home, Plan, Collect and the Process summary must not start the analysis (`tests/test_lifecycle.py` enforces it). Feedback is advisory: it must never change a score or a rule by itself.
- Free text people type (plan, feedback notes) is data: stored as typed (control characters removed, one line), shown with textContent only, defanged when it goes into a report.
- Removing a source (`/api/sources/remove`) is destructive: keep it confirmed (`confirmed: true`), non-feed only, batched in a background job, behind `require_idle`, and never delete an indicator that another source, a feed record or a verdict still uses (`tests/test_remove_source.py`).
- Uploads (`/api/upload`) stream to disk and run as background jobs; keep them token-protected, size-capped, and drained on early refusal (`_drain`).
- Provenance must point at the original text, not the refanged text. Reports defang indicators in Markdown.
- Normalization is conservative: never reorder query strings or change path case, and never change the case of an e-mail address's local part or of a file name.
- File names are extracted only when labelled or disguised (`invoice.pdf.exe`); do not add bare-name extraction without checking it against real logs (none were found in 104 MB of Loghub logs, and that is the point).
- Standard library only in the core; yaml/yara/networkx stay optional and degrade to SKIPPED, never to a pass.

## Commands

```bash
python -m pytest                      # includes corpus, scenario, and traceability gates
python -m threatweaver evaluate [--scenario]
python -m threatweaver run data/synthetic/scenario --out out
```

When changing behaviour: add a unit test; if it is a realistic shape, add it to `data/synthetic/` with labels derived by hand BEFORE running the code. Do not edit labels to make a failing run pass without deciding which side is wrong.
