# ThreatWeaver

Local prototype for CERT analysts. Spec: `docs/SPEC.md` (scope and decisions). README has the design, measurements and limitations.

## Status

Modules A-H are built. Further work should be driven by real-data feedback, not new modules.

## Rules (non-negotiable)

- Public or synthetic data only. Fixtures use RFC 5737 / 3849 addresses and `example.*` domains.
- No automatic blocking, quarantining or outbound sending. Triage suggests; humans decide. `tests/test_pipeline.py::test_nothing_in_the_package_can_block_anything` greps for risky imports; keep it passing.
- Network access exists only in `feeds fetch` (`feeds/common.py`). Never add network calls elsewhere. Feeds are limited to two (URLhaus, Feodo Tracker); `feeds/__init__.py` asserts it.
- The URLhaus Auth-Key comes from `URLHAUS_AUTH_KEY` and must never be stored, logged or put in an error message.
- Advisories: no bypass of the confidentiality check, reviewer != author, hash-locked approval, a typed `APPROVE <id>` phrase entered by a person (terminal prompt or dashboard box). Do not add an "auto-approve" or `--yes` path, and never approve or publish an advisory on a user's behalf, including through the dashboard API.
- Dashboard (`web/`): loopback only, token on every API route, Host/Origin checks, strict CSP with no inline code or styles, and data rendered with textContent only (no innerHTML). Log text and feed fields are attacker-influenced. Never put the URLhaus key in any response.
- Scale: ingest reads files in chunks (never the whole file), and correlation, triage and the report must not hold every sighting in memory or do work proportional to cases x links. Memory may grow with distinct indicators, not with log size. `tests/test_analysis_scale.py` and `tests/test_streaming_ingest.py` enforce this; keep them passing and do not loosen their thresholds to make a change fit.
- The saved analysis (`analysis_cache.py`, `<db>.analysis.gz`) is a cache: JSON only (never pickle), written atomically, and a damaged file must be ignored, not trusted. Its fingerprint must keep covering the analysis code, every source (id, name, kind, SHA-256) and the deletion counter (`meta.epoch`); if you add a table or option that changes the result, include it. Keep `ioc_source_stats` maintained in ingest, removal and `store.ensure_stats`. Do not add a statement that reads every sighting except the same-line stream in `correlate.py`; `tests/test_analysis_persistence.py` enforces this.
- MITRE ATT&CK hints (`attack.py`, `attack_data.py`): possibilities to check, never findings, and they must not change a triage score. Every hint states its basis (feed, shape, log, volume). `attack_data.py` is generated from attack.mitre.org (identifiers, names, tactics only), keeps MITRE's copyright notice and license text, and is never fetched at run time; every technique a pattern uses must exist in it (`tests/test_attack.py` checks). Log text is read for hints but never copied into a report. Reading stored lines stays bounded (first `MAX_LINES` per indicator, cheap `needles` before any regex) and hashes are skipped. The page only links to https://attack.mitre.org/, and the Markdown report shows that address defanged.
- Removing a source (`/api/sources/remove`) is destructive: keep it confirmed (`confirmed: true`), non-feed only, batched in a background job, behind `require_idle`, and never delete an indicator that another source or a feed record still uses (`tests/test_remove_source.py`).
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
