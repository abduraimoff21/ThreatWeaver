# ThreatWeaver

Local prototype for CERT analysts. Spec: `docs/SPEC.md` (scope and decisions). README has the design, measurements and limitations.

## Status

Modules A-H are built. Further work should be driven by real-data feedback, not new modules.

## Rules (non-negotiable)

- Public or synthetic data only. Fixtures use RFC 5737 / 3849 addresses and `example.*` domains.
- No automatic blocking, quarantining or outbound sending. Triage suggests; humans decide. `tests/test_pipeline.py::test_nothing_in_the_package_can_block_anything` greps for risky imports; keep it passing.
- Network access exists only in `feeds fetch` (`feeds/common.py`). Never add network calls elsewhere. Feeds are limited to two (URLhaus, Feodo Tracker); `feeds/__init__.py` asserts it.
- The URLhaus Auth-Key comes from `URLHAUS_AUTH_KEY` and must never be stored, logged or put in an error message.
- Advisories: no bypass of the confidentiality check, reviewer != author, hash-locked approval, interactive approval. Do not add an "auto-approve" or `--yes` path.
- Provenance must point at the original text, not the refanged text. Reports defang indicators in Markdown.
- Normalization is conservative: never reorder query strings or change path case.
- Standard library only in the core; yaml/yara/networkx stay optional and degrade to SKIPPED, never to a pass.

## Commands

```bash
python -m pytest                      # includes corpus, scenario, and traceability gates
python -m threatweaver evaluate [--scenario]
python -m threatweaver run data/synthetic/scenario --out out
```

When changing behaviour: add a unit test; if it is a realistic shape, add it to `data/synthetic/` with labels derived by hand BEFORE running the code. Do not edit labels to make a failing run pass without deciding which side is wrong.
