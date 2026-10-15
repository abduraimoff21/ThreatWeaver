# ThreatWeaver

Local prototype for CERT analysts. Spec: `docs/SPEC.md` (scope source of truth). README has the design and limitations.

## Current scope

Milestone 1 only: IOC extraction (A) and normalization/dedup (B). Do not add feeds, enrichment, correlation, triage or reporting until the user starts the next milestone.

## Rules

- Public or synthetic data only. Use RFC 5737 / 3849 addresses and `example.*` domains in fixtures.
- No automatic blocking or outbound actions. No network access in Milestone 1.
- Standard library only (NetworkX is optional and for later milestones).
- Provenance must always point at the original text, not the refanged text.
- Normalization must be conservative: never reorder query strings or change path case.

## Commands

```bash
python -m pytest                 # tests; includes the corpus precision/recall gate
python -m threatweaver evaluate  # per-type precision/recall
```

When changing extraction, add a case to `tests/` and, if it is a realistic document shape, to `data/synthetic/` with its `labels.json` entry (labels are the normalized values).
