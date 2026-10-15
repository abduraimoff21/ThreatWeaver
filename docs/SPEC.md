# ThreatWeaver — Project Spec

**Purpose:** Local prototype to help CERT analysts automate repetitive investigative tasks.

**Data sources:** Start with a couple of approved public threat intel feeds and synthetic logs.

## Modules

| ID | Module |
|----|--------|
| A | IOC extraction with validation |
| B | Normalization and de-duplication |
| C | Threat intel collection from at most two public feeds |
| D | Evidence correlation |
| E | Rule-based triage |
| F | Report generator |
| G | Sigma and YARA test harness (later) |
| H | Human-approved advisory publishing |

## Functional requirements

- Extract IPs, domains, URLs, hashes.
- Normalize them.
- Deduplicate with provenance.
- Enrich from public sources.
- Correlate evidence transparently.
- Apply simple triage rules.
- Generate investigation reports.

## Tech stack

Python, SQLite, optional NetworkX for graphs, Markdown and JSON reports. No paid AI APIs required.

## Testing

Measure:

- Extraction precision and recall
- Dedup correctness
- Correlation precision
- Report traceability
- Processing time versus manual baseline

## Plan

| Week | Focus |
|------|-------|
| 1 | Offline IOC work |
| 2 | Enrichment |
| 3 | Correlation and triage |
| 4 | Reports |

## Safety

- Use public or synthetic data only.
- No automatic blocking.
- No confidential disclosures.
- Human review required for advisories.

## Milestones

- **Milestone 1:** IOC extraction and normalization (modules A, B). Offline.
- **Milestone 2:** feeds (C: URLhaus and Feodo Tracker only), correlation (D), triage (E), reports (F).
- **Milestone 3:** Sigma and YARA test harness (G), human-approved advisory publishing (H), benchmark.

Decisions recorded while building:

- URLhaus bulk exports now require a free abuse.ch Auth-Key (environment variable `URLHAUS_AUTH_KEY`); Feodo Tracker needs none.
- Feed matching uses the newest snapshot of each feed; older snapshots are kept as history.
- "Publishing" an advisory writes local files only; a person must approve at an interactive terminal.
- A local dashboard (`threatweaver ui`) was added on request to replace command-line use. It is loopback-only, token-protected, and shows the same data and actions as the CLI; the human-approval rules for advisories are unchanged (typed phrase by a person, reviewer different from author).
- Observations now store the log line around each sighting (display only; not included in reports or advisories).
