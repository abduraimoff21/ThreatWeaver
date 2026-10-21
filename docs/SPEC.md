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

- Extract IPs, domains, URLs, hashes (later also e-mail addresses and attachment file names; see the decisions below).
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
- Large inputs: files up to 1 GB are accepted by the dashboard (streamed to disk, ingested in chunks as a background job). Ingest memory is bounded; analysis memory is bounded by the number of distinct indicators, not by log size.
- A source's SHA-256 is now the hash of the file's raw bytes (line endings preserved), so it matches `Get-FileHash`.
- The link graph shows a selection, not everything: the highest-priority indicators, what they connect to (at most 500), and each indicator's strongest links. A big log has far more links than a screen can show.
- E-mail addresses and attachment file names are indicators (`email`, `filename`). The part before the "@" and file names are kept exactly as written; an address's domain is recorded as a derived indicator linked by `email_domain` (weight 3), except for public mailbox providers. File names are extracted only when the text labels them as files or when an executable is dressed as a document (`invoice.pdf.exe`, rule TW-T11, +25), because unlabelled names are far too common in ordinary logs.
- The dashboard saves the finished analysis next to the database (`<db>.analysis.gz`, gzip JSON, never pickle, written atomically) and loads it on the next start, so only the first view after new data is slow. It is keyed by a fingerprint of the analysis code, every source's id/name/kind/SHA-256 and a deletion counter, so any upload, removal or upgrade rebuilds it; a damaged file is ignored. Links keep only their evidence count in this copy (the report holds the capped evidence). Per-indicator counts are kept in `ioc_source_stats`, maintained while ingesting and when removing, and back-filled once for databases made by older versions, so triage, correlation and the report no longer re-scan every sighting; only the same-line pass streams them.
- MITRE ATT&CK hints (module I) were added on request: for each indicator the dashboard and report name the kinds of attack it could belong to, the ATT&CK tactics and techniques of those, and what to check next. They are possibilities, not findings, they do not change the triage score, and every one says what it rests on (public feed, what the indicator is, words in stored log lines, or volume alone). They come from fixed, named patterns; the ATT&CK names and identifiers are bundled in `attack_data.py` (Enterprise v20, read from attack.mitre.org, with MITRE's copyright notice and license) so nothing is fetched at run time. Only the first 20 stored log lines of an indicator are read, and an IPv4 address counts as the source of a line only if it is the first address on it.
- An uploaded file or pasted text can be removed from the dashboard (Overview and Sources pages). Removal is permanent and confirmed twice (the page asks; the server refuses a request that does not say it was confirmed), runs as a background job in batches, deletes the source's sightings and relations plus every indicator seen nowhere else, and keeps indicators that another source or a feed record still refers to. Feed snapshots cannot be removed this way. The correlation cache is cleared.
