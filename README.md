# ThreatWeaver

**A local, offline-first assistant that automates the repetitive parts of a CERT investigation: pulling indicators out of messy text, de-duplicating them, enriching them from public threat intelligence, connecting the dots, and drafting a traceable report. A human makes every decision.**

ThreatWeaver is a research prototype. It reads logs and reports, finds IPs, domains, URLs and file hashes, checks them against two public feeds, explains how indicators relate, suggests a priority with the rules that produced it, and writes a report in which every claim points back to the exact line it came from. It never blocks, quarantines or sends anything.

- Python 3.11+, standard library only (optional extras listed below)
- Everything is stored in a single local SQLite file
- No paid or AI APIs, no accounts, no telemetry
- Full spec: [docs/SPEC.md](docs/SPEC.md)

---

## Contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Dashboard](#dashboard-no-commands-needed)
- [Usage guide](#usage-guide)
- [Reference](#reference)
- [Safety and data handling](#safety-and-data-handling)
- [Testing and measured results](#testing-and-measured-results)
- [Known limitations](#known-limitations)
- [Project layout](#project-layout)
- [Development](#development)
- [Data sources and acknowledgements](#data-sources-and-acknowledgements)

---

## What it does

| Step | You get |
|------|---------|
| **Extract** | IPv4, IPv6, domains, URLs and MD5 / SHA-1 / SHA-256 hashes from any text, with validation. Defanged indicators (`hxxps://evil[.]example[.]com`, `[at]`, `[dot]`) are understood. |
| **Normalize and de-duplicate** | `EVIL.example.com`, `evil.example.com.` and `evil[.]example[.]com` become one indicator. Every sighting is kept with its source, line number and original text. |
| **Enrich** | Matches against two public feeds: [Feodo Tracker](https://feodotracker.abuse.ch/) (botnet C2 IPs) and [URLhaus](https://urlhaus.abuse.ch/) (malware URLs). |
| **Correlate** | Four transparent rules link related indicators into cases. Each link names its rule and cites its evidence. |
| **Triage** | Nine readable rules produce a suggested level (high / medium / low / info) with the reasons and evidence behind it. |
| **Report** | Markdown and JSON investigation reports, defanged and fully traceable, with a built-in verifier. |
| **Test detection rules** | A harness that checks Sigma and YARA rules against labeled positive and negative samples. |
| **Publish advisories safely** | A review workflow with a confidentiality check, a separate reviewer and a typed approval, writing only local files. |

## How it works

```
 logs / reports / emails          Feodo Tracker        URLhaus
        |                              |                  |
        v                              +--------+---------+
  A  extract + validate                         v
        |                              C  feed snapshots (cached,
        v                                 rate-limited, hash-pinned)
  B  normalize + de-duplicate  <---------------+
        |          SQLite: iocs, observations, intel, relations, links
        v
  D  correlate --> E  triage --> F  report (Markdown + JSON, defanged, traceable)
                                          |
                  G  Sigma / YARA tests   v
                                  H  advisory draft -> human review -> local files
```

Design principles:

1. **Provenance first.** Nothing is merged away. Duplicates collapse into one indicator, but every sighting remains as evidence.
2. **No black boxes.** Correlation and triage are small named rules. There is no model and no hidden score.
3. **Suggest, never act.** Output is for an analyst. The package contains no blocking, quarantine or messaging code, and a test enforces it.
4. **Offline by default.** The only network call is `feeds fetch`, which you run yourself.

## Installation

Requirements: Python 3.11 or newer. No other packages are required.

```bash
git clone https://github.com/abduraimoff21/ThreatWeaver.git
cd ThreatWeaver
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1      macOS/Linux:  source .venv/bin/activate
pip install -e ".[dev]"
```

Without installing, you can run from the source tree: set `PYTHONPATH=src` (PowerShell: `$env:PYTHONPATH = "src"`) and use `python -m threatweaver`.

Optional extras:

| Package | Enables |
|---------|---------|
| `pyyaml` | YAML Sigma rule files (JSON rules work without it) |
| `yara-python` | Running YARA rules in the rule harness (without it, YARA suites are reported as SKIPPED) |
| `networkx` | `correlate.to_networkx()` graph export |

Check your setup:

```bash
python -m pytest
```

## Quick start

Everything below runs offline on bundled synthetic data. (Prefer a visual interface? Run `python -m threatweaver run data/synthetic/scenario --db demo.db --out out` once, then `python -m threatweaver ui --db demo.db`.)

```bash
# 1. Extract indicators from a document
python -m threatweaver extract data/synthetic/02-analyst-email.txt

# 2. Run the full pipeline on a synthetic incident (logs + feed snapshots) and write a report
python -m threatweaver run data/synthetic/scenario --db demo.db --out out

# 3. Read the report
#    out/report.md    human-readable, indicators defanged
#    out/report.json  machine-readable, exact values

# 4. Look at the triage verdicts and where an indicator came from
python -m threatweaver triage --db demo.db
python -m threatweaver show ipv4 203.0.113.45 --db demo.db
```

The synthetic data uses reserved documentation addresses (RFC 5737 / 3849) and `example.*` domains, so it is safe to share and experiment with.

## Dashboard (no commands needed)

Prefer clicking to typing? Start the local dashboard:

```bash
python -m threatweaver ui --db case.db
```

It prints a link like `http://127.0.0.1:8765/?token=...` and opens your browser. Open that exact link (it contains the access token). Press Ctrl+C in the terminal to stop it.

| Page | What you can do |
|------|-----------------|
| **Overview** | Counts, a priority chart, **drag and drop log files** (or paste text) to add them, **download feeds** with one click, and see your sources. |
| **Cases** | Groups of connected indicators, highest priority first. Quiet single-indicator cases are hidden unless you ask. |
| **Indicators** | Search and filter by value, type, level or source. Click a row for the full explanation. |
| **Link graph** | An interactive picture of what is connected. Shape shows the type, colour shows the level, line style shows why two things are linked. Click a node for details. |
| **Report** | The traceability check, the report preview, and downloads (Markdown and JSON). |
| **Advisories** | Draft from public evidence, run the confidentiality check, submit, review, approve and write the file, with the audit log. |
| **Sources** | Every file and feed snapshot with its SHA-256. |

Clicking any indicator opens a panel with the suggested level, **each rule that fired with its points and reason**, the feed record, connected indicators, and **the actual log lines where it appeared**. Indicators are shown defanged; tick "Show exact values" for the originals.

Notes:

- **URLhaus key:** the Download button for URLhaus is disabled until `URLHAUS_AUTH_KEY` is set in the terminal that starts the dashboard. The key is never shown in the browser or stored. Set it, then restart the dashboard.
- **Feeds:** the Download / Update buttons ask for confirmation first, because they are the only thing that contacts the internet.
- **Port:** the default is 8765. If it is busy, the next free port is used (check the printed link). `--port` chooses one, `--no-browser` only prints the link, `--out` sets where approved advisories are written (default `out/advisories`).
- **Log lines:** the dashboard shows the log line around each sighting. Databases made by an older version are upgraded automatically, but their old sightings have no stored line until you re-ingest the file.

How the dashboard protects you (it handles text that attackers may have influenced, and your browser may have other pages open):

- It listens on `127.0.0.1` only and refuses to start on any other address.
- Every request needs the random per-run token. Requests with a foreign `Host` or `Origin` are refused, so another web page (including DNS-rebinding tricks) cannot drive it. No CORS headers are ever sent.
- A strict Content-Security-Policy allows scripts and styles only from the dashboard itself: no inline code, no framing, no outside connections.
- Log and feed text is always inserted as plain text, never as HTML, and the page contains no code path that builds HTML from data. Tests enforce this.
- Everything stays on your machine. Treat the terminal link like a password while the dashboard runs.

## Usage guide

All commands accept `--db PATH` (default `threatweaver.db`). Run `python -m threatweaver <command> --help` for details.

### 1. Ingest your own data

```bash
python -m threatweaver ingest logs/proxy.log logs/dns.log reports/incident-123.txt --db case.db
python -m threatweaver list --db case.db --type domain           # unique indicators
python -m threatweaver show domain evil.example.com --db case.db # every sighting, with line numbers
```

Ingesting identical content twice is a no-op. Changed content under the same name is stored as a new source.

### 2. Add public threat intelligence

```bash
# Feodo Tracker: no key needed (CC0 data)
python -m threatweaver feeds fetch feodotracker --db case.db
```

URLhaus needs a free abuse.ch Auth-Key from https://auth.abuse.ch/ .

PowerShell:

```powershell
$env:URLHAUS_AUTH_KEY = "<your key>"
python -m threatweaver feeds fetch urlhaus --db case.db
```

macOS / Linux:

```bash
URLHAUS_AUTH_KEY=<your key> python -m threatweaver feeds fetch urlhaus --db case.db
```

- The key is read from the environment only. It is sent to abuse.ch in the request and is never written to the cache, the database, logs, error messages or git.
- Fetches are HTTPS-only, size-capped and cached in `.threatweaver-cache/`. Re-running inside a feed's polling limit (15 min for Feodo, 5 min for URLhaus) uses the cache. `--force` overrides this, so please be polite.
- Already have a snapshot file? `python -m threatweaver feeds load feodotracker feed.json --db case.db`.
- Only the newest snapshot of each feed is used for matching. Older snapshots stay in the database as history.

### 3. Correlate, triage and report

```bash
python -m threatweaver correlate --db case.db      # links and feed matches
python -m threatweaver triage --db case.db         # suggested levels with rule ids
python -m threatweaver report --db case.db --out out
```

`report` writes `out/report.md` and `out/report.json` and prints how many claims it verified against the database.

### 4. Test detection rules

```bash
python -m threatweaver rules test data/synthetic/rules/proxy_raw_ip_download.suite.json
```

A suite pairs a rule with labeled sample events. The harness reports true/false positives and negatives per case, and warns if a suite has no negative cases. Rules using unsupported features are reported as UNSUPPORTED, and missing optional backends as SKIPPED. Neither is ever shown as a pass.

### 5. Draft, review and publish an advisory

```bash
python -m threatweaver advisory draft   --author alice --db case.db   # public feed evidence only
python -m threatweaver advisory submit  1 --actor alice --db case.db  # runs the confidentiality check
python -m threatweaver advisory approve 1 --reviewer bob --db case.db # interactive terminal only
python -m threatweaver advisory publish 1 --actor carol --db case.db --out out/advisories
```

| Control | Behavior |
|---------|----------|
| Content | Drafts contain only medium/high indicators that have a public feed record and a routable address, defanged. Local sightings, file names, internal hosts and user names are left out. |
| Confidentiality check | Submission is refused while the text contains private/loopback addresses, internal host names (`.local .internal .corp .lan ...`), personal e-mail addresses, `confidential` / `TLP:AMBER` / `TLP:RED` markers, or any `--deny` term. There is no override: edit the text. |
| Approval | Needs a reviewer different from the author, the content hash they reviewed, and the typed phrase `APPROVE <id>`, typed at an interactive terminal or into the dashboard's approval box. Never a flag, never automatic. |
| Integrity | Any edit voids approval. Publishing re-checks the hash and re-runs the confidentiality check. Published advisories are immutable. |
| Audit | Every step is appended to an event log with the content hash. |
| Output | "Publish" writes `.md` and `.json` files locally. Nothing is sent anywhere. |

Names are self-asserted (there is no login), and a program holding the dashboard token or database could supply the approval phrase itself. The typed phrase is the human gate; real separation of duties needs your own process and access controls.

### Other commands

| Command | Purpose |
|---------|---------|
| `extract FILE [--json]` | Print normalized indicators without touching a database (`-` reads stdin) |
| `evaluate [--scenario]` | Precision / recall on the synthetic corpus, or correlation / triage / traceability on the scenario |
| `benchmark` | Processing time against an assumed manual baseline |

## Reference

### Correlation rules

| Rule | Weight | Meaning |
|------|:------:|---------|
| `url_host` | 3 | A URL and its host name or address |
| `same_line` | 2 | Two different indicators on the same line of the same source (skipped on lines with more than 8 indicators; overlapping text such as a hash inside a URL is ignored) |
| `hostname_ip` | 2 | A host name that spells out an IPv4 address (`192-0-2-7.isp.example.net`, `n192000002007...`, reversed octets), where that address was also observed |
| `shared_family` | 1 | Two indicators listed by a feed under the same malware family. Shown, but does not merge cases |

Indicators connected by links of weight 2 or more form a **case**. Feed matches are `exact` (the indicator itself is listed) or `hosts_feed_url` (the indicator hosts a listed URL).

### Triage rules

| Rule | Points | Fires when |
|------|:------:|------------|
| TW-T01 | +50 | Exact match in Feodo Tracker, listed online |
| TW-T02 | +45 | Exact match in URLhaus, listed online |
| TW-T03 | +25 | Exact match in a feed, not listed online |
| TW-T04 | +30 | Hosts a URL that a feed lists |
| TW-T05 | +10 | ...and that URL is online |
| TW-T06 | +10 | Seen in two or more local sources |
| TW-T07 | +10 | Defanged by an analyst in a source document |
| TW-T08 | +15 | Linked to an indicator that is high risk on its own merits |
| TW-T09 | cap | Private / loopback / link-local / multicast address: never above "info" |

Levels: **high** at 50 or more, **medium** at 25, **low** at 10, otherwise **info**. The thresholds are judgement calls, not calibrated values.

### Database tables

`sources` (every ingested file or feed snapshot, pinned by SHA-256) · `iocs` (unique type + value) · `observations` (each sighting with source, line, offsets, original text) · `intel` (feed records with the raw record) · `relations` (URL to host) · `links` (correlation cache) · `advisories` and `advisory_events`.

### Configuration

| Setting | Where | Purpose |
|---------|-------|---------|
| `URLHAUS_AUTH_KEY` | environment variable | abuse.ch Auth-Key for URLhaus |
| `--db PATH` | every command | SQLite file (default `threatweaver.db`) |
| `--cache-dir` | `feeds fetch` | Feed cache folder (default `.threatweaver-cache`) |
| `--deny TERM` | `advisory submit` / `publish` | Extra term that must not appear (repeatable) |

## Safety and data handling

- **Public or synthetic data.** Fixtures use documentation address ranges and `example.*` domains. If you run it on real logs, those logs and the resulting `.db` file stay on your machine. Treat the database as sensitive: it contains the text surrounding every indicator.
- **No automatic action.** Even a "high" verdict says containment is a human decision made through your normal change process.
- **Controlled network use.** `feeds fetch` (and the dashboard's confirmed Download buttons, which call it) is the only code path that touches the network, and it is limited to the two feeds. The dashboard itself listens on loopback only.
- **Credentials.** The only secret is the URLhaus key, handled as described above.
- **Reports are safe to paste.** Markdown output defangs every indicator. JSON keeps exact values for machines.
- **Respect feed terms.** Check the [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) and [abuse.ch](https://abuse.ch/terms-of-use/) terms before redistributing feed data.

## Testing and measured results

```bash
python -m pytest                 # 226 tests (225 pass; 1 needs yara-python and is skipped without it)
python -m threatweaver evaluate  # extraction precision / recall
python -m threatweaver evaluate --scenario
```

| Measure | Result | How far to trust it |
|---------|--------|---------------------|
| Extraction precision / recall | 1.000 / 1.000 on 61 labeled indicators in 10 documents | The corpus was written by the extractor's author, so it is a regression gate, not a generalisation estimate |
| Dedup correctness | Spelling variants collapse; distinct URLs stay distinct | Covered by unit tests |
| Correlation | 10 / 10 expected links, no false links; 6 / 6 feed matches | Labels were derived by hand from the rule definitions before running. This proves the code follows the rules, not that the rules fit real incidents |
| Triage | 10 / 10 levels as labeled | Same caveat; thresholds are not calibrated |
| Report traceability | 100% of claims resolve to stored rows; tampering is detected | Proves the report cites real rows, not that the rows are true |
| Time vs manual | About 3 ms for 10 indicators | The manual side is an **assumed** 30 s per indicator per feed, not a measurement. Replace it with timed analyst runs before quoting a speed-up |

Real-data check: on 6,000 lines of public Loghub logs (OpenSSH, Apache, Linux; 129 IPs and 38 host names), extraction matched an independent count and surfaced two bugs that were then fixed. No malware indicators exist in those logs, so triage correctly rated everything "info". These logs are not redistributed with the project.

What the numbers cannot tell you is how it behaves on your logs. Run it on a case, compare with an analyst's judgement, and turn each disagreement into a labeled test case.

## Known limitations

**Extraction**
- ASCII host names only; internationalised names in native script are not extracted (punycode `xn--` names are).
- Scheme-less URLs (`evil.com/a`) yield only the domain. Percent-encoded nested URLs are not decoded.
- Version strings that look like IPv4 (`10.2.3.4`) and hex-letter tokens such as `Bad::Cafe` can false-positive.
- The domain-suffix list is a bundled subset of the official one. Suffixes that double as file extensions (`.py .sh .pl .md .rs .so .zip .mov .cc`) are accepted in plain text only under registry-style names such as `edu.pl`, or when defanged, or as a URL host.
- Hashes beyond MD5 / SHA-1 / SHA-256 are not recognised.

**Feeds**
- Feodo Tracker was verified against the live feed. The URLhaus parser follows the documented layout and has been tested only on synthetic data.
- Feed listings are point-in-time and can be stale or wrong. Absence from a feed is not evidence of safety.
- Something that ages out of a feed's window stops matching, because only the newest snapshot counts.

**Correlation and triage**
- `same_line` is co-occurrence, not causation. `hostname_ip` relies on naming conventions and is a hint, not proof.
- `shared_family` uses only Feodo's `malware` field, because URLhaus tags are not reliable family names.

**Dashboard**
- Single-user and local: one shared token, no accounts. Reviewer and author names are typed by the person using it.
- The graph layout is computed once per view (drag nodes to adjust; it does not animate live), and the all-cases view shows at most the 300 highest-scoring linked indicators.
- Pages refresh when you press Refresh or take an action, not continuously.
- Verified in the Claude desktop app's built-in browser (dark theme); other browsers and the light theme have not been visually checked.

**Rules harness**
- The Sigma evaluator supports a documented subset: selections, `contains` / `startswith` / `endswith` / `re` / `cidr` / `all`, wildcards, and `and` / `or` / `not` / `1 of` / `all of` conditions. Aggregations, `near`, timeframes and other modifiers are refused.
- The YARA adapter has only been tested against a stub on this project's development machine, because `yara-python` has no wheel for its Python version.

## Project layout

```
docs/SPEC.md             spec, milestones and recorded decisions
src/threatweaver/
  defang.py extract.py   A  extraction and refanging
  normalize.py store.py  B  canonical forms, SQLite, de-duplication, provenance
  feeds/                 C  Feodo Tracker + URLhaus (parsers, fetcher, loader)
  correlate.py           D  correlation rules and cases
  triage.py              E  rule-based triage
  report.py              F  JSON / Markdown reports and traceability verifier
  rules.py               G  Sigma / YARA test harness
  advisory.py            H  advisory workflow
  web/                   local dashboard: api.py (data), server.py (security + HTTP), static/ (page)
  pipeline.py evaluate.py scenario_eval.py benchmark.py cli.py
data/synthetic/          labeled extraction corpus, scenario/ (logs + feed snapshots + labels), rules/
tests/                   pytest suite
```

## Development

- Add a unit test with every behavior change. For realistic shapes, add a document to `data/synthetic/` and write its expected labels **by hand before running the code**. If code and labels disagree, decide which side is wrong rather than editing whichever is convenient.
- The dashboard must keep rendering data as text only (no HTML string building), keep its Content-Security-Policy strict (no inline styles or scripts), and keep every API route behind the token.
- Keep the core standard-library only. Optional backends must degrade to SKIPPED, never to a pass.
- Do not add network calls outside `feeds/common.py`, an "auto-approve" path for advisories, or anything that acts on a system.
- See [CLAUDE.md](CLAUDE.md) for the working rules used when developing with an AI coding assistant.

## Data sources and acknowledgements

- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/): botnet C2 IP blocklist (CC0).
- [abuse.ch URLhaus](https://urlhaus.abuse.ch/): malware URL feed; see abuse.ch's [terms of use](https://abuse.ch/terms-of-use/).
- [Loghub](https://github.com/logpai/loghub): public system log samples used for real-data checks during development (downloaded locally, not included in this repository).

## License

No license has been chosen yet, so all rights are reserved by default. Add a `LICENSE` file before sharing or accepting contributions.
