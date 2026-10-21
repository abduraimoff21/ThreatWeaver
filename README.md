# ThreatWeaver

**A local, offline-first assistant that automates the repetitive parts of a CERT investigation: pulling indicators out of messy text, de-duplicating them, enriching them from public threat intelligence, connecting the dots, and drafting a traceable report. A human makes every decision.**

ThreatWeaver is a research prototype. It reads logs and reports, finds IPs, domains, URLs, e-mail addresses, attachment names and file hashes, checks them against two public feeds, explains how indicators relate, suggests a priority with the rules that produced it, and writes a report in which every claim points back to the exact line it came from. It never blocks, quarantines or sends anything.

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
| **Extract** | IPv4, IPv6, domains, URLs, **e-mail addresses**, **attachment and download file names** and MD5 / SHA-1 / SHA-256 hashes from any text, with validation. Defanged indicators (`hxxps://evil[.]example[.]com`, `bob[@]example[.]org`, `[at]`, `[dot]`) are understood. |
| **Normalize and de-duplicate** | `EVIL.example.com`, `evil.example.com.` and `evil[.]example[.]com` become one indicator. Every sighting is kept with its source, line number and original text. |
| **Enrich** | Matches against two public feeds: [Feodo Tracker](https://feodotracker.abuse.ch/) (botnet C2 IPs) and [URLhaus](https://urlhaus.abuse.ch/) (malware URLs). |
| **Correlate** | Five transparent rules link related indicators into cases. Each link names its rule and cites its evidence. |
| **Triage** | Eleven readable rules produce a suggested level (high / medium / low / info) with the reasons and evidence behind it. |
| **MITRE ATT&CK hints** | For each indicator, the kinds of attack it could belong to, the ATT&CK tactics and techniques they use, and what to check next. Possibilities to check, not findings. |
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
| **Overview** | Counts, a priority chart, **what the activity could be (MITRE ATT&CK)**, **drag and drop log files** (or paste text) to add them, **download feeds** with one click, and see your sources, each with a **Remove** button. |
| **Cases** | Groups of connected indicators, highest priority first. Quiet single-indicator cases are hidden unless you ask. |
| **Indicators** | Search and filter by value, type, level, source or MITRE ATT&CK hint. Click a row for the full explanation, including what it could be and what to check next. |
| **Link graph** | An interactive picture of what is connected. **Scroll or pinch to zoom, drag the background to pan**, drag a node to move it, hover one to light up only what it connects to, and use *Find* and *Full screen*. Shape shows the type, colour shows the level, line style shows why two things are linked, and a faint circle groups a case (click its caption to open it). Filters choose the priority to start from, how many indicators to draw, which link types to show and how many links to draw per indicator. Click a node for details. |
| **Report** | The traceability check, the report preview, and downloads (Markdown and JSON). |
| **Advisories** | Draft from public evidence, run the confidentiality check, submit, review, approve and write the file, with the audit log. |
| **Sources** | Every file and feed snapshot with its SHA-256, and a **Remove** button for each upload. |

Clicking any indicator opens a panel with the suggested level, **each rule that fired with its points and reason**, the feed record, connected indicators, and **the actual log lines where it appeared**. Indicators are shown defanged; tick "Show exact values" for the originals.

Notes:

- **URLhaus key:** the Download button for URLhaus is disabled until `URLHAUS_AUTH_KEY` is set in the terminal that starts the dashboard. The key is never shown in the browser or stored by ThreatWeaver. **An environment variable lives only in the terminal where you set it**: a new terminal, or a restart from another one, starts without it, and the page then says the key is not set. Set it again in the terminal you start the dashboard from (the page shows the PowerShell steps, with the key typed hidden), or save it once for your Windows account with `setx URLHAUS_AUTH_KEY "your-key"` and open a new terminal (it is then kept as plain text in your user settings, so do not paste it into chats or tickets).
- **Removing an upload:** on the Overview and Sources pages, every file or pasted text you added has a **Remove** button. After you confirm, it deletes everything extracted from that source (all its sightings, and every indicator seen nowhere else) in the background with a progress bar. Indicators that another upload or a feed record still refers to are kept. Cases, the graph, the counts and reports update. The original file is not touched and can be added again. It needs the same exclusive access as an upload (other writes wait), and refuses feed snapshots. Removal is permanent, so the page asks first and the server refuses a request that does not say it was confirmed. Speed: about 840,000 sightings in 6 seconds on a test copy; a source with millions takes minutes. The database file does not get smaller by itself: the space is reused by later uploads, and `python -c "import sqlite3; sqlite3.connect('case.db').execute('VACUUM')"` (with the dashboard stopped, and free disk space about the size of the database) shrinks it. If the dashboard is closed in the middle of a removal, the source is still listed: remove it again to finish.
- **Feeds:** the Download / Update buttons ask for confirmation first, because they are the only thing that contacts the internet.
- **Port:** the default is 8765. If it is busy, the next free port is used (check the printed link). `--port` chooses one, `--no-browser` only prints the link, `--out` sets where approved advisories are written (default `out/advisories`).
- **Log lines:** the dashboard shows the log line around each sighting. Databases made by an older version are upgraded automatically, but their old sightings have no stored line until you re-ingest the file.
- **Big files (up to 1 GB each):** the browser streams the file to a temporary file on disk (it is never loaded into the page), then it is processed in the background with a progress bar and an estimate. You can keep browsing the data you already have. A file is added all at once, so its results appear only when it has finished. While one is processing, actions that write (feed downloads, advisory steps, pasted text) wait with a clear message. You need roughly three times the file size in free disk space (the temporary copy plus the growing database). Measured on one real SSH log repeated to 0.96 GiB: 4 s to upload, about 16 minutes to process, the server stayed under 80 MB of memory. Closing the dashboard while a file is processing discards that file's work (nothing partial is kept): upload it again.
- **Pasted text** is limited to 20 MB; use a file for anything bigger.
- **Very large result sets:** the Cases page shows 200 cases at a time and hides quiet single-indicator cases until you ask; use Indicators to search everything.

How the dashboard protects you (it handles text that attackers may have influenced, and your browser may have other pages open):

- It listens on `127.0.0.1` only and refuses to start on any other address.
- Every request needs the random per-run token. Requests with a foreign `Host` or `Origin` are refused, so another web page (including DNS-rebinding tricks) cannot drive it. No CORS headers are ever sent.
- A strict Content-Security-Policy allows scripts and styles only from the dashboard itself: no inline code, no framing, no outside connections.
- Uploads need the token and a matching Host and Origin like every other request, must be sent as `application/octet-stream`, are size-capped, go to a private temporary folder that is deleted afterwards, and are refused before anything is written if the disk is too full.
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

Ingesting identical content twice is a no-op. Changed content under the same name is stored as a new source. Files are read in chunks, so the command line handles any size with a small, fixed amount of memory and prints progress every 5% for files over 32 MB. The SHA-256 shown for a source is the file's own (it matches `Get-FileHash`).

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
| `email_domain` | 3 | An e-mail address and its domain. Not made for public mailbox providers (`gmail.com`, `outlook.com`, ...): the address is kept, but the provider is not recorded as a domain indicator, so unrelated addresses are not pulled into one case |
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
| TW-T10 | +10 / +25 / +30 | High-volume repeat activity: 100 / 1,000 / 10,000 or more sightings of an IP, domain or URL. Never reaches "high" on its own |
| TW-T11 | +25 | A file name that hides an executable behind a document extension (`invoice.pdf.exe`). On its own it reaches "medium": worth a look, not proof |

Levels: **high** at 50 or more, **medium** at 25, **low** at 10, otherwise **info**. The thresholds are judgement calls, not calibrated values.

### MITRE ATT&CK hints

Beside each triage level, the dashboard and the report say what kind of attack an indicator could belong to, which [MITRE ATT&CK](https://attack.mitre.org) tactics and techniques that kind of attack uses, and what an analyst could check next. These are **possibilities to check, not findings**: ThreatWeaver reads only feed listings, the shape of an indicator and a few stored log lines, so it can say where to look but not what happened. They do not change the triage score. Where they show: the **Overview** (what the whole data could be; click one to list its indicators), an **indicator's** details (why it was suggested, the techniques as links, *What to check next*), a **case** page, the **Indicators** list (a *Could be* column and filter), and a *MITRE ATT&CK view* in the report (Markdown and JSON).

Each suggestion says what it is based on, strongest first: **public feed** (Feodo Tracker or URLhaus lists it), **what the indicator is** (a disguised file name, an e-mail address tied to a risky domain), **words in stored log lines** (a scanner's name, failed-login messages, an exploit string) and **volume only** (the weakest: it only says the indicator is very busy).

| Id | Could be | Based on | Fires when | Techniques |
|----|----------|----------|------------|------------|
| `AT-01` | Botnet command-and-control server | public feed | Exact match in Feodo Tracker (any status) | `T1071` |
| `AT-02` | Link that serves malware | public feed | Exact match in URLhaus | `T1105`, `T1204.001`, `T1189` |
| `AT-03` | Server that hosts malware downloads | public feed | Host of a URL that URLhaus lists | `T1608.001`, `T1584`, `T1583` |
| `AT-04` | Program disguised as a document | what the indicator is | A file name that hides an executable behind a document extension | `T1036.007`, `T1204.002` |
| `AT-05` | E-mail with a disguised attachment | what the indicator is | That file name and an e-mail address on the same line (both get it) | `T1566.001`, `T1036.007`, `T1204.002` |
| `AT-06` | E-mail address tied to a risky domain | what the indicator is | An e-mail address whose domain is high risk | `T1566`, `T1583.001` |
| `AT-07` | Repeated failed logins | words in stored log lines | 3 or more of the stored lines hold failed-login messages (Failed password, Invalid user, authentication failure ...) | `T1110`, `T1110.001` |
| `AT-08` | Port or host scanner | words in stored log lines | The name of a network scanner (Nmap, masscan, zmap, zgrab) | `T1595.001`, `T1595.002` (inside the network: `T1046`) |
| `AT-09` | Web vulnerability scanner | words in stored log lines | The name of a web vulnerability scanner (Nikto, Nuclei, WPScan, Nessus, OpenVAS, Acunetix ...) | `T1595.002` (inside the network: `T1046`) |
| `AT-10` | File and directory guessing tool | words in stored log lines | The name of a directory-guessing tool (gobuster, dirbuster, ffuf, wfuzz ...) | `T1595.003` |
| `AT-11` | Password-guessing tool | words in stored log lines | The name of a password-guessing tool (Hydra, Patator, Ncrack, Medusa) | `T1110`, `T1110.001` |
| `AT-12` | SQL injection attempt | words in stored log lines | sqlmap, or typical SQL injection text (UNION SELECT, ' OR '1'='1, information_schema) | `T1190` (inside the network: `T1210`) |
| `AT-13` | Exploit string against a public service | words in stored log lines | Path traversal, /etc/passwd, a Log4Shell string or a Shellshock string | `T1190` (inside the network: `T1210`) |
| `AT-14` | Encoded or hidden PowerShell | words in stored log lines | PowerShell with an encoded command, FromBase64String, or a hidden window running a download | `T1059.001`, `T1027` |
| `AT-15` | Command that downloads a file | words in stored log lines | certutil -urlcache, bitsadmin /transfer, Invoke-WebRequest, Net.WebClient downloads, curl or wget piped into a shell | `T1105`, `T1059` |
| `AT-16` | System tool used to run remote content | words in stored log lines | mshta or regsvr32 loading a remote script | `T1218.005`, `T1218.010` |
| `AT-17` | Probing for files that are not there | words in stored log lines | 5 or more stored lines about missing files or directories (File does not exist, Directory index forbidden) | `T1595.003` |
| `AT-18` | Connection probes that never start a real session | words in stored log lines | 3 or more stored lines about dropped or malformed connections (Did not receive identification string ...) | `T1595` (inside the network: `T1046`) |
| `AT-19` | Very heavy repeat activity (volume only) | volume only (weakest) | 1,000 or more sightings (TW-T10 at 25 points or more) and no log text that explains them | `T1595`, `T1110`, `T1071`, `T1498`, `T1499` (inside the network: `T1046`, `T1110`, `T1071`, `T1498`, `T1499`) |

- **Malware families.** When a feed names a family ATT&CK also describes (Dridex, Emotet, IcedID, QakBot, TrickBot, Bazar; any spelling, such as Heodo or QuakBot), the page also offers *ATT&CK lists N techniques for Emotet*, grouped by tactic. That is everything ATT&CK records about the family in general, not what happened in your data.
- **Log lines.** At most the first 20 stored lines of each indicator are read (hashes are skipped), and some patterns need several of them. A line names several addresses, so for patterns about acting on others (scanning, guessing, exploiting) an IPv4 address only counts on lines where it comes **first**, the usual place for the source in firewall, flow and web logs. Log text is read to find the hints and is never copied into the report.
- **Private addresses.** An address in a private range that scans or exploits is already inside the network, so it gets the inside-the-network technique (for example Network Service Discovery instead of Active Scanning) and the page says so.
- **Data.** The names, identifiers and tactic membership come from `attack_data.py`: ATT&CK Enterprise v20, read from attack.mitre.org on 2026-10-21 (no descriptions are copied). ATT&CK changes: v20 splits Defense Evasion into *Stealth* and *Defense Impairment*, and the names above follow v20. To update, re-read the tactic pages and the software pages of the new version into `attack_data.py`; `tests/test_attack.py` checks that every technique a pattern or family uses exists. The dashboard makes no request to attack.mitre.org: a technique is a link that your browser opens when you click it.
- **Measured.** Reading the stored lines adds about 40 microseconds per indicator (0.3 s for the 6,900 indicators of two Loghub logs, where it flagged 1,327 indicators for repeated failed logins in the OpenSSH log).
- MITRE's notice: "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." ATT&CK does not enumerate every possible behaviour, and an attack can be present without being suggested here.

### Database tables

`sources` (every ingested file or feed snapshot, pinned by SHA-256) · `iocs` (unique type + value) · `observations` (each sighting with source, line, offsets, original text) · `ioc_source_stats` (sightings per indicator and source, kept up to date while ingesting so analysis does not re-read every sighting) · `meta` (a counter that changes on every removal) · `intel` (feed records with the raw record) · `relations` (URL to host, e-mail address to domain; removed together with their source) · `links` (correlation cache) · `advisories` and `advisory_events`.

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
python -m pytest                 # 545 tests (544 pass; 1 needs yara-python and is skipped without it)
python -m threatweaver evaluate  # extraction precision / recall
python -m threatweaver evaluate --scenario
```

| Measure | Result | How far to trust it |
|---------|--------|---------------------|
| Extraction precision / recall | 1.000 / 1.000 on 84 labeled indicators in 11 documents (including e-mail addresses, attachment names and look-alikes that must not match) | The corpus was written by the extractor's author, so it is a regression gate, not a generalisation estimate |
| Dedup correctness | Spelling variants collapse; distinct URLs stay distinct | Covered by unit tests |
| Correlation | 10 / 10 expected links, no false links; 6 / 6 feed matches | Labels were derived by hand from the rule definitions before running. This proves the code follows the rules, not that the rules fit real incidents |
| Triage | 10 / 10 levels as labeled | Same caveat; thresholds are not calibrated |
| Report traceability | 100% of claims resolve to stored rows; tampering is detected | Proves the report cites real rows, not that the rows are true |
| Time vs manual | About 3 ms for 10 indicators | The manual side is an **assumed** 30 s per indicator per feed, not a measurement. Replace it with timed analyst runs before quoting a speed-up |
| Large input | One real 73 MB SSH log repeated to 0.96 GiB (9.2 million lines, 7.76 million sightings, 1,603 distinct indicators): upload 4 s, ingest 16 min at about 70 MB of server memory, then analysis 43 s at 62 MB peak (an earlier version needed 132 s and 4.4 GB). 800,000 distinct indicators: ingest 51 s, analysis 54 s at about 2.5 GB | The 1 GB file is one log repeated, so it has few distinct indicators; memory in analysis grows with **distinct indicators** (about 3 KB each), not with log size. A log with millions of distinct IPs would need many GB |

Real-data check: on 6,000 lines of public Loghub logs (OpenSSH, Apache, Linux; 129 IPs and 38 host names), extraction matched an independent count and surfaced two bugs that were then fixed. No malware indicators exist in those logs, so triage correctly rated everything "info". These logs are not redistributed with the project.

What the numbers cannot tell you is how it behaves on your logs. Run it on a case, compare with an analyst's judgement, and turn each disagreement into a labeled test case.

## Known limitations

**Extraction**
- ASCII host names only; internationalised names in native script are not extracted (punycode `xn--` names are).
- Scheme-less URLs (`evil.com/a`) yield only the domain. Percent-encoded nested URLs are not decoded.
- Version strings that look like IPv4 (`10.2.3.4`) and hex-letter tokens such as `Bad::Cafe` can false-positive.
- The domain-suffix list is a bundled subset of the official one. Suffixes that double as file extensions (`.py .sh .pl .md .rs .so .zip .mov .cc`) are accepted in plain text only when the name has four or more labels (`arx58.internetdsl.tpnet.pl`) or a registry-style second level (`wsi.edu.pl`), or when defanged, or as a URL host. Short names such as `awstats.pl` stay rejected, which also means a short real name like `onet.pl` is missed in plain text.
- An IP address written inside a host name (`62.99.164.82.isp.example.net`, `host-156.202.121.254-static.example.net`) is extracted as the host name, not as a separate IP. The `hostname_ip` rule links the two when the IP also appears on its own.
- Hashes beyond MD5 / SHA-1 / SHA-256 are not recognised.
- **E-mail addresses** are ASCII only, with a domain that passes the same checks as any other. `lodash@4.17.21`, `logo@2x.png`, `root@localhost` and `git@github.com:org/repo` are deliberately not addresses. The part before the `@` is kept exactly as written (a mail system may treat it as case-sensitive); the domain is lower-cased. `user@host.example.com` from an ssh prompt looks like an address and is extracted as one.
- **File names** are extracted only where the text labels them as files (`filename=`, a MIME `name=`, `Attachment:`, `Attached file:`, `File name:`) or where an executable is dressed as a document (`invoice.pdf.exe`, `photo.jpg.scr`). A bare `setup.exe` in a sentence is not extracted, which keeps ordinary logs free of noise (none were found in 104 MB of real logs) but misses names that are mentioned without a label. Names with spaces are captured only inside quotes. Attachments are not linked to the e-mail they came with unless they are on the same line, because plain text carries no message boundaries.
- Binary files (pcap, `.evtx`, archives, PDFs) are not understood and yield nothing; convert them to text first.
- Ingest reads files in 4 MB chunks that end on a line boundary. A single "line" longer than 64 MB is split at whitespace, so an indicator could in principle be cut in half there.

**Feeds**
- Feodo Tracker was verified against the live feed. The URLhaus parser follows the documented layout and has been tested only on synthetic data.
- Feed listings are point-in-time and can be stale or wrong. Absence from a feed is not evidence of safety.
- Something that ages out of a feed's window stops matching, because only the newest snapshot counts.

**Correlation and triage**
- `same_line` is co-occurrence, not causation. `hostname_ip` relies on naming conventions and is a hint, not proof.
- `shared_family` uses only Feodo's `malware` field, because URLhaus tags are not reliable family names.

**Reports on large inputs**
- Each indicator in a report shows at most 20 sightings, 20 evidence references per rule or link, and 20 feed matches. The true totals are always stated, and the database keeps everything. Single indicators with no links and no triage rule fired are listed in one compact table instead of one section each.

**Triage**
- Volume (TW-T10) is the only signal that needs no feed, and it is deliberately weak: the tiers are absolute counts, not scaled to log size, so public DNS servers, CDNs, monitoring and anything noisy that you run will also score. It tops out at "medium" and says so in its reason. It does not read what the log line says, so 57,000 sightings of an IP could be failed logins or normal traffic.
- Thresholds and points are judgement calls, not calibrated values.

**Dashboard**
- Memory in the analysis step grows with the number of **distinct** indicators (about 3 KB each: 800,000 distinct indicators used about 2.5 GB). Logs with many millions of distinct IPs or domains will not fit on a small machine.
- One large file is processed at a time (others queue). There is no cancel button, and a processing file is lost if the dashboard is closed.
- The analysis (correlation, triage, report) is saved beside the database as `<name>.analysis.gz` and loaded again on the next start, so only the first view after new data is slow. The dashboard prepares it in the background when it starts and after an upload or removal finishes. Measured on a synthetic 4.19 million-sighting database: previously 2 to 2.5 minutes for the first view and again after every restart; now about 35 s the first time and about 2 s after a restart. The pass that looks for indicators on the same line still reads every sighting, so the first view after new data grows with log size (roughly 50 s is expected at 14 million sightings; not measured). A database made by an older version gets one extra pass the first time to fill in its per-indicator counts.
- The saved file is only a cache and is safe to delete (it is git-ignored). It is tied to the exact sources in the database and to the analysis code, so it is rebuilt automatically after an upload, a removal or an upgrade. It is plain compressed JSON; a damaged or unreadable file is ignored and the analysis is recomputed.
- Single-user and local: one shared token, no accounts. Reviewer and author names are typed by the person using it.
- The link graph is a **selection**, not everything. A big log has far more links than a screen can show (a test with 150 indicators had 8,086 links between them, which draws as a solid disc), so it starts from the highest-priority indicators, adds what they connect to (at most 500 indicators), and draws each indicator's strongest links (3 by default; the page says how many were left out). Every link is still listed in an indicator's detail panel (strongest 100). The layout is computed once per view (drag nodes to adjust; it does not animate live).
- A case page lists its 500 highest-scoring indicators; use the Indicators page to search the rest.
- Pages refresh when you press Refresh or take an action, not continuously.
- The Report page shows a preview of the first 600 lines; the download buttons give the whole report.
- Verified in the Claude desktop app's built-in browser (dark theme). The link graph (zoom, pan, hover, find, full screen, touch pinch) was also driven in desktop Chrome, light and dark; other browsers have not been visually checked.

**MITRE ATT&CK hints**
- They are possibilities, not findings, and not complete: a pattern is a few words or a feed listing, so an attack that does not use those words is not suggested, and a harmless tool (an authorised scanner, an administrator's PowerShell) can be.
- Only the first 20 stored lines of an indicator are read. An address that scans late in a long log, after 20 harmless lines, gets no log-based hint. An address is treated as the source only if it is the first address on the line; logs that put the destination first will point at the wrong side.
- Lines stored by an older version have no log text, so only the feed and indicator-shape hints appear until the file is added again.
- The Overview counts every indicator a hint was suggested for, so a log in which every address both scans and is scanned flags nearly all of them. The page lists the strongest evidence first.

**Rules harness**
- The Sigma evaluator supports a documented subset: selections, `contains` / `startswith` / `endswith` / `re` / `cidr` / `all`, wildcards, and `and` / `or` / `not` / `1 of` / `all of` conditions. Aggregations, `near`, timeframes and other modifiers are refused.
- The YARA adapter has only been tested against a stub on this project's development machine, because `yara-python` has no wheel for its Python version.

## Project layout

```
docs/SPEC.md             spec, milestones and recorded decisions
src/threatweaver/
  defang.py extract.py   A  extraction and refanging
  files.py               file-name helpers (extensions, "invoice.pdf.exe")
  normalize.py store.py  B  canonical forms, SQLite, de-duplication, provenance
  analysis_cache.py      saved analysis (<db>.analysis.gz) and the fingerprint that keeps it honest
  feeds/                 C  Feodo Tracker + URLhaus (parsers, fetcher, loader)
  correlate.py           D  correlation rules and cases
  triage.py              E  rule-based triage
  report.py              F  JSON / Markdown reports and traceability verifier
  attack.py              MITRE ATT&CK hints (patterns, what to check); attack_data.py is the generated ATT&CK reference data
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

- [MITRE ATT&CK®](https://attack.mitre.org/): tactic and technique names and identifiers (Enterprise v20), used under MITRE's license. "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/): botnet C2 IP blocklist (CC0).
- [abuse.ch URLhaus](https://urlhaus.abuse.ch/): malware URL feed; see abuse.ch's [terms of use](https://abuse.ch/terms-of-use/).
- [Loghub](https://github.com/logpai/loghub): public system log samples used for real-data checks during development (downloaded locally, not included in this repository).

## License

MIT. See [LICENSE](LICENSE).
