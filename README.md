# ThreatWeaver

Local prototype to help CERT analysts automate repetitive investigative tasks. Spec: [docs/SPEC.md](docs/SPEC.md).

**Status: all modules A–H built.** Python standard library only; optional `pyyaml` (YAML Sigma rules), `yara-python` (YARA rules), `networkx` (graph export). No paid APIs.

## Safety

- Public or synthetic data only. Test fixtures use RFC 5737 / 3849 addresses and `example.*` domains.
- **Nothing blocks, quarantines or sends anything.** A test fails the build if the package imports anything that could. Triage output is a suggestion; even "high" says containment is a human decision.
- The only network access is `feeds fetch`, which you run yourself. It is HTTPS-only, size-capped, cached, and refuses to re-fetch inside each feed's rate limit.
- Advisories need a person: confidentiality check, a different reviewer, an interactive typed approval, hash-locked text. "Publish" writes local files only. See [Advisories](#advisories-module-h).

## Quick start

```bash
pip install -e ".[dev]"                          # or: PYTHONPATH=src
python -m pytest                                 # 182 tests (1 needs yara-python)
python -m threatweaver evaluate                  # extraction precision/recall
python -m threatweaver evaluate --scenario       # correlation, triage, traceability
python -m threatweaver run data/synthetic/scenario --db demo.db --out out   # full offline demo -> out/report.md
python -m threatweaver rules test data/synthetic/rules/*.suite.json
python -m threatweaver benchmark
```

Using real feeds (you run these; nothing happens automatically):

```bash
python -m threatweaver feeds fetch feodotracker --db case.db                # no key needed, CC0
URLHAUS_AUTH_KEY=<your free key> python -m threatweaver feeds fetch urlhaus --db case.db
python -m threatweaver ingest my-logs/*.log --db case.db
python -m threatweaver report --db case.db --out out
```

URLhaus requires a free abuse.ch Auth-Key (https://auth.abuse.ch/). It is read from the environment, put in the request URL only, and never written to the cache, the database or error messages. Please keep to the feeds' polling limits (5 min URLhaus, 15 min Feodo); the cache enforces that unless you pass `--force`. Check the feeds' terms before redistributing their data.

## Modules

| | Module | Where | What it does |
|--|--|--|--|
| A | Extraction | `defang.py`, `extract.py` | IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256, validated; refangs `hxxp`, `[.]`, `[at]`, ...; URL hosts and nested URLs also emitted; provenance points at the original text. |
| B | Normalize + dedup | `normalize.py`, `store.py` | Conservative canonical forms; SQLite with one row per indicator and one row per sighting (source, line, offsets, original text). Re-ingesting the same content is a no-op. |
| C | Feeds | `feeds/` | Exactly two: Feodo Tracker (C2 IPs) and URLhaus (malware URLs). Header-driven parsers, cached rate-limited fetcher, snapshot-level provenance, raw record kept. |
| D | Correlation | `correlate.py` | Four rules, each link names its rule and cites evidence rows: `url_host`, `same_line`, `hostname_ip`, `shared_family`. Feed matches: `exact` and `hosts_feed_url`. Only the newest snapshot of each feed counts. |
| E | Triage | `triage.py` | Nine named rules with points, reasons and evidence; levels high/medium/low/info; private addresses capped at info. |
| F | Report | `report.py` | JSON + Markdown from the same dict; indicators defanged in Markdown; `verify_traceability` re-reads every cited row. |
| G | Rule harness | `rules.py` | Sigma subset evaluator (pure Python) and YARA via `yara-python`; labeled positive/negative cases; refuses unsupported features instead of passing them. |
| H | Advisories | `advisory.py` | draft -> submitted -> approved -> published, with an append-only event log. |

## What is measured (and how far to trust it)

| Spec item | Result on the synthetic data | Caveat |
|--|--|--|
| Extraction precision / recall | 1.000 / 1.000 on 57 labeled IOCs in 9 documents | Corpus written by the extractor's author; a regression gate, not a generalisation estimate. |
| Dedup correctness | Spelling variants collapse; distinct URLs stay distinct (`tests/test_normalize.py`) | |
| Correlation precision | 1.000 (10/10 links, 0 false) and feed matches 6/6 | Labels were derived by hand from the rule definitions before running. This checks the code does what the rules say, **not** that the rules are right for real incidents. |
| Triage | 10/10 levels as labeled | Same caveat; thresholds are judgement calls, not calibrated. |
| Report traceability | 1.000 of 94 claims resolve to stored rows; tampering is detected | Proves the report cites real rows, not that the rows are true. |
| Time vs manual baseline | ~3 ms for 10 indicators | The manual side is an **assumed** 30 s per indicator per feed. Replace it with timed analyst runs before quoting any speed-up. Dataset is tiny. |

What none of this tells you: how it behaves on real logs and real feed snapshots. The first real run should be reviewed by an analyst against their own judgement, and any disagreement turned into a new labeled case.

## Advisories (module H)

```bash
python -m threatweaver advisory draft  --author alice --db case.db     # public feed evidence only
python -m threatweaver advisory submit 1 --actor alice --db case.db    # runs the confidentiality check
python -m threatweaver advisory approve 1 --reviewer bob --db case.db  # interactive terminal only
python -m threatweaver advisory publish 1 --actor carol --db case.db --out out/advisories
```

- The draft contains only indicators rated medium/high **with a public feed record** and a routable address, defanged. Local sightings, source file names and internal hosts are left out.
- Submit is refused while the text has private/loopback addresses, internal host names (`.local .internal .corp .lan ...`), e-mail addresses (except `example.*`), `confidential` / `TLP:AMBER` / `TLP:RED` markers, or `--deny` terms. There is no override; edit the text.
- Approval needs a reviewer different from the author, the content hash they were shown, and the typed phrase `APPROVE <id>`. Any edit voids approval. Publish re-checks the hash and the confidentiality rules.
- **Limits:** names are self-asserted (no login), and code could supply the phrase itself. The CLI prompt is the human gate; real separation of duties needs your process and access controls.

## Known limitations

Extraction: ASCII domains only; scheme-less URLs give only the domain; percent-encoded nested URLs are not decoded; version strings like `10.2.3.4` and hex-letter tokens like `Bad::Cafe` can false-positive; the TLD list is a bundled subset (feed loading skips it); `.py .sh .pl .md .rs .so .zip .mov .cc` domains need defanging or a URL context.

Feeds: the live fetch path was exercised only with fake responses; real network behaviour of URLhaus and Feodo has not been run from this repo. Parsers follow the documented layouts (Feodo JSON verified against a sample; URLhaus CSV columns from documentation and are header-driven). Feodo `hostname` is stored but not turned into a link. `shared_family` uses only Feodo's `malware` field because URLhaus tags are not reliable family names.

Correlation: `same_line` is co-occurrence, not causation; `hostname_ip` only fires when the IP the name spells out was also observed (a hostname encoding an unseen IP is not linked), covers dotted/dashed/zero-padded/12-digit forms in either octet order, and cites at most 10 sightings of the hostname plus the first of the IP; lines with more than 8 indicators are skipped; matching ignores older snapshots, so something that aged out of a feed's window stops matching.

Rules: the Sigma subset excludes aggregations, `near`, timeframes and most modifiers; the YARA adapter was only tested with a stub because `yara-python` has no wheel for this machine's Python.

## Layout

```
docs/SPEC.md             project spec and recorded decisions
src/threatweaver/        package (feeds/ subpackage for module C)
data/synthetic/          extraction corpus; scenario/ (logs + feed snapshots + labels); rules/ (Sigma/YARA suites)
tests/                   pytest suite
```
