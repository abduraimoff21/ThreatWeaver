# ThreatWeaver

Local prototype to help CERT analysts automate repetitive investigative tasks. The full spec is in [docs/SPEC.md](docs/SPEC.md).

**Status: Milestone 1 — IOC extraction (module A) and normalization / de-duplication with provenance (module B).**
Offline only: no feeds, no enrichment, no network calls, no paid APIs. Standard library only.

## Safety

Public or synthetic data only. Nothing here blocks, changes or publishes anything; it reads text and writes a local SQLite file. Advisories (module H) will require human approval.

## Quick start

```bash
pip install -e ".[dev]"          # or just set PYTHONPATH=src
python -m pytest                 # unit tests + corpus quality gate
python -m threatweaver evaluate  # precision / recall on data/synthetic
python -m threatweaver extract data/synthetic/02-analyst-email.txt
python -m threatweaver ingest data/synthetic/*.txt data/synthetic/*.log --db demo.db
python -m threatweaver list --db demo.db --type domain
python -m threatweaver show domain evil-login.example.com --db demo.db
```

## What it does

| Step | Module | Behaviour |
|------|--------|-----------|
| Refang | `defang.py` | `hxxps://evil[.]example[.]com`, `[dot]`, `(.)`, `[@]`, `[at]`, `[:]` are undone before extraction; every character keeps a map back to the original text. |
| Extract | `extract.py` | IPv4, IPv6, domains, URLs, MD5/SHA-1/SHA-256, each validated (octet ranges, label rules, TLD allowlist, exact hash lengths, placeholder / all-digit hash rejection). The host of every URL is also emitted, marked as derived. URLs nested in a query string are extracted too (depth capped at 3). |
| Normalize | `normalize.py` | Lowercase hosts, trailing dot removed, IPv6 compressed, IPv4-mapped IPv6 collapsed to IPv4, default ports and fragments dropped, dot-segments resolved, percent-encoding canonicalised. Query strings and path case are **never** altered. IPs get a `scope` attribute (private / global / loopback ...). |
| Store | `store.py` | SQLite. `iocs` is unique on (type, value); `observations` keeps one row per sighting with source, line, character offsets and the original (possibly defanged) text; URL hosts link to their URL's observation. Re-ingesting identical content is a no-op. |
| Evaluate | `evaluate.py` | Precision / recall per type against `data/synthetic/labels.json`, plus throughput. |

## Measured so far

On the 9-document synthetic corpus (57 labeled IOCs, including a negatives document with file names, bad IPs, timestamps, MACs and near-miss hashes): precision 1.000, recall 1.000, no errors. Throughput is roughly 1.5–2 MB/s of text. Adversarial inputs (100k-long dot / colon / bracket runs, thousands of nested URLs) finish in well under a second.

**Read that number carefully.** The corpus is small and was written by the same author as the extractor, so it works as a regression gate, not as evidence of how the extractor generalises. Before relying on the numbers, add an independently labeled set of real-world-shaped logs and reports (still synthetic or public data).

## Known limitations

- ASCII only: Unicode / IDN domains written in native script are not extracted (punycode `xn--` is).
- Scheme-less URLs (`evil.com/a`) and protocol-relative `//evil.com/a` yield only the domain. Percent-encoded nested URLs are not decoded.
- Email addresses are not their own IOC type; only the domain part is extracted.
- Version strings that look like IPv4 (`10.2.3.4`) are extracted. Identifier-like tokens built from hex letters, e.g. `Bad::Cafe`, parse as IPv6 and are extracted.
- The TLD list in `tlds.py` is a bundled subset of the IANA root zone. TLDs that double as common file extensions (`.py .sh .pl .md .rs .so .zip .mov .cc`) are accepted only when defanged or when they are a URL host, so a bare `evil.sh` or Polish `.pl` domain in plain text is missed by design.
- No decoding of hashes in other forms (base64, `0x` prefixes), no SHA-512, no ssdeep / imphash.

## Layout

```
docs/SPEC.md             project spec (source of truth for scope)
src/threatweaver/        package
data/synthetic/          labeled synthetic documents (RFC 5737 / 3849 addresses, example.* domains)
tests/                   pytest suite
```

## Next

Milestone 2 (week 2): enrichment from at most two approved public feeds (module C). Not started.
