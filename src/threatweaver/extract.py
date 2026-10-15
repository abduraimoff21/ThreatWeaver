"""Module A: IOC extraction with validation.

Pure text in, candidates out. No network, no database. Each candidate is
validated (octet ranges, label rules, TLD allowlist, hash length) so that
obvious false positives such as `999.1.1.1`, `report.pdf` or a 33-character
hex string never leave this module.

Pass order matters because later passes skip text already claimed by earlier
ones: URLs, hashes, IPv6, IPv4, domains. The one exception is hashes, which
are also extracted from inside URLs (e.g. a sandbox report link).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .defang import refang
from .models import HASH_LENGTHS, Candidate, IocType
from .tlds import AMBIGUOUS_TLDS, COMMON_SECOND_LEVELS, KNOWN_TLDS

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\\^{}|]+", re.IGNORECASE)
_HASH_RE = re.compile(r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![A-Za-z0-9])")
# A trailing ".word" or "-word" means the digits are part of a host name (62.99.164.82.isp.example.net,
# host-156.202.121.254-static.example.net), not an address. A range such as 10.0.0.1-10.0.0.5 is still two addresses.
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\w|-[A-Za-z])")
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{2,}(?:\.[0-9.]+)?(?![\w:])")
_DOMAIN_RE = re.compile(r"(?<![\w.\-/\\])[A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+(?![\w\-])")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

MAX_URL_NESTING = 3
_HEX_DIGITS =frozenset("0123456789abcdefABCDEF")
_TRAILING_PUNCT = ".,;:!?*"
_BRACKETS = {")": "(", "]": "["}


def valid_domain_syntax(name: str) -> bool:
    """Hostname label rules only (no TLD allowlist); the TLD must not be all digits."""
    name = name.lower().rstrip(".")
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    return len(labels) >= 2 and all(_LABEL_RE.match(label) for label in labels) and not labels[-1].isdigit()


def valid_domain(name: str, *, allow_ambiguous: bool = False) -> bool:
    name = name.lower().rstrip(".")
    if not valid_domain_syntax(name):
        return False
    tld = name.rsplit(".", 1)[-1]
    if tld.startswith("xn--"):
        return len(tld) > 4
    if tld in AMBIGUOUS_TLDS:
        # e.g. wsi.edu.pl: a registry-style second level makes a host name far likelier than a file name.
        labels = name.split(".")
        # Files are named like awstats.pl; host names have more labels (arx58.internetdsl.tpnet.pl).
        return allow_ambiguous or len(labels) >= 4 or (len(labels) >= 3 and labels[-2] in COMMON_SECOND_LEVELS)
    return tld in KNOWN_TLDS


def _trim_url(url: str) -> str:
    """Drop sentence punctuation and unbalanced closing brackets from the end."""
    while url:
        last = url[-1]
        if last in _TRAILING_PUNCT:
            url = url[:-1]
        elif last in _BRACKETS and url.count(last) > url.count(_BRACKETS[last]):
            url = url[:-1]
        else:
            break
    return url


def _url_host(url: str) -> tuple[IocType, str] | None:
    """Return the validated host of `url` as (type, host), or None if invalid."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port
    except ValueError:
        return None
    if not host:
        return None
    try:
        ipaddress.IPv4Address(host)
        return IocType.IPV4, host
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(host)
        return IocType.IPV6, host
    except ValueError:
        pass
    if valid_domain(host, allow_ambiguous=True):
        return IocType.DOMAIN, host
    return None


def _valid_hash(h: str) -> bool:
    # Reject placeholders (all one character) and pure-digit strings, which
    # are almost always numeric IDs rather than digests.
    return len(set(h.lower())) > 1 and not h.isdigit()


def extract(text: str) -> list[Candidate]:
    """Find all IOC candidates in `text`, in order of appearance."""
    rf = refang(text)
    t = rf.text
    claimed = bytearray(len(t))
    found: list[Candidate] = []

    def is_claimed(a: int, b: int) -> bool:
        return any(claimed[a:b])

    def make(kind: IocType, a: int, b: int, value: str | None = None, derived_from: Candidate | None = None) -> Candidate:
        oa, ob = rf.original_span(a, b)
        return Candidate(
            type=kind,
            value=value if value is not None else t[a:b],
            raw=text[oa:ob],
            start=oa,
            end=ob,
            defanged=rf.was_defanged(a, b),
            derived_from=derived_from,
        )

    # 1. URLs (and their host, recorded as a derived candidate). A URL can
    #    carry another URL in its query (redirects); those are extracted too.
    #    Nesting depth is capped so adversarial input cannot blow up the scan.
    pending = [(0, len(t), 0)]
    while pending:
        lo, hi, depth = pending.pop()
        for m in _URL_RE.finditer(t, lo, hi):
            url = _trim_url(m.group())
            host = _url_host(url)
            if host is None:
                continue
            a, b = m.start(), m.start() + len(url)
            cand = make(IocType.URL, a, b)
            found.append(cand)
            found.append(make(host[0], a, b, value=host[1], derived_from=cand))
            claimed[a:b] = b"\x01" * (b - a)
            if depth < MAX_URL_NESTING:
                pending.append((a + 1, b, depth + 1))

    # 2. Hashes (allowed inside URLs)
    for m in _HASH_RE.finditer(t):
        h = m.group()
        if _valid_hash(h):
            found.append(make(HASH_LENGTHS[len(h)], m.start(), m.end()))
            claimed[m.start() : m.end()] = b"\x01" * len(h)

    # 3. IPv6
    for m in _IPV6_RE.finditer(t):
        a, b = m.span()
        if is_claimed(a, b):
            continue
        if not any(ch in _HEX_DIGITS for ch in m.group()):
            continue  # a bare "::" is syntax, not an address
        try:
            ipaddress.IPv6Address(m.group())
        except ValueError:
            continue
        found.append(make(IocType.IPV6, a, b))
        claimed[a:b] = b"\x01" * (b - a)

    # 4. IPv4
    for m in _IPV4_RE.finditer(t):
        a, b = m.span()
        if is_claimed(a, b):
            continue
        try:
            ipaddress.IPv4Address(m.group())
        except ValueError:
            continue
        found.append(make(IocType.IPV4, a, b))
        claimed[a:b] = b"\x01" * (b - a)

    # 5. Domains
    for m in _DOMAIN_RE.finditer(t):
        a, b = m.span()
        if is_claimed(a, b):
            continue
        if valid_domain(m.group(), allow_ambiguous=rf.was_defanged(a, b)):
            found.append(make(IocType.DOMAIN, a, b))
            claimed[a:b] = b"\x01" * (b - a)

    found.sort(key=lambda c: (c.start, c.derived_from is not None))
    return found
