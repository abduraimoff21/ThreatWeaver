"""Module A: IOC extraction with validation.

Pure text in, candidates out. No network, no database. Each candidate is
validated (octet ranges, label rules, TLD allowlist, hash length) so that
obvious false positives such as `999.1.1.1`, `report.pdf` or a 33-character
hex string never leave this module.

Pass order matters because later passes skip text already claimed by earlier
ones: URLs, hashes, e-mail addresses, file names, IPv6, IPv4, domains. Hashes
are the exception: they are also extracted from inside URLs (a sandbox report
link) and from inside file names (`<md5>.exe`).

E-mail addresses are found by walking out from each "@". Their domain is also
recorded, as a derived candidate (like the host of a URL), except for public
mailbox providers. File names are only extracted where the text labels them as
files (`filename=`, `Attachment:`, a MIME `name=`) or where an executable
hides behind a document extension (`invoice.pdf.exe`); see files.py.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from .defang import refang
from .files import DOCUMENT_EXTENSIONS, EXECUTABLE_EXTENSIONS, MAX_FILENAME, disguised_executable, valid_filename
from .models import HASH_LENGTHS, Candidate, IocType
from .tlds import AMBIGUOUS_TLDS, COMMON_SECOND_LEVELS, FREE_MAIL_DOMAINS, KNOWN_TLDS

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

# --- e-mail addresses ------------------------------------------------------------------------------
_LOCAL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-")
_EMAIL_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+")
MAX_LOCAL_PART = 64
MAX_HOST = 253

# --- file names --------------------------------------------------------------------------------------
# A name counts as a file when the text says so: Content-Disposition `filename=`, a MIME `name=`, or a label
# such as `Attachment:` / `File name:`. Only the "attach" labels may be followed by a comma-separated list.
_FILE_MARKER = re.compile(
    r"filename\*?\s*=\s*"
    r"|content-type\s*:[^\r\n]{0,200}?;\s*name\*?\s*=\s*"
    r"|\b(?P<attach>attachments?|attached(?:\s+file)?)\s*[:=]\s*"
    r"|\bfile\s?name\s*[:=]\s*",
    re.IGNORECASE,
)
# Where a label can start, found with plain substring search (a regex scan of every position costs more than all the
# other passes together on ordinary logs). Each word is part of a label; the number is how far before it the label starts.
_FILE_KEYWORDS = (("ilename", 1), ("ttach", 1), ("ile name", 1), ("content-type", 0))
_QUOTED_NAME = re.compile(r"\"([^\"\r\n]{1,255})\"|'([^'\r\n]{1,255})'")
_BARE_NAME = re.compile(r"[^ \t\r\n\"'<>|;,]{1,256}")  # one longer than allowed, so an over-long token is refused rather than cut
MAX_RFC2231 = 600  # a percent-encoded name with its charset prefix is longer than the name it spells
_RFC2231_NAME = re.compile(r"[^ \t\r\n\"<>|;,]{1,601}")
_LIST_SEP = re.compile(r"[ \t]*[,;][ \t]*")
_RFC2231 = re.compile(r"^[A-Za-z0-9\-]*'[A-Za-z\-]*'")
_DISGUISED_RE = re.compile(
    r"\.(?:" + "|".join(sorted(DOCUMENT_EXTENSIONS)) + r")\.(?:" + "|".join(sorted(EXECUTABLE_EXTENSIONS)) + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.()~+&#$%!@")
_NAME_TRAILING = ".,;:!?)]}>"


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


def _email_at(t: str, at: int) -> tuple[int, int, int] | None:
    """The e-mail address around the "@" at index `at` of `t`, as (start, end, domain_start), or None.

    Practical rather than complete RFC 5322: an ASCII local part of at most 64 characters, then a domain that
    passes the same checks as any other domain. `lodash@4.17.21`, `logo@2x.png`, `root@localhost` and the scp
    form `git@github.com:org/repo` are not addresses.
    """
    start = at
    while start > 0 and at - start <= MAX_LOCAL_PART and t[start - 1] in _LOCAL_CHARS:
        start -= 1
    if at - start > MAX_LOCAL_PART or (start > 0 and t[start - 1].isalnum()):
        return None  # too long, or it starts with a letter outside ASCII
    while start < at and t[start] in ".-+%":
        start += 1  # a local part starts with a letter, digit or underscore
    local = t[start:at]
    if not local or local.endswith(".") or ".." in local:
        return None
    m = _EMAIL_HOST_RE.match(t, at + 1, min(len(t), at + 2 + MAX_HOST))
    if m is None:
        return None
    end = m.end()
    after = t[end:end + 1]
    if after and (after.isalnum() or after in "_-"):
        return None  # the domain runs on into something that is not a domain
    if after == ":" and t[end + 1:end + 2] and (t[end + 1].isalpha() or t[end + 1] in "/~._"):
        return None  # user@host:path (scp / git remotes)
    if not valid_domain(t[at + 1:end], allow_ambiguous=True):
        return None
    return start, end, at + 1


def _file_markers(t: str) -> list[re.Match[str]]:
    """Every file-name label in `t`, in order. Cost is proportional to the number of keyword hits, not to the text."""
    lowered = t.lower()
    if len(lowered) != len(t):  # a few characters change length when lower-cased; fall back to scanning
        return list(_FILE_MARKER.finditer(t))
    starts: set[int] = set()
    for word, back in _FILE_KEYWORDS:
        i = lowered.find(word)
        while i != -1:
            starts.add(max(0, i - back))
            i = lowered.find(word, i + 1)
    found = []
    for pos in sorted(starts):
        m = _FILE_MARKER.match(t, pos)
        if m is not None:
            found.append(m)
    return found


def _read_name(t: str, p: int, rfc2231: bool = False) -> tuple[int, int] | None:
    """The file-name token at `p`: the inside of a quoted string, or a bare run up to whitespace or a delimiter.
    An RFC 2231 value (`filename*=UTF-8''name`) legitimately contains apostrophes."""
    m = _QUOTED_NAME.match(t, p)
    if m is not None:
        group = 1 if m.group(1) is not None else 2
        return m.start(group), m.end(group)
    m = (_RFC2231_NAME if rfc2231 else _BARE_NAME).match(t, p)
    if m is None or m.end() - p > (MAX_RFC2231 if rfc2231 else MAX_FILENAME):
        return None
    e = m.end()
    while e > p and t[e - 1] in _NAME_TRAILING:
        e -= 1  # sentence punctuation after the name
    return (p, e) if e > p else None


def _file_name(t: str, a: int, b: int, rfc2231: bool) -> tuple[int, int, str] | None:
    """Turn the token t[a:b] into (start, end, name): the basename of a path, with an RFC 2231 prefix removed."""
    token = t[a:b]
    if rfc2231 and _RFC2231.match(token):
        name = unquote(token.split("'", 2)[2])
        name = name[max(name.rfind("/"), name.rfind("\\")) + 1:]
        return (a, b, name) if valid_filename(name) else None
    cut = max(token.rfind("/"), token.rfind("\\")) + 1
    name = token[cut:]
    return (a + cut, b, name) if valid_filename(name) and not valid_domain(name) else None


def extract(text: str) -> list[Candidate]:
    """Find all IOC candidates in `text`, in order of appearance."""
    rf = refang(text)
    t = rf.text
    # 0 = free, 1 = claimed by a URL, e-mail or file name, 2 = claimed by a hash. Hashes may sit inside
    # URLs and file names, and the other way round, so only "1" blocks those passes.
    claimed = bytearray(len(t))
    found: list[Candidate] = []

    def is_claimed(a: int, b: int) -> bool:
        return any(claimed[a:b])

    def blocked(a: int, b: int) -> bool:
        return 1 in claimed[a:b]

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
            claimed[m.start() : m.end()] = b"\x02" * len(h)

    # 2b. E-mail addresses, found by walking out from each "@". The domain part is a derived candidate, like
    #     the host of a URL, unless it is a public mailbox provider (see FREE_MAIL_DOMAINS).
    at = t.find("@")
    while at != -1:
        span = _email_at(t, at)
        if span is not None and not blocked(span[0], span[1]):
            a, b, host_at = span
            email = make(IocType.EMAIL, a, b)
            found.append(email)
            if t[host_at:b].lower() not in FREE_MAIL_DOMAINS:
                found.append(make(IocType.DOMAIN, host_at, b, derived_from=email))
            claimed[a:b] = b"\x01" * (b - a)
        at = t.find("@", at + 1)

    # 2c. File names: the ones the text labels as files, then executables dressed as documents.
    for m in _file_markers(t):
        p = m.end()
        while True:  # "Attachments: a.pdf, b.docx" is a list; every other label names one file
            token = _read_name(t, p, rfc2231="*" in m.group())
            if token is None:
                break
            name = _file_name(t, token[0], token[1], rfc2231="*" in m.group())
            if name is None:
                break
            if not blocked(name[0], name[1]):
                found.append(make(IocType.FILENAME, name[0], name[1], value=name[2]))
                claimed[name[0]:name[1]] = b"\x01" * (name[1] - name[0])
            sep = _LIST_SEP.match(t, token[1] + (1 if t[p] in "\"'" else 0)) if m.group("attach") else None
            if sep is None:
                break
            p = sep.end()
    for m in _DISGUISED_RE.finditer(t):
        end = m.end()
        start = m.start()
        while start > 0 and m.start() - start < MAX_FILENAME and t[start - 1] in _NAME_CHARS and claimed[start - 1] != 1:
            start -= 1
        while start < m.start() and t[start] in ".-":
            start += 1
        name = t[start:end]
        if disguised_executable(name) and valid_filename(name) and not blocked(start, end):
            found.append(make(IocType.FILENAME, start, end))
            claimed[start:end] = b"\x01" * (end - start)

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
