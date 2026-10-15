"""Module B (part 1): canonical forms for IOCs.

`(type, value)` of the result is the dedup key, so two spellings of the same
indicator must collapse to the same string and two different indicators must
not. Normalization is conservative: it only applies rewrites that cannot change
what the indicator refers to (case of hosts, default ports, fragments, dot
segments, percent-encoding of unreserved characters). Query strings are never
reordered.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .extract import valid_domain
from .models import HASH_LENGTHS, Candidate, IocType, NormalizedIoc

_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _ip_attrs(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, str]:
    if ip.is_loopback:
        scope = "loopback"
    elif ip.is_link_local:
        scope = "link_local"
    elif ip.is_multicast:
        scope = "multicast"
    elif ip.is_unspecified:
        scope = "unspecified"
    elif ip.is_private:
        scope = "private"  # includes RFC 5737 / 3849 documentation ranges
    elif ip.is_global:
        scope = "global"
    else:
        scope = "reserved"
    return {"scope": scope}


def _normalize_ip(value: str) -> NormalizedIoc:
    ip = ipaddress.ip_address(value.split("%", 1)[0])  # drop IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    kind = IocType.IPV4 if ip.version == 4 else IocType.IPV6
    return NormalizedIoc(kind, str(ip), _ip_attrs(ip))


def _normalize_domain(value: str) -> str:
    name = value.strip().lower().rstrip(".")
    if not name.isascii():
        name = name.encode("idna").decode("ascii")
    if not valid_domain(name, allow_ambiguous=True):
        raise ValueError(f"not a valid domain: {value!r}")
    return name


def _normalize_pct(s: str) -> str:
    def fix(m: re.Match[str]) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()

    return _PCT_RE.sub(fix, s)


def _remove_dot_segments(path: str) -> str:
    out: list[str] = []
    segments = path.split("/")
    for i, seg in enumerate(segments):
        if seg == ".":
            if i == len(segments) - 1:
                out.append("")
        elif seg == "..":
            if len(out) > 1:
                out.pop()
            if i == len(segments) - 1:
                out.append("")
        else:
            out.append(seg)
    result = "/".join(out)
    return result if result.startswith("/") else "/" + result


def _normalize_url(value: str) -> NormalizedIoc:
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"unsupported URL scheme: {value!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"URL has no host: {value!r}")
    port = parts.port

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        host_n = _normalize_domain(host)
    else:
        host_n = str(ip) if ip.version == 4 else f"[{ip}]"

    netloc = host_n
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += ":" + parts.password
        netloc = f"{userinfo}@{netloc}"

    path = _remove_dot_segments(_normalize_pct(parts.path) or "/")
    url = f"{scheme}://{netloc}{path}"
    if parts.query:
        url += "?" + _normalize_pct(parts.query)
    # Fragments are never sent to the server, so they do not identify the resource.
    return NormalizedIoc(IocType.URL, url, {"host": host_n.strip("[]")})


def normalize_value(kind: IocType, value: str) -> NormalizedIoc:
    """Normalize a raw indicator of known type. Raises ValueError if invalid."""
    if kind in (IocType.IPV4, IocType.IPV6):
        result = _normalize_ip(value)
        # IPv4-mapped IPv6 (::ffff:a.b.c.d) is allowed to collapse to IPv4.
        if kind == IocType.IPV4 and result.type != IocType.IPV4:
            raise ValueError(f"not an IPv4 address: {value!r}")
        if kind == IocType.IPV6 and ":" not in value:
            raise ValueError(f"not an IPv6 address: {value!r}")
        return result
    if kind == IocType.DOMAIN:
        return NormalizedIoc(kind, _normalize_domain(value))
    if kind == IocType.URL:
        return _normalize_url(value)
    if kind in (IocType.MD5, IocType.SHA1, IocType.SHA256):
        h = value.strip().lower()
        if HASH_LENGTHS.get(len(h)) != kind or not re.fullmatch(r"[0-9a-f]+", h):
            raise ValueError(f"not a valid {kind.value}: {value!r}")
        return NormalizedIoc(kind, h)
    raise ValueError(f"unknown IOC type: {kind!r}")


def normalize(candidate: Candidate) -> NormalizedIoc | None:
    """Normalize an extracted candidate; None if it fails normalization."""
    try:
        return normalize_value(candidate.type, candidate.value)
    except ValueError:
        return None
