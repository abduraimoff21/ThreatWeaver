"""Shared data types for IOC extraction and normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


HASH_LENGTHS = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}


@dataclass(frozen=True)
class Candidate:
    """An IOC as found in text, before normalization.

    `value` is the refanged text; `raw` is the exact slice of the original
    input (still defanged, if it was). `start`/`end` index the original input.
    A candidate with `derived_from` set was not written in the text on its own;
    it is the host part of a URL.
    """

    type: IocType
    value: str
    raw: str
    start: int
    end: int
    defanged: bool = False
    derived_from: Candidate | None = None


@dataclass(frozen=True)
class NormalizedIoc:
    """Canonical form of an IOC. (type, value) is the dedup key."""

    type: IocType
    value: str
    attrs: dict[str, str] = field(default_factory=dict, compare=False, hash=False)
