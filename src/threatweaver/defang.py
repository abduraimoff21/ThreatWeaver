"""Refang defanged indicators while keeping a map back to the original text.

Analysts share IOCs as `hxxps://evil[.]example[.]com` so they are not
clickable. We undo that before extraction, but provenance must still point at
what was actually written, so every refanged character remembers the span of
original text it came from.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

_DEFANGED = re.compile(
    r"""
      (?P<scheme>\bhxxp(?P<s>s?)(?=\[:\]|:|\[://\]))
    | (?P<dot>\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\})
    | (?P<sep>\[://\])
    | (?P<colon>\[:\])
    | (?P<at>\[\s*at\s*\]|\(\s*at\s*\)|\[@\])
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class Refanged:
    """The refanged text plus a map back to the original.

    Only the rewritten segments are stored (one entry per `[.]`, `hxxp`, ...), not one entry per
    character, so memory does not grow with the size of the input. Outside a rewrite, a refanged
    character sits at a constant offset from its original position.
    """

    text: str
    _out_start: list[int]  # refanged-text start of each rewrite (sorted, disjoint)
    _out_end: list[int]
    _orig_start: list[int]  # the original text each rewrite replaced
    _orig_end: list[int]

    def _char(self, p: int) -> tuple[int, int]:
        """Original (start, end) of the single refanged character at index `p`."""
        i = bisect_right(self._out_start, p) - 1
        if i >= 0:
            if p < self._out_end[i]:
                return self._orig_start[i], self._orig_end[i]
            delta = self._orig_end[i] - self._out_end[i]
        else:
            delta = 0
        return p + delta, p + delta + 1

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a [start, end) span of `text` back to the original input."""
        return self._char(start)[0], self._char(end - 1)[1]

    def was_defanged(self, start: int, end: int) -> bool:
        """True if any part of [start, end) came from a rewrite."""
        i = bisect_right(self._out_start, end - 1) - 1
        return i >= 0 and self._out_end[i] > start


def refang(original: str) -> Refanged:
    parts: list[str] = []
    out_start: list[int] = []
    out_end: list[int] = []
    orig_start: list[int] = []
    orig_end: list[int] = []
    out_len = 0
    pos = 0

    for m in _DEFANGED.finditer(original):
        plain = original[pos:m.start()]
        parts.append(plain)
        out_len += len(plain)
        if m.group("scheme"):
            rep = "http" + m.group("s")
        elif m.group("dot"):
            rep = "."
        elif m.group("sep"):
            rep = "://"
        elif m.group("colon"):
            rep = ":"
        else:
            rep = "@"
        parts.append(rep)
        out_start.append(out_len)
        out_end.append(out_len + len(rep))
        orig_start.append(m.start())
        orig_end.append(m.end())
        out_len += len(rep)
        pos = m.end()
    parts.append(original[pos:])
    return Refanged("".join(parts), out_start, out_end, orig_start, orig_end)


def defang(value: str) -> str:
    """Make an indicator safe to paste into reports and chat (inverse of `refang`).

    `refang(defang(x)).text == x` for every normalized IOC value.
    """
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = {"http": "hxxp", "https": "hxxps"}.get(scheme.lower(), scheme)
        return f"{scheme}://{rest.replace('.', '[.]')}"
    if ":" in value:  # IPv6
        return value.replace(":", "[:]")
    return value.replace(".", "[.]")
