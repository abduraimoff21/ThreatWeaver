"""Refang defanged indicators while keeping a map back to the original text.

Analysts share IOCs as `hxxps://evil[.]example[.]com` so they are not
clickable. We undo that before extraction, but provenance must still point at
what was actually written, so every refanged character remembers the span of
original text it came from.
"""

from __future__ import annotations

import re
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
    text: str
    _starts: list[int]  # original start offset of each refanged character
    _ends: list[int]  # original end offset (exclusive) of each refanged character
    _changed: list[tuple[int, int]]  # refanged-text intervals produced by a rewrite

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a [start, end) span of `text` back to the original input."""
        return self._starts[start], self._ends[end - 1]

    def was_defanged(self, start: int, end: int) -> bool:
        return any(a < end and start < b for a, b in self._changed)


def refang(original: str) -> Refanged:
    parts: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    changed: list[tuple[int, int]] = []
    out_len = 0
    pos = 0

    def keep(a: int, b: int) -> None:
        nonlocal out_len
        parts.append(original[a:b])
        starts.extend(range(a, b))
        ends.extend(range(a + 1, b + 1))
        out_len += b - a

    for m in _DEFANGED.finditer(original):
        keep(pos, m.start())
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
        starts.extend([m.start()] * len(rep))
        ends.extend([m.end()] * len(rep))
        changed.append((out_len, out_len + len(rep)))
        out_len += len(rep)
        pos = m.end()
    keep(pos, len(original))
    return Refanged("".join(parts), starts, ends, changed)
