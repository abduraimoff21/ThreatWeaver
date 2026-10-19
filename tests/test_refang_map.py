"""The refang offset map must behave exactly like the original per-character version.

`ReferenceRefanged` below is the original implementation (two Python ints per character of
input). The production version stores only the rewritten segments, so memory no longer grows
with the size of the input. A randomized comparison proves the two answer identically.
"""

import random

import pytest

from threatweaver.defang import _DEFANGED, defang, refang


class ReferenceRefanged:
    def __init__(self, original):
        parts, starts, ends, changed = [], [], [], []
        out_len = 0
        pos = 0

        def keep(a, b):
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
        self.text = "".join(parts)
        self._starts, self._ends, self._changed = starts, ends, changed

    def original_span(self, start, end):
        return self._starts[start], self._ends[end - 1]

    def was_defanged(self, start, end):
        return any(a < end and start < b for a, b in self._changed)


TOKENS = [
    "[.]", "(.)", "{.}", "[dot]", "(DOT)", "{ dot }", "[ . ]", "hxxp", "hxxps", "HXXP", "://", ":", "[:]", "[://]",
    "[at]", "(at)", "[@]", "@", "a", "bc", "evil", "example", "com", ".", "-", " ", "\n", "\r\n", "é", "漢", "1.2.3.4",
    "203[.]0[.]113[.]9", "hxxps://bad[.]example[.]com/x", "[", "]", "(", ")", "{", "}",
]


def random_text(rng):
    return "".join(rng.choice(TOKENS) for _ in range(rng.randint(0, 40)))


def test_matches_the_original_implementation_on_random_input():
    rng = random.Random(20261015)
    compared = 0
    for _ in range(3000):
        text = random_text(rng)
        ref, new = ReferenceRefanged(text), refang(text)
        assert new.text == ref.text, repr(text)
        n = len(ref.text)
        if n == 0:
            continue
        for _ in range(12):
            start = rng.randrange(n)
            end = rng.randint(start + 1, n)
            assert new.original_span(start, end) == ref.original_span(start, end), (text, start, end)
            assert new.was_defanged(start, end) == ref.was_defanged(start, end), (text, start, end)
            compared += 1
        assert new.was_defanged(0, n) == ref.was_defanged(0, n)
    assert compared > 20000


@pytest.mark.parametrize("text", ["", "plain text", "[.]", "hxxp://a[.]b", "x[.]y[.]z[.]", "[at][at]", "a" * 1000 + "[.]" + "b" * 1000])
def test_edge_inputs_match(text):
    ref, new = ReferenceRefanged(text), refang(text)
    assert new.text == ref.text
    for start in range(0, len(ref.text), max(1, len(ref.text) // 7)):
        for end in range(start + 1, len(ref.text) + 1, max(1, len(ref.text) // 5)):
            assert new.original_span(start, end) == ref.original_span(start, end)
            assert new.was_defanged(start, end) == ref.was_defanged(start, end)


def test_memory_does_not_grow_with_input_size():
    """The map holds one entry per rewrite, not per character."""
    text = ("a" * 1000 + "[.]") * 2000  # 2 MB, 2000 rewrites
    r = refang(text)
    stored = sum(len(v) for v in vars(r).values() if isinstance(v, list))
    assert stored < 20_000  # the old version stored about 4 million integers here
    assert r.original_span(1000, 1001) == (1000, 1003)  # the rewritten "[.]" maps back to its 3 original chars
    assert r.original_span(1001, 1002) == (1003, 1004)  # text after the rewrite is shifted by 2


def test_defang_round_trip_still_holds():
    for value in ["203.0.113.9", "evil.example.com", "https://a.example.com/x?y=1", "2001:db8::1"]:
        assert refang(defang(value)).text == value
