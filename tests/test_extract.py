import pytest

from threatweaver.extract import extract
from threatweaver.normalize import normalize


def found(text: str) -> set[tuple[str, str]]:
    out = set()
    for cand in extract(text):
        norm = normalize(cand)
        if norm:
            out.add((norm.type.value, norm.value))
    return out


@pytest.mark.parametrize(
    "text, expected",
    [
        ("from 192.0.2.1 to 198.51.100.2", {("ipv4", "192.0.2.1"), ("ipv4", "198.51.100.2")}),
        ("1.1.1.1-1.1.1.5 and 8.8.8.8:53", {("ipv4", "1.1.1.1"), ("ipv4", "1.1.1.5"), ("ipv4", "8.8.8.8")}),
        ("fe80::1%eth0 and ::1", {("ipv6", "fe80::1"), ("ipv6", "::1")}),
        ("Bob <bob@Example.COM>.", {("domain", "example.com")}),
        ("hash=D41D8CD98F00B204E9800998ECF8427E;x", {("md5", "d41d8cd98f00b204e9800998ecf8427e")}),
        ("xn--80ak6aa92e.com", {("domain", "xn--80ak6aa92e.com")}),
        ("evil.example.com/no/scheme", {("domain", "evil.example.com")}),
        # found on real sshd logs (Loghub): IP-prefixed reverse-DNS names and a .pl host
        ("from 62.99.164.82.sh.interxion.inode.at port 22", {("domain", "62.99.164.82.sh.interxion.inode.at")}),
        ("rhost=68.143.156.89.nw.nuvox.net user=root", {("domain", "68.143.156.89.nw.nuvox.net")}),
        ("host biblioteka.wsi.edu.pl closed", {("domain", "biblioteka.wsi.edu.pl")}),
        ("from 1.2.3.4. next", {("ipv4", "1.2.3.4")}),
        # found on the full Loghub datasets: IP-in-name followed by a hyphen word, and .pl hosts with 4+ labels
        ("from host-156.202.121.254-static.tedata.net ok", {("domain", "host-156.202.121.254-static.tedata.net")}),
        ("relay arx58.internetdsl.tpnet.pl closed", {("domain", "arx58.internetdsl.tpnet.pl")}),
        ("relay klik18.klik.bydgoszcz.pl closed", {("domain", "klik18.klik.bydgoszcz.pl")}),
        ("range 10.0.0.1-10.0.0.5", {("ipv4", "10.0.0.1"), ("ipv4", "10.0.0.5")}),
    ],
)
def test_positive_cases(text, expected):
    assert found(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "999.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "01.02.03.04",
        "12:30:45",
        "aa:bb:cc:dd:ee:ff",
        "std::string",
        "::",
        "report.pdf settings.json notes.md setup.py deploy.sh parser.pl main.rs lib.so",
        "a.b.py test.module.py",
        "awstats.pl webapp.pl proxycheck.pl textenv.pl",
        "libfoo.so.1 /usr/lib/libfoo.so",
        "C:\\temp\\evil.com",
        "server_01.local localhost",
        "0123456789abcdef0123456789abcde",  # 31 hex
        "0123456789abcdef0123456789abcdef0",  # 33 hex
        "00000000000000000000000000000000",  # placeholder
        "12345678901234567890123456789012",  # all digits
        "http://",
        "http://nothing",
        "http://999.1.1.1/x",
        "http://example.com:99999/x",
        "hxxp://",
    ],
)
def test_negative_cases(text):
    assert found(text) == set()


def test_nested_url_in_query_is_extracted():
    got = found("see http://a.example.com/x?u=http://b.example.net/y now")
    assert ("url", "http://a.example.com/x?u=http://b.example.net/y") in got
    assert ("url", "http://b.example.net/y") in got
    assert ("domain", "a.example.com") in got
    assert ("domain", "b.example.net") in got


def test_hash_inside_url_is_kept_and_host_is_derived():
    h = "0123456789abcdef0123456789abcdef01234567"
    got = found(f"https://sandbox.example.com/r/{h}/x")
    assert ("sha1", h) in got
    assert ("domain", "sandbox.example.com") in got


def test_ambiguous_tld_requires_defang_or_url_host():
    assert found("see setup.py") == set()
    assert ("domain", "evil.sh") in found("evil[.]sh")
    assert ("domain", "evil.sh") in found("http://evil.sh/a")


def test_provenance_points_at_original_text_not_refanged_text():
    text = "C2: hxxps://bad[.]example[.]com/x ok"
    cands = extract(text)
    url = next(c for c in cands if c.type == "url")
    assert url.raw == "hxxps://bad[.]example[.]com/x"
    assert text[url.start : url.end] == url.raw
    assert url.defanged
    host = next(c for c in cands if c.derived_from is url)
    assert host.value == "bad.example.com"


def test_plain_text_is_not_marked_defanged():
    (cand,) = extract("hit 192.0.2.1 here")
    assert not cand.defanged and cand.raw == "192.0.2.1"


@pytest.mark.parametrize(
    "hostile",
    [
        "http://a.example.com/?u=" * 5_000,
        "http://a.example.com/" * 20_000,
        "a." * 100_000,
        "ab:" * 100_000,
        "[.]" * 100_000,
    ],
    ids=["nested-url-query", "url-run", "dot-run", "colon-run", "defang-run"],
)
def test_hostile_input_terminates_quickly_without_crashing(hostile):
    import time

    start = time.perf_counter()
    extract(hostile)
    assert time.perf_counter() - start < 5
