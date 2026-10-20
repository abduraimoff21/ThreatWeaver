import pytest

from threatweaver.models import IocType
from threatweaver.normalize import normalize_value

# Each group: spellings that MUST collapse to the same normalized value.
SAME = [
    (IocType.DOMAIN, ["Evil.Example.COM", "evil.example.com.", " evil.example.com "]),
    (IocType.IPV4, ["203.0.113.45", "::ffff:203.0.113.45"]),
    (IocType.IPV6, ["2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "2001:DB8::1%eth0"]),
    (IocType.MD5, ["D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"]),
    (
        IocType.URL,
        [
            "http://Evil.Example.com/a",
            "HTTP://evil.example.com:80/a",
            "http://evil.example.com/a#frag",
            "http://evil.example.com/b/../a",
            "http://evil.example.com/./a",
        ],
    ),
    (IocType.URL, ["https://x.example.com", "https://x.example.com/", "https://x.example.com:443/"]),
    (IocType.URL, ["http://x.example.com/%7Euser", "http://x.example.com/~user"]),
    (IocType.URL, ["http://x.example.com/?q=%2f", "http://x.example.com/?q=%2F"]),
    (IocType.EMAIL, ["bob@example.org", "bob@Example.ORG", " bob@example.org ", "bob@example.org."]),
    (IocType.FILENAME, ["invoice.pdf.exe", " invoice.pdf.exe "]),
]

# Pairs that MUST stay distinct: normalization must not over-merge.
DIFFERENT = [
    (IocType.URL, "http://x.example.com/a", "http://x.example.com/A"),
    (IocType.URL, "http://x.example.com/a", "https://x.example.com/a"),
    (IocType.URL, "http://x.example.com/a", "http://x.example.com:8080/a"),
    (IocType.URL, "http://x.example.com/?a=1&b=2", "http://x.example.com/?b=2&a=1"),
    (IocType.URL, "http://x.example.com/a%2Fb", "http://x.example.com/a/b"),
    (IocType.URL, "http://u@x.example.com/", "http://x.example.com/"),
    (IocType.DOMAIN, "a.example.com", "example.com"),
    # the part before the "@" may be case-sensitive, so it is never rewritten
    (IocType.EMAIL, "bob@example.org", "Bob@example.org"),
    (IocType.EMAIL, "bob@example.org", "bob+tag@example.org"),
    (IocType.EMAIL, "bob@example.org", "bob@mail.example.org"),
    # whether a file name's case matters depends on the file system, so it is never rewritten
    (IocType.FILENAME, "Invoice.PDF.exe", "invoice.pdf.exe"),
]


@pytest.mark.parametrize("kind, spellings", SAME)
def test_equivalent_spellings_collapse(kind, spellings):
    assert len({normalize_value(kind, s).value for s in spellings}) == 1


@pytest.mark.parametrize("kind, a, b", DIFFERENT)
def test_distinct_indicators_stay_distinct(kind, a, b):
    assert normalize_value(kind, a).value != normalize_value(kind, b).value


def test_mapped_ipv6_collapses_to_ipv4_type():
    assert normalize_value(IocType.IPV6, "::ffff:192.0.2.77").type == IocType.IPV4


def test_ip_scope_attrs():
    assert normalize_value(IocType.IPV4, "127.0.0.1").attrs["scope"] == "loopback"
    assert normalize_value(IocType.IPV4, "10.1.2.3").attrs["scope"] == "private"
    assert normalize_value(IocType.IPV4, "8.8.8.8").attrs["scope"] == "global"


@pytest.mark.parametrize(
    "kind, bad",
    [
        (IocType.IPV4, "999.1.1.1"),
        (IocType.IPV4, "2001:db8::1"),
        (IocType.IPV6, "1.2.3.4"),
        (IocType.DOMAIN, "not_a_domain"),
        (IocType.DOMAIN, "foo.notatld"),
        (IocType.MD5, "d41d8cd98f00b204e9800998ecf8427"),
        (IocType.MD5, "z41d8cd98f00b204e9800998ecf8427e"),
        (IocType.SHA1, "d41d8cd98f00b204e9800998ecf8427e"),
        (IocType.URL, "gopher://x.example.com/"),
        (IocType.URL, "http:///nohost"),
        (IocType.URL, "http://x.example.com:notaport/"),
        (IocType.EMAIL, "not-an-email"),
        (IocType.EMAIL, "bob@localhost"),
        (IocType.EMAIL, "@example.org"),
        (IocType.EMAIL, "bob.@example.org"),
        (IocType.EMAIL, "b..ob@example.org"),
        (IocType.EMAIL, "bob smith@example.org"),
        (IocType.EMAIL, "bob@example.notatld"),
        (IocType.EMAIL, "x" * 65 + "@example.org"),
        (IocType.FILENAME, "noextension"),
        (IocType.FILENAME, "dir/invoice.pdf"),
        (IocType.FILENAME, "C:invoice.pdf"),
        (IocType.FILENAME, "what?.pdf"),
        (IocType.FILENAME, ".pdf"),
        (IocType.FILENAME, "a" * 256 + ".pdf"),
        (IocType.FILENAME, "tab\tname.pdf"),
        (IocType.FILENAME, ""),
    ],
)
def test_invalid_values_raise(kind, bad):
    with pytest.raises(ValueError):
        normalize_value(kind, bad)


def test_email_and_file_name_attributes():
    assert normalize_value(IocType.EMAIL, "Bob@Example.ORG").attrs == {"domain": "example.org"}
    plain = normalize_value(IocType.FILENAME, "report.pdf").attrs
    assert plain == {"extension": "pdf"}
    assert "disguised" in normalize_value(IocType.FILENAME, "report.pdf.exe").attrs
    assert "disguised" not in normalize_value(IocType.FILENAME, "setup.exe").attrs
    assert "disguised" not in normalize_value(IocType.FILENAME, "report.exe.pdf").attrs  # the real extension is a document
    assert "disguised" not in normalize_value(IocType.FILENAME, "pdf.exe").attrs  # nothing in front of the document extension
    assert "disguised" not in normalize_value(IocType.FILENAME, "setup.dll.exe").attrs  # two programs: not dressed as a document
    assert "disguised" in normalize_value(IocType.FILENAME, "REPORT.PDF.EXE").attrs  # extensions are compared without case


def test_normalization_is_idempotent():
    for kind, spellings in SAME:
        for s in spellings:
            once = normalize_value(kind, s)
            assert normalize_value(once.type, once.value).value == once.value
