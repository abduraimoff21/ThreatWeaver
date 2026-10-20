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
        ("Bob <bob@Example.COM>.", {("email", "bob@example.com"), ("domain", "example.com")}),
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


# ---------------------------------------------------------------------------------- e-mail addresses
@pytest.mark.parametrize(
    "text, expected",
    [
        ("From: Mallory <mallory@evil.example.com>", {("email", "mallory@evil.example.com"), ("domain", "evil.example.com")}),
        # the domain is lower-cased, the part before the @ is kept as written
        ("Mallory.Smith+tag@Evil.Example.COM", {("email", "Mallory.Smith+tag@evil.example.com"), ("domain", "evil.example.com")}),
        # defanged in every common way
        ("bob[@]example[.]org", {("email", "bob@example.org"), ("domain", "example.org")}),
        ("bob[at]example[.]org and carol(at)example(dot)net", {("email", "bob@example.org"), ("domain", "example.org"),
                                                                 ("email", "carol@example.net"), ("domain", "example.net")}),
        ("mailto:help@desk.example.org?subject=x", {("email", "help@desk.example.org"), ("domain", "desk.example.org")}),
        ("to=<user@mail.example.com>, relay=x", {("email", "user@mail.example.com"), ("domain", "mail.example.com")}),
        ("sent to a.b-c_d@sub.example.co.uk.", {("email", "a.b-c_d@sub.example.co.uk"), ("domain", "sub.example.co.uk")}),
        # an ambiguous TLD is fine after an "@": a file name never follows one
        ("ceo@payments.example.zip", {("email", "ceo@payments.example.zip"), ("domain", "payments.example.zip")}),
        # a public mailbox provider: the address is kept, the provider is not turned into a domain indicator
        ("scammer@gmail.com", {("email", "scammer@gmail.com")}),
        ("SCAMMER@GMAIL.COM", {("email", "SCAMMER@gmail.com")}),
        # an ssh-style user@host:22 is still an address-shaped token
        ("ssh admin@jump.example.com:22", {("email", "admin@jump.example.com"), ("domain", "jump.example.com")}),
    ],
)
def test_email_addresses(text, expected):
    assert found(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("lodash@4.17.21 react@18.2.0", set()),  # package versions
        ("the icon logo@2x.png and sprite@3x.jpg", set()),  # retina image names
        ("root@localhost admin@server_01 user@host", set()),  # no domain
        ("a@b", set()),
        (".bob@example.org", {("email", "bob@example.org"), ("domain", "example.org")}),  # a leading dot is not part of the name
        ("bob.@example.org", {("domain", "example.org")}),  # but a trailing one makes it invalid
        ("bo..b@example.org", {("domain", "example.org")}),
        ("@example.org", {("domain", "example.org")}),  # no local part
        ("bob@example.org-evil", set()),  # the domain runs on into something else
        ("http://user:pass@files.example.com:8443/x", {("url", "http://user:pass@files.example.com:8443/x"), ("domain", "files.example.com")}),
        ("git clone git@github.com:org/repo.git", {("domain", "github.com")}),  # scp-style remote, not an address
        ("x" * 65 + "@example.org", {("domain", "example.org")}),  # local part longer than 64
        ("bob@999.1.1.1", set()),
        ("éric@example.org", {("domain", "example.org")}),  # a local part that starts outside ASCII is not guessed at
    ],
)
def test_email_lookalikes(text, expected):
    assert found(text) == expected
    # the extractor itself must refuse them: the normalizer would catch some, which would hide a regression here
    assert {c.value for c in extract(text) if c.type == "email"} == {v for k, v in expected if k == "email"}


def test_email_domain_is_a_derived_candidate_with_provenance_on_the_original_text():
    text = "Sender: billing@invoice-update[.]example[.]org (spoofed)"
    cands = extract(text)
    email = next(c for c in cands if c.type == "email")
    assert email.raw == "billing@invoice-update[.]example[.]org" and email.defanged
    assert text[email.start:email.end] == email.raw
    domain = next(c for c in cands if c.type == "domain")
    assert domain.derived_from is email and domain.raw == "invoice-update[.]example[.]org"
    assert text[domain.start:domain.end] == domain.raw


def test_free_mail_provider_has_no_derived_domain_but_a_standalone_mention_still_counts():
    cands = extract("scammer@gmail.com wrote; see also gmail.com")
    assert [c.type.value for c in cands if c.derived_from] == []
    assert ("domain", "gmail.com") in found("scammer@gmail.com wrote; see also gmail.com")


# ---------------------------------------------------------------------------------------- file names
@pytest.mark.parametrize(
    "text, expected",
    [
        ('Content-Disposition: attachment; filename="Invoice 4471.pdf.exe"', {"Invoice 4471.pdf.exe"}),
        ("Content-Disposition: attachment; filename=statement.docm;", {"statement.docm"}),
        ('Content-Type: application/zip; name="Q3 results.zip"', {"Q3 results.zip"}),
        ("Attachment: Statement_Oct.docm", {"Statement_Oct.docm"}),
        ("Attached file: plan.xlsx.", {"plan.xlsx"}),  # sentence punctuation is not part of the name
        ("Attachments: remit.xlsm, Q3-report.pdf; notes.txt", {"remit.xlsm", "Q3-report.pdf", "notes.txt"}),
        ("File name: Payroll_2026.xlsm", {"Payroll_2026.xlsm"}),
        ("filename*=UTF-8''Rechnung%20Mai.pdf.scr", {"Rechnung Mai.pdf.scr"}),
        # only the file name of a path is kept
        ("Attachment: C:\\Users\\bob\\Desktop\\invoice.pdf", {"invoice.pdf"}),
        ("filename=../../etc/cron.d/job.sh", {"job.sh"}),
        # defanged in the text
        ("Attachment: invoice[.]pdf[.]exe", {"invoice.pdf.exe"}),
        # an executable dressed as a document is recognised without a label
        ("Dropper written to C:\\Users\\Public\\Receipt_9921.pdf.scr on the host", {"Receipt_9921.pdf.scr"}),
        ("opened photo.jpg.exe and report.docx.vbs", {"photo.jpg.exe", "report.docx.vbs"}),
    ],
)
def test_file_names(text, expected):
    got = {v for k, v in found(text) if k == "filename"}
    assert got == expected


@pytest.mark.parametrize(
    "text",
    [
        "Files in the build: archive.zip, setup.exe, invoice.pdf, config.json, libfoo.so.1",  # unlabelled names
        "setup.exe ran and wrote report.pdf",
        "name=value filename without equals attachment of 3 files",
        "Attachment: none",  # no extension
        "Attachment: README",
        "Attachment: update.com",  # reads as a domain; the domain pass owns it
        'filename="=?UTF-8?B?aW52b2ljZS5wZGY=?="',  # an encoded word, not a name
        "Content-Disposition: attachment; filename=",
        "X-Attachment-Id: f_abc123.pdf",
        "see www.pdf.js and lib.js.map",  # a library site, not a disguised program
        "GET /download?filename=",
        "http://files.example.com/invoice.pdf.exe",  # inside a URL it is part of the URL
    ],
)
def test_names_that_are_not_attachments(text):
    assert {v for k, v in found(text) if k == "filename"} == set()


def test_a_hash_inside_a_file_name_is_still_found_and_so_is_the_name():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    got = found(f"Attachment: {h}.pdf.exe")
    assert ("md5", h) in got and ("filename", f"{h}.pdf.exe") in got


def test_file_name_provenance_points_at_the_name_in_the_original_text():
    text = 'Content-Disposition: attachment; filename="Inv[.]pdf[.]exe" end'
    (cand,) = [c for c in extract(text) if c.type == "filename"]
    assert cand.value == "Inv.pdf.exe" and cand.raw == "Inv[.]pdf[.]exe" and cand.defanged
    assert text[cand.start:cand.end] == cand.raw


def test_an_email_inside_a_url_is_not_extracted_twice():
    types = [c.type.value for c in extract("ftp://bob@files.example.com/x")]
    assert "email" not in types and types.count("domain") == 1


@pytest.mark.parametrize(
    "hostile",
    [
        "http://a.example.com/?u=" * 5_000,
        "http://a.example.com/" * 20_000,
        "a." * 100_000,
        "ab:" * 100_000,
        "[.]" * 100_000,
        "@" * 200_000,
        "a@" * 100_000,
        "a" * 1_000_000 + "@example.org",
        "a@b." * 50_000,
        "x@" + "a" * 500_000 + ".com",
        "filename=" * 100_000,
        "Attachment: " * 50_000,
        "Attachments: a.pdf," * 30_000,
        'filename="' * 50_000,
        ".pdf.exe" * 50_000,
        "a.pdf.exe " * 50_000,
        "content-type: x; name=" * 20_000,
    ],
    ids=["nested-url-query", "url-run", "dot-run", "colon-run", "defang-run", "at-run", "at-pairs", "long-local",
         "email-dots", "long-domain", "filename-markers", "attachment-markers", "attachment-list", "open-quotes",
         "disguised-run", "disguised-words", "mime-markers"],
)
def test_hostile_input_terminates_quickly_without_crashing(hostile):
    import time

    start = time.perf_counter()
    extract(hostile)
    assert time.perf_counter() - start < 5
