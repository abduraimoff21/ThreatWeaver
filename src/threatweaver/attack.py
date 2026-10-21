"""Module I: MITRE ATT&CK hints.

For each indicator, name the kinds of attack it could belong to and the ATT&CK tactics and techniques they use, with
a few questions an analyst can ask next. Everything here is a *possibility to check*, not a finding: ThreatWeaver
reads only feed listings, the shape of an indicator, and the text of a few stored log lines, so it can suggest where
to look but cannot say what happened. Nothing here blocks, quarantines or sends anything, and nothing reaches the
network: the ATT&CK names come from `attack_data.py`, and links to attack.mitre.org are plain addresses a person
may open.

Where a hint comes from (`basis`, strongest first)
  feed    a public feed lists the indicator (Feodo Tracker, URLhaus); a known malware family adds the techniques
          ATT&CK lists for that family
  shape   what the indicator is: a file name that hides an executable, an e-mail address tied to a risky domain
  log     words in the stored log line (a scanner's name, failed-login messages, an exploit string); only the
          first MAX_LINES lines of each indicator are read, and a pattern may need several of them
  volume  only the number of sightings; the weakest hint, shown when nothing better explains a very busy indicator

Adding a pattern: give it an id, add its techniques (they must exist in `attack_data.TECHNIQUES`; a test checks),
write the questions to ask, and add a positive and a negative test case.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import attack_data as data

FRAMEWORK = f"MITRE ATT&CK {data.DOMAIN} {data.VERSION}"
COPYRIGHT = "\u00a9 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
NOTICE = (
    "Possibilities to check, not findings. They come from public feed listings, the shape of an indicator and the "
    "text of a few stored log lines, and say where an analyst could look. ATT&CK does not list every possible "
    "behaviour, and an attack can be present without being suggested here."
)
MAX_LINES = 20  # stored log lines read per indicator
BASIS_LABEL = {
    "feed": "Public feed",
    "shape": "What the indicator is",
    "log": "Words in stored log lines",
    "volume": "Volume only (weakest)",
}
HASH_TYPES = frozenset({"md5", "sha1", "sha256"})  # their log lines say nothing about the kind of attack

TACTIC_NAMES = dict(data.TACTICS)
TACTIC_ORDER = [name for _, name in data.TACTICS]
_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


# ------------------------------------------------------------------ reference data
def technique_url(technique_id: str) -> str:
    base, _, sub = technique_id.partition(".")
    return f"{data.URL}/techniques/{base}/" + (f"{sub}/" if sub else "")


def technique(technique_id: str) -> dict[str, Any]:
    name, tactic_ids = data.TECHNIQUES[technique_id]
    names = {TACTIC_NAMES[t] for t in tactic_ids.split()}
    return {"id": technique_id, "name": name, "url": technique_url(technique_id),
            "tactics": [t for t in TACTIC_ORDER if t in names]}


def software_url(software_id: str) -> str:
    return f"{data.URL}/software/{software_id}/"


def _normal(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


_FAMILY = {alias: key for key, (_, _, aliases, _) in data.SOFTWARE.items() for alias in aliases}


def families(names: Iterable[Any]) -> list[str]:
    """Keys of the malware families (as ATT&CK names them) among `names`: feed fields or tags, any spelling."""
    found = {_FAMILY[_normal(n)] for n in names if isinstance(n, str) and _normal(n) in _FAMILY}
    return sorted(found)


def software_view(key: str) -> dict[str, Any]:
    """One family as ATT&CK describes it: its page, and the techniques listed there grouped by tactic."""
    software_id, name, _, technique_ids = data.SOFTWARE[key]
    return {"key": key, "id": software_id, "name": name, "url": software_url(software_id),
            "techniques_total": len(technique_ids), "by_tactic": by_tactic(dict.fromkeys(technique_ids, 0), only_counted=False)}


def by_tactic(counts: Mapping[str, int], only_counted: bool = True) -> list[dict[str, Any]]:
    """Techniques grouped under each tactic they belong to, in matrix order. `counts` maps technique id to the
    number of indicators it was suggested for."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for tid, n in counts.items():
        if only_counted and not n:
            continue
        info = technique(tid)
        for tactic in info["tactics"]:
            groups.setdefault(tactic, []).append({"id": tid, "name": info["name"], "url": info["url"], "indicators": n})
    return [{"tactic": t, "techniques": sorted(groups[t], key=lambda x: (-x["indicators"], x["id"]))}
            for t in TACTIC_ORDER if t in groups]


# ------------------------------------------------------------------ patterns
@dataclass(frozen=True)
class Pattern:
    id: str
    title: str
    basis: str
    meaning: str
    techniques: tuple[str, ...]
    check: tuple[str, ...]
    regex: re.Pattern[str] | None = None  # log patterns: matched against each stored line
    min_lines: int = 1  # ... and needed in at least this many of them
    evidence: str = ""  # what the matching lines contain, for the "why" sentence
    # Lower-case text that every line the regex matches must contain. A cheap `in` test on it decides whether the (much
    # slower) regex runs at all, which is what keeps this fast on logs with millions of indicators. A test checks it.
    needles: tuple[str, ...] = ()
    # Techniques to suggest instead when the indicator is an address inside a private range: scanning, guessing or
    # exploiting from a machine that is already inside the network is Discovery or Lateral Movement, not Reconnaissance.
    inside: tuple[str, ...] = ()
    # The pattern describes someone acting on others (scanning, guessing, exploiting). An address then counts only on
    # lines where it comes first, which is where firewall, flow and web logs put the source; the address after it is the target.
    from_source: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_HUMAN = "Any containment (isolating a system, blocking an address) is a decision for a person through your normal change process."
_SP = r"(?:%20|\+|\s)"  # a space, as it appears in raw text or in a URL

PATTERNS: tuple[Pattern, ...] = (
    Pattern("AT-01", "Botnet command-and-control server", "feed",
            "Feodo Tracker lists this address as a server that infected machines call home to. Systems that talk to it may be infected.",
            ("T1071",),
            ("Find which of your systems talked to this address (firewall, proxy, DNS and flow logs) and when.",
             "Look at those systems for the malware family the feed names. A blocked connection attempt is a different case from a session that was answered.",
             "Look for what came after the first contact: new programs, downloaded files, connections to other addresses the feed lists.",
             _HUMAN)),
    Pattern("AT-02", "Link that serves malware", "feed",
            "URLhaus lists this URL as a place malware is downloaded from. Someone who opened it may have fetched the malware.",
            ("T1105", "T1204.001", "T1189"),
            ("Check proxy and DNS logs for who requested this URL and whether the download finished.",
             "If a file came down, hash it and look for that hash on the affected system; check whether it was run.",
             "Find how the person got the link (e-mail, web page, chat). That decides which technique applies.")),
    Pattern("AT-03", "Server that hosts malware downloads", "feed",
            "A URL on this host is listed by URLhaus as serving malware. The host is either the attacker's own or a legitimate site that was broken into.",
            ("T1608.001", "T1584", "T1583"),
            ("Check whether the host looks like the attacker's own (recently registered, no real content) or a compromised legitimate site.",
             "Look at who in your network contacted it, and for the other URLs it serves.")),
    Pattern("AT-04", "Program disguised as a document", "shape",
            "The file name puts a program extension after a document extension (invoice.pdf.exe), a common way to get a program opened as if it were a document.",
            ("T1036.007", "T1204.002"),
            ("Find where the file arrived (mail gateway, download, shared folder) and who opened it.",
             "Look for a program started from that file name, and for the hash of the file.")),
    Pattern("AT-05", "E-mail with a disguised attachment", "shape",
            "An e-mail address appears on the same line as a file name that hides a program behind a document extension. This is the usual look of a phishing e-mail with a malicious attachment.",
            ("T1566.001", "T1036.007", "T1204.002"),
            ("Search the mail system for this sender and attachment name and list every recipient.",
             "Check who opened or ran the attachment. Senders are often spoofed, so compare the message headers.")),
    Pattern("AT-06", "E-mail address tied to a risky domain", "shape",
            "The address belongs to a domain that is high risk in this data. Mail from it could be phishing sent from infrastructure the attacker controls.",
            ("T1566", "T1583.001"),
            ("Search mail logs for this sender and for other senders at the same domain.",
             "Check how new the domain is, and whether links in those messages were clicked.")),
    Pattern("AT-07", "Repeated failed logins", "log",
            "Failed-login messages from this address: someone may be guessing passwords.",
            ("T1110", "T1110.001"),
            ("Look for a successful login from the same address after the failures. That changes the case.",
             "Check whether the accounts tried exist (invalid-user messages mean names are being guessed) and whether the service should be reachable from the internet.",
             "Compare with other addresses doing the same. Many addresses against one account is a different pattern from one address against many."),
            _rx(r"failed password|failed publickey|authentication failure|invalid user|failed login|login (?:failed|incorrect)|logon failure|"
                r"possible break-in attempt|too many authentication failures|access denied for user|incorrect password"),
            3, "failed-login messages",
            ("failed", "authentication fail", "invalid user", "logon failure", "break-in", "denied for user", "incorrect")),
    Pattern("AT-08", "Port or host scanner", "log",
            "The log names a network scanner. Scanning looks for hosts and services to attack next.",
            ("T1595.001", "T1595.002"),
            ("Check which ports and hosts were probed and whether anything answered.",
             "Scanning is routine noise on public addresses. It matters when the same address comes back with exploit attempts or logins."),
            _rx(r"\bnmap\b|nmap scripting engine|\bmasscan\b|\bzmap\b|\bzgrab\b|\bunicornscan\b"), 1, "the name of a network scanner",
            ("nmap", "masscan", "zmap", "zgrab", "unicornscan"), inside=("T1046",), from_source=True),
    Pattern("AT-09", "Web vulnerability scanner", "log",
            "The log names a tool that tests web sites for known weaknesses.",
            ("T1595.002",),
            ("Check which paths were requested and what the server answered.",
             "Look for the same address later sending exploit strings or getting successful answers on admin pages."),
            _rx(r"\bnikto\b|\bnuclei\b|\bwpscan\b|\bnessus\b|\bopenvas\b|\bacunetix\b|\bw3af\b|\barachni\b|\bskipfish\b"), 1,
            "the name of a web vulnerability scanner",
            ("nikto", "nuclei", "wpscan", "nessus", "openvas", "acunetix", "w3af", "arachni", "skipfish"), inside=("T1046",), from_source=True),
    Pattern("AT-10", "File and directory guessing tool", "log",
            "The log names a tool that requests thousands of likely page names to find hidden content.",
            ("T1595.003",),
            ("Check for requests that were answered successfully on paths that should not be public.",
             "See whether the address came back with attacks against what it found."),
            _rx(r"\bgobuster\b|\bdirbuster\b|\bdirb\b|\bffuf\b|\bwfuzz\b|\bferoxbuster\b"), 1, "the name of a directory-guessing tool",
            ("gobuster", "dirbuster", "dirb", "ffuf", "wfuzz", "feroxbuster"), from_source=True),
    Pattern("AT-11", "Password-guessing tool", "log",
            "The log names a tool built to guess passwords against a login.",
            ("T1110", "T1110.001"),
            ("Check authentication logs for the targeted service, and for successful logins from the same address.",
             "Review lockout and multi-factor settings for the accounts involved through your normal change process."),
            _rx(r"\(hydra\)|thc-hydra|\bpatator\b|\bncrack\b|\bmedusa v?\d"), 1, "the name of a password-guessing tool",
            ("(hydra)", "thc-hydra", "patator", "ncrack", "medusa"), from_source=True),
    Pattern("AT-12", "SQL injection attempt", "log",
            "The log names a SQL injection tool or contains typical SQL injection text. The aim is to read or change a web application's database.",
            ("T1190",),
            ("Check the web server's answers and the application's database logs around the time of these lines.",
             "Look for error answers followed by an unusual amount of data leaving the server.",
             "Fixing or filtering the application is a decision for its owner."),
            _rx(rf"\bsqlmap\b|\bunion{_SP}+(?:all{_SP}+)?select\b|(?:%27|'){_SP}*or{_SP}+(?:%27|')?\d(?:%27|')?{_SP}*={_SP}*(?:%27|')?\d|information_schema"),
            1, "the name of an SQL injection tool or SQL injection text",
            ("sqlmap", "union", "information_schema", "' ", "'+", "%27"), inside=("T1210",), from_source=True),
    Pattern("AT-13", "Exploit string against a public service", "log",
            "The log contains text typical of well-known attacks on web servers (path traversal, Log4Shell, Shellshock).",
            ("T1190",),
            ("Check that the target actually runs what the string attacks. A Log4j string aimed at a system without Log4j is noise.",
             "Look at the answer codes, and at outbound connections from the server after the request."),
            _rx(r"\.\./\.\./|%2e%2e(?:%2f|%5c)|/etc/passwd|\$\{jndi:|\(\)\s*\{\s*:\s*;\s*\}"), 1, "an exploit string",
            ("../../", "%2e%2e", "/etc/passwd", "${jndi:", "()"), inside=("T1210",), from_source=True),
    Pattern("AT-14", "Encoded or hidden PowerShell", "log",
            "The log shows PowerShell run with an encoded command or a hidden window. Attackers use this to hide what a script does.",
            ("T1059.001", "T1027"),
            ("Decode the command (it is usually base64 text) and read what it does.",
             "Find the parent program that started it and the user it ran as.",
             "The addresses and URLs inside it may already be indicators here."),
            _rx(r"\bpowershell(?:\.exe)?\b[^\r\n]{0,300}?\s-e(?:c|nc\w*)?\s+[A-Za-z0-9+/=]{16,}|frombase64string|"
                r"-(?:w|windowstyle)\s+hidden\b[^\r\n]{0,200}?\b(?:iex|invoke-expression|downloadstring)\b"), 1, "an encoded or hidden PowerShell command",
            ("powershell", "frombase64string", "hidden")),
    Pattern("AT-15", "Command that downloads a file", "log",
            "The log shows a command-line download (certutil, bitsadmin, PowerShell, curl or wget piped into a shell), a way to bring a tool onto a system.",
            ("T1105", "T1059"),
            ("Check which program ran the command and what started it.",
             "Find the file it fetched, hash it, and see whether it was run.",
             "Administrators use these commands too. Compare with change records."),
            _rx(r"\bcertutil(?:\.exe)?\b[^\r\n]{0,200}\s-urlcache\b|\bbitsadmin(?:\.exe)?\b[^\r\n]{0,200}\s/transfer\b|"
                r"\binvoke-webrequest\b|\biwr\s+https?:|\bnew-object\s+(?:system\.)?net\.webclient\b|\.download(?:file|string)\(|"
                r"\b(?:curl|wget)\b[^\r\n|]{0,200}\|\s*(?:ba|z)?sh\b"), 1, "a command that downloads a file",
            ("certutil", "bitsadmin", "invoke-web", "iwr", "webclient", ".download", "curl", "wget")),
    Pattern("AT-16", "System tool used to run remote content", "log",
            "The log shows mshta or regsvr32 loading a remote script. Attackers use trusted Windows programs to run code without a file of their own.",
            ("T1218.005", "T1218.010"),
            ("Check which user and parent program started it.",
             "Retrieve the remote file only in an isolated analysis environment, never from a normal workstation."),
            _rx(r"\bmshta(?:\.exe)?\s+(?:vbscript:|javascript:|https?:)|\bregsvr32(?:\.exe)?\b[^\r\n]{0,200}(?:/i:\s*https?:|scrobj\.dll)"),
            1, "a system tool loading remote content",
            ("mshta", "regsvr32")),
    Pattern("AT-17", "Probing for files that are not there", "log",
            "Many requests for pages or directories that do not exist: a sign of someone guessing at what a server holds.",
            ("T1595.003",),
            ("Check whether any request from this address got a successful answer.",
             "Probing for missing files is routine internet noise. It matters if the same address later succeeds somewhere."),
            _rx(r"file does not exist|directory index forbidden|script not found or unable to stat"), 5, "errors about missing files or directories",
            ("does not exist", "index forbidden", "script not found"), from_source=True),
    Pattern("AT-18", "Connection probes that never start a real session", "log",
            "Connections that are dropped before any real exchange, or that speak the wrong protocol: usually a scan for open services.",
            ("T1595",),
            ("Check whether the same address connected to other services, and whether any of them let it in.",),
            _rx(r"did not receive identification string|bad protocol version identification|protocol major versions differ|invalid http request"),
            3, "dropped or malformed connection attempts",
            ("identification string", "protocol version", "versions differ", "http request"), inside=("T1046",), from_source=True),
    Pattern("AT-19", "Very heavy repeat activity (volume only)", "volume",
            "Thousands of sightings. Volume alone cannot say what kind of activity this is. Scanning, password guessing, a C2 check-in, a denial of service and a noisy but harmless client all look like this.",
            ("T1595", "T1110", "T1071", "T1498", "T1499"),
            ("Open the stored log lines. Many connections to many ports points to scanning; many to one login page or service to password guessing; "
             "a steady beat of small connections to one server to a C2 check-in; a flood of traffic to a denial of service.",
             "Compare with what is normal for this address. Public DNS servers, CDNs and your own monitoring all score here."),
            inside=("T1046", "T1110", "T1071", "T1498", "T1499")),
)
BY_ID = {p.id: p for p in PATTERNS}
# (needle, patterns that own it): a plain `in` test per needle on the lower-cased line. Measured faster than one regex over
# all of them, whether as a pre-check or as a scan.
_NEEDLES: tuple[tuple[str, tuple[Pattern, ...]], ...] = tuple(
    (needle, tuple(p for p in PATTERNS if needle in p.needles)) for needle in sorted({n for p in PATTERNS for n in p.needles}))
ROLE_NOTE = " A log line names several indicators, so this one may be the source or the target of what the line describes; check which."
SOURCE_NOTE = " On lines that name several addresses, only those where it comes first (the usual place for the source) were counted."
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
INSIDE_NOTE = (" The address is inside a private range, so this points to a machine already in the network (or to an authorised "
               "internal scanner); the techniques shown are the inside-the-network ones.")
VOLUME_FLOOR = 25  # TW-T10 points (1,000+ sightings) needed before volume alone is worth a hint


# ------------------------------------------------------------------ assessing one indicator
@dataclass(frozen=True)
class Facts:
    """What `assess` may use about one indicator."""

    type: str
    disguised: bool = False  # a file name that hides a program behind a document extension
    rules: Mapping[str, int] = field(default_factory=dict)  # triage rule id -> points
    matches: Sequence[Mapping[str, Any]] = ()  # feed matches, as the report lists them
    sightings: int = 0
    lines: Sequence[str] = ()  # the first stored log lines
    linked_email: bool = False  # an e-mail address shares a line with it
    linked_disguised_file: bool = False  # a disguised file name shares a line with it
    linked_risky_domain: bool = False  # its domain is high risk
    internal: bool = False  # an address in a private, loopback or link-local range
    value: str = ""  # the indicator itself, to tell the source of a line from its target


def _clean(text: str, limit: int = 40) -> str:
    return re.sub(r"[^\w .+\-]", "", text)[:limit]


def _family_text(keys: Sequence[str], raw_names: Iterable[Any]) -> str:
    if keys:
        return ", ".join(data.SOFTWARE[k][1] for k in keys)
    unknown = sorted({_clean(n) for n in raw_names if isinstance(n, str) and n.strip()})
    return ", ".join(unknown[:3])


def _is_target(line: str, f: Facts) -> bool:
    """True when the indicator is an IPv4 address that comes after another address on this line."""
    if f.type != "ipv4" or not f.value:
        return False
    addresses = _IPV4.findall(line)
    return f.value in addresses and len(set(addresses)) > 1 and addresses[0] != f.value


def assess(f: Facts) -> list[dict[str, Any]]:
    """The patterns that apply to one indicator: [{"pattern", "why", "techniques", "software"}], in pattern order."""
    rules = f.rules
    found: dict[str, dict[str, Any]] = {}

    def add(pid: str, why: str, software: Sequence[str] = ()) -> None:
        p = BY_ID[pid]
        inside = f.internal and bool(p.inside)
        note = (SOURCE_NOTE if f.type == "ipv4" else ROLE_NOTE) if p.from_source else ""
        found[pid] = {"pattern": pid, "why": why + note + (INSIDE_NOTE if inside else ""),
                      "techniques": list(p.inside if inside else p.techniques), "software": list(software)}

    exact = [m for m in f.matches if m.get("via") == "exact"]
    feodo = [m for m in exact if m.get("feed") == "feodotracker"]
    if feodo:
        names = [m["fields"].get("malware") for m in feodo]
        keys = families(names)
        state = "online" if any(m["fields"].get("status") == "online" for m in feodo) else "not online in the snapshot"
        label = _family_text(keys, names)
        add("AT-01", f"Feodo Tracker lists this address as a botnet C2 server{f' ({label})' if label else ''}, {state}.", keys)
    urlhaus = [m for m in exact if m.get("feed") == "urlhaus"]
    if urlhaus:
        tags = [t for m in urlhaus for t in (m["fields"].get("tags") or [])]
        keys = families(tags)
        label = _family_text(keys, [])
        add("AT-02", f"URLhaus lists this URL as distributing malware{f', tagged {label}' if label else ''}.", keys)
    hosted = [m for m in f.matches if m.get("via") == "hosts_feed_url"]
    if hosted:
        tags = [t for m in hosted for t in (m["fields"].get("tags") or [])]
        keys = families(tags)
        label = _family_text(keys, [])
        n = len({m.get("listed_url") for m in hosted})
        add("AT-03", f"URLhaus lists {n} URL(s) on this host as distributing malware{f', tagged {label}' if label else ''}.", keys)

    if f.type == "filename" and f.disguised:
        add("AT-04", "The name puts a program extension after a document extension.")
        if f.linked_email:
            add("AT-05", "An e-mail address appears on the same line as this file name.")
    if f.type == "email":
        if f.linked_disguised_file:
            add("AT-05", "A file name that hides a program behind a document extension appears on the same line as this address.")
        if f.linked_risky_domain:
            add("AT-06", "Its domain is high risk in this data.")

    if f.type not in HASH_TYPES and f.lines:
        counts: Counter[str] = Counter()
        for line in f.lines:
            low = line.lower()
            wanted: set[Pattern] = set()
            for needle, owners in _NEEDLES:
                if needle in low:
                    wanted.update(owners)
            for p in wanted:
                if p.regex.search(line) and not (p.from_source and _is_target(line, f)):
                    counts[p.id] += 1
        for p in PATTERNS:
            if p.regex is None:
                continue
            n = counts[p.id]
            if n >= p.min_lines:
                if f.sightings > len(f.lines):
                    how = f"{n} of the first {len(f.lines)} stored log lines for this indicator"
                else:
                    how = f"All {n} stored log lines for this indicator" if n == len(f.lines) else f"{n} of the {len(f.lines)} stored log lines for this indicator"
                add(p.id, f"{how} contain {p.evidence}.")

    if rules.get("TW-T10", 0) >= VOLUME_FLOOR and not any(BY_ID[pid].basis == "log" for pid in found):
        add("AT-19", f"Seen {f.sightings:,} times, and none of the stored log lines point to a specific kind of activity.")
    return [found[p.id] for p in PATTERNS if p.id in found]


# ------------------------------------------------------------------ counting across indicators
def rollup(findings_per_indicator: Iterable[Sequence[Mapping[str, Any]]]) -> dict[str, dict[str, int]]:
    """How many indicators each pattern, technique and malware family was suggested for (each counted once per indicator)."""
    patterns: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    software: Counter[str] = Counter()
    for findings in findings_per_indicator:
        patterns.update({f["pattern"] for f in findings})
        techniques.update({t for f in findings for t in f["techniques"]})
        software.update({k for f in findings for k in f["software"]})
    return {"patterns": dict(sorted(patterns.items())), "techniques": dict(sorted(techniques.items())),
            "software": dict(sorted(software.items()))}


def catalog() -> dict[str, dict[str, Any]]:
    """Every pattern, for the report and the pages: what it means and what to check."""
    return {p.id: {"title": p.title, "basis": p.basis, "basis_label": BASIS_LABEL[p.basis], "meaning": p.meaning,
                   "check": list(p.check), "techniques": list(p.techniques)} for p in PATTERNS}


def summary(total: Mapping[str, Mapping[str, int]]) -> dict[str, Any]:
    """The report's ATT&CK section, from the roll-up over all indicators."""
    used = set(total["techniques"])
    for key in total["software"]:
        used.update(data.SOFTWARE[key][3])
    return {
        "framework": FRAMEWORK, "copyright": COPYRIGHT, "notice": NOTICE, "source": data.URL,
        "patterns": {pid: {**info, "indicators": total["patterns"].get(pid, 0)} for pid, info in catalog().items()},
        "by_tactic": by_tactic(total["techniques"]),
        "techniques": {tid: {**technique(tid), "indicators": total["techniques"].get(tid, 0)} for tid in sorted(used)},
        "software": {key: {**software_view(key), "indicators": n} for key, n in total["software"].items()},
    }


# ------------------------------------------------------------------ views for the dashboard
_BASIS_RANK = {"feed": 0, "shape": 1, "log": 2, "volume": 3}


def finding_view(finding: Mapping[str, Any]) -> dict[str, Any]:
    """One suggestion for one indicator, with the text of its pattern and the full names of its techniques."""
    p = BY_ID[finding["pattern"]]
    return {"pattern": p.id, "title": p.title, "basis": p.basis, "basis_label": BASIS_LABEL[p.basis], "meaning": p.meaning,
            "why": finding["why"], "check": list(p.check),
            "techniques": [technique(t) for t in finding["techniques"]],
            "software": [software_view(k) for k in finding["software"]]}


def patterns_view(counts: Mapping[str, int]) -> list[dict[str, Any]]:
    """Patterns with at least one indicator, strongest evidence first, then most indicators."""
    rows = [{"pattern": pid, "title": BY_ID[pid].title, "basis": BY_ID[pid].basis, "basis_label": BASIS_LABEL[BY_ID[pid].basis],
             "indicators": n} for pid, n in counts.items() if n]
    return sorted(rows, key=lambda r: (_BASIS_RANK[r["basis"]], -r["indicators"], r["pattern"]))


def roll_view(roll: Mapping[str, Mapping[str, int]] | None) -> dict[str, Any]:
    """A roll-up (a case's, or everything's) as the pages show it."""
    roll = roll or {"patterns": {}, "techniques": {}, "software": {}}
    return {"patterns": patterns_view(roll["patterns"]), "by_tactic": by_tactic(roll["techniques"]),
            "software": [{"key": k, "name": data.SOFTWARE[k][1], "indicators": n} for k, n in roll["software"].items()]}
