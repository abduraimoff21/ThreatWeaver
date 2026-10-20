"""Bundled TLD allowlist so extraction works offline.

This is deliberately a curated subset of the IANA root zone: every ISO
country-code TLD plus the common generic ones. Anything not listed (and not a
punycode `xn--` TLD) is rejected, which is what keeps `report.pdf` and
`settings.json` from being extracted as domains.

Refresh from https://data.iana.org/TLD/tlds-alpha-by-domain.txt when
network use is allowed (Milestone C).
"""

CC_TLDS = frozenset(
    """
    ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj
    bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx
    cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg
    gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq
    ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt
    lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na
    nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py
    qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy
    sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve
    vg vi vn vu wf ws ye yt za zm zw
    """.split()
)

GENERIC_TLDS = frozenset(
    """
    com net org info biz edu gov mil int name pro mobi asia tel travel jobs museum
    aero coop xyz top site online club shop store tech app dev page cloud live icu
    vip work link click world today life fun space website email blog news agency
    network digital services solutions support systems group company center
    download review stream win bid loan men party trade date faith racing science
    cyou buzz rest bar monster
    """.split()
)

# TLDs that double as very common file extensions. A bare `setup.py` or
# `notes.md` is far more likely a filename than a domain, so these are only
# accepted when the text was defanged or the name is the host of a URL.
AMBIGUOUS_TLDS = frozenset({"py", "sh", "pl", "md", "rs", "so", "zip", "mov", "cc"})

# Second-level labels used under country TLDs (edu.pl, com.py, co.in ...). With one of these in
# front of an ambiguous TLD the name is accepted even without defanging or a URL context.
COMMON_SECOND_LEVELS = frozenset({"com", "net", "org", "edu", "gov", "mil", "co", "ac", "info", "biz"})

KNOWN_TLDS = CC_TLDS | GENERIC_TLDS

# Public mailbox providers. An address there (someone@gmail.com) is kept as an e-mail indicator, but its
# provider is not turned into a domain indicator of its own: every unrelated address at the same provider
# would otherwise be linked together through it, and `gmail.com` would rank on volume alone.
FREE_MAIL_DOMAINS = frozenset(
    """
    gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com aol.com icloud.com
    me.com mac.com proton.me protonmail.com pm.me gmx.com gmx.net gmx.de mail.com mail.ru yandex.com yandex.ru
    zoho.com qq.com 163.com 126.com sina.com rediffmail.com tutanota.com tuta.io
    """.split()
)
