"""abuse.ch URLhaus: malware distribution URLs.

Access: since 2025 the bulk exports need a free Auth-Key
(https://auth.abuse.ch/). Put it in the URLHAUS_AUTH_KEY environment
variable. Do not fetch more often than every 5 minutes. Terms:
https://abuse.ch/terms-of-use/

The export is CSV with `#` comment lines; the column header is itself a
comment line. Parsing is driven by that header so added or reordered columns
do not break it.
"""

from __future__ import annotations

import csv
from collections.abc import Mapping

from ..models import IocType
from .common import FeedRecord, FeedSpec, ParseResult

DEFAULT_COLUMNS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


def parse(text: str) -> ParseResult:
    result = ParseResult()
    columns: list[str] | None = None
    rows: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            if candidate.startswith("id,") and "url" in candidate.split(","):
                columns = next(csv.reader([candidate]))
            continue
        rows.append(line)

    for row in csv.reader(rows, skipinitialspace=True):
        if columns is None and row and row[0] == "id":
            columns = row  # header given as a plain, uncommented line
            continue
        cols = columns or DEFAULT_COLUMNS
        if len(row) < len(cols):
            result.skipped += 1
            continue
        data = dict(zip(cols, row))
        url = data.get("url", "").strip()
        if not url:
            result.skipped += 1
            continue
        tags = [t.strip() for t in data.get("tags", "").split(",") if t.strip() and t.strip() != "None"]
        result.records.append(
            FeedRecord(
                feed="urlhaus",
                type=IocType.URL,
                value=url,
                key=data.get("id", "").strip() or url,
                fields={
                    "status": data.get("url_status", "").strip().lower(),
                    "first_seen": data.get("dateadded", "").strip(),
                    "last_online": data.get("last_online", "").strip(),
                    "threat": data.get("threat", "").strip(),
                    "tags": tags,
                    "reference": data.get("urlhaus_link", "").strip(),
                    "reporter": data.get("reporter", "").strip(),
                },
                raw=",".join(row),
            )
        )
    return result


def build_url(env: Mapping[str, str]) -> str:
    return f"https://urlhaus-api.abuse.ch/v2/files/exports/{env.get('URLHAUS_AUTH_KEY', '')}/recent.csv"


SPEC = FeedSpec(
    name="urlhaus",
    min_interval_seconds=5 * 60,
    parse=parse,
    build_url=build_url,
    needs_env="URLHAUS_AUTH_KEY",
    terms_url="https://abuse.ch/terms-of-use/",
)
