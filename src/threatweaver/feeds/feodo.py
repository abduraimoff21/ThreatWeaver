"""abuse.ch Feodo Tracker: botnet C2 IP addresses (Emotet, QakBot, ...).

No credential needed. The JSON blocklist covers the last 30 days and is
published under CC0. Updated every 5 minutes; abuse.ch recommends polling
no more than every 15 minutes.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from typing import Any

from ..models import IocType
from .common import FeedError, FeedRecord, FeedSpec, ParseResult

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def parse(text: str) -> ParseResult:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedError(f"feodotracker: not valid JSON ({exc.msg})") from None
    if not isinstance(data, list):
        raise FeedError("feodotracker: expected a JSON array of records")

    result = ParseResult()
    for item in data:
        value = item.get("ip_address") if isinstance(item, dict) else None
        try:
            ip = ipaddress.ip_address(value)
        except (ValueError, TypeError):
            result.skipped += 1
            continue
        fields: dict[str, Any] = {
            "status": str(item.get("status") or "").lower(),
            "malware": item.get("malware") or "",
            "port": item.get("port"),
            "hostname": item.get("hostname"),
            "as_number": item.get("as_number"),
            "as_name": item.get("as_name"),
            "country": item.get("country"),
            "first_seen": item.get("first_seen") or "",
            "last_online": item.get("last_online") or "",
        }
        result.records.append(
            FeedRecord(
                feed="feodotracker",
                type=IocType.IPV4 if ip.version == 4 else IocType.IPV6,
                value=str(value),
                key=f"{ip}:{item.get('port')}",
                fields=fields,
                raw=json.dumps(item, sort_keys=True),
            )
        )
    return result


def build_url(env: Mapping[str, str]) -> str:
    return URL


SPEC = FeedSpec(
    name="feodotracker",
    min_interval_seconds=15 * 60,
    parse=parse,
    build_url=build_url,
    terms_url="https://feodotracker.abuse.ch/blocklist/",
)
