"""Shared feed types and a polite, cached, HTTPS-only fetcher.

Module C is limited to two public feeds (URLhaus and Feodo Tracker). Fetching
is always an explicit command, never a side effect of analysis; results are
cached on disk so repeated runs stay inside each feed's rate limits.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import IocType

USER_AGENT = "ThreatWeaver/0.1 (CERT research prototype; polite, cached)"
MAX_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 30


class FeedError(RuntimeError):
    """A feed could not be fetched or parsed. Messages never contain credentials."""


@dataclass(frozen=True)
class FeedRecord:
    """One indicator asserted by a feed, with the feed's own fields preserved."""

    feed: str
    type: IocType
    value: str  # as the feed wrote it; normalized on load
    key: str  # stable id within the feed (URLhaus id, "ip:port" for Feodo)
    fields: dict[str, Any]
    raw: str  # the original record text, kept for traceability


@dataclass
class ParseResult:
    records: list[FeedRecord] = field(default_factory=list)
    skipped: int = 0  # malformed rows that were ignored


@dataclass(frozen=True)
class FeedSpec:
    name: str
    min_interval_seconds: int
    parse: Callable[[str], ParseResult]
    build_url: Callable[[Mapping[str, str]], str]
    needs_env: str | None = None  # name of the environment variable holding a credential
    terms_url: str = ""


def _redact(message: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            message = message.replace(secret, "***")
    return message


def fetch_text(
    spec: FeedSpec,
    cache_dir: str | Path,
    *,
    force: bool = False,
    env: Mapping[str, str] | None = None,
    opener: Callable[..., Any] = urllib.request.urlopen,
    now: Callable[[], float] = time.time,
) -> tuple[str, bool]:
    """Return (feed text, from_cache). Hits the network only if the cache is stale.

    The credential (if any) is read from the environment, used in the request
    URL, and never written to the cache, the logs, or error messages.
    """
    env = os.environ if env is None else env
    cache = Path(cache_dir)
    body_path = cache / f"{spec.name}.txt"
    meta_path = cache / f"{spec.name}.meta.json"

    if not force and body_path.exists() and meta_path.exists():
        fetched_at = json.loads(meta_path.read_text(encoding="utf-8")).get("fetched_at", 0)
        if now() - fetched_at < spec.min_interval_seconds:
            return body_path.read_text(encoding="utf-8"), True

    secret = ""
    if spec.needs_env:
        secret = env.get(spec.needs_env, "")
        if not secret:
            raise FeedError(
                f"{spec.name} needs a free abuse.ch Auth-Key in the {spec.needs_env} environment variable "
                "(get one at https://auth.abuse.ch/)."
            )
    url = spec.build_url(env)
    if not url.lower().startswith("https://"):
        raise FeedError(f"{spec.name}: refusing non-HTTPS feed URL")

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            data = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise FeedError(_redact(f"{spec.name}: HTTP {exc.code}", [secret])) from None
    except (urllib.error.URLError, OSError) as exc:
        raise FeedError(_redact(f"{spec.name}: {type(exc).__name__}: {exc}", [secret])) from None
    if len(data) > MAX_BYTES:
        raise FeedError(f"{spec.name}: response larger than {MAX_BYTES} bytes, discarded")

    text = data.decode("utf-8", errors="replace")
    cache.mkdir(parents=True, exist_ok=True)
    body_path.write_text(text, encoding="utf-8")
    meta_path.write_text(json.dumps({"fetched_at": now()}), encoding="utf-8")
    return text, False
