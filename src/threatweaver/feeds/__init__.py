"""Module C: public threat intel feeds (URLhaus, Feodo Tracker). Hard limit: two feeds."""

from .common import FeedError, FeedRecord, FeedSpec, ParseResult, fetch_text
from .loader import LoadResult, load_feed
from .urlhaus import SPEC as URLHAUS
from .feodo import SPEC as FEODO

FEEDS = {FEODO.name: FEODO, URLHAUS.name: URLHAUS}
assert len(FEEDS) <= 2, "spec: collect from at most two public feeds"

__all__ = [
    "FEEDS", "FEODO", "URLHAUS", "FeedError", "FeedRecord", "FeedSpec",
    "LoadResult", "ParseResult", "fetch_text", "load_feed",
]
