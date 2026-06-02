"""URL-related helpers."""
from __future__ import annotations

import re


def has_pii(url: str) -> bool:
    return re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", url, re.I) is not None


def escape_urlscan_query(value: str) -> str:
    return re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/])', r"\\\\\1", value)
