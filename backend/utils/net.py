"""Network normalization helpers."""
from __future__ import annotations


def normalize_mac(mac: str) -> str:
    value = (mac or "").strip().lower()
    return value.replace("-", ":").replace(".", ":")
