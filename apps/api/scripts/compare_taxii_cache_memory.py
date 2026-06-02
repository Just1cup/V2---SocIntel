from __future__ import annotations

import gc
import os
import sys
import time
import tracemalloc
from pathlib import Path


os.environ.setdefault("JWT_SECRET", "test-secret-value-with-more-than-32-characters")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.taxii_service import TaxiiService  # noqa: E402


ENTRY_COUNT = 120
PAYLOAD_BYTES = 100 * 1024
AFTER_CACHE_MAX_BYTES = 2 * 1024 * 1024
AFTER_CACHE_MAX_ENTRY_BYTES = 512 * 1024


def make_payload(index: int) -> dict:
    return {
        "objects": [
            {
                "id": f"attack-pattern--{index}",
                "type": "attack-pattern",
                "description": f"{index}-" + ("x" * PAYLOAD_BYTES),
            }
        ]
    }


def payload_size(payload: dict) -> int:
    return len(payload["objects"][0]["description"].encode("utf-8"))


def measure(label: str, operation):
    gc.collect()
    tracemalloc.start()
    start = time.perf_counter()
    result = operation()
    duration_ms = (time.perf_counter() - start) * 1000
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "label": label,
        "duration_ms": round(duration_ms, 2),
        "tracemalloc_current_mb": round(current / 1024 / 1024, 2),
        "tracemalloc_peak_mb": round(peak / 1024 / 1024, 2),
        **result,
    }


def before_unbounded_cache():
    cache: dict[str, tuple[float, dict]] = {}
    retained_bytes = 0
    for index in range(ENTRY_COUNT):
        payload = make_payload(index)
        retained_bytes += payload_size(payload)
        cache[f"key-{index}"] = (time.monotonic() + 600, payload)
    return {
        "entries": len(cache),
        "retained_payload_mb": round(retained_bytes / 1024 / 1024, 2),
    }


def after_bounded_cache():
    service = TaxiiService()
    service._cache_max_bytes = AFTER_CACHE_MAX_BYTES
    service._cache_max_entry_bytes = AFTER_CACHE_MAX_ENTRY_BYTES
    service._cache_max_entries = ENTRY_COUNT
    for index in range(ENTRY_COUNT):
        payload = make_payload(index)
        service._store_cache_entry(
            f"key-{index}",
            time.monotonic() + 600,
            payload_size(payload),
            payload,
        )
    return {
        "entries": len(service._cache),
        "retained_payload_mb": round(service._cache_bytes / 1024 / 1024, 2),
    }


if __name__ == "__main__":
    before = measure("before_unbounded_entry_count_cache", before_unbounded_cache)
    after = measure("after_bounded_byte_budget_cache", after_bounded_cache)
    print(
        {
            "entry_count": ENTRY_COUNT,
            "payload_bytes_each": PAYLOAD_BYTES,
            "after_cache_max_mb": AFTER_CACHE_MAX_BYTES // 1024 // 1024,
            "before": before,
            "after": after,
        }
    )
