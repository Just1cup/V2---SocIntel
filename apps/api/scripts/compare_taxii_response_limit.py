from __future__ import annotations

import gc
import os
import sys
import time
import tracemalloc
from pathlib import Path


os.environ.setdefault("JWT_SECRET", "test-secret-value-with-more-than-32-characters")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.taxii_service import TaxiiService, TaxiiUpstreamError  # noqa: E402


RESPONSE_BYTES = 12 * 1024 * 1024
LIMIT_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 64 * 1024


class ChunkedResponse:
    def __init__(self, total_bytes: int):
        self.total_bytes = total_bytes

    def iter_bytes(self):
        remaining = self.total_bytes
        chunk = b"x" * CHUNK_BYTES
        while remaining > 0:
            size = min(CHUNK_BYTES, remaining)
            remaining -= size
            yield chunk[:size]


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


def before_full_body_read():
    body = bytearray()
    for chunk in ChunkedResponse(RESPONSE_BYTES).iter_bytes():
        body.extend(chunk)
    return {"read_mb": round(len(body) / 1024 / 1024, 2), "rejected": False}


def after_bounded_body_read():
    service = TaxiiService()
    service._response_max_bytes = LIMIT_BYTES
    try:
        service._read_response_bytes(ChunkedResponse(RESPONSE_BYTES))
    except TaxiiUpstreamError:
        return {"read_limit_mb": LIMIT_BYTES // 1024 // 1024, "rejected": True}
    return {"read_limit_mb": LIMIT_BYTES // 1024 // 1024, "rejected": False}


if __name__ == "__main__":
    before = measure("before_full_upstream_body_read", before_full_body_read)
    after = measure("after_bounded_streaming_read", after_bounded_body_read)
    print(
        {
            "response_mb": RESPONSE_BYTES // 1024 // 1024,
            "limit_mb": LIMIT_BYTES // 1024 // 1024,
            "before": before,
            "after": after,
        }
    )
