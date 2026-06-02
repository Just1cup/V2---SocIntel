"""Timing helpers."""
from __future__ import annotations

import time
from typing import Any, Callable


def time_call(fn: Callable[[], Any]) -> tuple[Any, int]:
    start = time.perf_counter()
    result = fn()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return result, elapsed_ms
