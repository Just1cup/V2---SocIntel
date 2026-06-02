"""Mutable analysis context (state + synchronization)."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

import requests

from .models import RiskFactor


class AnalysisContext:
    def __init__(self, ioc_type: str = "generic") -> None:
        self.raw_risk = 0
        self.findings: list[str] = []
        self.sections: set[str] = set()
        self.lock = threading.Lock()
        self.positive_hits = 0
        self.active_ioc_type = ioc_type
        self.timings: dict[str, int] = {}
        self.risk_factors: list[RiskFactor] = []
        self.provider_data: dict[str, dict[str, Any]] = {}
        self.urlscan_timeout = False
        self.urlscan_result_url: str | None = None
        self.urlscan_summary: dict[str, Any] = {
            "url": None,
            "type": None,
            "task": {
                "reportURL": None,
                "screenshotURL": None,
            },
        }
        self.session = requests.Session()

    def add_risk(self, delta: int, reason: str | None = None, source: str | None = None) -> None:
        with self.lock:
            self.raw_risk += delta
            if reason:
                self.risk_factors.append(RiskFactor(reason=reason, points=delta, source=source))

    def add_hit(self) -> None:
        with self.lock:
            self.positive_hits += 1

    def add_finding(self, message: str) -> None:
        with self.lock:
            self.findings.append(message)

    def extend_findings(self, messages: list[str]) -> None:
        with self.lock:
            self.findings.extend(messages)

    def section_once(self, title: str, desc: str) -> None:
        key = title.lower()
        with self.lock:
            if key in self.sections:
                return
            self.sections.add(key)
            self.findings.append(f"=== {title} — {desc} ===")

    def update_provider_data(self, provider: str, payload: dict[str, Any]) -> None:
        key = provider.strip()
        with self.lock:
            current = self.provider_data.get(key, {})
            current.update(payload)
            self.provider_data[key] = current

    def timeit(self, name: str, fn: Callable[[], Any]) -> Any:
        start = time.perf_counter()
        try:
            return fn()
        finally:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            with self.lock:
                self.timings[name] = elapsed_ms
