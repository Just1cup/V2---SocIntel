"""Domain models for SOCINTEL analysis."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class RiskFactor:
    reason: str
    points: int
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    section: str
    message: str


@dataclass
class AnalysisResult:
    risk: int
    level: str
    findings: list[str]
    verdict: str
    recommendations: list[str]
    risk_factors: list[dict[str, Any]]
    risk_meta: dict[str, Any]
    timings_ms: dict[str, int]
    provider_data: dict[str, Any] | None = None
