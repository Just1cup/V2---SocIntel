from __future__ import annotations

import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings


def _resolve_legacy_repo_path() -> Path:
    if settings.legacy_backend_path:
        return Path(settings.legacy_backend_path).resolve()
    return Path(__file__).resolve().parents[5] / "socintel"


def _load_legacy_analyze():
    legacy_repo = _resolve_legacy_repo_path()
    if not legacy_repo.exists():
        raise FileNotFoundError(f"Legacy SOCINTEL repository not found at {legacy_repo}")
    legacy_repo_str = str(legacy_repo)
    if legacy_repo_str not in sys.path:
        sys.path.insert(0, legacy_repo_str)
    from backend.orchestrator import analyze  # type: ignore

    return analyze


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def run_legacy_analysis(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    analyze = _load_legacy_analyze()
    result = analyze(ioc_type, ioc_value)
    payload = {
        "risk": result.risk,
        "level": str(result.level).lower(),
        "verdict": result.verdict,
        "findings": _jsonable(result.findings),
        "recommendations": _jsonable(result.recommendations),
        "risk_factors": _jsonable(result.risk_factors),
        "risk_meta": _jsonable(result.risk_meta),
        "timings_ms": _jsonable(result.timings_ms),
        "provider_details": _jsonable(getattr(result, "provider_data", None)),
    }
    return payload
