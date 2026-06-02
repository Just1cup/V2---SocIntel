from __future__ import annotations

import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings

REPO_ROOT = Path(__file__).resolve().parents[4]


def _resolve_legacy_repo_path() -> Path:
    if settings.legacy_backend_path:
        legacy_path = Path(settings.legacy_backend_path)
        if legacy_path.is_absolute():
            return legacy_path.resolve()
        return (REPO_ROOT / legacy_path).resolve()
    return REPO_ROOT


def _load_legacy_modules():
    legacy_repo = _resolve_legacy_repo_path()
    if not legacy_repo.exists():
        raise FileNotFoundError(f"Legacy SOCINTEL repository not found at {legacy_repo}")
    legacy_repo_str = str(legacy_repo)
    if legacy_repo_str not in sys.path:
        sys.path.insert(0, legacy_repo_str)
    from backend.orchestrator import analyze  # type: ignore
    from backend.config import Config  # type: ignore

    return analyze, Config


def _build_legacy_config(legacy_config_cls):
    return legacy_config_cls(
        vt_api_key=settings.vt_api_key,
        abuse_api_key=settings.abuse_api_key,
        otx_api_key=settings.otx_api_key,
        urlscan_api_key=settings.urlscan_api_key,
        shodan_api_key=settings.shodan_api_key,
    )


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def _resolve_ioc_type(ioc_type: str, ioc_value: str) -> str:
    if ioc_type == "domain_email":
        return "email" if "@" in ioc_value else "domain"
    return ioc_type


def run_legacy_analysis(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    analyze, legacy_config_cls = _load_legacy_modules()
    resolved_ioc_type = _resolve_ioc_type(ioc_type, ioc_value)
    result = analyze(
        resolved_ioc_type,
        ioc_value,
        config=_build_legacy_config(legacy_config_cls),
    )
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
