"""High-level orchestration entrypoints."""
from __future__ import annotations

from .analyzers import domain, email, hash as hash_analyzer, ip, mac, web
from .config import Config, load_config
from .context import AnalysisContext
from .models import AnalysisResult
from .scoring import recommendations, risk_explanation, risk_profile, verdict
from .utils.logging import log_error


_HANDLER_BY_TYPE = {
    "ip": ip.analyze,
    "web": web.analyze,
    "domain": web.analyze,
    "url": web.analyze,
    "email": email.analyze,
    "hash": hash_analyzer.analyze,
    "mac": mac.analyze,
}


def _build_result(ctx: AnalysisContext, ioc_type: str) -> AnalysisResult:
    normalized, level = risk_profile(ctx, ioc_type)
    explanation = risk_explanation(ctx, ioc_type, normalized, level)
    return AnalysisResult(
        risk=normalized,
        level=level,
        findings=list(ctx.findings),
        verdict=verdict(ioc_type, normalized, level),
        recommendations=recommendations(ioc_type, level, normalized),
        risk_factors=explanation["factors"],
        risk_meta={
            "raw_score": explanation["raw_score"],
            "max_score": explanation["max_score"],
            "level": explanation["level"],
            "positive_hits": explanation["positive_hits"],
            "adjusted": explanation["adjusted"],
            "notes": explanation["notes"],
            "urlscan_timeout": ctx.urlscan_timeout,
            "urlscan_result_url": ctx.urlscan_result_url,
            "urlscan_summary": ctx.urlscan_summary,
        },
        timings_ms=dict(ctx.timings),
        provider_data=dict(ctx.provider_data),
    )


def analyze(ioc_type: str, value: str, config: Config | None = None) -> AnalysisResult:
    conf = config or load_config()
    ctx = AnalysisContext(ioc_type=ioc_type)
    handler = _HANDLER_BY_TYPE.get(ioc_type)
    if handler and value:
        try:
            handler(ctx, value, conf)
        except Exception as exc:
            log_error(f"{ioc_type}_intel", f"Falha ao processar {ioc_type}: {value}", exc)
    return _build_result(ctx, ioc_type)


def analyze_many(iocs: list[tuple[str, str]], config: Config | None = None) -> AnalysisResult:
    conf = config or load_config()
    ctx = AnalysisContext(ioc_type="generic")
    final_ioc_type = "generic"

    for ioc_type, value in iocs:
        if not value:
            continue
        handler = _HANDLER_BY_TYPE.get(ioc_type)
        if not handler:
            continue
        final_ioc_type = ioc_type
        ctx.active_ioc_type = ioc_type
        try:
            handler(ctx, value, conf)
        except Exception as exc:
            log_error(f"{ioc_type}_intel", f"Falha ao processar {ioc_type}: {value}", exc)

    return _build_result(ctx, final_ioc_type)
