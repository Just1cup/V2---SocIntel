"""AlienVault OTX provider."""
from __future__ import annotations

import time

import requests

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def _get_otx(ctx: AnalysisContext, url: str, headers: dict, timeout: int):
    # OTX can intermittently fail with SSLEOF; retry once with fresh connection semantics.
    try:
        return ctx.session.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.SSLError:
        time.sleep(0.35)
        retry_headers = {**headers, "Connection": "close"}
        return ctx.session.get(url, headers=retry_headers, timeout=timeout)


def analyze_ip(ctx: AnalysisContext, ip: str, config: Config) -> None:
    ctx.section_once("AlienVault OTX", "Threat intel comunitário via pulses")
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": config.otx_api_key}
    try:
        r = _get_otx(ctx, otx_url, headers, config.request_timeout_short)
        if r.status_code == 200:
            data = r.json()
            pulse_info = data.get("pulse_info", {}) or {}
            pulses = pulse_info.get("count", 0)
            ctx.update_provider_data(
                "AlienVault OTX",
                {
                    "kind": "ip",
                    "pulse_count": pulses,
                    "reputation": data.get("reputation"),
                    "sections": list(data.keys()),
                },
            )
            if pulses > 0:
                otx_score = min(pulses * 2, 30)
                ctx.add_risk(otx_score, reason=f"presente em {pulses} pulses", source="AlienVault OTX")
                ctx.add_hit()
                ctx.add_finding(f"AlienVault OTX: IP presente em {pulses} pulses (+{otx_score} pontos)")
            else:
                ctx.add_finding("AlienVault OTX: IP não encontrado em nenhum pulse")
        elif r.status_code == 401:
            ctx.add_finding("AlienVault OTX: API key inválida (HTTP 401)")
        else:
            ctx.add_finding(f"AlienVault OTX: status {r.status_code}")
            log_error("AlienVault OTX", f"HTTP {r.status_code} em IP {ip}")
    except requests.exceptions.SSLError:
        ctx.add_finding("AlienVault OTX: falha TLS/SSL ao consultar a API")
        log_error("AlienVault OTX", f"Falha TLS/SSL ao consultar IP {ip}")
    except Exception as exc:
        ctx.add_finding("AlienVault OTX: erro de conexão com a API")
        log_error("AlienVault OTX", f"Falha ao consultar IP {ip}", exc)


def analyze_domain(ctx: AnalysisContext, domain: str, config: Config) -> None:
    ctx.section_once("AlienVault OTX", "Threat intel comunitário via pulses")
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": config.otx_api_key}
    try:
        r = _get_otx(ctx, otx_url, headers, config.request_timeout_short)
        if r.status_code == 200:
            data = r.json()
            pulse_info = data.get("pulse_info", {}) or {}
            pulses = pulse_info.get("count", 0)
            ctx.update_provider_data(
                "AlienVault OTX",
                {
                    "kind": "domain",
                    "pulse_count": pulses,
                    "reputation": data.get("reputation"),
                    "sections": list(data.keys()),
                },
            )
            if pulses > 0:
                ctx.add_risk(25, reason=f"presente em {pulses} pulses", source="AlienVault OTX")
                ctx.add_hit()
                ctx.add_finding(f"AlienVault OTX: domínio presente em {pulses} pulses")
            else:
                ctx.add_finding("AlienVault OTX: domínio não encontrado em nenhum pulse")
        elif r.status_code == 401:
            ctx.add_finding("AlienVault OTX: API key inválida (HTTP 401)")
        else:
            ctx.add_finding(f"AlienVault OTX: status {r.status_code}")
            log_error("AlienVault OTX", f"HTTP {r.status_code} em domínio {domain}")
    except requests.exceptions.SSLError:
        ctx.add_finding("AlienVault OTX: falha TLS/SSL ao consultar a API")
        log_error("AlienVault OTX", f"Falha TLS/SSL ao consultar domínio {domain}")
    except Exception as exc:
        ctx.add_finding("AlienVault OTX: erro de conexão com a API")
        log_error("AlienVault OTX", f"Falha ao consultar domínio {domain}", exc)
