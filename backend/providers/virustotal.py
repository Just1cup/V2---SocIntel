"""VirusTotal provider functions."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def analyze_ip(ctx: AnalysisContext, ip: str, config: Config) -> None:
    ctx.section_once("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.vt_api_key}
    try:
        r = ctx.session.get(vt_url, headers=headers, timeout=config.request_timeout_short)
        if r.status_code == 200:
            attributes = r.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            ctx.update_provider_data(
                "VirusTotal",
                {
                    "kind": "ip",
                    "last_analysis_stats": stats,
                    "reputation": attributes.get("reputation"),
                    "country": attributes.get("country"),
                    "as_owner": attributes.get("as_owner"),
                    "asn": attributes.get("asn"),
                    "network": attributes.get("network"),
                    "tags": attributes.get("tags") or [],
                },
            )
            mal = stats.get("malicious", 0)
            if mal > 0:
                vt_score = mal * 5
                ctx.add_risk(vt_score, reason=f"{mal} detecções maliciosas", source="VirusTotal")
                ctx.add_hit()
                ctx.add_finding(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
            else:
                ctx.add_finding("VirusTotal: nenhuma detecção maliciosa")
        else:
            ctx.add_finding(f"VirusTotal: status {r.status_code}")
            log_error("VirusTotal", f"HTTP {r.status_code} em IP {ip}")
    except Exception as exc:
        ctx.add_finding(f"VirusTotal: erro - {str(exc)}")
        log_error("VirusTotal", f"Falha ao consultar IP {ip}", exc)


def analyze_domain(ctx: AnalysisContext, domain: str, config: Config) -> None:
    ctx.section_once("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": config.vt_api_key}
    try:
        r = ctx.session.get(vt_url, headers=headers, timeout=config.request_timeout_short)
        if r.status_code == 200:
            attributes = r.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            ctx.update_provider_data(
                "VirusTotal",
                {
                    "kind": "domain",
                    "last_analysis_stats": stats,
                    "reputation": attributes.get("reputation"),
                    "categories": attributes.get("categories") or {},
                    "creation_date": attributes.get("creation_date"),
                    "last_modification_date": attributes.get("last_modification_date"),
                    "registrar": attributes.get("registrar"),
                    "tags": attributes.get("tags") or [],
                },
            )
            mal = stats.get("malicious", 0)
            if mal > 0:
                vt_score = mal * 5
                ctx.add_risk(vt_score, reason=f"{mal} detecções maliciosas", source="VirusTotal")
                ctx.add_hit()
                ctx.add_finding(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
            else:
                ctx.add_finding("VirusTotal: nenhuma detecção maliciosa")
        else:
            log_error("VirusTotal", f"HTTP {r.status_code} em domínio {domain}")
    except Exception as exc:
        ctx.add_finding(f"VirusTotal: erro - {str(exc)}")
        log_error("VirusTotal", f"Falha ao consultar domínio {domain}", exc)


def analyze_hash(ctx: AnalysisContext, hash_value: str, config: Config) -> None:
    ctx.section_once("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": config.vt_api_key}
    try:
        r = ctx.session.get(vt_url, headers=headers, timeout=config.request_timeout_short)
        if r.status_code == 200:
            attributes = r.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            ctx.update_provider_data(
                "VirusTotal",
                {
                    "kind": "hash",
                    "last_analysis_stats": stats,
                    "meaningful_name": attributes.get("meaningful_name"),
                    "names": attributes.get("names") or [],
                    "sha256": attributes.get("sha256"),
                    "size": attributes.get("size"),
                    "type_description": attributes.get("type_description"),
                    "times_submitted": attributes.get("times_submitted"),
                },
            )
            mal = stats.get("malicious", 0)
            if mal > 0:
                vt_score = mal * 5
                ctx.add_risk(vt_score, reason=f"{mal} detecções maliciosas", source="VirusTotal")
                ctx.add_hit()
                ctx.add_finding(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
            else:
                ctx.add_finding("VirusTotal: hash não detectado como malicioso")

            file_name = attributes.get("meaningful_name")
            if not file_name:
                names = attributes.get("names") or []
                if names:
                    file_name = names[0]
            if file_name:
                ctx.add_finding(f"VirusTotal: nome do executável {file_name}")
        else:
            ctx.add_finding(f"VirusTotal: status {r.status_code}")
            log_error("VirusTotal", f"HTTP {r.status_code} em hash {hash_value}")
    except Exception as exc:
        ctx.add_finding(f"VirusTotal: erro - {str(exc)}")
        log_error("VirusTotal", f"Falha ao consultar hash {hash_value}", exc)
