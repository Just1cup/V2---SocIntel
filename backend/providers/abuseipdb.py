"""AbuseIPDB provider."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def analyze_ip(ctx: AnalysisContext, ip: str, config: Config) -> None:
    ctx.section_once("AbuseIPDB", "Histórico de abuso reportado para IPs")
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.abuse_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = ctx.session.get(abuse_url, headers=headers, params=params, timeout=config.request_timeout_short)
        if r.status_code == 200:
            data = r.json()["data"]
            score = data["abuseConfidenceScore"]
            ctx.update_provider_data(
                "AbuseIPDB",
                {
                    "abuse_confidence_score": score,
                    "total_reports": data.get("totalReports"),
                    "country_code": data.get("countryCode"),
                    "country_name": data.get("countryName"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "hostnames": data.get("hostnames") or [],
                    "is_public": data.get("isPublic"),
                    "is_whitelisted": data.get("isWhitelisted"),
                    "last_reported_at": data.get("lastReportedAt"),
                },
            )
            if score > 0:
                ctx.add_risk(score, reason=f"abuseConfidenceScore {score}%", source="AbuseIPDB")
                ctx.add_hit()
                ctx.add_finding(f"AbuseIPDB: score {score}% (+{score} pontos)")
            else:
                ctx.add_finding("AbuseIPDB: score 0% (sem risco)")
        else:
            ctx.add_finding(f"AbuseIPDB: status {r.status_code}")
            log_error("AbuseIPDB", f"HTTP {r.status_code} em IP {ip}")
    except Exception as exc:
        ctx.add_finding(f"AbuseIPDB: erro - {str(exc)}")
        log_error("AbuseIPDB", f"Falha ao consultar IP {ip}", exc)
