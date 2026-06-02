"""DNS provider."""
from __future__ import annotations

import dns.resolver

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def analyze_domain(ctx: AnalysisContext, domain: str, config: Config) -> None:
    del config
    ctx.section_once("DNS", "Presença de MX e sinais de infraestrutura")
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = [str(answer.exchange).rstrip(".") for answer in answers]
        ctx.update_provider_data(
            "DNS",
            {
                "domain": domain,
                "mx_present": True,
                "mx_records": records,
            },
        )
        ctx.add_finding("MX record presente (envio de e-mail possível)")
    except Exception:
        ctx.update_provider_data(
            "DNS",
            {
                "domain": domain,
                "mx_present": False,
                "mx_records": [],
            },
        )
        ctx.add_risk(20, reason="sem MX record (domínio suspeito)", source="DNS")
        ctx.add_hit()
        ctx.add_finding("Sem MX record (domínio suspeito)")
        log_error("DNS", f"Falha ao resolver MX de {domain}")
