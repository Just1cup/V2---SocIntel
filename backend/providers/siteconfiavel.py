"""SiteConfiavel provider."""
from __future__ import annotations

from bs4 import BeautifulSoup
from urllib.parse import urlparse

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def analyze_target(ctx: AnalysisContext, target: str, config: Config) -> None:
    ctx.section_once("SiteConfiavel", "Classificação pública de confiança do site")
    domain = ""
    try:
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            domain = urlparse(target).netloc
        else:
            domain = target
        domain = domain.replace("www.", "")

        url = f"https://www.siteconfiavel.com.br/site/{domain}"
        headers = {"User-Agent": "Mozilla/5.0 (SOCINTEL OSINT Scanner)"}

        r = ctx.session.get(url, headers=headers, timeout=config.request_timeout_medium)
        if r.status_code != 200:
            ctx.add_finding("SiteConfiavel: não foi possível consultar")
            log_error("SiteConfiavel", f"HTTP {r.status_code} em {domain}")
            return

        soup = BeautifulSoup(r.text, "html.parser")
        page_text = soup.get_text(" ", strip=True).lower()

        if any(x in page_text for x in ["não é confiável", "nao é confiavel", "site perigoso", "site suspeito", "cuidado"]):
            ctx.add_finding("SiteConfiavel: ALERTA – site classificado como NÃO tendo as métricas de segurança necessárias.")
            ctx.add_risk(10, reason="classificado como não confiável", source="SiteConfiavel")
            ctx.add_hit()
        elif any(x in page_text for x in ["site confiável", "é confiável", "é seguro", "site seguro"]):
            ctx.add_finding("SiteConfiavel: site classificado como tendo as métricas de segurança necessárias.")
            ctx.add_risk(-20, reason="classificado como tendo as métricas de segurança necessárias!", source="SiteConfiavel")
        else:
            ctx.add_finding("SiteConfiavel: sem classificação clara")
    except Exception as exc:
        ctx.add_finding(f"SiteConfiavel: erro - {str(exc)}")
        log_error("SiteConfiavel", f"Falha ao consultar {domain}", exc)
