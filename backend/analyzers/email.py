"""Email analyzer wrapper."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from . import domain as domain_analyzer


def analyze(ctx: AnalysisContext, email: str, config: Config) -> None:
    if "@" not in email:
        ctx.add_finding("Email inválido")
        return
    domain = email.split("@")[1]
    ctx.section_once("Email", "Extração do domínio para análise")
    ctx.add_finding(f"Domínio do email: {domain}")
    domain_analyzer.analyze(ctx, domain, config)
