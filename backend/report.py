"""Output rendering helpers."""
from __future__ import annotations

import json

from .models import AnalysisResult


def render_human(result: AnalysisResult) -> str:
    lines = []
    lines.append("\n🔎 SOCINTEL - RESULTADO\n")
    lines.append(f"RISK SCORE: {result.risk}/100 ({result.level})\n")
    lines.append("🧭 COMO O SCORE FOI CALCULADO:")
    if result.risk_factors:
        for factor in result.risk_factors:
            points = factor.get("points", 0)
            sign = "+" if points >= 0 else ""
            source = factor.get("source")
            reason = factor.get("reason", "fator não especificado")
            prefix = f"{source}: " if source else ""
            lines.append(f"- {sign}{points} {prefix}{reason}")
    else:
        lines.append("- Nenhum fator de risco positivo foi identificado")
    lines.append(f"Score: {result.risk}/100 ({result.level})")
    for note in result.risk_meta.get("notes", []):
        lines.append(f"- {note}")
    for finding in result.findings:
        lines.append(f"✔ {finding}")
    lines.append("\n📌 VEREDITO SOC:")
    lines.append(result.verdict)
    lines.append("\n✅ RECOMENDAÇÕES:")
    for rec in result.recommendations:
        lines.append(f"- {rec}")
    return "\n".join(lines)


def render_json(result: AnalysisResult) -> str:
    return json.dumps(
        {
            "risk": result.risk,
            "level": result.level,
            "findings": result.findings,
            "verdict": result.verdict,
            "recommendations": result.recommendations,
            "risk_factors": result.risk_factors,
            "risk_meta": result.risk_meta,
            "timings_ms": result.timings_ms,
        }
    )
