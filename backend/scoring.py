"""Risk scoring and recommendation rules."""
from __future__ import annotations

from .context import AnalysisContext


def risk_max(ioc_type: str) -> int:
    max_by_type = {
        "ip": 172,
        "domain": 95,
        "url": 40,
        "hash": 40,
        "email": 95,
        "mac": 10,
        "generic": 100,
        "web": 100,
    }
    return max_by_type.get(ioc_type, 100)


def risk_profile(ctx: AnalysisContext, ioc_type: str) -> tuple[int, str]:
    max_score = risk_max(ioc_type)
    normalized = int(min(max(ctx.raw_risk / max_score * 100, 0), 100))

    if normalized >= 70 and ctx.positive_hits < 2:
        normalized = 69
        ctx.add_finding("Validação: apenas uma fonte positiva; risco ajustado para evitar alertas isolados")

    if normalized >= 70:
        level = "ALTO"
    elif normalized >= 40:
        level = "MÉDIO"
    else:
        level = "BAIXO"

    return normalized, level


def risk_explanation(ctx: AnalysisContext, ioc_type: str, normalized: int, level: str) -> dict:
    max_score = risk_max(ioc_type)
    raw_normalized = int(min(max(ctx.raw_risk / max_score * 100, 0), 100))
    adjusted = raw_normalized >= 70 and ctx.positive_hits < 2
    notes = []
    if adjusted:
        notes.append("Validação: apenas uma fonte positiva; risco ajustado para evitar alertas isolados")

    factors = sorted(
        (rf.to_dict() for rf in (ctx.risk_factors or [])),
        key=lambda item: item.get("points", 0),
        reverse=True,
    )

    return {
        "raw_score": ctx.raw_risk,
        "max_score": max_score,
        "normalized": normalized,
        "level": level,
        "positive_hits": ctx.positive_hits,
        "adjusted": adjusted,
        "notes": notes,
        "factors": factors,
    }


def recommendations(ioc_type: str, level: str, normalized: int) -> list[str]:
    base = {
        "ALTO": [
            "Sinais fortes de maliciosidade nas bases consultadas",
            "Priorizar a correlação com logs e alertas do cliente",
        ],
        "MÉDIO": [
            "Indícios moderados nas bases consultadas",
            "Reforçar monitoramento e correlacionar com eventos internos",
        ],
        "BAIXO": [
            "Sem sinais relevantes nas bases consultadas",
            "Manter monitoramento e reavaliar se houver novos alertas",
        ],
    }
    by_ioc = {
        "ip": {
            "ALTO": ["IP listado como malicioso em múltiplas fontes; destacar para o cliente"],
            "MÉDIO": ["IP com sinais parciais; correlacionar com tráfego recente"],
            "BAIXO": ["IP não encontrado como malicioso nas bases consultadas; validar geolocalização/ASN"],
        },
        "domain": {
            "ALTO": ["Domínio com reputação negativa; correlacionar com acessos e alertas do cliente"],
            "MÉDIO": ["Domínio com sinais moderados; monitorar DNS/WHOIS e acessos"],
            "BAIXO": ["Domínio não encontrado como malicioso nas bases consultadas; acompanhar DNS/WHOIS"],
        },
        "url": {
            "ALTO": ["URL classificada como maliciosa; correlacionar com acessos do cliente"],
            "MÉDIO": ["URL com indícios; revisar contexto e origem"],
            "BAIXO": ["URL não encontrada como maliciosa nas bases consultadas; reavaliar se houver novos eventos"],
        },
        "hash": {
            "ALTO": ["Hash com detecções confirmadas; correlacionar com endpoints do cliente"],
            "MÉDIO": ["Hash com sinais parciais; verificar prevalência e origem"],
            "BAIXO": ["Hash não encontrado como malicioso nas bases consultadas; monitorar por novas detecções"],
        },
        "email": {
            "ALTO": ["Remetente/domínio com sinais de abuso; correlacionar com alertas de phishing"],
            "MÉDIO": ["Sinais moderados; verificar SPF/DMARC e reputação do domínio"],
            "BAIXO": ["Domínio do email não encontrado como malicioso nas bases consultadas; manter monitoramento"],
        },
        "mac": {
            "ALTO": ["MAC associado a fabricante suspeito; correlacionar com inventário do cliente"],
            "MÉDIO": ["MAC com fabricante incomum; monitorar comportamento na rede"],
            "BAIXO": ["Fabricante identificado; sem sinais de risco nas bases consultadas"],
        },
        "generic": {},
        "web": {},
    }
    recs = base[level] + by_ioc.get(ioc_type, {}).get(level, [])
    if normalized > 25 and ioc_type in {"ip", "domain", "url", "email", "hash"}:
        siem_queries = {
            "ip": "QRadar:\n- Como buscar: Add Filter (Source IP, Destination IP ou Source IP OR Destination IP)\n- Por quê: identificar origem/destino do tráfego e se o IP é atacante, vítima ou pivô\n- Group By: Source IP / Destination IP / Username",
            "domain": "QRadar:\n- Como buscar: Events -> botão direito no domínio -> Filter on value, depois Search e usar Group By\n- Por quê: comunicação suspeita (C2, download, exfiltração)\n- Group By: Destination IP / Hostname / Username",
            "url": "QRadar:\n- Como buscar: Add Filter (URL ou HTTP Request URL) ou Payload contains <URL>\n- Por quê: acesso a site malicioso ou download\n- Group By: URL / Source IP / Username",
            "email": "QRadar:\n- Como buscar: Add Filter (Sender, Recipient) ou Payload contains <email>\n- Por quê: phishing ou campanha de e-mail\n- Group By: Sender / Recipient / Subject",
            "hash": "QRadar:\n- Como buscar: Add Filter (Payload contains <hash>) e campos de processo (se houver)\n- Por quê: identificar execução de malware\n- Group By: Hostname / Process Name / Username",
            "mac": "QRadar:\n- Como buscar: Add Filter (MAC Address, Source MAC, Destination MAC)\n- Por quê: identificar dispositivo na rede\n- Group By: MAC / IP / Hostname",
        }
        recs.append(siem_queries.get(ioc_type, "Buscar no SIEM por eventos relacionados ao indicador"))
    return recs


def verdict(ioc_type: str, normalized: int, level: str) -> str:
    if level == "ALTO":
        return f"ALTO RISCO – provável ameaça. Score {normalized}/100"
    if level == "MÉDIO":
        return f"RISCO MÉDIO – análise adicional recomendada. Score {normalized}/100"
    return f"BAIXO RISCO – sem sinais relevantes nas bases consultadas. Score {normalized}/100"
