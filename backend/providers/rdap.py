"""RDAP provider."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def analyze_ip(ctx: AnalysisContext, ip: str, config: Config) -> None:
    del config
    ctx.section_once("RDAP", "Registro do provedor, país e range do IP")

    endpoints = [
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
        f"https://rdap.lacnic.net/rdap/ip/{ip}",
    ]

    for url in endpoints:
        try:
            r = ctx.session.get(url, timeout=8)
            if r.status_code != 200:
                continue

            data = r.json()
            name = data.get("name") or data.get("handle") or "unknown"
            country = data.get("country") or "unknown"
            start = data.get("startAddress") or ""
            end = data.get("endAddress") or ""
            ctx.update_provider_data(
                "RDAP",
                {
                    "owner": name,
                    "country": country,
                    "range_start": start,
                    "range_end": end,
                    "handle": data.get("handle"),
                    "parent_handle": data.get("parentHandle"),
                    "ip_version": data.get("ipVersion"),
                    "name": data.get("name"),
                    "type": data.get("type"),
                },
            )

            ctx.add_finding(f"RDAP: owner={name} country={country} range={start}-{end}")
            ctx.add_risk(2, reason="dados de registro e range obtidos", source="RDAP")
            return
        except Exception:
            continue

    ctx.add_finding("RDAP: não foi possível obter dados (endpoints falharam)")
    log_error("RDAP", f"Falha ao consultar RDAP para IP {ip}")
