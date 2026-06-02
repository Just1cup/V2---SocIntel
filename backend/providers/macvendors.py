"""MACVendors provider."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error
from ..utils.net import normalize_mac


def analyze_mac(ctx: AnalysisContext, mac: str, config: Config) -> None:
    ctx.section_once("MAC Vendors", "Fabricante do dispositivo pelo prefixo MAC")
    mac = normalize_mac(mac)
    if not mac:
        ctx.add_finding("MAC Vendor: MAC inválido")
        return

    try:
        r = ctx.session.get(f"https://api.macvendors.com/{mac}", timeout=config.request_timeout_medium)
        if r.status_code == 200 and r.text:
            vendor = r.text.strip()
            ctx.add_finding(f"MAC Vendor: {vendor}")
            ctx.add_risk(1, reason="fabricante identificado", source="MAC Vendor")
            ctx.add_hit()
        elif r.status_code == 404:
            ctx.add_finding("MAC Vendor: fabricante não encontrado")
        else:
            ctx.add_finding(f"MAC Vendor: erro HTTP {r.status_code}")
    except Exception as exc:
        ctx.add_finding(f"MAC Vendor: erro - {str(exc)}")
        log_error("MAC Vendor", f"Falha ao consultar MAC {mac}", exc)
