"""Shodan provider (free mode via InternetDB)."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def _extract_int_from_label(text: str, label: str) -> int | None:
    pattern = rf"{re.escape(label)}\s*[:=]?\s*(\d+)"
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def _scrape_shodan_host_page(ctx: AnalysisContext, ip: str) -> bool:
    """Fallback scraping when InternetDB has no useful data."""
    page_url = f"https://www.shodan.io/host/{ip}"
    headers = {
        "User-Agent": "SOCINTEL/2.0 (shodan fallback scraping)",
        "Accept": "text/html,application/xhtml+xml",
    }
    try:
        r = ctx.session.get(page_url, headers=headers, timeout=10, allow_redirects=True)
    except Exception as exc:
        log_error("Shodan", f"Falha ao acessar página web para IP {ip}", exc)
        return False

    if r.status_code >= 400:
        log_error("Shodan", f"HTTP {r.status_code} ao acessar página web para IP {ip}")
        return False

    soup = BeautifulSoup(r.text or "", "html.parser")
    page_text = soup.get_text(" ", strip=True)

    open_ports = _extract_int_from_label(page_text, "Open Ports")
    vulnerabilities = _extract_int_from_label(page_text, "Vulnerabilities")

    # Best-effort: capture common "port/service" references shown in host pages.
    ports_found = sorted({int(p) for p in re.findall(r"\b([1-9]\d{1,4})/(?:tcp|udp)\b", page_text, re.IGNORECASE)})
    if not ports_found:
        ports_found = sorted({int(p) for p in re.findall(r"\bport\s+([1-9]\d{1,4})\b", page_text, re.IGNORECASE)})
    ports_found = [p for p in ports_found if 1 <= p <= 65535]

    has_signal = any(
        value is not None and value > 0
        for value in (open_ports, vulnerabilities)
    ) or bool(ports_found)

    if not has_signal:
        return False

    ctx.update_provider_data(
        "Shodan",
        {
            "source": "scraping",
            "open_ports": open_ports if open_ports is not None else len(ports_found),
            "vulnerabilities": vulnerabilities if vulnerabilities is not None else 0,
            "ports_found": ports_found,
        },
    )

    ctx.add_finding(
        "Shodan (scraping): "
        f"open_ports={open_ports if open_ports is not None else len(ports_found)} "
        f"vulns={vulnerabilities if vulnerabilities is not None else 0}"
    )

    if ports_found:
        ctx.add_finding(f"Shodan (scraping): portas observadas {', '.join(map(str, ports_found[:12]))}")
        port_score = min(len(ports_found), 10)
        ctx.add_risk(
            port_score,
            reason=f"{len(ports_found)} portas expostas detectadas via scraping",
            source="Shodan",
        )
        ctx.add_hit()

    if vulnerabilities and vulnerabilities > 0:
        vuln_score = min(vulnerabilities * 3, 15)
        ctx.add_risk(
            vuln_score,
            reason=f"{vulnerabilities} vulnerabilidades reportadas na página do Shodan",
            source="Shodan",
        )
        ctx.add_hit()

    return True


def analyze_ip(ctx: AnalysisContext, ip: str, config: Config) -> None:
    """Query Shodan InternetDB for a single IP (free/public endpoint)."""
    del config
    ctx.section_once("Shodan", "Serviços expostos e vulnerabilidades (modo free via InternetDB)")
    url = f"https://internetdb.shodan.io/{ip}"

    try:
        r = ctx.session.get(url, timeout=8)

        if r.status_code == 200:
            data = r.json()
            ports = data.get("ports") or []
            cpes = data.get("cpes") or []
            vulns = data.get("vulns") or []
            hostnames = data.get("hostnames") or []
            ctx.update_provider_data(
                "Shodan",
                {
                    "source": "internetdb",
                    "open_ports": len(ports),
                    "ports": ports,
                    "cpes": cpes,
                    "vulnerabilities": len(vulns),
                    "vulns": vulns,
                    "hostnames": hostnames,
                },
            )

            ctx.add_finding(
                "Shodan: "
                f"open_ports={len(ports)} vulns={len(vulns)} cpes={len(cpes)} hostnames={len(hostnames)}"
            )

            if ports:
                port_score = min(len(ports), 15)
                ctx.add_risk(
                    port_score,
                    reason=f"{len(ports)} portas expostas detectadas",
                    source="Shodan",
                )
                ctx.add_hit()
            else:
                ctx.add_finding("Shodan: nenhuma porta exposta reportada")

            if vulns:
                vuln_score = min(len(vulns) * 4, 20)
                ctx.add_risk(
                    vuln_score,
                    reason=f"{len(vulns)} vulnerabilidades reportadas no InternetDB",
                    source="Shodan",
                )
                ctx.add_hit()
                ctx.add_finding(f"Shodan: vulnerabilidades reportadas={len(vulns)}")

            if hostnames:
                ctx.add_finding(f"Shodan: hostnames {', '.join(hostnames[:6])}")
            return

        if r.status_code == 404:
            ctx.add_finding("Shodan: IP não encontrado no InternetDB (modo free)")
            if _scrape_shodan_host_page(ctx, ip):
                ctx.add_finding("Shodan: fallback por scraping web aplicado")
            return

        ctx.add_finding(f"Shodan: status {r.status_code}")
        if _scrape_shodan_host_page(ctx, ip):
            ctx.add_finding("Shodan: fallback por scraping web aplicado")
        log_error("Shodan", f"HTTP {r.status_code} em IP {ip}")

    except Exception as exc:
        # Keep output safe and concise.
        ctx.add_finding("Shodan: erro de conexão com a API")
        if _scrape_shodan_host_page(ctx, ip):
            ctx.add_finding("Shodan: fallback por scraping web aplicado")
        log_error("Shodan", f"Falha ao consultar IP {ip}", exc)
