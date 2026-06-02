"""Blacklist Master scraping provider."""
from __future__ import annotations

from bs4 import BeautifulSoup
from urllib.parse import quote_plus

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def _find_blacklist_table(soup: BeautifulSoup):
    for table in soup.find_all("table"):
        attrs = [table.get("id", ""), " ".join(table.get("class", []) or [])]
        if any("myip800" in str(value).lower() for value in attrs):
            return table

    for candidate in soup.find_all("table"):
        txt = candidate.get_text(" ", strip=True).lower()
        if "status" in txt and ("blacklist" in txt or "not listed" in txt):
            return candidate
    return None


def _extract_blacklist_counts_from_table(soup: BeautifulSoup) -> tuple[int, int] | None:
    table = _find_blacklist_table(soup)
    if table is None:
        return None

    status_index = None
    header = table.find("tr")
    if header:
        header_cells = header.find_all(["th", "td"])
        for idx, cell in enumerate(header_cells):
            if "status" in cell.get_text(" ", strip=True).lower():
                status_index = idx
                break

    total = 0
    listed = 0

    for row in table.find_all("tr"):
        cells = row.find_all("td")
        if not cells:
            continue
        total += 1

        if status_index is not None and status_index < len(cells):
            status_text = cells[status_index].get_text(" ", strip=True).lower()
        else:
            status_text = cells[-1].get_text(" ", strip=True).lower()

        # Regra solicitada:
        # - "not listed" => não conta
        # - qualquer outro status => conta como listado (+1)
        if "not listed" not in status_text:
            listed += 1

    if total == 0:
        return None
    if listed > total:
        listed = total
    return listed, total
    return None


def analyze_domain(ctx: AnalysisContext, domain: str, config: Config) -> None:
    del config
    ctx.section_once("Blacklist Master", "Verificação pública de domínio em listas de bloqueio")
    domain = (domain or "").strip().lower()
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    domain = domain.split("/", 1)[0]
    if not domain:
        ctx.add_finding("Blacklist Master: domínio inválido")
        return

    urls = [
        f"https://blacklistmaster.com/?s={quote_plus(domain)}",
        f"https://www.blacklistmaster.com/?s={quote_plus(domain)}",
        f"https://blacklistmaster.com/check?s={quote_plus(domain)}",
        f"https://www.blacklistmaster.com/check?s={quote_plus(domain)}",
    ]
    headers = {"User-Agent": "Mozilla/5.0 (SOCINTEL OSINT Scanner)"}

    last_error = None
    for url in urls:
        try:
            r = ctx.session.get(url, headers=headers, timeout=8)
            if r.status_code != 200:
                last_error = f"HTTP {r.status_code}"
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            counts = _extract_blacklist_counts_from_table(soup)
            if counts is not None:
                listed, total = counts
                ctx.add_finding(f"Blacklist Master: domínio presente em {listed} de {total} blacklists")
                if listed > 0:
                    score = min(listed * 3, 25)
                    ctx.add_risk(
                        score,
                        reason=f"domínio presente em {listed} de {total} blacklists",
                        source="Blacklist Master",
                    )
                    ctx.add_hit()
                return
        except Exception as exc:
            last_error = str(exc)
            log_error("Blacklist Master", f"Falha ao consultar {domain} via {url}", exc)

    ctx.add_finding("Blacklist Master: não foi possível consultar")
    if last_error:
        log_error("Blacklist Master", f"Consulta indisponível para {domain}: {last_error}")
