"""WHOIS provider."""
from __future__ import annotations

import socket

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error


def _whois_socket_lookup(domain: str) -> dict | None:
    try:
        whois_server = "whois.iana.org"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())

        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        sock.close()

        resp_text = response.decode("utf-8", errors="ignore")
        result = {"organization": None, "status": None, "created": None}

        for line in resp_text.split("\n"):
            line_lower = line.lower()
            if any(x in line_lower for x in ["organization:", "org:", "company:"]):
                result["organization"] = line.split(":", 1)[-1].strip()
            if "status:" in line_lower:
                result["status"] = line.split(":", 1)[-1].strip()
            if any(x in line_lower for x in ["created:", "creation date:", "created date:"]):
                result["created"] = line.split(":", 1)[-1].strip()
        return result
    except Exception:
        return None


def analyze_domain(ctx: AnalysisContext, domain: str, config: Config) -> None:
    del config
    ctx.section_once("WHOIS", "Registro do domínio e dados cadastrais")
    try:
        whois_data = _whois_socket_lookup(domain)
        if whois_data:
            ctx.update_provider_data(
                "WHOIS",
                {
                    "domain": domain,
                    "organization": whois_data.get("organization"),
                    "status": whois_data.get("status"),
                    "created": whois_data.get("created"),
                },
            )
            lines = [f"WHOIS: Dominio {domain}"]
            if whois_data.get("created"):
                lines.append(f"  └─ Registrado em: {whois_data['created']}")
            if whois_data.get("status"):
                lines.append(f"  └─ Status: {whois_data['status']}")
            if whois_data.get("organization"):
                lines.append(f"  └─ Organização: {whois_data['organization']}")
            else:
                lines.append("  └─ Organização: Não informada")
            ctx.extend_findings(lines)
        else:
            ctx.add_finding("WHOIS: falha ao obter dados")
            log_error("WHOIS", f"Falha ao obter dados do domínio {domain}")
    except Exception:
        ctx.add_finding("WHOIS: falha ao obter dados")
        log_error("WHOIS", f"Falha ao obter dados do domínio {domain}")
