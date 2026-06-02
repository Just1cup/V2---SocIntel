from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import settings


ABUSE_CH_USER_AGENT = "SOCINTEL/2.0 abuse.ch enrichment"
URLHAUS_BASE_URL = "https://urlhaus-api.abuse.ch/v1"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
RDAP_ENDPOINTS = (
    "https://rdap.org/ip/{ip}",
    "https://rdap.arin.net/registry/ip/{ip}",
    "https://rdap.db.ripe.net/ip/{ip}",
    "https://rdap.apnic.net/ip/{ip}",
    "https://rdap.lacnic.net/rdap/ip/{ip}",
    "https://rdap.afrinic.net/rdap/ip/{ip}",
)
FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
PROVIDER_ERROR_STATUS = {
    "auth_failed",
    "no_api_key",
    "invalid_api_key",
    "auth_key_invalid",
    "user_blacklisted",
    "rate_limited",
    "upstream_error",
    "network_error",
    "invalid_json",
}


@dataclass(frozen=True)
class EnrichmentSignal:
    source: str
    risk_delta: int
    finding: str
    details: dict[str, Any]


def _safe_hostname(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    candidate = candidate.strip().strip(".").lower()
    if not candidate or "/" in candidate or len(candidate) > 253:
        return None
    return candidate


def _is_public_host(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname not in {"localhost", "local"}
    return ip.is_global


def _is_hash(value: str) -> bool:
    cleaned = value.strip().lower()
    return len(cleaned) in {32, 40, 64} and all(char in "0123456789abcdef" for char in cleaned)


def _urlhaus_headers() -> dict[str, str]:
    headers = dict(FORM_HEADERS)
    auth_key = settings.abuse_ch_api_key or settings.urlhaus_auth_key
    if auth_key:
        headers["Auth-Key"] = auth_key
    return headers


def _malwarebazaar_headers() -> dict[str, str]:
    headers = dict(FORM_HEADERS)
    auth_key = settings.malwarebazaar_api_key or settings.abuse_ch_api_key
    if auth_key:
        headers["Auth-Key"] = auth_key
    return headers


def _post_form(
    client: httpx.Client,
    url: str,
    data: dict[str, str],
    headers: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    try:
        response = client.post(url, data=data, headers=headers or FORM_HEADERS)
    except httpx.HTTPError as exc:
        return {"query_status": "network_error", "error": exc.__class__.__name__}
    if response.status_code == 401:
        return {"query_status": "auth_failed"}
    if response.status_code == 429:
        return {"query_status": "rate_limited"}
    if response.status_code >= 400:
        return {"query_status": "upstream_error", "http_status": response.status_code}
    try:
        payload = response.json()
    except ValueError:
        return {"query_status": "invalid_json"}
    return payload if isinstance(payload, dict) else None


def _provider_error_signal(source: str, scope: str, payload: dict[str, Any]) -> EnrichmentSignal | None:
    status = str(payload.get("query_status") or "")
    if status not in PROVIDER_ERROR_STATUS:
        return None
    return EnrichmentSignal(
        source=source,
        risk_delta=0,
        finding=f"{source}: integração indisponível para {scope} ({status})",
        details={"query_status": status, "status": "error", "http_status": payload.get("http_status")},
    )


def _urlhaus_url_signal(client: httpx.Client, url_value: str) -> EnrichmentSignal | None:
    payload = _post_form(client, f"{URLHAUS_BASE_URL}/url/", {"url": url_value}, _urlhaus_headers())
    if not payload:
        return None
    status = str(payload.get("query_status") or "")
    if error_signal := _provider_error_signal("URLhaus", "URL", payload):
        return error_signal
    if status in {"no_results", "invalid_url"}:
        return EnrichmentSignal(
            source="URLhaus",
            risk_delta=0,
            finding="URLhaus: URL não encontrada na base de distribuição de malware",
            details={"query_status": status},
        )
    if status != "ok":
        return EnrichmentSignal(
            source="URLhaus",
            risk_delta=0,
            finding=f"URLhaus: consulta de URL retornou {status}",
            details={"query_status": status},
        )
    threat = payload.get("threat") or "malware"
    url_status = payload.get("url_status") or "unknown"
    tags = payload.get("tags") if isinstance(payload.get("tags"), list) else []
    risk_delta = 35 if url_status == "online" else 20
    return EnrichmentSignal(
        source="URLhaus",
        risk_delta=risk_delta,
        finding=f"URLhaus: URL associada a {threat} com status {url_status}",
        details={
            "query_status": status,
            "url_status": url_status,
            "threat": threat,
            "tags": tags[:10],
            "firstseen": payload.get("date_added") or payload.get("firstseen"),
            "urlhaus_reference": payload.get("urlhaus_reference"),
            "payloads": payload.get("payloads") if isinstance(payload.get("payloads"), list) else [],
        },
    )


def _urlhaus_host_signal(client: httpx.Client, host: str) -> EnrichmentSignal | None:
    if not _is_public_host(host):
        return None
    payload = _post_form(client, f"{URLHAUS_BASE_URL}/host/", {"host": host}, _urlhaus_headers())
    if not payload:
        return None
    status = str(payload.get("query_status") or "")
    if error_signal := _provider_error_signal("URLhaus", "host", payload):
        return error_signal
    if status == "no_results":
        return EnrichmentSignal(
            source="URLhaus",
            risk_delta=0,
            finding="URLhaus: host não encontrado na base de malware URLs",
            details={"query_status": status},
        )
    if status != "ok":
        return EnrichmentSignal(
            source="URLhaus",
            risk_delta=0,
            finding=f"URLhaus: consulta de host retornou {status}",
            details={"query_status": status},
        )
    urls = payload.get("urls") if isinstance(payload.get("urls"), list) else []
    online_count = sum(1 for item in urls if isinstance(item, dict) and item.get("url_status") == "online")
    risk_delta = min(20 + online_count * 5, 45)
    return EnrichmentSignal(
        source="URLhaus",
        risk_delta=risk_delta,
        finding=f"URLhaus: host presente em {len(urls)} URLs maliciosas ({online_count} online)",
        details={
            "query_status": status,
            "host": host,
            "url_count": len(urls),
            "online_count": online_count,
            "urls": urls[:10],
        },
    )


def _urlhaus_payload_signal(client: httpx.Client, hash_value: str) -> EnrichmentSignal | None:
    if len(hash_value) == 32:
        payload = _post_form(client, f"{URLHAUS_BASE_URL}/payload/", {"md5_hash": hash_value}, _urlhaus_headers())
    elif len(hash_value) == 64:
        payload = _post_form(client, f"{URLHAUS_BASE_URL}/payload/", {"sha256_hash": hash_value}, _urlhaus_headers())
    else:
        return None
    if not payload:
        return None
    status = str(payload.get("query_status") or "")
    if error_signal := _provider_error_signal("URLhaus", "payload", payload):
        return error_signal
    if status == "no_results":
        return EnrichmentSignal(
            source="URLhaus",
            risk_delta=0,
            finding="URLhaus: hash não encontrado em payloads coletados",
            details={"query_status": status},
        )
    if status != "ok":
        return EnrichmentSignal(
            source="URLhaus",
            risk_delta=0,
            finding=f"URLhaus: consulta de payload retornou {status}",
            details={"query_status": status},
        )
    signature = payload.get("signature") or "payload malicioso"
    urls = payload.get("urls") if isinstance(payload.get("urls"), list) else []
    return EnrichmentSignal(
        source="URLhaus",
        risk_delta=45,
        finding=f"URLhaus: hash observado como {signature} em {len(urls)} URLs",
        details={
            "query_status": status,
            "signature": signature,
            "firstseen": payload.get("firstseen"),
            "file_type": payload.get("file_type"),
            "file_size": payload.get("file_size"),
            "urls": urls[:10],
        },
    )


def _malwarebazaar_signal(client: httpx.Client, hash_value: str) -> EnrichmentSignal | None:
    payload = _post_form(
        client,
        MALWAREBAZAAR_URL,
        {"query": "get_info", "hash": hash_value},
        _malwarebazaar_headers(),
    )
    if not payload:
        return None
    status = str(payload.get("query_status") or "")
    if error_signal := _provider_error_signal("MalwareBazaar", "hash", payload):
        return error_signal
    if status == "hash_not_found":
        return EnrichmentSignal(
            source="MalwareBazaar",
            risk_delta=0,
            finding="MalwareBazaar: hash não encontrado",
            details={"query_status": status},
        )
    if status != "ok":
        return EnrichmentSignal(
            source="MalwareBazaar",
            risk_delta=0,
            finding=f"MalwareBazaar: consulta retornou {status}",
            details={"query_status": status},
        )
    data = payload.get("data") if isinstance(payload.get("data"), list) else []
    sample = data[0] if data and isinstance(data[0], dict) else {}
    signature = sample.get("signature") or "malware"
    tags = sample.get("tags") if isinstance(sample.get("tags"), list) else []
    return EnrichmentSignal(
        source="MalwareBazaar",
        risk_delta=50,
        finding=f"MalwareBazaar: hash associado a {signature}",
        details={
            "query_status": status,
            "signature": signature,
            "tags": tags[:10],
            "first_seen": sample.get("first_seen"),
            "file_type": sample.get("file_type"),
            "file_name": sample.get("file_name"),
            "delivery_method": sample.get("delivery_method"),
            "sha256_hash": sample.get("sha256_hash"),
            "yara_rules": sample.get("yara_rules") if isinstance(sample.get("yara_rules"), list) else [],
        },
    )


def _rdap_ip_signal(client: httpx.Client, ip_value: str) -> EnrichmentSignal | None:
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    if not ip.is_global:
        return None

    for endpoint in RDAP_ENDPOINTS:
        try:
            response = client.get(endpoint.format(ip=ip_value), headers={"Accept": "application/rdap+json, application/json"})
            if response.status_code != 200:
                continue
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue

        name = payload.get("name") or payload.get("handle") or "unknown"
        country = payload.get("country") or "unknown"
        start = payload.get("startAddress") or ""
        end = payload.get("endAddress") or ""
        return EnrichmentSignal(
            source="RDAP",
            risk_delta=2,
            finding=f"RDAP: owner={name} country={country} range={start}-{end}",
            details={
                "owner": name,
                "country": country,
                "range_start": start,
                "range_end": end,
                "handle": payload.get("handle"),
                "parent_handle": payload.get("parentHandle"),
                "ip_version": payload.get("ipVersion"),
                "name": payload.get("name"),
                "type": payload.get("type"),
                "source_endpoint": endpoint.format(ip=ip_value),
            },
        )
    return None


def enrich_ioc(ioc_type: str, ioc_value: str) -> list[EnrichmentSignal]:
    if not settings.enable_abuse_ch_enrichment:
        return []

    value = ioc_value.strip()
    if not value:
        return []

    timeout = httpx.Timeout(settings.ioc_enrichment_timeout_seconds)
    headers = {"User-Agent": ABUSE_CH_USER_AGENT}
    signals: list[EnrichmentSignal] = []

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=False) as client:
        if ioc_type in {"url", "web"} or value.startswith(("http://", "https://")):
            url_signal = _urlhaus_url_signal(client, value)
            if url_signal:
                signals.append(url_signal)
            host = _safe_hostname(value)
            if host:
                host_signal = _urlhaus_host_signal(client, host)
                if host_signal:
                    signals.append(host_signal)
        elif ioc_type in {"domain", "domain_email", "email", "ip"}:
            host = _safe_hostname(value)
            if host:
                host_signal = _urlhaus_host_signal(client, host)
                if host_signal:
                    signals.append(host_signal)
            if ioc_type == "ip":
                rdap_signal = _rdap_ip_signal(client, value)
                if rdap_signal:
                    signals.append(rdap_signal)

        if ioc_type == "hash" and _is_hash(value):
            urlhaus_signal = _urlhaus_payload_signal(client, value.lower())
            if urlhaus_signal:
                signals.append(urlhaus_signal)
            bazaar_signal = _malwarebazaar_signal(client, value.lower())
            if bazaar_signal:
                signals.append(bazaar_signal)

    return signals


def apply_enrichment(payload: dict[str, Any], ioc_type: str, ioc_value: str) -> dict[str, Any]:
    signals = enrich_ioc(ioc_type, ioc_value)
    if not signals:
        return payload

    findings = list(payload.get("findings") or [])
    risk_factors = list(payload.get("risk_factors") or [])
    provider_details = dict(payload.get("provider_details") or {})
    total_delta = 0

    for signal in signals:
        if signal.source == "RDAP":
            findings = [
                finding
                for finding in findings
                if not (isinstance(finding, str) and finding.startswith("RDAP:") and "endpoints falharam" in finding)
            ]
        findings.append(signal.finding)
        provider_details.setdefault(signal.source, {}).update(signal.details)
        if signal.risk_delta:
            total_delta += signal.risk_delta
            risk_factors.append(
                {
                    "reason": signal.finding.replace(f"{signal.source}: ", "", 1),
                    "points": signal.risk_delta,
                    "source": signal.source,
                }
            )

    payload["findings"] = findings
    payload["risk_factors"] = risk_factors
    payload["provider_details"] = provider_details
    payload["risk"] = max(0, min(100, int(payload.get("risk") or 0) + total_delta))
    if total_delta and payload["risk"] >= 70:
        payload["level"] = "alto"
        payload["verdict"] = "high_risk"
    elif total_delta and payload["risk"] >= 40:
        payload["level"] = "medio"
        payload["verdict"] = "medium_risk"
    return payload
