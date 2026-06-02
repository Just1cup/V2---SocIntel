"""urlscan.io provider."""
from __future__ import annotations

import time
from urllib.parse import urlparse

from ..config import Config
from ..context import AnalysisContext
from ..utils.logging import log_error
from ..utils.url import escape_urlscan_query, has_pii


def _urlscan_request(ctx: AnalysisContext, method: str, url: str, headers: dict, config: Config, params: dict | None = None, json: dict | None = None) -> dict:
    backoff = 1.0
    for attempt in range(config.urlscan_max_retries + 1):
        try:
            r = ctx.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json,
                timeout=config.request_timeout_long,
                allow_redirects=True,
            )
            status = r.status_code

            if status == 429 or 500 <= status <= 599:
                if attempt == config.urlscan_max_retries:
                    log_error("urlscan.io", f"HTTP {status} em {url}")
                    return {"ok": False, "status": status, "json": {}, "error": r.text}
                time.sleep(backoff)
                backoff = min(backoff * 2, 16)
                continue

            if status >= 400:
                log_error("urlscan.io", f"HTTP {status} em {url}")
                return {"ok": False, "status": status, "json": {}, "error": r.text}

            try:
                data = r.json()
            except Exception:
                data = {}
            return {"ok": True, "status": status, "json": data, "error": ""}
        except Exception as exc:
            if attempt == config.urlscan_max_retries:
                log_error("urlscan.io", f"Falha de rede em {url}", exc)
                return {"ok": False, "status": 0, "json": {}, "error": str(exc)}
            time.sleep(backoff)
            backoff = min(backoff * 2, 16)
    return {"ok": False, "status": 0, "json": {}, "error": "retries exhausted"}


def _urlscan_result(ctx: AnalysisContext, scan_id: str, headers: dict, config: Config) -> dict:
    return _urlscan_request(
        ctx=ctx,
        method="get",
        url=f"https://urlscan.io/api/v1/result/{scan_id}/",
        headers=headers,
        config=config,
    )


def _wait_urlscan_result(ctx: AnalysisContext, scan_id: str, headers: dict, config: Config, timeout_sec: int = 20, interval_sec: int = 2) -> dict:
    deadline = time.time() + timeout_sec
    last_status = None
    while time.time() < deadline:
        result = _urlscan_result(ctx, scan_id, headers, config)
        last_status = result.get("status")
        if result.get("ok"):
            return result.get("json", {})
        if last_status not in (0, 202, 404):
            raise RuntimeError(f"urlscan.io: scan não foi concluido com sucesso (HTTP {last_status})")
        time.sleep(interval_sec)
    raise TimeoutError(f"urlscan.io: scan não foi concluido com sucesso (HTTP {last_status})")


def _append_urlscan_search_summary(ctx: AnalysisContext, result: dict) -> None:
    verdicts = result.get("verdicts", {}) or {}
    overall = verdicts.get("overall", {}) or {}
    overall_mal = overall.get("malicious")
    if overall_mal is not None:
        if overall_mal is False:
            ctx.add_finding("urlscan.io: não foram encontrados indicadores de risco")
        else:
            ctx.add_finding(f"urlscan.io: malicioso {overall_mal}")


def _normalize_urlscan_report_url(raw_url: str | None, scan_id: str | None = None) -> str | None:
    if scan_id:
        return f"https://urlscan.io/result/{scan_id}/"
    if not raw_url:
        return None

    # urlscan returns API URLs in "result"; convert to the human-readable report page.
    if "/api/v1/result/" in raw_url:
        suffix = raw_url.split("/api/v1/result/", 1)[1].strip("/")
        if suffix:
            return f"https://urlscan.io/result/{suffix}/"

    parsed = urlparse(raw_url)
    if parsed.netloc == "urlscan.io" and parsed.path.startswith("/result/"):
        return raw_url
    return raw_url


def _valid_urlscan_type(raw_type: str | None) -> str | None:
    if raw_type is None:
        return None
    cleaned = str(raw_type).strip()
    if not cleaned:
        return None
    if cleaned.lower() in {"other", "n/a", "na"}:
        return None
    return cleaned


def _extract_urlscan_summary(payload: dict, fallback_scan_id: str | None = None) -> dict:
    task = payload.get("task", {}) or {}
    page = payload.get("page", {}) or {}

    report_url = (
        task.get("reportURL")
        or payload.get("reportURL")
        or _normalize_urlscan_report_url(payload.get("result"), fallback_scan_id)
    )
    screenshot_url = task.get("screenshotURL") or payload.get("screenshotURL") or payload.get("screenshot")

    url_value = page.get("url") or task.get("url") or payload.get("url")
    type_value = _valid_urlscan_type(
        payload.get("type")
        or page.get("mimeType")
        or task.get("source")
    )

    return {
        "url": url_value,
        "type": type_value,
        "task": {
            "reportURL": report_url,
            "screenshotURL": screenshot_url,
        },
    }


def _update_urlscan_context(ctx: AnalysisContext, payload: dict, fallback_scan_id: str | None = None) -> None:
    summary = _extract_urlscan_summary(payload, fallback_scan_id=fallback_scan_id)
    ctx.urlscan_summary = summary
    ctx.update_provider_data("urlscan.io", summary)
    report_url = (summary.get("task", {}) or {}).get("reportURL")
    if report_url:
        ctx.urlscan_result_url = report_url


def _append_urlscan_extracted_fields(ctx: AnalysisContext) -> None:
    summary = ctx.urlscan_summary or {}
    task = summary.get("task", {}) or {}

    url_value = summary.get("url")
    type_value = summary.get("type")
    report_url = task.get("reportURL")
    screenshot_url = task.get("screenshotURL")

    if url_value:
        ctx.add_finding(f"urlscan.io: url {url_value}")
    if type_value:
        ctx.add_finding(f"urlscan.io: type {type_value}")
    if report_url:
        ctx.add_finding(f"urlscan.io: reportURL {report_url}")
    if screenshot_url:
        ctx.add_finding(f"urlscan.io: screenshotURL {screenshot_url}")


def analyze_url(ctx: AnalysisContext, url: str, config: Config) -> None:
    ctx.section_once("urlscan.io", "Scan e análise de comportamento da URL")

    if not config.urlscan_api_key:
        ctx.add_finding("urlscan.io: API key não configurada (defina URLSCAN_API_KEY)")
        log_error("urlscan.io", "API key não configurada")
        return

    headers = {
        "API-Key": config.urlscan_api_key,
        "User-Agent": config.user_agent,
        "Accept": "application/json",
    }

    safe_url = escape_urlscan_query(url)
    query = f'page.url:"{safe_url}" AND date:>now-7d'
    params = {"q": query, "size": 1}

    search = _urlscan_request(ctx, "get", "https://urlscan.io/api/v1/search/", headers, config, params=params)
    if search["ok"]:
        results = search["json"].get("results", [])
        if results:
            _update_urlscan_context(ctx, results[0])
            result_url = (ctx.urlscan_summary.get("task", {}) or {}).get("reportURL")
            if result_url:
                ctx.add_finding(f"urlscan.io: resultado {result_url}")
                ctx.urlscan_result_url = result_url
            _append_urlscan_extracted_fields(ctx)
            _append_urlscan_search_summary(ctx, results[0])
            return
        ctx.add_finding("urlscan.io: nenhum scan recente encontrado")
    else:
        ctx.add_finding(f"urlscan.io: erro na busca (HTTP {search['status']}) {search['error']}")

    visibility = "unlisted" if has_pii(url) else "public"
    payload = {
        "url": url,
        "visibility": visibility,
        "customagent": config.user_agent,
        "tags": ["socintel"],
    }

    submit = _urlscan_request(
        ctx,
        "post",
        "https://urlscan.io/api/v1/scan/",
        {**headers, "Content-Type": "application/json"},
        config,
        json=payload,
    )

    if submit["ok"]:
        scan_id = submit["json"].get("uuid", "")
        _update_urlscan_context(ctx, submit["json"], fallback_scan_id=scan_id or None)
        result_url = (ctx.urlscan_summary.get("task", {}) or {}).get("reportURL")
        if result_url:
            ctx.add_finding(f"urlscan.io: resultado {result_url}")
            ctx.urlscan_result_url = result_url

        if scan_id:
            try:
                result = _wait_urlscan_result(ctx, scan_id, headers, config, timeout_sec=20, interval_sec=2)
                _update_urlscan_context(ctx, result, fallback_scan_id=scan_id)
                verdicts = result.get("verdicts", {})
                overall = verdicts.get("overall", {})
                overall_mal = overall.get("malicious")
                if overall_mal is not None:
                    if overall_mal is False:
                        ctx.add_finding("urlscan.io: não foram encontrados indicadores de risco")
                        ctx.add_risk(-20, reason="classificado como não malicioso", source="urlscan.io")
                    else:
                        ctx.add_finding(f"urlscan.io: malicioso {overall_mal}")

                search_after = _urlscan_request(ctx, "get", "https://urlscan.io/api/v1/search/", headers, config, params=params)
                if search_after["ok"]:
                    results_after = search_after["json"].get("results", [])
                    if results_after:
                        _append_urlscan_search_summary(ctx, results_after[0])
                _append_urlscan_extracted_fields(ctx)
            except Exception:
                ctx.urlscan_timeout = True
                ctx.add_finding("urlscan.io: scan pendente (resultado ainda não disponível)")
                _append_urlscan_extracted_fields(ctx)
                log_error("urlscan.io", f"Timeout ao obter resultado do scan {scan_id}")
    else:
        ctx.add_finding(f"urlscan.io: erro ao enviar scan (HTTP {submit['status']}) {submit['error']}")
        ctx.urlscan_timeout = True
        log_error("urlscan.io", f"Falha ao enviar scan (HTTP {submit['status']})")
