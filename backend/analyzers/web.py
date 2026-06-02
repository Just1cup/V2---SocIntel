"""Web analyzer (domain + URL)."""
from __future__ import annotations

import concurrent.futures
from urllib.parse import urlparse

from ..config import Config
from ..context import AnalysisContext
from ..providers import urlscan
from . import domain as domain_analyzer


def _analyze_url(ctx: AnalysisContext, url: str, config: Config) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        futures = [
            executor.submit(ctx.timeit, "urlscan.io", lambda: urlscan.analyze_url(ctx, url, config)),
        ]
        for future in futures:
            future.result()


def analyze(ctx: AnalysisContext, value: str, config: Config) -> None:
    ctx.section_once("Web", "Análise combinada de domínio e URL")

    input_value = (value or "").strip()
    url_value = None
    domain_value = None

    if input_value.startswith("http://") or input_value.startswith("https://"):
        url_value = input_value
        domain_value = urlparse(input_value).netloc
    elif "/" in input_value or "?" in input_value:
        url_value = f"http://{input_value}"
        domain_value = urlparse(url_value).netloc
    else:
        domain_value = input_value

    if domain_value:
        domain_analyzer.analyze(ctx, domain_value, config)

    if not url_value and domain_value:
        url_value = f"http://{domain_value}"

    if url_value:
        _analyze_url(ctx, url_value, config)
