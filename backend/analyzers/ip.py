"""IP analyzer orchestration."""
from __future__ import annotations

import concurrent.futures

from ..config import Config
from ..context import AnalysisContext
from ..providers import abuseipdb, otx, rdap, shodan, virustotal


def analyze(ctx: AnalysisContext, ip: str, config: Config) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(ctx.timeit, "VirusTotal", lambda: virustotal.analyze_ip(ctx, ip, config)),
            executor.submit(ctx.timeit, "AbuseIPDB", lambda: abuseipdb.analyze_ip(ctx, ip, config)),
            executor.submit(ctx.timeit, "AlienVault OTX", lambda: otx.analyze_ip(ctx, ip, config)),
            executor.submit(ctx.timeit, "RDAP", lambda: rdap.analyze_ip(ctx, ip, config)),
            executor.submit(ctx.timeit, "Shodan", lambda: shodan.analyze_ip(ctx, ip, config)),
        ]
        for future in futures:
            future.result()
