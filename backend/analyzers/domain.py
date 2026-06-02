"""Domain analyzer orchestration."""
from __future__ import annotations

import concurrent.futures

from ..config import Config
from ..context import AnalysisContext
from ..providers import blacklistmaster, dnsintel, otx, siteconfiavel, virustotal, whois


def analyze(ctx: AnalysisContext, domain: str, config: Config) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            executor.submit(ctx.timeit, "VirusTotal", lambda: virustotal.analyze_domain(ctx, domain, config)),
            executor.submit(ctx.timeit, "WHOIS", lambda: whois.analyze_domain(ctx, domain, config)),
            executor.submit(ctx.timeit, "DNS", lambda: dnsintel.analyze_domain(ctx, domain, config)),
            executor.submit(ctx.timeit, "AlienVault OTX", lambda: otx.analyze_domain(ctx, domain, config)),
            executor.submit(ctx.timeit, "SiteConfiavel", lambda: siteconfiavel.analyze_target(ctx, domain, config)),
            executor.submit(ctx.timeit, "Blacklist Master", lambda: blacklistmaster.analyze_domain(ctx, domain, config)),
        ]
        for future in futures:
            future.result()
