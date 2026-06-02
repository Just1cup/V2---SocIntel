"""MAC analyzer wrapper."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from ..providers import macvendors


def analyze(ctx: AnalysisContext, mac: str, config: Config) -> None:
    macvendors.analyze_mac(ctx, mac, config)
