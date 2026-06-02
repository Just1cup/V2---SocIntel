"""Hash analyzer wrapper."""
from __future__ import annotations

from ..config import Config
from ..context import AnalysisContext
from ..providers import virustotal


def analyze(ctx: AnalysisContext, hash_value: str, config: Config) -> None:
    virustotal.analyze_hash(ctx, hash_value, config)
