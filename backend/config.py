"""Configuration loading for SOCINTEL backend."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    vt_api_key: str | None
    abuse_api_key: str | None
    otx_api_key: str | None
    urlscan_api_key: str | None
    shodan_api_key: str | None
    request_timeout_short: int = 5
    request_timeout_medium: int = 8
    request_timeout_long: int = 12
    user_agent: str = "SOCINTEL/2.0 (urlscan integration)"
    urlscan_max_retries: int = 4


_DEF_DOTENV = Path(__file__).resolve().parent / ".env"


def _read_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def load_config(dotenv_path: Path | None = None) -> Config:
    env_path = dotenv_path or _DEF_DOTENV
    # Prefer backend/.env over inherited shell env vars to avoid stale keys.
    load_dotenv(dotenv_path=env_path, override=True)

    return Config(
        vt_api_key=_read_env("VT_API_KEY"),
        abuse_api_key=_read_env("ABUSE_API_KEY"),
        otx_api_key=_read_env("OTX_API_KEY"),
        urlscan_api_key=_read_env("URLSCAN_API_KEY"),
        shodan_api_key=_read_env("SHODAN_API_KEY"),
    )
