from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


AllowedIocType = Literal["ip", "domain", "domain_email", "url", "hash", "mac"]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,253}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _is_public_host(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.lower() not in {"localhost", "local"}
    return ip.is_global


class AnalysisJobCreate(BaseModel):
    ioc_type: AllowedIocType
    ioc_value: str = Field(min_length=1, max_length=512)

    @field_validator("ioc_value")
    @classmethod
    def normalize_ioc_value(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_ioc_by_type(self) -> "AnalysisJobCreate":
        value = self.ioc_value
        if self.ioc_type == "ip":
            try:
                ip = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("Invalid IP address.") from exc
            if not ip.is_global:
                raise ValueError("Only public IP addresses can be enriched.")
        elif self.ioc_type == "url":
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL must use http or https and include a host.")
            if not _is_public_host(parsed.hostname):
                raise ValueError("Only public URL hosts can be enriched.")
        elif self.ioc_type in {"domain", "domain_email"}:
            candidate = value.rsplit("@", 1)[-1] if "@" in value else value
            if "@" in value and not EMAIL_RE.match(value):
                raise ValueError("Invalid email format.")
            if not DOMAIN_RE.match(candidate.lower()):
                raise ValueError("Invalid domain format.")
        elif self.ioc_type == "hash":
            if not HASH_RE.match(value):
                raise ValueError("Hash must be MD5, SHA1, or SHA256 hexadecimal.")
        elif self.ioc_type == "mac":
            if not MAC_RE.match(value):
                raise ValueError("Invalid MAC address.")
        return self


class AnalysisJobResponse(BaseModel):
    id: str
    tenant_id: str
    ioc_type: str
    ioc_value: str
    status: str
    priority: str


class AnalysisResultSummary(BaseModel):
    id: str
    tenant_id: str
    job_id: str
    verdict: str
    level: str
    risk_score: int
    findings: list[str] | None = None
    recommendations: list[str] | None = None
    risk_factors: list[dict] | None = None
    risk_meta: dict | None = None
    timings_ms: dict | None = None
    provider_details: dict | None = None
    legacy_verdict: str | None = None
    confidence_score: float | None = None
    scoring: dict | None = None


class AnalysisJobDetail(BaseModel):
    id: str
    tenant_id: str
    owner_user_id: str
    requested_by_user_id: str
    ioc_type: str
    ioc_value: str
    status: str
    priority: str
    provider_fingerprint: str | None = None
    result_payload: list[str] | None = None
