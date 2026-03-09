from pydantic import BaseModel


class AnalysisJobCreate(BaseModel):
    case_id: str | None = None
    investigation_id: str | None = None
    ioc_type: str
    ioc_value: str


class AnalysisJobResponse(BaseModel):
    id: str
    tenant_id: str
    case_id: str | None
    investigation_id: str | None
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


class AnalysisJobDetail(BaseModel):
    id: str
    tenant_id: str
    case_id: str | None
    investigation_id: str | None
    owner_user_id: str
    requested_by_user_id: str
    ioc_type: str
    ioc_value: str
    status: str
    priority: str
    provider_fingerprint: str | None = None
    result_payload: list[str] | None = None
