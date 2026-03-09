from pydantic import BaseModel


class InvestigationSummary(BaseModel):
    id: str
    tenant_id: str
    case_id: str
    owner_user_id: str
    title: str
    status: str


class InvestigationCreate(BaseModel):
    title: str
    summary: str | None = None
