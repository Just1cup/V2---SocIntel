from pydantic import BaseModel


class CaseSummary(BaseModel):
    id: str
    tenant_id: str
    owner_user_id: str
    name: str
    status: str
    visibility: str


class CaseDetail(CaseSummary):
    description: str | None = None
    team_id: str | None = None


class CaseCreate(BaseModel):
    name: str
    description: str | None = None
    visibility: str = "private"
