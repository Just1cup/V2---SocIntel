from pydantic import BaseModel

from app.schemas.common import TenantScopedModel


class TeamSummary(TenantScopedModel):
    name: str
    slug: str


class TeamMembershipSummary(BaseModel):
    id: str
    tenant_id: str
    team_id: str
    user_id: str
    role: str
