from pydantic import BaseModel


class TenantSummary(BaseModel):
    id: str
    name: str
    slug: str
    status: str
