from pydantic import BaseModel


class TenantScopedModel(BaseModel):
    id: str
    tenant_id: str
