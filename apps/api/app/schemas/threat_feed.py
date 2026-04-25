from typing import Any

from pydantic import BaseModel


class TaxiiSourceSummary(BaseModel):
    id: str
    name: str
    description: str
    base_url: str
    api_root: str


class TaxiiResponse(BaseModel):
    source: TaxiiSourceSummary
    endpoint: str
    data: dict[str, Any]

