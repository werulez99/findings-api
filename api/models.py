import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class FindingSummary(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    protocol_name: str | None
    firm_name: str | None
    vulnerability_category: str | None
    attack_vector: str | None
    tags: list[str]
    risk_score: int | None
    short_summary: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingDetail(FindingSummary):
    description: str
    enrichment_status: str


class FindingsPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingSummary]
