from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class IncidentOut(BaseModel):
    id: int
    incident_code: str
    title: str
    description: str
    severity: str
    status: str
    source_ip: str | None
    destination_ip: str | None
    traffic_record_id: int | None
    detection_result_id: int | None
    detection_explanation: str
    investigation_notes: str | None
    assigned_to: int | None
    assignee_name: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None

    model_config = {"from_attributes": True}


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int
    page: int
    page_size: int
    pages: int


class IncidentDetail(IncidentOut):
    related_records: list[dict] = Field(default_factory=list)
    related_ip: dict | None = None
    activity_log: list[dict] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status: str | None = Field(
        default=None, pattern="^(NEW|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$"
    )
    investigation_notes: str | None = Field(default=None, max_length=10000)
    assigned_to: int | None = None

    @field_validator("investigation_notes")
    @classmethod
    def strip_notes(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None
