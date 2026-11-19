from datetime import datetime

from pydantic import BaseModel, Field


class IPOut(BaseModel):
    id: int
    ip_address: str
    direction: str
    is_private: bool
    classification: str
    risk_score: float
    event_count: int
    anomaly_count: int
    incident_count: int
    max_severity: str
    top_prediction: str | None
    first_seen: datetime
    last_seen: datetime
    notes: str | None

    model_config = {"from_attributes": True}


class IPPage(BaseModel):
    items: list[IPOut]
    total: int
    page: int
    page_size: int
    pages: int


class IPDetail(IPOut):
    related_incidents: list[dict] = Field(default_factory=list)
    recent_activity: list[dict] = Field(default_factory=list)
    risk_model: str = (
        "Heuristic risk indicator derived from severity weights, anomaly frequency, "
        "event frequency and recency. Not a reputation score or calibrated probability."
    )


class IPUpdate(BaseModel):
    notes: str | None = Field(default=None, max_length=5000)
    classification: str | None = Field(
        default=None,
        pattern="^(OBSERVED|WATCHLIST|SUSPICIOUS|HIGH_RISK|MONITORED_DESTINATION)$",
    )
