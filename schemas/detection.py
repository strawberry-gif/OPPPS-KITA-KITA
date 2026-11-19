from datetime import datetime

from pydantic import BaseModel, Field


class PredictionInput(BaseModel):
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = "TCP"
    features: dict[str, float] = Field(default_factory=dict)


class DetectionOut(BaseModel):
    id: int
    traffic_record_id: int
    is_anomaly: bool
    anomaly_score: float
    predicted_label: str
    confidence: float
    severity: str
    severity_score: float
    explanation: dict
    created_at: datetime
    model_version_id: int | None
    source_ip: str | None = None
    destination_ip: str | None = None
    timestamp: datetime | None = None

    model_config = {"from_attributes": True}


class DetectionPage(BaseModel):
    items: list[DetectionOut]
    total: int
    page: int
    page_size: int
    pages: int


class RunDetectionRequest(BaseModel):
    limit: int = Field(default=2000, ge=1, le=20000)
    import_id: int | None = None


class RunDetectionResult(BaseModel):
    processed: int
    attacks: int
    anomalies: int
    incidents_created: int
    skipped: int
    duration_seconds: float
    severity_counts: dict[str, int]
    model: str
    anomaly_model: str


class PredictionResult(BaseModel):
    predicted_label: str
    confidence: float
    is_anomaly: bool
    anomaly_score: float
    severity: str
    severity_score: float
    explanation: dict
    model_version_id: int | None
    anomaly_model_version_id: int | None
