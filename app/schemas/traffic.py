from datetime import datetime

from pydantic import BaseModel, Field


class TrafficRecordOut(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_count: float
    flow_duration: float
    packet_length: float
    flow_bytes_per_sec: float
    flow_packets_per_sec: float
    tcp_flags: str | None
    dataset_label: str | None
    source: str
    dataset_import_id: int | None
    severity: str | None = None
    predicted_label: str | None = None
    is_anomaly: bool | None = None

    model_config = {"from_attributes": True}


class TrafficRecordDetail(TrafficRecordOut):
    features: dict
    detection: dict | None = None


class TrafficPage(BaseModel):
    items: list[TrafficRecordOut]
    total: int
    page: int
    page_size: int
    pages: int


class DatasetImportOut(BaseModel):
    id: int
    original_name: str
    sha256: str
    row_count: int
    accepted_rows: int
    rejected_rows: int
    feature_mapping: dict
    label_column: str | None
    status: str
    error_message: str | None
    uploaded_by: int | None
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ImportResult(BaseModel):
    dataset: DatasetImportOut
    detected_columns: dict
    warnings: list[str] = Field(default_factory=list)
    analysis: dict


class FeatureSchemaOut(BaseModel):
    canonical_features: list[str]
    aliases: dict[str, list[str]]
    required_minimum: int
    allowed_extensions: list[str]
    max_upload_mb: int
    max_rows: int
