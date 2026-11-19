from datetime import datetime

from pydantic import BaseModel, Field


class CountItem(BaseModel):
    label: str
    count: int


class TimelinePoint(BaseModel):
    bucket: str
    total: int
    anomalies: int
    attacks: int
    critical: int = 0
    high: int = 0


class RecentIncident(BaseModel):
    id: int
    incident_code: str
    title: str
    severity: str
    status: str
    source_ip: str | None
    created_at: datetime


class ModelSummary(BaseModel):
    id: int
    name: str
    algorithm: str
    task_type: str
    version: str
    metrics: dict
    trained_at: datetime


class Overview(BaseModel):
    range: str
    totals: dict
    severity_counts: dict
    protocol_distribution: list[CountItem]
    attack_distribution: list[CountItem]
    timeline: list[TimelinePoint]
    recent_incidents: list[RecentIncident]
    top_source_ips: list[dict]
    active_models: list[ModelSummary]
    generated_at: datetime


class AnalyticsResponse(BaseModel):
    range: str
    totals: dict
    timeline: list[TimelinePoint]
    severity_distribution: list[CountItem]
    protocol_distribution: list[CountItem]
    attack_distribution: list[CountItem]
    top_source_ips: list[dict]
    top_destination_ports: list[CountItem]
    status_distribution: list[CountItem]
    detection_history: list[dict]


class HealthResponse(BaseModel):
    status: str
    database: str
    active_classifier: dict | None = None
    active_anomaly_model: dict | None = None
    models_ready: bool
    live_capture_available: bool
    live_capture_running: bool
    server_time: datetime
    version: str = "1.0.0"
