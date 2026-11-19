from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.user import utcnow


class TrafficRecord(Base):
    __tablename__ = "traffic_records"
    __table_args__ = (
        Index("ix_traffic_timestamp_label", "timestamp", "dataset_label"),
        Index("ix_traffic_src_ip_timestamp", "src_ip", "timestamp"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    dataset_import_id: Mapped[int | None] = mapped_column(
        ForeignKey("dataset_imports.id", ondelete="CASCADE"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=utcnow
    )
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), default="OTHER", index=True)
    packet_count: Mapped[float] = mapped_column(Float, default=0)
    flow_duration: Mapped[float] = mapped_column(Float, default=0)
    packet_length: Mapped[float] = mapped_column(Float, default=0)
    flow_bytes_per_sec: Mapped[float] = mapped_column(Float, default=0)
    flow_packets_per_sec: Mapped[float] = mapped_column(Float, default=0)
    tcp_flags: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dataset_label: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(20), default="upload", index=True)
    features: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    dataset_import = relationship("DatasetImport", back_populates="traffic_records")
    detection = relationship(
        "DetectionResult",
        back_populates="traffic_record",
        uselist=False,
        cascade="all, delete-orphan",
    )


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    traffic_record_id: Mapped[int] = mapped_column(
        ForeignKey("traffic_records.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    model_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    anomaly_model_id: Mapped[int | None] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True
    )
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0)
    predicted_label: Mapped[str] = mapped_column(String(80), default="BENIGN", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    severity: Mapped[str] = mapped_column(String(20), default="INFORMATIONAL", index=True)
    severity_score: Mapped[float] = mapped_column(Float, default=0)
    explanation: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    traffic_record = relationship("TrafficRecord", back_populates="detection")
    model_version = relationship(
        "ModelVersion", foreign_keys=[model_version_id], back_populates="detections"
    )


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
