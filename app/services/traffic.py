from __future__ import annotations

import math
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models.traffic import DetectionResult, TrafficRecord


def record_dict(
    record: TrafficRecord, detection: DetectionResult | None = None
) -> dict:
    return {
        "id": record.id,
        "timestamp": record.timestamp,
        "src_ip": record.src_ip,
        "dst_ip": record.dst_ip,
        "src_port": record.src_port,
        "dst_port": record.dst_port,
        "protocol": record.protocol,
        "packet_count": record.packet_count,
        "flow_duration": record.flow_duration,
        "packet_length": record.packet_length,
        "flow_bytes_per_sec": record.flow_bytes_per_sec,
        "flow_packets_per_sec": record.flow_packets_per_sec,
        "tcp_flags": record.tcp_flags,
        "dataset_label": record.dataset_label,
        "source": record.source,
        "dataset_import_id": record.dataset_import_id,
        "severity": detection.severity if detection else None,
        "predicted_label": detection.predicted_label if detection else None,
        "is_anomaly": detection.is_anomaly if detection else None,
    }


def detection_summary(detection: DetectionResult | None) -> dict | None:
    if detection is None:
        return None
    return {
        "id": detection.id,
        "is_anomaly": detection.is_anomaly,
        "anomaly_score": detection.anomaly_score,
        "predicted_label": detection.predicted_label,
        "confidence": detection.confidence,
        "severity": detection.severity,
        "severity_score": detection.severity_score,
        "explanation": detection.explanation,
        "model_version_id": detection.model_version_id,
        "created_at": detection.created_at,
    }


def list_records(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 25,
    search: str | None = None,
    protocol: str | None = None,
    dataset_label: str | None = None,
    severity: str | None = None,
    anomaly: bool | None = None,
    source: str | None = None,
    import_id: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    filters = []
    if search:
        term = f"%{search.strip()}%"
        filters.append(or_(TrafficRecord.src_ip.ilike(term), TrafficRecord.dst_ip.ilike(term)))
    if protocol:
        filters.append(TrafficRecord.protocol == protocol.upper())
    if dataset_label:
        if dataset_label.upper() == "BENIGN":
            filters.append(TrafficRecord.dataset_label == "BENIGN")
        elif dataset_label.upper() == "ATTACK":
            filters.append(TrafficRecord.dataset_label.notin_(["BENIGN"]))
            filters.append(TrafficRecord.dataset_label.is_not(None))
        else:
            filters.append(TrafficRecord.dataset_label == dataset_label)
    if severity:
        filters.append(DetectionResult.severity == severity)
    if anomaly is not None:
        filters.append(DetectionResult.is_anomaly.is_(anomaly))
    if source:
        filters.append(TrafficRecord.source == source)
    if import_id is not None:
        filters.append(TrafficRecord.dataset_import_id == import_id)
    if start:
        filters.append(TrafficRecord.timestamp >= start)
    if end:
        filters.append(TrafficRecord.timestamp <= end)

    query = (
        select(TrafficRecord, DetectionResult)
        .outerjoin(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
        .order_by(TrafficRecord.timestamp.desc())
    )
    count_query = (
        select(func.count(func.distinct(TrafficRecord.id)))
        .select_from(TrafficRecord)
        .outerjoin(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
    )
    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)
    total = int(db.scalar(count_query) or 0)
    rows = db.execute(
        query.offset((page - 1) * page_size).limit(page_size)
    ).all()
    return [record_dict(record, detection) for record, detection in rows], total


def get_record(db: Session, record_id: int) -> dict:
    row = db.execute(
        select(TrafficRecord, DetectionResult)
        .outerjoin(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(TrafficRecord.id == record_id)
    ).first()
    if row is None:
        raise NotFoundError("Traffic record not found")
    record, detection = row
    data = record_dict(record, detection)
    data["features"] = record.features
    data["detection"] = detection_summary(detection)
    return data


def list_detections(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    predicted_label: str | None = None,
    anomaly: bool | None = None,
    search: str | None = None,
) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    filters = []
    if severity:
        filters.append(DetectionResult.severity == severity)
    if predicted_label:
        filters.append(DetectionResult.predicted_label == predicted_label)
    if anomaly is not None:
        filters.append(DetectionResult.is_anomaly.is_(anomaly))
    if search:
        term = f"%{search.strip()}%"
        filters.append(or_(TrafficRecord.src_ip.ilike(term), TrafficRecord.dst_ip.ilike(term)))

    query = (
        select(DetectionResult, TrafficRecord)
        .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
        .order_by(DetectionResult.created_at.desc())
    )
    count_query = (
        select(func.count(DetectionResult.id))
        .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
    )
    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)
    total = int(db.scalar(count_query) or 0)
    rows = db.execute(
        query.offset((page - 1) * page_size).limit(page_size)
    ).all()
    items = []
    for detection, record in rows:
        items.append(
            {
                "id": detection.id,
                "traffic_record_id": detection.traffic_record_id,
                "is_anomaly": detection.is_anomaly,
                "anomaly_score": detection.anomaly_score,
                "predicted_label": detection.predicted_label,
                "confidence": detection.confidence,
                "severity": detection.severity,
                "severity_score": detection.severity_score,
                "explanation": detection.explanation,
                "created_at": detection.created_at,
                "model_version_id": detection.model_version_id,
                "source_ip": record.src_ip,
                "destination_ip": record.dst_ip,
                "timestamp": record.timestamp,
            }
        )
    return items, total


def traffic_stats(db: Session) -> dict:
    total = int(db.scalar(select(func.count(TrafficRecord.id))) or 0)
    analyzed = int(db.scalar(select(func.count(DetectionResult.id))) or 0)
    mini = db.scalar(select(func.min(TrafficRecord.timestamp)))
    maxi = db.scalar(select(func.max(TrafficRecord.timestamp)))
    return {
        "total_records": total,
        "analyzed": analyzed,
        "unprocessed": max(total - analyzed, 0),
        "earliest": mini,
        "latest": maxi,
    }
