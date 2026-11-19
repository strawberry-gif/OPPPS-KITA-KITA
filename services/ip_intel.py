from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models.incident import SecurityIncident
from app.models.ip import SuspiciousIP
from app.models.traffic import DetectionResult, TrafficRecord


def ip_dict(row: SuspiciousIP) -> dict:
    return {
        "id": row.id,
        "ip_address": row.ip_address,
        "direction": row.direction,
        "is_private": row.is_private,
        "classification": row.classification,
        "risk_score": row.risk_score,
        "event_count": row.event_count,
        "anomaly_count": row.anomaly_count,
        "incident_count": row.incident_count,
        "max_severity": row.max_severity,
        "top_prediction": row.top_prediction,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "notes": row.notes,
    }


def list_ips(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 25,
    search: str | None = None,
    direction: str | None = None,
    classification: str | None = None,
    min_risk: float | None = None,
    private: bool | None = None,
) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    filters = []
    if search:
        filters.append(SuspiciousIP.ip_address.ilike(f"%{search.strip()}%"))
    if direction:
        filters.append(or_(SuspiciousIP.direction == direction, SuspiciousIP.direction == "both"))
    if classification:
        filters.append(SuspiciousIP.classification == classification)
    if min_risk is not None:
        filters.append(SuspiciousIP.risk_score >= min_risk)
    if private is not None:
        filters.append(SuspiciousIP.is_private.is_(private))

    count_query = select(func.count(SuspiciousIP.id))
    query = select(SuspiciousIP)
    if filters:
        count_query = count_query.where(*filters)
        query = query.where(*filters)
    total = int(db.scalar(count_query) or 0)
    rows = db.scalars(
        query.order_by(SuspiciousIP.risk_score.desc(), SuspiciousIP.last_seen.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [ip_dict(row) for row in rows], total


def get_ip_detail(db: Session, ip_id: int) -> dict:
    row = db.get(SuspiciousIP, ip_id)
    if row is None:
        raise NotFoundError("IP address not found")
    result = ip_dict(row)

    incidents = db.scalars(
        select(SecurityIncident)
        .where(SecurityIncident.source_ip == row.ip_address)
        .order_by(SecurityIncident.created_at.desc())
        .limit(10)
    ).all()
    result["related_incidents"] = [
        {
            "id": incident.id,
            "incident_code": incident.incident_code,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": incident.created_at,
        }
        for incident in incidents
    ]

    activity_rows = db.execute(
        select(TrafficRecord, DetectionResult)
        .outerjoin(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(
            or_(
                TrafficRecord.src_ip == row.ip_address,
                TrafficRecord.dst_ip == row.ip_address,
            )
        )
        .order_by(TrafficRecord.timestamp.desc())
        .limit(20)
    ).all()
    result["recent_activity"] = [
        {
            "id": record.id,
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "dst_port": record.dst_port,
            "protocol": record.protocol,
            "packet_count": record.packet_count,
            "predicted_label": detection.predicted_label if detection else None,
            "is_anomaly": detection.is_anomaly if detection else None,
            "severity": detection.severity if detection else None,
            "dataset_label": record.dataset_label,
        }
        for record, detection in activity_rows
    ]
    return result


def update_ip(db: Session, ip_id: int, notes: str | None, classification: str | None) -> dict:
    row = db.get(SuspiciousIP, ip_id)
    if row is None:
        raise NotFoundError("IP address not found")
    if notes is not None:
        row.notes = notes
    if classification is not None and row.direction != "destination":
        row.classification = classification
    db.commit()
    db.refresh(row)
    return ip_dict(row)
