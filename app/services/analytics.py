from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, case, distinct, func, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationError
from app.ml.detector import get_active_models
from app.models.incident import SecurityIncident
from app.models.ip import SuspiciousIP
from app.models.traffic import DetectionResult, TrafficRecord
from app.services.incidents import incident_dict

RANGES = {
    "24h": (timedelta(hours=24), "hour"),
    "7d": (timedelta(days=7), "day"),
    "30d": (timedelta(days=30), "day"),
    "all": (None, "day"),
}


def resolve_range(value: str) -> tuple[str, datetime | None, str]:
    if value not in RANGES:
        raise ValidationError("Range must be one of 24h, 7d, 30d or all")
    delta, bucket = RANGES[value]
    start = datetime.now(timezone.utc) - delta if delta else None
    return value, start, bucket


def _traffic_filter(start: datetime | None):
    return TrafficRecord.timestamp >= start if start else None


def summarize(db: Session, range_value: str) -> dict:
    range_value, start, bucket = resolve_range(range_value)
    traffic_condition = _traffic_filter(start)

    total_query = select(func.count(TrafficRecord.id))
    if traffic_condition is not None:
        total_query = total_query.where(traffic_condition)
    total_records = int(db.scalar(total_query) or 0)

    analyzed_query = select(func.count(DetectionResult.id)).join(
        TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id
    )
    if traffic_condition is not None:
        analyzed_query = analyzed_query.where(traffic_condition)
    analyzed = int(db.scalar(analyzed_query) or 0)

    def count_detections(*conditions) -> int:
        query = (
            select(func.count(DetectionResult.id))
            .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
            .where(*conditions)
        )
        if traffic_condition is not None:
            query = query.where(traffic_condition)
        return int(db.scalar(query) or 0)

    anomalies = count_detections(DetectionResult.is_anomaly.is_(True))
    attacks = count_detections(DetectionResult.predicted_label != "BENIGN")
    normal = count_detections(
        DetectionResult.predicted_label == "BENIGN",
        DetectionResult.is_anomaly.is_(False),
    )

    severity_rows = db.execute(
        select(DetectionResult.severity, func.count(DetectionResult.id))
        .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(*([traffic_condition] if traffic_condition is not None else []))
        .group_by(DetectionResult.severity)
    ).all()
    severity_counts = {row[0]: int(row[1]) for row in severity_rows}

    unique_sources = int(
        db.scalar(
            select(func.count(distinct(TrafficRecord.src_ip))).where(
                *([traffic_condition] if traffic_condition is not None else [])
            )
        )
        or 0
    )

    suspicious_total = int(db.scalar(select(func.count(SuspiciousIP.id))) or 0)
    new_ips_query = select(func.count(SuspiciousIP.id))
    if start:
        new_ips_query = new_ips_query.where(SuspiciousIP.first_seen >= start)
    new_ips = int(db.scalar(new_ips_query) or 0)

    incident_query = select(func.count(SecurityIncident.id))
    if start:
        incident_query = incident_query.where(SecurityIncident.created_at >= start)
    incidents_total = int(db.scalar(incident_query) or 0)
    open_incidents = int(
        db.scalar(
            select(func.count(SecurityIncident.id)).where(
                SecurityIncident.status.in_(["NEW", "INVESTIGATING"])
            )
        )
        or 0
    )
    resolved_query = select(func.count(SecurityIncident.id)).where(
        SecurityIncident.status.in_(["RESOLVED", "FALSE_POSITIVE"])
    )
    if start:
        resolved_query = resolved_query.where(SecurityIncident.created_at >= start)
    resolved = int(db.scalar(resolved_query) or 0)

    bytes_query = select(func.coalesce(func.sum(TrafficRecord.packet_count * TrafficRecord.packet_length), 0))
    if traffic_condition is not None:
        bytes_query = bytes_query.where(traffic_condition)
    observed_bytes = float(db.scalar(bytes_query) or 0)

    totals = {
        "total_records": total_records,
        "analyzed": analyzed,
        "normal": normal,
        "anomalies": anomalies,
        "attacks": attacks,
        "unprocessed": max(total_records - analyzed, 0),
        "detection_rate": round(anomalies / analyzed * 100, 2) if analyzed else 0.0,
        "attack_rate": round(attacks / analyzed * 100, 2) if analyzed else 0.0,
        "suspicious_ips": suspicious_total,
        "new_suspicious_ips": new_ips,
        "incidents": incidents_total,
        "open_incidents": open_incidents,
        "resolved_incidents": resolved,
        "unique_sources": unique_sources,
        "observed_bytes": round(observed_bytes, 0),
        "severity_counts": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFORMATIONAL": severity_counts.get("INFORMATIONAL", 0),
        },
    }

    return {
        "range": range_value,
        "start": start,
        "bucket": bucket,
        "totals": totals,
        "severity_counts": totals["severity_counts"],
    }


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize database timestamps so bucket keys match regardless of session TZ."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _timeline(db: Session, start: datetime | None, bucket: str) -> list[dict]:
    start = _as_utc(start)
    # Build buckets in UTC explicitly. PostgreSQL date_trunc() uses the session
    # timezone for timestamptz values, which would otherwise shift bucket keys.
    bucket_expr = func.date_trunc(
        bucket, func.timezone("UTC", TrafficRecord.timestamp)
    ).label("bucket")
    conditions = [TrafficRecord.timestamp >= start] if start else []
    rows = db.execute(
        select(
            bucket_expr,
            func.count(TrafficRecord.id),
            func.coalesce(
                func.sum(case((DetectionResult.is_anomaly.is_(True), 1), else_=0)), 0
            ),
            func.coalesce(
                func.sum(
                    case(
                        (
                            and_(
                                DetectionResult.id.is_not(None),
                                DetectionResult.predicted_label != "BENIGN",
                            ),
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ),
            func.coalesce(
                func.sum(case((DetectionResult.severity == "CRITICAL", 1), else_=0)), 0
            ),
            func.coalesce(
                func.sum(case((DetectionResult.severity == "HIGH", 1), else_=0)), 0
            ),
        )
        .select_from(TrafficRecord)
        .outerjoin(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(*conditions)
        .group_by(bucket_expr)
        .order_by(bucket_expr)
    ).all()

    mapped = {
        (_as_utc(row[0]).isoformat() if row[0] else ""): {
            "total": int(row[1]),
            "anomalies": int(row[2]),
            "attacks": int(row[3]),
            "critical": int(row[4]),
            "high": int(row[5]),
        }
        for row in rows
    }
    if not start:
        earliest = _as_utc(db.scalar(select(func.min(TrafficRecord.timestamp))))
        if earliest is None:
            return []
        start = earliest
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    if bucket == "hour":
        cursor = start.replace(minute=0, second=0, microsecond=0)
    else:
        cursor = start.replace(hour=0, minute=0, second=0, microsecond=0)
    end = datetime.now(timezone.utc)
    points: list[dict] = []
    guard = 0
    while cursor <= end and guard < 800:
        key = cursor.isoformat()
        data = mapped.get(key, {})
        points.append(
            {
                "bucket": key,
                "total": data.get("total", 0),
                "anomalies": data.get("anomalies", 0),
                "attacks": data.get("attacks", 0),
                "critical": data.get("critical", 0),
                "high": data.get("high", 0),
            }
        )
        cursor += step
        guard += 1
    return points


def _distribution(db: Session, stmt) -> list[dict]:
    return [
        {"label": str(row[0]) if row[0] is not None else "unknown", "count": int(row[1])}
        for row in db.execute(stmt).all()
    ]


def analytics(db: Session, range_value: str) -> dict:
    summary = summarize(db, range_value)
    start = summary["start"]
    traffic_condition = _traffic_filter(start)
    conditions = [traffic_condition] if traffic_condition is not None else []

    protocol_distribution = _distribution(
        db,
        select(TrafficRecord.protocol, func.count(TrafficRecord.id))
        .where(*conditions)
        .group_by(TrafficRecord.protocol)
        .order_by(func.count(TrafficRecord.id).desc()),
    )

    severity_distribution = _distribution(
        db,
        select(DetectionResult.severity, func.count(DetectionResult.id))
        .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(*conditions)
        .group_by(DetectionResult.severity),
    )

    attack_distribution = _distribution(
        db,
        select(DetectionResult.predicted_label, func.count(DetectionResult.id))
        .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(DetectionResult.predicted_label != "BENIGN", *conditions)
        .group_by(DetectionResult.predicted_label)
        .order_by(func.count(DetectionResult.id).desc()),
    )

    port_distribution = _distribution(
        db,
        select(TrafficRecord.dst_port, func.count(TrafficRecord.id))
        .where(TrafficRecord.dst_port.is_not(None), *conditions)
        .group_by(TrafficRecord.dst_port)
        .order_by(func.count(TrafficRecord.id).desc())
        .limit(10),
    )

    status_distribution = _distribution(
        db,
        select(SecurityIncident.status, func.count(SecurityIncident.id)).group_by(
            SecurityIncident.status
        ),
    )

    ip_query = select(SuspiciousIP).where(
        SuspiciousIP.direction.in_(["source", "both"])
    )
    if start:
        ip_query = ip_query.where(SuspiciousIP.last_seen >= start)
    top_ips = db.scalars(
        ip_query.order_by(SuspiciousIP.risk_score.desc()).limit(10)
    ).all()

    timeline = _timeline(db, start, summary["bucket"])
    return {
        "range": summary["range"],
        "totals": summary["totals"],
        "timeline": timeline,
        "severity_distribution": severity_distribution,
        "protocol_distribution": protocol_distribution,
        "attack_distribution": attack_distribution,
        "top_source_ips": [
            {
                "ip_address": row.ip_address,
                "risk_score": row.risk_score,
                "classification": row.classification,
                "event_count": row.event_count,
                "incident_count": row.incident_count,
                "max_severity": row.max_severity,
                "is_private": row.is_private,
            }
            for row in top_ips
        ],
        "top_destination_ports": port_distribution,
        "status_distribution": status_distribution,
        "detection_history": [
            {
                "bucket": point["bucket"],
                "anomalies": point["anomalies"],
                "attacks": point["attacks"],
            }
            for point in timeline
        ],
    }


def overview(db: Session, range_value: str) -> dict:
    summary = summarize(db, range_value)
    start = summary["start"]
    traffic_condition = _traffic_filter(start)
    conditions = [traffic_condition] if traffic_condition is not None else []

    protocol_distribution = _distribution(
        db,
        select(TrafficRecord.protocol, func.count(TrafficRecord.id))
        .where(*conditions)
        .group_by(TrafficRecord.protocol)
        .order_by(func.count(TrafficRecord.id).desc()),
    )
    attack_distribution = _distribution(
        db,
        select(DetectionResult.predicted_label, func.count(DetectionResult.id))
        .join(TrafficRecord, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(DetectionResult.predicted_label != "BENIGN", *conditions)
        .group_by(DetectionResult.predicted_label)
        .order_by(func.count(DetectionResult.id).desc()),
    )

    incidents_query = select(SecurityIncident).order_by(SecurityIncident.created_at.desc())
    if start:
        incidents_query = incidents_query.where(SecurityIncident.created_at >= start)
    recent_incidents = db.scalars(incidents_query.limit(8)).all()

    ip_query = select(SuspiciousIP).where(
        SuspiciousIP.direction.in_(["source", "both"])
    )
    if start:
        ip_query = ip_query.where(SuspiciousIP.last_seen >= start)
    top_ips = db.scalars(
        ip_query.order_by(SuspiciousIP.risk_score.desc()).limit(6)
    ).all()

    classifier, anomaly = get_active_models(db)
    active_models = []
    for row in (classifier, anomaly):
        if row is not None:
            active_models.append(
                {
                    "id": row.id,
                    "name": row.name,
                    "algorithm": row.algorithm,
                    "task_type": row.task_type,
                    "version": row.version,
                    "metrics": row.metrics,
                    "trained_at": row.trained_at,
                }
            )

    return {
        "range": summary["range"],
        "totals": summary["totals"],
        "severity_counts": summary["severity_counts"],
        "protocol_distribution": protocol_distribution,
        "attack_distribution": attack_distribution,
        "timeline": _timeline(db, start, summary["bucket"]),
        "recent_incidents": [
            {
                "id": incident.id,
                "incident_code": incident.incident_code,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "source_ip": incident.source_ip,
                "created_at": incident.created_at,
            }
            for incident in recent_incidents
        ],
        "top_source_ips": [
            {
                "ip_address": row.ip_address,
                "risk_score": row.risk_score,
                "classification": row.classification,
                "event_count": row.event_count,
                "incident_count": row.incident_count,
                "max_severity": row.max_severity,
                "is_private": row.is_private,
            }
            for row in top_ips
        ],
        "active_models": active_models,
        "generated_at": datetime.now(timezone.utc),
    }
