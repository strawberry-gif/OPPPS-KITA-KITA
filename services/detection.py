from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import ConflictError
from app.ml.detector import ModelNotReadyError, get_active_models, predict_frames
from app.models.incident import SecurityIncident
from app.models.ip import SuspiciousIP
from app.models.traffic import DetectionResult, TrafficRecord
from app.services.audit import record_audit
from app.services.severity import (
    SEVERITY_ORDER,
    SEVERITY_POINTS,
    classify_severity,
    severity_rank,
)
from app.utils.ip import is_private_ip, is_public_ip

INCIDENT_WINDOW_MINUTES = 30
RECENT_WINDOW_MINUTES = 15
_run_lock = threading.Lock()


def _incident_code() -> str:
    return f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def _incident_title(predicted_label: str, source_ip: str | None, is_anomaly: bool) -> str:
    source = source_ip or "unknown source"
    if predicted_label == "BENIGN":
        return f"Anomalous traffic from {source}"
    if predicted_label == "ANOMALY":
        return f"Anomalous traffic from {source}"
    return f"Possible {predicted_label} activity from {source}"


def _recent_event_counts(db: Session) -> dict[str, int]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=RECENT_WINDOW_MINUTES)
    rows = db.execute(
        select(TrafficRecord.src_ip, func.count(DetectionResult.id))
        .join(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(
            TrafficRecord.timestamp >= cutoff,
            TrafficRecord.src_ip.is_not(None),
            or_(
                DetectionResult.is_anomaly.is_(True),
                DetectionResult.severity.in_(["MEDIUM", "HIGH", "CRITICAL"]),
            ),
        )
        .group_by(TrafficRecord.src_ip)
    ).all()
    return {row[0]: int(row[1]) for row in rows}


def _risk_score(
    max_severity: str, anomaly_count: int, event_count: int, last_seen: datetime
) -> float:
    severity_points = SEVERITY_POINTS.get(max_severity, 0)
    recency = 15.0
    if last_seen:
        aware = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        age_hours = max(
            0.0, (datetime.now(timezone.utc) - aware).total_seconds() / 3600
        )
        if age_hours <= 1:
            recency = 100.0
        elif age_hours <= 24:
            recency = 70.0
        elif age_hours <= 24 * 7:
            recency = 40.0
    score = (
        0.35 * severity_points
        + 0.25 * min(100.0, anomaly_count * 4.0)
        + 0.20 * min(100.0, event_count * 2.0)
        + 0.20 * recency
    )
    return round(max(0.0, min(100.0, score)), 1)


def _classification(risk: float) -> str:
    if risk >= 75:
        return "HIGH_RISK"
    if risk >= 50:
        return "SUSPICIOUS"
    if risk >= 25:
        return "WATCHLIST"
    return "OBSERVED"


def _merge_ip(
    db: Session,
    stats: dict,
    ip_value: str,
    *,
    direction: str,
    severity: str,
    is_anomaly: bool,
    prediction: str,
    seen_at: datetime,
    incident_created: bool,
) -> None:
    if not ip_value:
        return
    key = ip_value
    entry = stats.setdefault(
        key,
        {
            "direction": direction,
            "event_count": 0,
            "anomaly_count": 0,
            "incident_count": 0,
            "max_severity": "INFORMATIONAL",
            "last_seen": seen_at,
            "predictions": defaultdict(int),
        },
    )
    if entry["direction"] != direction:
        entry["direction"] = "both"
    entry["event_count"] += 1
    if is_anomaly:
        entry["anomaly_count"] += 1
    if incident_created:
        entry["incident_count"] += 1
    if severity_rank(severity) > severity_rank(entry["max_severity"]):
        entry["max_severity"] = severity
    aware_seen = seen_at if seen_at.tzinfo else seen_at.replace(tzinfo=timezone.utc)
    aware_last = (
        entry["last_seen"]
        if entry["last_seen"].tzinfo
        else entry["last_seen"].replace(tzinfo=timezone.utc)
    )
    if aware_seen > aware_last:
        entry["last_seen"] = seen_at
    if prediction not in ("BENIGN", "ANOMALY"):
        entry["predictions"][prediction] += 1


def _persist_ips(db: Session, stats: dict) -> None:
    if not stats:
        return
    existing_rows = db.scalars(
        select(SuspiciousIP).where(SuspiciousIP.ip_address.in_(list(stats.keys())))
    ).all()
    existing = {row.ip_address: row for row in existing_rows}

    for address, data in stats.items():
        private = is_private_ip(address)
        row = existing.get(address)
        if row is None:
            row = SuspiciousIP(
                ip_address=address,
                is_private=private,
                first_seen=data["last_seen"],
                direction=data["direction"],
            )
            db.add(row)
        row.event_count = (row.event_count or 0) + data["event_count"]
        row.anomaly_count = (row.anomaly_count or 0) + data["anomaly_count"]
        row.incident_count = (row.incident_count or 0) + data["incident_count"]
        if severity_rank(data["max_severity"]) > severity_rank(row.max_severity or "INFORMATIONAL"):
            row.max_severity = data["max_severity"]
        if row.first_seen is None or data["last_seen"] < row.first_seen:
            row.first_seen = data["last_seen"]
        if row.last_seen is None or data["last_seen"] > row.last_seen:
            row.last_seen = data["last_seen"]
        if data["predictions"]:
            row.top_prediction = max(
                data["predictions"].items(), key=lambda pair: pair[1]
            )[0]
        if row.direction != data["direction"]:
            row.direction = "both"
        risk = _risk_score(
            row.max_severity or "INFORMATIONAL",
            row.anomaly_count or 0,
            row.event_count or 0,
            row.last_seen,
        )
        if row.direction == "destination":
            risk = round(risk * 0.45, 1)
            row.classification = "MONITORED_DESTINATION"
        else:
            row.classification = _classification(risk)
        row.risk_score = risk


def run_detection(
    db: Session,
    *,
    limit: int = 2000,
    import_id: int | None = None,
    user_id: int | None = None,
    record_ids: list[int] | None = None,
) -> dict:
    if not _run_lock.acquire(blocking=False):
        raise ConflictError("A detection run is already in progress. Try again shortly.")
    try:
        return _run_detection(
            db,
            limit=limit,
            import_id=import_id,
            user_id=user_id,
            record_ids=record_ids,
        )
    finally:
        _run_lock.release()


def _run_detection(
    db: Session,
    *,
    limit: int,
    import_id: int | None,
    user_id: int | None,
    record_ids: list[int] | None = None,
) -> dict:
    started = time.perf_counter()
    classifier, anomaly = get_active_models(db)
    if classifier is None and anomaly is None:
        raise ModelNotReadyError(
            "No active detection models. Train models before analyzing traffic."
        )

    query = (
        select(TrafficRecord)
        .outerjoin(DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id)
        .where(DetectionResult.id.is_(None))
        .order_by(TrafficRecord.timestamp.asc())
        .limit(limit)
    )
    if import_id is not None:
        query = query.where(TrafficRecord.dataset_import_id == import_id)
    if record_ids:
        query = query.where(TrafficRecord.id.in_(record_ids))
    records = list(db.scalars(query).all())

    if not records:
        return {
            "processed": 0,
            "attacks": 0,
            "anomalies": 0,
            "incidents_created": 0,
            "skipped": 0,
            "duration_seconds": 0.0,
            "severity_counts": {level: 0 for level in SEVERITY_ORDER},
            "model": classifier.name if classifier else "Unsupervised only",
            "anomaly_model": anomaly.name if anomaly else "None",
        }

    recent_counts = _recent_event_counts(db)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=INCIDENT_WINDOW_MINUTES)
    recent_incidents = db.execute(
        select(SecurityIncident.source_ip, SecurityIncident.title).where(
            SecurityIncident.created_at >= cutoff,
            SecurityIncident.status.in_(["NEW", "INVESTIGATING"]),
        )
    ).all()
    dedupe = {(row[0], row[1]) for row in recent_incidents}
    threshold = _incident_threshold(db)

    severity_counts = {level: 0 for level in SEVERITY_ORDER}
    attacks = 0
    anomalies = 0
    incidents_created = 0
    ip_stats: dict[str, dict] = {}
    batch_size = 500

    for offset in range(0, len(records), batch_size):
        batch = records[offset : offset + batch_size]
        predictions, _, _ = predict_frames(db, [record.features for record in batch])
        staged: list[tuple[TrafficRecord, dict, str, float, dict, DetectionResult]] = []
        for record, prediction in zip(batch, predictions):
            attack = prediction["predicted_label"] not in ("BENIGN",)
            if attack:
                attacks += 1
            if prediction["is_anomaly"]:
                anomalies += 1
            recent_counts[record.src_ip] = recent_counts.get(record.src_ip, 0) + (
                1 if prediction["is_anomaly"] or attack else 0
            )
            severity, severity_score, explanation = classify_severity(
                predicted_label=prediction["predicted_label"],
                confidence=prediction["confidence"],
                attack_probability=prediction.get("attack_probability", 0),
                is_anomaly=prediction["is_anomaly"],
                anomaly_score=prediction["anomaly_score"],
                features=record.features,
                source_ip=record.src_ip,
                source_is_public=is_public_ip(record.src_ip),
                recent_events=recent_counts.get(record.src_ip, 0),
            )
            severity_counts[severity] += 1
            detection = DetectionResult(
                traffic_record_id=record.id,
                model_version_id=prediction.get("model_version_id"),
                anomaly_model_id=prediction.get("anomaly_model_id"),
                is_anomaly=prediction["is_anomaly"],
                anomaly_score=prediction["anomaly_score"],
                predicted_label=prediction["predicted_label"],
                confidence=prediction["confidence"],
                severity=severity,
                severity_score=severity_score,
                explanation=explanation,
            )
            db.add(detection)
            staged.append((record, prediction, severity, severity_score, explanation, detection))

        db.flush()
        for record, prediction, severity, _, explanation, detection in staged:
            attack = prediction["predicted_label"] not in ("BENIGN",)
            should_track = (
                attack
                or prediction["is_anomaly"]
                or severity_rank(severity) >= severity_rank("MEDIUM")
            )
            incident_created = False
            if should_track and severity_rank(severity) >= severity_rank(threshold):
                title = _incident_title(
                    prediction["predicted_label"], record.src_ip, prediction["is_anomaly"]
                )
                if (record.src_ip, title) not in dedupe:
                    dedupe.add((record.src_ip, title))
                    summary = explanation["summary"]
                    signals = explanation.get("signals", [])
                    explanation_text = summary + (
                        " Key signals: "
                        + "; ".join(
                            f"{item['rule']} (+{item['weight']})" for item in signals[:4]
                        )
                        if signals
                        else ""
                    )
                    db.add(
                        SecurityIncident(
                            incident_code=_incident_code(),
                            title=title,
                            description=(
                                f"Detection on traffic record #{record.id}. "
                                "This incident is derived from model output and heuristic rules; "
                                "it is not a confirmed compromise."
                            ),
                            severity=severity,
                            status="NEW",
                            source_ip=record.src_ip,
                            destination_ip=record.dst_ip,
                            traffic_record_id=record.id,
                            detection_result_id=detection.id,
                            detection_explanation=explanation_text,
                        )
                    )
                    incident_created = True
                    incidents_created += 1

            if should_track and record.src_ip:
                _merge_ip(
                    db,
                    ip_stats,
                    record.src_ip,
                    direction="source",
                    severity=severity,
                    is_anomaly=prediction["is_anomaly"],
                    prediction=prediction["predicted_label"],
                    seen_at=record.timestamp,
                    incident_created=incident_created,
                )
            if (
                should_track
                and record.dst_ip
                and is_private_ip(record.dst_ip)
                and is_public_ip(record.src_ip)
            ):
                _merge_ip(
                    db,
                    ip_stats,
                    record.dst_ip,
                    direction="destination",
                    severity=severity,
                    is_anomaly=prediction["is_anomaly"],
                    prediction=prediction["predicted_label"],
                    seen_at=record.timestamp,
                    incident_created=False,
                )

    _persist_ips(db, ip_stats)
    record_audit(
        db,
        user_id=user_id,
        action="detection.run",
        entity_type="detection",
        detail={
            "processed": len(records),
            "attacks": attacks,
            "anomalies": anomalies,
            "incidents_created": incidents_created,
            "import_id": import_id,
        },
    )
    db.commit()
    duration = time.perf_counter() - started
    return {
        "processed": len(records),
        "attacks": attacks,
        "anomalies": anomalies,
        "incidents_created": incidents_created,
        "skipped": 0,
        "duration_seconds": round(duration, 3),
        "severity_counts": severity_counts,
        "model": classifier.name if classifier else "Unsupervised only",
        "anomaly_model": anomaly.name if anomaly else "None",
    }


def _incident_threshold(db: Session) -> str:
    from app.services.app_settings import get_value

    value = get_value(db, "incident_min_severity", settings.incident_min_severity)
    return value if value in SEVERITY_ORDER else settings.incident_min_severity


def detection_to_dict(detection: DetectionResult) -> dict:
    return {
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
    }
