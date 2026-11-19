from __future__ import annotations

import math
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.errors import NotFoundError, ValidationError
from app.models.audit import AuditLog
from app.models.incident import SecurityIncident
from app.models.traffic import DetectionResult, TrafficRecord
from app.models.user import User
from app.services.audit import record_audit
from app.services.app_settings import get_value

VALID_STATUSES = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


def incident_dict(incident: SecurityIncident) -> dict:
    return {
        "id": incident.id,
        "incident_code": incident.incident_code,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "source_ip": incident.source_ip,
        "destination_ip": incident.destination_ip,
        "traffic_record_id": incident.traffic_record_id,
        "detection_result_id": incident.detection_result_id,
        "detection_explanation": incident.detection_explanation,
        "investigation_notes": incident.investigation_notes,
        "assigned_to": incident.assigned_to,
        "assignee_name": incident.assignee.full_name if incident.assignee else None,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "resolved_at": incident.resolved_at,
    }


def list_incidents(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 25,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    query = select(SecurityIncident).options(joinedload(SecurityIncident.assignee))
    count_query = select(func.count(SecurityIncident.id))

    filters = []
    if status:
        filters.append(SecurityIncident.status == status)
    if severity:
        filters.append(SecurityIncident.severity == severity)
    if search:
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                SecurityIncident.title.ilike(term),
                SecurityIncident.incident_code.ilike(term),
                SecurityIncident.source_ip.ilike(term),
                SecurityIncident.investigation_notes.ilike(term),
            )
        )
    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total = int(db.scalar(count_query) or 0)
    rows = db.scalars(
        query.order_by(SecurityIncident.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [incident_dict(row) for row in rows], total


def get_incident_detail(db: Session, incident_id: int) -> dict:
    incident = db.scalar(
        select(SecurityIncident)
        .options(joinedload(SecurityIncident.assignee))
        .where(SecurityIncident.id == incident_id)
    )
    if incident is None:
        raise NotFoundError("Incident not found")
    result = incident_dict(incident)

    related = []
    if incident.source_ip:
        rows = db.execute(
            select(TrafficRecord, DetectionResult)
            .outerjoin(
                DetectionResult, DetectionResult.traffic_record_id == TrafficRecord.id
            )
            .where(TrafficRecord.src_ip == incident.source_ip)
            .order_by(TrafficRecord.timestamp.desc())
            .limit(15)
        ).all()
        related = [
            {
                "id": record.id,
                "timestamp": record.timestamp,
                "destination_ip": record.dst_ip,
                "destination_port": record.dst_port,
                "protocol": record.protocol,
                "packet_count": record.packet_count,
                "predicted_label": detection.predicted_label if detection else None,
                "severity": detection.severity if detection else None,
                "dataset_label": record.dataset_label,
            }
            for record, detection in rows
        ]
    result["related_records"] = related

    activity = db.scalars(
        select(AuditLog)
        .where(AuditLog.entity_type == "incident", AuditLog.entity_id == str(incident.id))
        .order_by(AuditLog.created_at.desc())
        .limit(50)
    ).all()
    result["activity_log"] = [
        {
            "action": entry.action,
            "detail": entry.detail,
            "created_at": entry.created_at,
            "user_id": entry.user_id,
        }
        for entry in activity
    ]
    return result


def update_incident(
    db: Session, incident_id: int, payload: dict, user: User
) -> dict:
    incident = db.get(SecurityIncident, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found")

    changes: dict = {}
    new_status = payload.get("status")
    if new_status is not None:
        if new_status not in VALID_STATUSES:
            raise ValidationError("Invalid incident status")
        if (
            new_status in {"RESOLVED", "FALSE_POSITIVE"}
            and get_value(db, "analyst_note_required_on_close", "false") == "true"
            and not (payload.get("investigation_notes") or incident.investigation_notes)
        ):
            raise ValidationError("Investigation notes are required before closing an incident")
        changes["status"] = {"from": incident.status, "to": new_status}
        incident.status = new_status
        if new_status in {"RESOLVED", "FALSE_POSITIVE"}:
            incident.resolved_at = datetime.now(timezone.utc)
            incident.closed_by = user.id
        else:
            incident.resolved_at = None
            incident.closed_by = None

    if "investigation_notes" in payload and payload["investigation_notes"] is not None:
        incident.investigation_notes = payload["investigation_notes"]
        changes["investigation_notes"] = "updated"

    assigned = payload.get("assigned_to")
    if assigned is not None:
        if assigned == 0:
            incident.assigned_to = None
            changes["assigned_to"] = None
        else:
            assignee = db.get(User, assigned)
            if assignee is None or not assignee.is_active:
                raise ValidationError("Assigned user does not exist or is inactive")
            incident.assigned_to = assigned
            changes["assigned_to"] = assigned

    record_audit(
        db,
        user_id=user.id,
        action="incident.update",
        entity_type="incident",
        entity_id=str(incident.id),
        detail=changes,
        ip_address=None,
    )
    db.commit()
    db.refresh(incident)
    return incident_dict(incident)


def status_counts(db: Session) -> dict[str, int]:
    rows = db.execute(
        select(SecurityIncident.status, func.count()).group_by(SecurityIncident.status)
    ).all()
    counts = {"NEW": 0, "INVESTIGATING": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0}
    for status, count in rows:
        counts[status] = int(count)
    return counts


def severity_counts(db: Session, start: datetime | None = None) -> dict[str, int]:
    query = select(SecurityIncident.severity, func.count()).group_by(
        SecurityIncident.severity
    )
    if start:
        query = query.where(SecurityIncident.created_at >= start)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for severity, count in db.execute(query).all():
        counts[severity] = int(count)
    return counts
