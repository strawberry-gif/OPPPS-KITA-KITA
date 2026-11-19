from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAdmin
from app.models.audit import AuditLog
from app.schemas.model import SettingsOut, SettingsUpdate
from app.services.app_settings import get_all, update_values
from app.services.audit import record_audit
from sqlalchemy import select

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("", response_model=SettingsOut)
def read_settings(user: CurrentUser, db: DbSession) -> dict:
    values, descriptions = get_all(db)
    return {"values": values, "descriptions": descriptions}


@router.put("", response_model=SettingsOut)
def write_settings(
    payload: SettingsUpdate, admin: RequireAdmin, db: DbSession
) -> dict:
    values = update_values(db, payload.values)
    record_audit(
        db,
        user_id=admin.id,
        action="settings.update",
        entity_type="settings",
        detail={"values": payload.values},
    )
    db.commit()
    _, descriptions = get_all(db)
    return {"values": values, "descriptions": descriptions}


@router.get("/audit")
def audit_log(
    admin: RequireAdmin,
    db: DbSession,
    limit: int = Query(100, ge=1, le=500),
) -> list[dict]:
    rows = db.scalars(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    ).all()
    return [
        {
            "id": row.id,
            "user_id": row.user_id,
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "detail": row.detail,
            "ip_address": row.ip_address,
            "created_at": row.created_at,
        }
        for row in rows
    ]
