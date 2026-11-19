from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.schemas.ip import IPDetail, IPPage, IPUpdate
from app.services.ip_intel import get_ip_detail, list_ips, update_ip

router = APIRouter(prefix="/api/ips", tags=["Suspicious IPs"])


@router.get("", response_model=IPPage)
def ips(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = None,
    direction: str | None = Query(None, pattern="^(source|destination|both)$"),
    classification: str | None = None,
    min_risk: float | None = Query(None, ge=0, le=100),
    private: bool | None = None,
) -> dict:
    items, total = list_ips(
        db,
        page=page,
        page_size=page_size,
        search=search,
        direction=direction,
        classification=classification,
        min_risk=min_risk,
        private=private,
    )
    pages = (total + page_size - 1) // page_size
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/{ip_id}", response_model=IPDetail)
def ip_detail(ip_id: int, user: CurrentUser, db: DbSession) -> dict:
    return get_ip_detail(db, ip_id)


@router.patch("/{ip_id}")
def update_ip_record(
    ip_id: int, payload: IPUpdate, user: RequireAnalyst, db: DbSession
) -> dict:
    from app.services.audit import record_audit

    result = update_ip(db, ip_id, payload.notes, payload.classification)
    record_audit(
        db,
        user_id=user.id,
        action="ip.update",
        entity_type="ip",
        entity_id=str(ip_id),
        detail=payload.model_dump(exclude_none=True),
    )
    db.commit()
    return result
