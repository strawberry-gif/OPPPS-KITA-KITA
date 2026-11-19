from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.schemas.incident import IncidentDetail, IncidentPage, IncidentUpdate
from app.services.incidents import (
    get_incident_detail,
    list_incidents,
    update_incident,
)

router = APIRouter(prefix="/api/incidents", tags=["Security Incidents"])


@router.get("", response_model=IncidentPage)
def incidents(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    status: str | None = Query(None, pattern="^(NEW|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$"),
    severity: str | None = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)$"),
    search: str | None = None,
) -> dict:
    items, total = list_incidents(
        db,
        page=page,
        page_size=page_size,
        status=status,
        severity=severity,
        search=search,
    )
    pages = (total + page_size - 1) // page_size
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/{incident_id}", response_model=IncidentDetail)
def incident_detail(incident_id: int, user: CurrentUser, db: DbSession) -> dict:
    return get_incident_detail(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update(
    incident_id: int,
    payload: IncidentUpdate,
    user: RequireAnalyst,
    db: DbSession,
) -> dict:
    update_incident(db, incident_id, payload.model_dump(exclude_unset=True), user)
    return get_incident_detail(db, incident_id)
