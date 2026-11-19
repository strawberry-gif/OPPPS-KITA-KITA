from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession
from app.schemas.dashboard import AnalyticsResponse
from app.services.analytics import analytics

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@router.get("", response_model=AnalyticsResponse)
def get_analytics(user: CurrentUser, db: DbSession, range: str = "7d") -> dict:
    return analytics(db, range)
