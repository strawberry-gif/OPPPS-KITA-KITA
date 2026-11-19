from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import CurrentUser, DbSession
from app.ml.detector import get_active_models
from app.schemas.dashboard import HealthResponse, Overview
from app.services.analytics import overview as overview_service
from app.services.live_capture import capture_manager

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/overview", response_model=Overview)
def overview(
    user: CurrentUser, db: DbSession, range: str = "7d"
) -> dict:
    return overview_service(db, range)


@router.get("/health", response_model=HealthResponse)
def health(db: DbSession) -> dict:
    try:
        db.execute(text("SELECT 1"))
        database = "connected"
    except Exception:
        database = "unavailable"
    classifier, anomaly = get_active_models(db)
    capture = capture_manager.status()
    return {
        "status": "ok" if database == "connected" else "degraded",
        "database": database,
        "active_classifier": (
            {
                "id": classifier.id,
                "name": classifier.name,
                "version": classifier.version,
            }
            if classifier
            else None
        ),
        "active_anomaly_model": (
            {
                "id": anomaly.id,
                "name": anomaly.name,
                "version": anomaly.version,
            }
            if anomaly
            else None
        ),
        "models_ready": classifier is not None and anomaly is not None,
        "live_capture_available": capture["available"],
        "live_capture_running": capture["running"],
        "server_time": datetime.now(timezone.utc),
    }
