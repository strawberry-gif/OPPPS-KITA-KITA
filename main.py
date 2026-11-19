from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app.api.routes import (
    analytics,
    auth,
    dashboard,
    detection,
    incidents,
    ips,
    models,
    monitoring,
    settings_routes,
    traffic,
)
from app.core.config import PROJECT_ROOT, settings
from app.core.errors import AppError
from app.core.security import hash_password
from app.database.session import SessionLocal
from app.models.user import User
from app.services.app_settings import ensure_defaults

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("oppps")

FRONTEND_DIR = PROJECT_ROOT / "frontend"


def bootstrap() -> None:
    settings.models_path.mkdir(parents=True, exist_ok=True)
    (settings.datasets_path / "uploads").mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "docs").mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    try:
        count = db.scalar(select(func.count(User.id))) or 0
        if count == 0:
            admin = User(
                email=settings.admin_email.lower(),
                full_name=settings.admin_name,
                role="admin",
                hashed_password=hash_password(settings.admin_password),
            )
            db.add(admin)
            db.commit()
            logger.warning(
                "Created initial administrator %s. Change the default password after login.",
                settings.admin_email,
            )
        ensure_defaults(db)
    except OperationalError as exc:
        db.rollback()
        logger.error(
            "Database tables are not initialized. Run 'alembic upgrade head' or "
            "'python scripts/init_db.py'. Detail: %s",
            exc,
        )
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap()
    yield


app = FastAPI(
    title="OPPPS KITA-KITA",
    description=(
        "Intelligent Cyber Threat Detection & Network Security Monitoring System. "
        "Flow analysis, anomaly detection, threat classification, and incident triage."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
    )
    if request.url.path.startswith("/static/"):
        # Static files are served by the local app; force revalidation so fixes are
        # picked up immediately while still allowing ETag-based 304 responses.
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    elif request.url.path in {"/", "/app", "/login"}:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = [
        {
            "location": ".".join(str(part) for part in error.get("loc", [])),
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "validation_error"),
        }
        for error in exc.errors()[:20]
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed", "errors": errors},
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500, content={"detail": "Internal server error"}
    )


app.include_router(auth.router)
app.include_router(auth.users_router)
app.include_router(dashboard.router)
app.include_router(traffic.router)
app.include_router(detection.router)
app.include_router(ips.router)
app.include_router(incidents.router)
app.include_router(analytics.router)
app.include_router(models.router)
app.include_router(settings_routes.router)
app.include_router(monitoring.router)


@app.get("/api", tags=["System"])
def api_root() -> dict:
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/dashboard/health",
    }


app.mount(
    "/static",
    StaticFiles(directory=str(FRONTEND_DIR / "static")),
    name="static",
)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/app")


@app.get("/app", include_in_schema=False)
def app_shell() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/login", include_in_schema=False)
def login_shell() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "static" / "assets" / "favicon.svg")
