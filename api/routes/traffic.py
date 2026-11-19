from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, File, Form, Query, UploadFile
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.config import settings
from app.core.errors import ValidationError
from app.ml.detector import ModelNotReadyError
from app.ml.features import ALIASES, CANONICAL_FEATURES
from app.models.dataset import DatasetImport
from app.schemas.traffic import (
    DatasetImportOut,
    FeatureSchemaOut,
    ImportResult,
    TrafficPage,
)
from app.services.detection import run_detection
from app.services.ingestion import import_dataset
from app.services.traffic import get_record, list_records, traffic_stats

router = APIRouter(prefix="/api/traffic", tags=["Network Traffic"])
logger = logging.getLogger(__name__)


@router.get("/schema", response_model=FeatureSchemaOut)
def feature_schema(user: CurrentUser) -> dict:
    return {
        "canonical_features": CANONICAL_FEATURES,
        "aliases": ALIASES,
        "required_minimum": 3,
        "allowed_extensions": sorted(settings.upload_extensions),
        "max_upload_mb": settings.upload_max_mb,
        "max_rows": settings.upload_max_rows,
    }


@router.post("/import", response_model=ImportResult, status_code=201)
async def upload_dataset(
    user: RequireAnalyst,
    db: DbSession,
    file: Annotated[UploadFile, File()],
    mapping: Annotated[str | None, Form()] = None,
    label_column: Annotated[str | None, Form()] = None,
    analyze: Annotated[bool, Form()] = True,
) -> dict:
    parsed_mapping = None
    if mapping:
        if len(mapping) > 20000:
            raise ValidationError("Mapping JSON is too large")
        try:
            parsed_mapping = json.loads(mapping)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Invalid mapping JSON: {exc.msg}") from exc
        if not isinstance(parsed_mapping, dict):
            raise ValidationError("Mapping JSON must be an object")

    dataset, result = await import_dataset(
        db,
        file,
        user.id,
        mapping=parsed_mapping,
        label_column=label_column or None,
    )
    analysis = result["analysis"]
    warnings = result["warnings"]
    if analyze:
        try:
            detection_result = run_detection(
                db, limit=settings.upload_max_rows, import_id=dataset.id, user_id=user.id
            )
            analysis["detection"] = detection_result
        except ModelNotReadyError:
            warnings.append(
                "Traffic was imported but not analyzed because no active models exist. "
                "Train models, then run detection."
            )
        except Exception:
            # Never surface raw exception text to API clients; keep details in the server log.
            db.rollback()
            logger.exception("Detection failed after import %s", dataset.id)
            warnings.append(
                "Traffic was imported and stored, but analysis did not complete. "
                "The flows remain available and can be analyzed again from the detection page."
            )
    return {
        "dataset": DatasetImportOut.model_validate(dataset),
        "detected_columns": analysis["mapped_features"],
        "warnings": warnings,
        "analysis": analysis,
    }


@router.get("/imports", response_model=list[DatasetImportOut])
def imports(user: CurrentUser, db: DbSession) -> list[DatasetImport]:
    return list(
        db.scalars(
            select(DatasetImport).order_by(DatasetImport.created_at.desc()).limit(100)
        ).all()
    )


@router.get("/records", response_model=TrafficPage)
def records(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = None,
    protocol: str | None = None,
    label: str | None = None,
    severity: str | None = None,
    anomaly: bool | None = None,
    source: str | None = None,
    import_id: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict:
    items, total = list_records(
        db,
        page=page,
        page_size=page_size,
        search=search,
        protocol=protocol,
        dataset_label=label,
        severity=severity,
        anomaly=anomaly,
        source=source,
        import_id=import_id,
        start=start,
        end=end,
    )
    pages = (total + page_size - 1) // page_size
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/records/{record_id}")
def record_detail(record_id: int, user: CurrentUser, db: DbSession) -> dict:
    return get_record(db, record_id)


@router.get("/stats")
def stats(user: CurrentUser, db: DbSession) -> dict:
    return traffic_stats(db)
