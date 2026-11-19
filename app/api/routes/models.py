from __future__ import annotations

import json
import threading
from pathlib import Path

from fastapi import APIRouter
from sqlalchemy import select, update

from app.api.deps import CurrentUser, DbSession, RequireAdmin
from app.core.config import PROJECT_ROOT, settings
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.ml.detector import registry
from app.ml.train import train_models
from app.models.model_version import ModelVersion
from app.schemas.model import ModelVersionOut, TrainRequest, TrainResponse

router = APIRouter(prefix="/api/models", tags=["Model Performance"])
_train_lock = threading.Lock()


def _resolve_dataset(path_value: str | None) -> str | None:
    if not path_value:
        return None
    candidate = Path(path_value)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    resolved = candidate.resolve()
    datasets_root = settings.datasets_path.resolve()
    if datasets_root not in resolved.parents and resolved != datasets_root:
        raise ValidationError("Training dataset must be located inside the datasets directory")
    if not resolved.exists():
        raise ValidationError("Training dataset path does not exist")
    if resolved.suffix.lower() != ".csv":
        raise ValidationError("Training dataset must be a CSV file")
    return str(resolved)


@router.get("", response_model=list[ModelVersionOut])
def list_models(user: CurrentUser, db: DbSession) -> list[ModelVersion]:
    return list(
        db.scalars(
            select(ModelVersion).order_by(ModelVersion.trained_at.desc(), ModelVersion.id)
        ).all()
    )


@router.get("/active", response_model=list[ModelVersionOut])
def active_models(user: CurrentUser, db: DbSession) -> list[ModelVersion]:
    return list(
        db.scalars(
            select(ModelVersion).where(ModelVersion.is_active.is_(True))
        ).all()
    )


@router.get("/comparison")
def comparison(user: CurrentUser) -> dict:
    path = PROJECT_ROOT / "docs" / "model_metrics.json"
    if not path.exists():
        return {"latest_run": None}
    try:
        return {"latest_run": json.loads(path.read_text(encoding="utf-8"))}
    except (json.JSONDecodeError, OSError):
        return {"latest_run": None}


@router.get("/{model_id}", response_model=ModelVersionOut)
def model_detail(model_id: int, user: CurrentUser, db: DbSession) -> ModelVersion:
    row = db.get(ModelVersion, model_id)
    if row is None:
        raise NotFoundError("Model version not found")
    return row


@router.post("/train", response_model=TrainResponse)
def train(payload: TrainRequest, admin: RequireAdmin, db: DbSession) -> dict:
    if not _train_lock.acquire(blocking=False):
        raise ConflictError("A training run is already in progress")
    try:
        dataset = _resolve_dataset(payload.dataset_path)
        result = train_models(
            dataset_path=dataset,
            test_size=payload.test_size,
            random_state=payload.random_state,
            db=db,
        )
        report = result["report"]
        models = result["models"]
        classifier = next(
            (row for row in models if row.task_type == "classification" and row.is_active),
            None,
        )
        anomaly = next(
            (row for row in models if row.task_type == "anomaly" and row.is_active),
            None,
        )
        registry.clear()
        return {
            "run_id": report["run_id"],
            "dataset": report["dataset"],
            "rows": report["dataset_rows"],
            "duration_seconds": report["duration_seconds"],
            "models": [ModelVersionOut.model_validate(row) for row in models],
            "comparison": report["comparison"],
            "active_classifier_id": classifier.id if classifier else None,
            "active_anomaly_id": anomaly.id if anomaly else None,
        }
    finally:
        _train_lock.release()


@router.post("/{model_id}/activate", response_model=ModelVersionOut)
def activate(model_id: int, admin: RequireAdmin, db: DbSession) -> ModelVersion:
    row = db.get(ModelVersion, model_id)
    if row is None:
        raise NotFoundError("Model version not found")
    artifact = Path(row.artifact_path)
    if not artifact.is_absolute():
        artifact = PROJECT_ROOT / artifact
    if not artifact.exists():
        raise ValidationError("Model artifact file is missing; retrain instead")
    db.execute(
        update(ModelVersion)
        .where(ModelVersion.task_type == row.task_type)
        .values(is_active=False)
    )
    row.is_active = True
    db.commit()
    db.refresh(row)
    registry.clear()
    return row
