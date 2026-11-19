from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.ml.detector import predict_frames, predict_single
from app.models.traffic import DetectionResult
from app.schemas.detection import (
    DetectionPage,
    PredictionInput,
    PredictionResult,
    RunDetectionRequest,
    RunDetectionResult,
)
from app.services.detection import run_detection
from app.services.severity import classify_severity
from app.services.traffic import list_detections
from app.utils.ip import is_public_ip

router = APIRouter(prefix="/api/detection", tags=["Threat Detection"])


@router.post("/run", response_model=RunDetectionResult)
def analyze_traffic(
    payload: RunDetectionRequest, user: RequireAnalyst, db: DbSession
) -> dict:
    return run_detection(
        db, limit=payload.limit, import_id=payload.import_id, user_id=user.id
    )


@router.get("/results", response_model=DetectionPage)
def results(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: str | None = None,
    predicted_label: str | None = None,
    anomaly: bool | None = None,
    search: str | None = None,
) -> dict:
    items, total = list_detections(
        db,
        page=page,
        page_size=page_size,
        severity=severity,
        predicted_label=predicted_label,
        anomaly=anomaly,
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


@router.get("/results/{detection_id}")
def result_detail(detection_id: int, user: CurrentUser, db: DbSession) -> dict:
    row = db.get(DetectionResult, detection_id)
    if row is None:
        raise NotFoundError("Detection result not found")
    record = row.traffic_record
    return {
        "id": row.id,
        "traffic_record_id": row.traffic_record_id,
        "predicted_label": row.predicted_label,
        "confidence": row.confidence,
        "is_anomaly": row.is_anomaly,
        "anomaly_score": row.anomaly_score,
        "severity": row.severity,
        "severity_score": row.severity_score,
        "explanation": row.explanation,
        "created_at": row.created_at,
        "model_version_id": row.model_version_id,
        "traffic_record": {
            "id": record.id if record else None,
            "timestamp": record.timestamp if record else None,
            "src_ip": record.src_ip if record else None,
            "dst_ip": record.dst_ip if record else None,
            "dst_port": record.dst_port if record else None,
            "protocol": record.protocol if record else None,
            "dataset_label": record.dataset_label if record else None,
            "features": record.features if record else {},
        },
    }


@router.post("/predict", response_model=PredictionResult)
def predict(payload: PredictionInput, user: RequireAnalyst, db: DbSession) -> dict:
    features = dict(payload.features)
    if payload.dst_port is not None:
        features.setdefault("destination_port", float(payload.dst_port))
    if payload.protocol.upper() == "TCP":
        features.setdefault("protocol_num", 6)
    elif payload.protocol.upper() == "UDP":
        features.setdefault("protocol_num", 17)
    elif payload.protocol.upper() == "ICMP":
        features.setdefault("protocol_num", 1)
    prediction, classifier, anomaly_model = predict_single(db, features)
    severity, score, explanation = classify_severity(
        predicted_label=prediction["predicted_label"],
        confidence=prediction["confidence"],
        attack_probability=prediction.get("attack_probability", 0),
        is_anomaly=prediction["is_anomaly"],
        anomaly_score=prediction["anomaly_score"],
        features=features,
        source_ip=payload.src_ip,
        source_is_public=is_public_ip(payload.src_ip),
        recent_events=0,
    )
    return {
        "predicted_label": prediction["predicted_label"],
        "confidence": prediction["confidence"],
        "is_anomaly": prediction["is_anomaly"],
        "anomaly_score": prediction["anomaly_score"],
        "severity": severity,
        "severity_score": score,
        "explanation": explanation,
        "model_version_id": classifier.id if classifier else None,
        "anomaly_model_version_id": anomaly_model.id if anomaly_model else None,
    }
