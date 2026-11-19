from __future__ import annotations

import threading
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import PROJECT_ROOT
from app.ml.features import CANONICAL_FEATURES, feature_frame_from_records
from app.models.model_version import ModelVersion


class ModelNotReadyError(RuntimeError):
    pass


class ModelRegistry:
    def __init__(self) -> None:
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def load(self, artifact_path: str) -> dict:
        path = Path(artifact_path)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        key = str(path.resolve())
        with self._lock:
            cached = self._cache.get(key)
            if cached is None:
                if not path.exists():
                    raise ModelNotReadyError(
                        f"Model artifact is missing: {path.name}. Retrain the models."
                    )
                cached = joblib.load(path)
                self._cache[key] = cached
            return cached

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


registry = ModelRegistry()


def get_active_models(db: Session) -> tuple[ModelVersion | None, ModelVersion | None]:
    classifier = db.scalar(
        select(ModelVersion)
        .where(ModelVersion.task_type == "classification", ModelVersion.is_active.is_(True))
        .order_by(ModelVersion.trained_at.desc())
        .limit(1)
    )
    anomaly = db.scalar(
        select(ModelVersion)
        .where(ModelVersion.task_type == "anomaly", ModelVersion.is_active.is_(True))
        .order_by(ModelVersion.trained_at.desc())
        .limit(1)
    )
    return classifier, anomaly


def _anomaly_scores(bundle: dict, frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    pipeline = bundle["pipeline"]
    flags = pipeline.predict(frame) == -1
    raw = pipeline.decision_function(frame)
    p5 = float(bundle.get("score_p5", -0.15))
    p95 = float(bundle.get("score_p95", 0.10))
    span = p95 - p5
    if abs(span) < 1e-9:
        normalized = np.where(raw < p95, 0.5, 0.0)
    else:
        normalized = (p95 - raw) / span
    return flags, np.clip(normalized, 0.0, 1.0)


def predict_frames(
    db: Session, records_features: list[dict]
) -> tuple[list[dict], ModelVersion | None, ModelVersion | None]:
    classifier_row, anomaly_row = get_active_models(db)
    if classifier_row is None and anomaly_row is None:
        raise ModelNotReadyError(
            "No active models are configured. Train models from the Model Performance page."
        )
    frame = feature_frame_from_records(records_features)
    results: list[dict] = [{} for _ in range(len(records_features))]

    if anomaly_row is not None:
        bundle = registry.load(anomaly_row.artifact_path)
        flags, scores = _anomaly_scores(bundle, frame)
        for index in range(len(results)):
            results[index].update(
                {
                    "is_anomaly": bool(flags[index]),
                    "anomaly_score": round(float(scores[index]), 4),
                    "anomaly_model_id": anomaly_row.id,
                }
            )
    else:
        for item in results:
            item.update(
                {"is_anomaly": False, "anomaly_score": 0.0, "anomaly_model_id": None}
            )

    if classifier_row is not None:
        bundle = registry.load(classifier_row.artifact_path)
        pipeline = bundle["pipeline"]
        classes = list(bundle.get("classes") or pipeline.named_steps["model"].classes_)
        predicted = pipeline.predict(frame)
        probabilities = pipeline.predict_proba(frame)
        benign_index = classes.index("BENIGN") if "BENIGN" in classes else None
        for index, label in enumerate(predicted):
            row_probs = probabilities[index]
            confidence = float(np.max(row_probs))
            if benign_index is not None:
                attack_probability = float(1.0 - row_probs[benign_index])
            else:
                attack_probability = 1.0 if label != "BENIGN" else 0.0
            results[index].update(
                {
                    "predicted_label": str(label),
                    "confidence": round(confidence, 4),
                    "attack_probability": round(attack_probability, 4),
                    "model_version_id": classifier_row.id,
                }
            )
    else:
        for index, item in enumerate(results):
            is_anomaly = bool(item.get("is_anomaly"))
            item.update(
                {
                    "predicted_label": "ANOMALY" if is_anomaly else "BENIGN",
                    "confidence": round(float(item.get("anomaly_score", 0)), 4),
                    "attack_probability": round(float(item.get("anomaly_score", 0)), 4),
                    "model_version_id": None,
                }
            )

    return results, classifier_row, anomaly_row


def predict_single(db: Session, features: dict) -> tuple[dict, ModelVersion | None, ModelVersion | None]:
    results, classifier, anomaly = predict_frames(db, [features])
    return results[0], classifier, anomaly
