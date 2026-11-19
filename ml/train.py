from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import PROJECT_ROOT, settings
from app.database.session import SessionLocal
from app.ml.features import CANONICAL_FEATURES, normalize_label
from app.models.model_version import ModelVersion

BENIGN = "BENIGN"


def _version() -> str:
    return datetime.now(timezone.utc).strftime("v%Y%m%d.%H%M%S")


def load_training_frame(path: Path | None = None) -> tuple[pd.DataFrame, Path]:
    dataset_path = path or (settings.datasets_path / "processed" / "train.csv")
    if not dataset_path.is_absolute():
        dataset_path = PROJECT_ROOT / dataset_path
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {dataset_path}. Run scripts/generate_dataset.py first."
        )
    frame = pd.read_csv(dataset_path)
    if "label" in frame.columns:
        label_series = frame["label"]
    elif "dataset_label" in frame.columns:
        label_series = frame["dataset_label"]
    else:
        raise ValueError("Training dataset must contain a 'label' or 'dataset_label' column")

    frame["label"] = label_series.map(normalize_label)
    frame = frame.dropna(subset=["label"]).copy()
    for feature in CANONICAL_FEATURES:
        if feature not in frame.columns:
            frame[feature] = np.nan
        frame[feature] = pd.to_numeric(frame[feature], errors="coerce")
    usable = frame[CANONICAL_FEATURES].notna().any(axis=1)
    frame = frame.loc[usable].reset_index(drop=True)
    if len(frame) < 100:
        raise ValueError("Not enough usable rows to train models (minimum 100)")
    return frame, dataset_path


def _binary_metrics(pipeline: Pipeline, x_test: pd.DataFrame, y_binary: np.ndarray) -> dict:
    raw = pipeline.decision_function(x_test)
    predicted = pipeline.predict(x_test) == -1
    metrics = {
        "precision": float(precision_score(y_binary, predicted, zero_division=0)),
        "recall": float(recall_score(y_binary, predicted, zero_division=0)),
        "f1": float(f1_score(y_binary, predicted, zero_division=0)),
        "accuracy": float(accuracy_score(y_binary, predicted)),
        "confusion_matrix": confusion_matrix(y_binary, predicted).tolist(),
        "labels": ["normal", "anomaly"],
    }
    if len(np.unique(y_binary)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_binary, -raw))
    else:
        metrics["roc_auc"] = None
    return metrics


def _classifier_metrics(
    pipeline: Pipeline, x_test: pd.DataFrame, y_test: pd.Series, labels: list[str]
) -> dict:
    predicted = pipeline.predict(x_test)
    result = {
        "accuracy": float(accuracy_score(y_test, predicted)),
        "precision_weighted": float(
            precision_score(y_test, predicted, average="weighted", zero_division=0)
        ),
        "recall_weighted": float(
            recall_score(y_test, predicted, average="weighted", zero_division=0)
        ),
        "f1_weighted": float(
            f1_score(y_test, predicted, average="weighted", zero_division=0)
        ),
        "f1_macro": float(
            f1_score(y_test, predicted, average="macro", zero_division=0)
        ),
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=labels).tolist(),
        "labels": labels,
        "per_class": classification_report(
            y_test, predicted, output_dict=True, zero_division=0
        ),
    }
    try:
        probabilities = pipeline.predict_proba(x_test)
        if len(labels) > 1 and probabilities.shape[1] == len(labels):
            result["roc_auc_ovr_weighted"] = float(
                roc_auc_score(
                    y_test,
                    probabilities,
                    multi_class="ovr",
                    average="weighted",
                    labels=labels,
                )
            )
        elif len(labels) == 2:
            result["roc_auc_ovr_weighted"] = float(
                roc_auc_score(
                    (y_test == labels[1]).astype(int), probabilities[:, 1]
                )
            )
    except (ValueError, IndexError):
        result["roc_auc_ovr_weighted"] = None
    return result


def _artifact_metadata(model, algorithm: str, task_type: str, version: str) -> dict:
    bundle = {
        "pipeline": model,
        "feature_names": CANONICAL_FEATURES,
        "algorithm": algorithm,
        "task_type": task_type,
        "version": version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    if task_type == "anomaly":
        scorer = model.named_steps["model"]
        benign_scores = getattr(model, "training_scores_", None)
        p5, p95 = (-0.15, 0.10)
        if benign_scores is not None and len(benign_scores):
            p5 = float(np.percentile(benign_scores, 5))
            p95 = float(np.percentile(benign_scores, 95))
        bundle["score_p5"] = p5
        bundle["score_p95"] = p95
        bundle["threshold"] = float(scorer.offset_)
    else:
        bundle["classes"] = list(model.named_steps["model"].classes_)
    return bundle


def _save_artifact(pipeline: Pipeline, algorithm: str, task_type: str, version: str) -> Path:
    settings.models_path.mkdir(parents=True, exist_ok=True)
    bundle = _artifact_metadata(pipeline, algorithm, task_type, version)
    filename = f"{task_type}_{algorithm}_{version}.joblib".replace(" ", "_")
    path = settings.models_path / filename
    joblib.dump(bundle, path, compress=3)
    return path


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def train_models(
    dataset_path: str | Path | None = None,
    test_size: float = 0.25,
    random_state: int = 42,
    db: Session | None = None,
    persist: bool = True,
) -> dict:
    started = time.perf_counter()
    frame, resolved_path = load_training_frame(
        Path(dataset_path) if dataset_path else None
    )
    labels = sorted(frame["label"].unique().tolist())
    if len(labels) < 2:
        raise ValueError("Training requires at least two label classes")

    x = frame[CANONICAL_FEATURES]
    y = frame["label"]
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=test_size, random_state=random_state, stratify=y
    )

    version = _version() + "-" + uuid.uuid4().hex[:4]
    run_id = uuid.uuid4().hex
    median_imputer = Pipeline(
        [("imputer", SimpleImputer(strategy="median", keep_empty_features=True))]
    )

    benign_train = x_train.loc[y_train == BENIGN]
    if len(benign_train) < 50:
        benign_train = x_train

    anomaly_pipeline = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=150,
                    contamination=settings.anomaly_contamination,
                    max_samples="auto",
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    anomaly_pipeline.fit(benign_train)
    benign_scores = anomaly_pipeline.decision_function(benign_train)
    anomaly_pipeline.training_scores_ = benign_scores
    y_test_binary = (y_test != BENIGN).astype(int).to_numpy()
    anomaly_metrics = _binary_metrics(anomaly_pipeline, x_test, y_test_binary)
    anomaly_metrics.update(
        {
            "test_rows": int(len(x_test)),
            "train_rows_normal_only": int(len(benign_train)),
            "contamination": settings.anomaly_contamination,
        }
    )
    anomaly_path = _save_artifact(
        anomaly_pipeline, "isolation_forest", "anomaly", version
    )

    supervised_specs = [
        (
            "RandomForest",
            "Random Forest Classifier",
            RandomForestClassifier(
                n_estimators=140,
                max_depth=22,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                random_state=random_state,
                n_jobs=-1,
            ),
        ),
        (
            "DecisionTree",
            "Decision Tree Classifier",
            DecisionTreeClassifier(
                max_depth=14,
                min_samples_leaf=4,
                class_weight="balanced",
                random_state=random_state,
            ),
        ),
    ]

    candidates = []
    for algorithm, name, estimator in supervised_specs:
        pipeline = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
                ("model", estimator),
            ]
        )
        pipeline.fit(x_train, y_train)
        metrics = _classifier_metrics(pipeline, x_test, y_test, labels)
        metrics["test_rows"] = int(len(x_test))
        metrics["train_rows"] = int(len(x_train))
        artifact = _save_artifact(pipeline, algorithm.lower(), "classification", version)
        model = pipeline.named_steps["model"]
        importances = getattr(model, "feature_importances_", None)
        top_features = []
        if importances is not None:
            ranked = sorted(
                zip(CANONICAL_FEATURES, importances), key=lambda pair: pair[1], reverse=True
            )[:12]
            top_features = [
                {"feature": feature, "importance": float(value)}
                for feature, value in ranked
            ]
        metrics["top_features"] = top_features
        candidates.append(
            {
                "algorithm": algorithm,
                "name": name,
                "pipeline": pipeline,
                "metrics": metrics,
                "artifact": artifact,
                "hyperparameters": dict(estimator.get_params()),
            }
        )

    best = max(candidates, key=lambda item: item["metrics"]["f1_weighted"])
    duration = time.perf_counter() - started

    comparison = {
        name: {
            "accuracy": item["metrics"]["accuracy"],
            "precision": item["metrics"]["precision_weighted"],
            "recall": item["metrics"]["recall_weighted"],
            "f1": item["metrics"]["f1_weighted"],
            "f1_macro": item["metrics"]["f1_macro"],
            "roc_auc": item["metrics"].get("roc_auc_ovr_weighted"),
        }
        for name, item in [(c["algorithm"], c) for c in candidates]
    }
    comparison["IsolationForest"] = {
        "precision": anomaly_metrics["precision"],
        "recall": anomaly_metrics["recall"],
        "f1": anomaly_metrics["f1"],
        "roc_auc": anomaly_metrics["roc_auc"],
    }

    report = {
        "run_id": run_id,
        "version": version,
        "dataset": _relative(resolved_path),
        "dataset_rows": int(len(frame)),
        "label_distribution": frame["label"].value_counts().to_dict(),
        "test_rows": int(len(x_test)),
        "train_rows": int(len(x_train)),
        "duration_seconds": round(duration, 3),
        "comparison": comparison,
        "selected_classifier": best["algorithm"],
        "anomaly_metrics": anomaly_metrics,
        "classifier_metrics": {
            candidate["algorithm"]: candidate["metrics"] for candidate in candidates
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    models: list[ModelVersion] = []
    if persist:
        own_session = db is None
        session = db or SessionLocal()
        try:
            session.execute(
                update(ModelVersion)
                .where(ModelVersion.task_type == "classification")
                .values(is_active=False)
            )
            session.execute(
                update(ModelVersion)
                .where(ModelVersion.task_type == "anomaly")
                .values(is_active=False)
            )
            for candidate in candidates:
                metrics = candidate["metrics"]
                is_active = candidate is best
                row = ModelVersion(
                    name=candidate["name"],
                    algorithm=candidate["algorithm"],
                    task_type="classification",
                    version=version,
                    artifact_path=_relative(candidate["artifact"]),
                    feature_names=CANONICAL_FEATURES,
                    metrics=metrics,
                    hyperparameters={
                        key: value
                        for key, value in candidate["hyperparameters"].items()
                        if isinstance(value, (str, int, float, bool)) or value is None
                    },
                    training_rows=int(len(x_train)),
                    test_rows=int(len(x_test)),
                    dataset_source=_relative(resolved_path),
                    is_active=is_active,
                    notes=(
                        "Selected automatically by highest weighted F1 on the held-out test split."
                        if is_active
                        else "Retained for comparison. Not used by the live detection pipeline."
                    ),
                )
                session.add(row)
                models.append(row)
            anomaly_row = ModelVersion(
                name="Isolation Forest Anomaly Detector",
                algorithm="IsolationForest",
                task_type="anomaly",
                version=version,
                artifact_path=_relative(anomaly_path),
                feature_names=CANONICAL_FEATURES,
                metrics=anomaly_metrics,
                hyperparameters={
                    "n_estimators": 150,
                    "contamination": settings.anomaly_contamination,
                    "max_samples": "auto",
                    "random_state": random_state,
                },
                training_rows=int(len(benign_train)),
                test_rows=int(len(x_test)),
                dataset_source=_relative(resolved_path),
                is_active=True,
                notes=(
                    "Trained only on BENIGN training rows. Anomaly labels are statistical "
                    "outliers, not confirmed attacks."
                ),
            )
            session.add(anomaly_row)
            models.append(anomaly_row)
            session.commit()
            for row in models:
                session.refresh(row)
        except Exception:
            session.rollback()
            raise
        finally:
            if own_session:
                session.close()

    report["model_ids"] = {row.algorithm: row.id for row in models}
    metrics_file = PROJECT_ROOT / "docs" / "model_metrics.json"
    metrics_file.parent.mkdir(parents=True, exist_ok=True)
    metrics_file.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return {"report": report, "models": models, "active_classifier": best}


def main() -> None:
    result = train_models()
    report = result["report"]
    print(f"Training run {report['run_id']} completed in {report['duration_seconds']}s")
    for name, scores in report["comparison"].items():
        print(f"  {name}: {scores}")
    print(f"Selected classifier: {report['selected_classifier']}")


if __name__ == "__main__":
    main()
