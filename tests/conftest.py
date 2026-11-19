"""Pytest fixtures for OPPPS KITA-KITA.

The suite runs against a dedicated PostgreSQL database (``oppps_test``). The
environment is prepared before any application module is imported so the
SQLAlchemy engine and Pydantic settings bind to the test database instead of
the development one.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _dotenv_values() -> dict[str, str]:
    try:
        from dotenv import dotenv_values
    except ImportError:  # pragma: no cover - python-dotenv is a project dependency
        return {}
    return {
        key: value
        for key, value in dotenv_values(PROJECT_ROOT / ".env").items()
        if value is not None
    }


_ENV = _dotenv_values()
_TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or _ENV.get(
    "TEST_DATABASE_URL"
)
if not _TEST_DATABASE_URL:
    raise RuntimeError(
        "TEST_DATABASE_URL must be set (or present in .env) before running tests."
    )

# Environment variables take precedence over values in .env.
os.environ["DATABASE_URL"] = _TEST_DATABASE_URL
os.environ.setdefault("SECRET_KEY", "pytest-secret-key-not-for-production-use")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("ADMIN_NAME", "Pytest Administrator")
os.environ.setdefault("LIVE_CAPTURE_ENABLED", "false")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.models  # noqa: E402,F401  (register every ORM model on Base.metadata)
from app.core.security import hash_password  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.session import SessionLocal, engine  # noqa: E402
from app.ml.features import CANONICAL_FEATURES  # noqa: E402
from app.models import ModelVersion, User  # noqa: E402
from app.services.app_settings import ensure_defaults  # noqa: E402

TEST_USERS = {
    "admin": ("admin@test.local", "AdminPass123!", "Pytest Administrator", "admin"),
    "analyst": ("analyst@test.local", "AnalystPass123!", "Pytest Analyst", "analyst"),
    "viewer": ("viewer@test.local", "ViewerPass123!", "Pytest Viewer", "viewer"),
}


def _latest_artifact(prefix: str) -> str:
    matches = sorted((PROJECT_ROOT / "models").glob(f"{prefix}*.joblib"))
    if not matches:
        pytest.skip(
            f"Model artifact '{prefix}*.joblib' is missing. Train the models first."
        )
    return str(matches[-1].resolve().relative_to(PROJECT_ROOT))


def _seed_model_versions(db) -> None:
    report_path = PROJECT_ROOT / "docs" / "model_metrics.json"
    report = {}
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    classifier_metrics = report.get("classifier_metrics", {})
    anomaly_metrics = report.get("anomaly_metrics", {})

    db.add_all(
        [
            ModelVersion(
                name="Random Forest Classifier",
                algorithm="RandomForest",
                task_type="classification",
                version="pytest-rf",
                artifact_path=_latest_artifact("classification_randomforest"),
                feature_names=CANONICAL_FEATURES,
                metrics=classifier_metrics.get("RandomForest", {"accuracy": 1.0}),
                hyperparameters={"n_estimators": 140},
                training_rows=9000,
                test_rows=3000,
                dataset_source="datasets/processed/train.csv",
                is_active=True,
                notes="Seeded for integration tests.",
            ),
            ModelVersion(
                name="Decision Tree Classifier",
                algorithm="DecisionTree",
                task_type="classification",
                version="pytest-dt",
                artifact_path=_latest_artifact("classification_decisiontree"),
                feature_names=CANONICAL_FEATURES,
                metrics=classifier_metrics.get("DecisionTree", {"accuracy": 0.99}),
                hyperparameters={"max_depth": 14},
                training_rows=9000,
                test_rows=3000,
                dataset_source="datasets/processed/train.csv",
                is_active=False,
                notes="Comparison model for activation tests.",
            ),
            ModelVersion(
                name="Isolation Forest Anomaly Detector",
                algorithm="IsolationForest",
                task_type="anomaly",
                version="pytest-if",
                artifact_path=_latest_artifact("anomaly_isolation_forest"),
                feature_names=CANONICAL_FEATURES,
                metrics=anomaly_metrics or {"f1": 0.6},
                hyperparameters={"n_estimators": 150, "contamination": 0.05},
                training_rows=7000,
                test_rows=3000,
                dataset_source="datasets/processed/train.csv",
                is_active=True,
                notes="Seeded for integration tests.",
            ),
        ]
    )


@pytest.fixture(scope="session", autouse=True)
def database():
    """Create a clean schema and seed deterministic accounts/models."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        for email, password, full_name, role in TEST_USERS.values():
            db.add(
                User(
                    email=email,
                    full_name=full_name,
                    role=role,
                    hashed_password=hash_password(password),
                    is_active=True,
                )
            )
        db.flush()
        ensure_defaults(db)
        _seed_model_versions(db)
        db.commit()
    finally:
        db.close()

    yield

    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="session", autouse=True)
def seeded_activity(database):
    """Import a small labelled dataset and run the real detection pipeline.

    The incident threshold is temporarily lowered so the fixture reliably
    produces incident and suspicious-IP records, then restored to its seeded
    value (HIGH). Existing incidents are not removed.
    """
    import pandas as pd
    from fastapi import UploadFile

    from app.models import AppSetting
    from app.services.detection import run_detection
    from app.services.ingestion import import_dataset

    source = PROJECT_ROOT / "datasets" / "sample" / "synthetic_flows.csv"
    if not source.exists():
        pytest.skip("Synthetic dataset is missing. Run scripts/generate_dataset.py.")
    frame = pd.read_csv(source)
    benign = frame[frame["label"] == "BENIGN"].head(30)
    attacks = frame[frame["label"] != "BENIGN"].groupby("label", group_keys=False).head(8)
    sample = pd.concat([benign, attacks]).sort_values("timestamp")

    seed_path = PROJECT_ROOT / "datasets" / "processed" / "_pytest_seed.csv"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(seed_path, index=False)

    db = SessionLocal()
    threshold_row = db.get(AppSetting, "incident_min_severity")
    original_threshold = threshold_row.value if threshold_row else "HIGH"
    summary = {"processed": 0}
    dataset_id = None
    try:
        if threshold_row is not None:
            threshold_row.value = "LOW"
            db.commit()
        upload = UploadFile(
            filename="pytest_seed.csv", file=io.BytesIO(seed_path.read_bytes())
        )
        dataset, _result = asyncio.run(
            import_dataset(db, upload, user_id=None, label_column="label")
        )
        dataset_id = dataset.id
        summary = run_detection(db, limit=500, import_id=dataset.id)
    finally:
        threshold_row = db.get(AppSetting, "incident_min_severity")
        if threshold_row is not None:
            threshold_row.value = original_threshold
            db.commit()
        db.close()
        seed_path.unlink(missing_ok=True)

    yield {"dataset_id": dataset_id, "summary": summary, "rows": len(sample)}


@pytest.fixture(scope="session")
def client(seeded_activity):
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    from app.api.routes import auth as auth_routes

    auth_routes._attempts.clear()
    yield
    auth_routes._attempts.clear()


def _login(client: TestClient, email: str, password: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/login", data={"username": email, "password": password}
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token_type"] == "bearer"
    return {"Authorization": f"Bearer {payload['access_token']}"}


@pytest.fixture(scope="session")
def credentials():
    return TEST_USERS


@pytest.fixture(scope="session")
def admin_headers(client):
    return _login(client, *TEST_USERS["admin"][:2])


@pytest.fixture(scope="session")
def analyst_headers(client):
    return _login(client, *TEST_USERS["analyst"][:2])


@pytest.fixture(scope="session")
def viewer_headers(client):
    return _login(client, *TEST_USERS["viewer"][:2])


@pytest.fixture()
def db_session(database):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="session")
def user_ids(client, admin_headers):
    response = client.get("/api/users", headers=admin_headers)
    assert response.status_code == 200, response.text
    return {row["email"]: row["id"] for row in response.json()}
