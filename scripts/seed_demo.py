"""Load the synthetic demo dataset through the real import + detection pipeline."""

from __future__ import annotations

import asyncio
import hashlib
import io
import sys
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy import func, select

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.database.session import SessionLocal  # noqa: E402
from app.ml.detector import get_active_models  # noqa: E402
from app.ml.train import train_models  # noqa: E402
from app.models.dataset import DatasetImport  # noqa: E402
from app.models.incident import SecurityIncident  # noqa: E402
from app.models.ip import SuspiciousIP  # noqa: E402
from app.models.traffic import DetectionResult, TrafficRecord  # noqa: E402
from app.services.detection import run_detection  # noqa: E402
from app.services.ingestion import import_dataset  # noqa: E402


async def _load(path: Path, db) -> DatasetImport:
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    existing = db.scalar(
        select(DatasetImport).where(
            DatasetImport.sha256 == digest,
            DatasetImport.status.in_(["processing", "completed"]),
        )
    )
    if existing is not None:
        print(f"Dataset already imported as #{existing.id}; skipping insertion.")
        return existing
    upload = UploadFile(filename=path.name, file=io.BytesIO(content))
    dataset, result = await import_dataset(
        db, upload, user_id=None, label_column="label"
    )
    print(
        f"Imported {result['analysis']['accepted']} flows "
        f"({result['analysis']['rejected']} rejected)."
    )
    return dataset


def main() -> None:
    dataset_path = ROOT / "datasets" / "sample" / "synthetic_flows.csv"
    if not dataset_path.exists():
        raise SystemExit(
            "Demo dataset is missing. Run: python scripts/generate_dataset.py"
        )
    db = SessionLocal()
    try:
        classifier, anomaly = get_active_models(db)
        if classifier is None or anomaly is None:
            print("No active models found; training models first...")
            train_models(db=db)
            classifier, anomaly = get_active_models(db)
        dataset = asyncio.run(_load(dataset_path, db))
        summary = run_detection(db, limit=20000, import_id=dataset.id)
        print(
            "Detection complete: "
            f"{summary['processed']} processed, {summary['attacks']} predicted attacks, "
            f"{summary['anomalies']} anomalies, {summary['incidents_created']} incidents."
        )
        print(
            "Database totals: "
            f"{db.scalar(select(func.count(TrafficRecord.id)))} traffic records, "
            f"{db.scalar(select(func.count(DetectionResult.id)))} detections, "
            f"{db.scalar(select(func.count(SuspiciousIP.id)))} tracked IPs, "
            f"{db.scalar(select(func.count(SecurityIncident.id)))} incidents."
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
