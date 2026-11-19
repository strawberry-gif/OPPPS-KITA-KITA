from __future__ import annotations

import hashlib
import io
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import PROJECT_ROOT, settings
from app.core.errors import ConflictError, ValidationError
from app.ml.features import CANONICAL_FEATURES, prepare_dataframe
from app.models.dataset import DatasetImport
from app.models.traffic import TrafficRecord

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(name: str) -> str:
    cleaned = SAFE_NAME.sub("_", Path(name).name).strip("._")
    return cleaned[:180] or "upload.csv"


def _read_csv(content: bytes) -> pd.DataFrame:
    last_error: Exception | None = None
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return pd.read_csv(
                io.BytesIO(content),
                nrows=settings.upload_max_rows + 1,
                low_memory=False,
                skipinitialspace=True,
                encoding=encoding,
            )
        except (UnicodeDecodeError, pd.errors.ParserError) as exc:
            last_error = exc
    raise ValidationError(f"Unable to parse CSV file: {last_error}")


async def import_dataset(
    db: Session,
    upload: UploadFile,
    user_id: int | None,
    mapping: dict | None = None,
    label_column: str | None = None,
) -> tuple[DatasetImport, dict]:
    filename = upload.filename or "upload.csv"
    extension = Path(filename).suffix.lower()
    if extension not in settings.upload_extensions:
        raise ValidationError(
            f"Unsupported file type '{extension}'. Allowed: {', '.join(sorted(settings.upload_extensions))}"
        )

    content = await upload.read()
    max_bytes = settings.upload_max_mb * 1024 * 1024
    if not content:
        raise ValidationError("Uploaded file is empty")
    if len(content) > max_bytes:
        raise ValidationError(f"File exceeds the {settings.upload_max_mb} MB upload limit")

    digest = hashlib.sha256(content).hexdigest()
    duplicate = db.scalar(
        select(DatasetImport).where(
            DatasetImport.sha256 == digest,
            DatasetImport.status.in_(["processing", "completed"]),
        )
    )
    if duplicate is not None:
        raise ConflictError(
            f"This dataset was already imported as #{duplicate.id} ({duplicate.original_name})"
        )

    try:
        frame = _read_csv(content)
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(f"CSV validation failed: {exc}") from exc

    if frame.empty:
        raise ValidationError("CSV contains no data rows")
    if len(frame) > settings.upload_max_rows:
        raise ValidationError(
            f"Dataset exceeds the {settings.upload_max_rows} row limit for a single import"
        )
    if len(frame.columns) < 3:
        raise ValidationError("CSV must contain at least three columns")

    try:
        prepared = prepare_dataframe(
            frame, explicit_mapping=mapping, label_column=label_column
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if prepared["accepted"] == 0:
        raise ValidationError(
            "No valid rows remained after validation. Check timestamps and required numerical fields."
        )

    stored_name = f"{digest[:12]}_{_safe_filename(filename)}"
    upload_dir = settings.datasets_path / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_path = upload_dir / stored_name
    stored_path.write_bytes(content)

    dataset = DatasetImport(
        original_name=filename[:255],
        stored_name=str(stored_path.relative_to(PROJECT_ROOT)),
        sha256=digest,
        row_count=prepared["source_rows"],
        accepted_rows=prepared["accepted"],
        rejected_rows=prepared["rejected"],
        feature_mapping={
            "column_map": prepared["column_map"],
            "metadata_map": prepared["metadata_map"],
            "scales": prepared["scale_map"],
        },
        label_column=prepared["label_column"],
        status="processing",
        uploaded_by=user_id,
    )
    db.add(dataset)
    db.flush()

    try:
        for offset in range(0, len(prepared["records"]), 1000):
            batch = prepared["records"][offset : offset + 1000]
            db.add_all(
                [
                    TrafficRecord(
                        dataset_import_id=dataset.id,
                        timestamp=record["timestamp"],
                        src_ip=record["src_ip"],
                        dst_ip=record["dst_ip"],
                        src_port=record["src_port"],
                        dst_port=record["dst_port"],
                        protocol=record["protocol"],
                        packet_count=record["packet_count"],
                        flow_duration=record["flow_duration"],
                        packet_length=record["packet_length"],
                        flow_bytes_per_sec=record["flow_bytes_per_sec"],
                        flow_packets_per_sec=record["flow_packets_per_sec"],
                        tcp_flags=record["tcp_flags"],
                        dataset_label=record["dataset_label"],
                        source="upload",
                        features=record["features"],
                    )
                    for record in batch
                ]
            )
            db.flush()
        dataset.status = "completed"
        dataset.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(dataset)
    except Exception as exc:
        db.rollback()
        failed = db.get(DatasetImport, dataset.id)
        if failed is not None:
            failed.status = "failed"
            failed.error_message = "Row insertion failed"
            db.commit()
        raise ValidationError(f"Dataset import failed while storing records: {exc}") from exc

    warnings: list[str] = []
    for field in prepared["missing_metadata"]:
        warnings.append(f"No source column detected for '{field}'. Values will be empty.")
    if prepared["rejected"]:
        percentage = prepared["rejected"] / max(prepared["source_rows"], 1) * 100
        warnings.append(
            f"{prepared['rejected']} rows ({percentage:.1f}%) were rejected during validation."
        )
    if label_column is None and prepared["label_column"] is None:
        warnings.append(
            "No label column was detected. Supervised evaluation is unavailable for this import; "
            "unsupervised anomaly detection still applies."
        )

    analysis = {
        "accepted": prepared["accepted"],
        "rejected": prepared["rejected"],
        "source_rows": prepared["source_rows"],
        "mapped_features": prepared["column_map"],
        "metadata_columns": prepared["metadata_map"],
        "unit_scales": prepared["scale_map"],
        "label_distribution": prepared["label_distribution"],
        "protocol_distribution": prepared["protocol_distribution"],
        "label_column": prepared["label_column"],
        "canonical_features": CANONICAL_FEATURES,
    }
    return dataset, {"analysis": analysis, "warnings": warnings}


def dataset_paths(db: Session) -> list[DatasetImport]:
    return list(
        db.scalars(select(DatasetImport).order_by(DatasetImport.created_at.desc()))
    )
