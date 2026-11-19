from datetime import datetime

from pydantic import BaseModel, Field


class ModelVersionOut(BaseModel):
    id: int
    name: str
    algorithm: str
    task_type: str
    version: str
    artifact_path: str
    feature_names: list
    metrics: dict
    hyperparameters: dict
    training_rows: int
    test_rows: int
    dataset_source: str
    is_active: bool
    notes: str | None
    trained_at: datetime

    model_config = {"from_attributes": True}


class TrainRequest(BaseModel):
    dataset_path: str | None = None
    test_size: float = Field(default=0.25, ge=0.1, le=0.4)
    random_state: int = 42


class TrainResponse(BaseModel):
    run_id: str
    dataset: str
    rows: int
    duration_seconds: float
    models: list[ModelVersionOut]
    comparison: dict
    active_classifier_id: int | None
    active_anomaly_id: int | None


class SettingsOut(BaseModel):
    values: dict
    descriptions: dict


class SettingsUpdate(BaseModel):
    values: dict[str, str]
