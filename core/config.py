from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "OPPPS KITA-KITA"
    app_env: str = "development"
    debug: bool = False
    secret_key: str = "change-me"
    access_token_expire_minutes: int = 480
    algorithm: str = "HS256"

    database_url: str = (
        "postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/oppps"
    )
    test_database_url: str = (
        "postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/oppps_test"
    )
    db_pool_size: int = 5
    db_max_overflow: int = 10

    admin_email: str = "admin@oppps.local"
    admin_password: str = "Admin@Oppps2026"
    admin_name: str = "SOC Administrator"

    upload_max_mb: int = 50
    upload_max_rows: int = 20000
    allowed_upload_extensions: str = ".csv"

    models_dir: str = "models"
    datasets_dir: str = "datasets"
    anomaly_contamination: float = 0.05
    incident_min_severity: str = "HIGH"
    detection_min_confidence: float = 0.55

    live_capture_enabled: bool = True
    live_capture_flush_seconds: int = 15
    live_capture_max_packets: int = 50000

    cors_origins: str = "http://127.0.0.1:8000,http://localhost:8000"

    @property
    def models_path(self) -> Path:
        path = Path(self.models_dir)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def datasets_path(self) -> Path:
        path = Path(self.datasets_dir)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def upload_extensions(self) -> set[str]:
        return {
            part.strip().lower()
            for part in self.allowed_upload_extensions.split(",")
            if part.strip()
        }

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
