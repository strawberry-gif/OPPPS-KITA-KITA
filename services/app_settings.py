from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import ValidationError
from app.models.traffic import AppSetting
from app.services.severity import SEVERITY_ORDER

DEFAULT_SETTINGS = {
    "incident_min_severity": (
        settings.incident_min_severity,
        "Minimum heuristic severity that automatically creates a security incident.",
    ),
    "default_dashboard_range": (
        "7d",
        "Default time range used by the dashboard and analytics views (24h, 7d, 30d or all).",
    ),
    "analyst_note_required_on_close": (
        "false",
        "When true, resolving or closing an incident requires investigation notes.",
    ),
}

ALLOWED_RANGES = {"24h", "7d", "30d", "all"}


def ensure_defaults(db: Session) -> None:
    existing = {
        row.key: row for row in db.scalars(select(AppSetting)).all()
    }
    changed = False
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if key not in existing:
            db.add(AppSetting(key=key, value=value, description=description))
            changed = True
    if changed:
        db.commit()


def get_all(db: Session) -> tuple[dict, dict]:
    rows = db.scalars(select(AppSetting).order_by(AppSetting.key)).all()
    values = {row.key: row.value for row in rows}
    descriptions = {row.key: row.description for row in rows}
    for key, (value, description) in DEFAULT_SETTINGS.items():
        values.setdefault(key, value)
        descriptions.setdefault(key, description)
    return values, descriptions


def get_value(db: Session, key: str, default: str | None = None) -> str | None:
    row = db.get(AppSetting, key)
    if row is not None:
        return row.value
    if key in DEFAULT_SETTINGS:
        return DEFAULT_SETTINGS[key][0]
    return default


def update_values(db: Session, values: dict[str, str]) -> dict:
    allowed = {"incident_min_severity", "default_dashboard_range", "analyst_note_required_on_close"}
    cleaned: dict[str, str] = {}
    for key, value in values.items():
        if key not in allowed:
            raise ValidationError(f"Unknown setting: {key}")
        text = str(value).strip()
        if key == "incident_min_severity":
            if text not in SEVERITY_ORDER:
                raise ValidationError(
                    f"incident_min_severity must be one of {', '.join(SEVERITY_ORDER)}"
                )
        elif key == "default_dashboard_range":
            if text not in ALLOWED_RANGES:
                raise ValidationError("default_dashboard_range must be 24h, 7d, 30d or all")
        elif key == "analyst_note_required_on_close":
            if text.lower() not in {"true", "false"}:
                raise ValidationError("analyst_note_required_on_close must be true or false")
            text = text.lower()
        cleaned[key] = text

    for key, value in cleaned.items():
        row = db.get(AppSetting, key)
        if row is None:
            description = DEFAULT_SETTINGS.get(key, ("", ""))[1]
            db.add(AppSetting(key=key, value=value, description=description))
        else:
            row.value = value
    db.commit()
    return get_all(db)[0]
