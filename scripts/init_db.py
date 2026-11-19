"""Create database tables and seed the first administrator.

For a migration-managed setup use: alembic upgrade head
This script is a convenience fallback for a fresh local database.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import func, select  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.session import SessionLocal, engine  # noqa: E402
from app.models import User  # noqa: E402
from app.services.app_settings import ensure_defaults  # noqa: E402


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        count = db.scalar(select(func.count(User.id))) or 0
        if count == 0:
            db.add(
                User(
                    email=settings.admin_email.lower(),
                    full_name=settings.admin_name,
                    role="admin",
                    hashed_password=hash_password(settings.admin_password),
                )
            )
            db.commit()
            print(f"Created administrator: {settings.admin_email}")
        else:
            print(f"Users already exist ({count}); administrator not recreated.")
        ensure_defaults(db)
    finally:
        db.close()
    print("Database schema is ready.")


if __name__ == "__main__":
    main()
