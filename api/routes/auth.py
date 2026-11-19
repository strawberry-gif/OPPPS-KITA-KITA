from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, DbSession, RequireAdmin
from app.core.config import settings
from app.core.errors import ConflictError, ValidationError
from app.core.security import create_access_token, hash_password, verify_password
from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import PasswordChange, Token, UserCreate, UserOut, UserUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
users_router = APIRouter(prefix="/api/users", tags=["Users"])

_attempt_lock = threading.Lock()
_attempts: dict[str, list[float]] = {}
WINDOW_SECONDS = 600
MAX_ATTEMPTS = 8
DUMMY_HASH = hash_password("not-a-real-password-value")


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_throttle(key: str) -> None:
    now = time.time()
    with _attempt_lock:
        attempts = [stamp for stamp in _attempts.get(key, []) if now - stamp < WINDOW_SECONDS]
        _attempts[key] = attempts
        if len(attempts) >= MAX_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
            )


def _register_failure(key: str) -> None:
    with _attempt_lock:
        _attempts.setdefault(key, []).append(time.time())


def _clear_failures(key: str) -> None:
    with _attempt_lock:
        _attempts.pop(key, None)


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    key = _client_key(request)
    _check_throttle(key)
    email = form.username.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        verify_password(form.password, DUMMY_HASH)
        _register_failure(key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not verify_password(form.password, user.hashed_password):
        _register_failure(key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled"
        )
    _clear_failures(key)
    user.last_login_at = datetime.now(timezone.utc)
    record_audit(
        db,
        user_id=user.id,
        action="auth.login",
        entity_type="user",
        entity_id=str(user.id),
        detail={"role": user.role},
        ip_address=key,
    )
    db.commit()
    token = create_access_token(user.email, user.role)
    return Token(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user


@router.post("/change-password")
def change_password(
    payload: PasswordChange,
    user: CurrentUser,
    db: DbSession,
) -> dict:
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if payload.current_password == payload.new_password:
        raise ValidationError("New password must differ from the current password")
    user.hashed_password = hash_password(payload.new_password)
    record_audit(
        db,
        user_id=user.id,
        action="auth.password_change",
        entity_type="user",
        entity_id=str(user.id),
        detail={},
    )
    db.commit()
    return {"message": "Password updated successfully"}


@users_router.get("", response_model=list[UserOut])
def list_users(user: RequireAdmin, db: DbSession) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)).all())


@users_router.get("/assignees")
def list_assignees(user: CurrentUser, db: DbSession) -> list[dict]:
    rows = db.scalars(
        select(User).where(User.is_active.is_(True)).order_by(User.full_name)
    ).all()
    return [
        {"id": row.id, "full_name": row.full_name or row.email, "email": row.email}
        for row in rows
    ]


@users_router.post("", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate, admin: RequireAdmin, db: DbSession
) -> User:
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise ConflictError("A user with this email already exists")
    user = User(
        email=email,
        full_name=payload.full_name,
        role=payload.role,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    record_audit(
        db,
        user_id=admin.id,
        action="user.create",
        entity_type="user",
        entity_id=email,
        detail={"role": payload.role},
    )
    db.commit()
    db.refresh(user)
    return user


@users_router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, payload: UserUpdate, admin: RequireAdmin, db: DbSession
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and payload.is_active is False:
        raise ValidationError("You cannot deactivate your own account")
    if payload.role is not None:
        if user.id == admin.id and payload.role != "admin":
            raise ValidationError("You cannot remove your own administrator role")
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    record_audit(
        db,
        user_id=admin.id,
        action="user.update",
        entity_type="user",
        entity_id=str(user.id),
        detail=payload.model_dump(exclude_none=True),
    )
    db.commit()
    db.refresh(user)
    return user
