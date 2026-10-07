"""User, session and login-attempt persistence."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.models.base import utcnow
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, LoginAttempt, SessionToken, User


def normalize_email(email: str) -> str:
    """Canonical email form used for storage, lookup and uniqueness."""
    return email.strip().lower()


def get_user_by_id(db: Session, user_id: str) -> User | None:
    return db.get(User, user_id)


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.execute(select(User).where(User.email == normalize_email(email))).scalar_one_or_none()


def email_exists(db: Session, email: str) -> bool:
    return (
        db.execute(select(User.id).where(User.email == normalize_email(email))).first() is not None
    )


def create_user(
    db: Session,
    *,
    email: str,
    password_hash: str,
    role: str = ROLE_CUSTOMER,
    display_name: str | None = None,
) -> User:
    """Create a user. ``role`` is only ever supplied by server-side code."""
    if role not in {ROLE_CUSTOMER, ROLE_ADMIN}:  # pragma: no cover - defensive
        raise ValueError("invalid role")
    user = User(
        email=normalize_email(email),
        password_hash=password_hash,
        role=role,
        display_name=(display_name or None),
    )
    db.add(user)
    db.flush()
    return user


def set_password(db: Session, user: User, password_hash: str) -> None:
    user.password_hash = password_hash
    user.password_changed_at = utcnow()
    db.flush()


def update_last_login(db: Session, user: User) -> None:
    user.last_login_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    db.flush()


def register_failed_login(
    db: Session, user: User | None, *, max_attempts: int, lockout_minutes: int
) -> bool:
    """Increment the failure counter; returns True when the account got locked."""
    if user is None:  # pragma: no cover - timing-equalised path
        return False
    user.failed_login_count += 1
    locked = False
    if user.failed_login_count >= max_attempts:
        user.locked_until = utcnow() + timedelta(minutes=lockout_minutes)
        user.failed_login_count = 0
        locked = True
    db.flush()
    return locked


def count_users(db: Session, *, role: str | None = None) -> int:
    statement = select(func.count(User.id))
    if role:
        statement = statement.where(User.role == role)
    return int(db.execute(statement).scalar_one())


def list_users(db: Session, *, limit: int, offset: int) -> list[User]:
    return list(
        db.execute(
            select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
        ).scalars()
    )


def delete_user(db: Session, user: User) -> None:
    """Delete a user; cascades remove their conversations, messages and sessions."""
    db.delete(user)
    db.flush()


def set_user_active(db: Session, user: User, *, is_active: bool) -> None:
    user.is_active = is_active
    db.flush()


def update_user_role(db: Session, user: User, role: str) -> None:
    if role not in {ROLE_CUSTOMER, ROLE_ADMIN}:  # pragma: no cover - defensive
        raise ValueError("invalid role")
    user.role = role
    db.flush()


# --------------------------------------------------------------------------
# Login attempts (throttling + audit)
# --------------------------------------------------------------------------
def record_login_attempt(
    db: Session,
    *,
    email: str | None,
    ip_address: str | None,
    success: bool,
    reason: str | None = None,
) -> LoginAttempt:
    attempt = LoginAttempt(
        email_normalized=normalize_email(email) if email else None,
        ip_address=(ip_address or None),
        success=success,
        reason=(reason or None),
    )
    db.add(attempt)
    db.flush()
    return attempt


def count_recent_failures(
    db: Session,
    *,
    window_minutes: int,
    email: str | None = None,
    ip_address: str | None = None,
) -> int:
    since = utcnow() - timedelta(minutes=window_minutes)
    statement = select(func.count(LoginAttempt.id)).where(
        LoginAttempt.success.is_(False), LoginAttempt.created_at >= since
    )
    if email:
        statement = statement.where(LoginAttempt.email_normalized == normalize_email(email))
    if ip_address:
        statement = statement.where(LoginAttempt.ip_address == ip_address)
    return int(db.execute(statement).scalar_one())


def purge_old_login_attempts(db: Session, *, keep_days: int = 30) -> int:
    cutoff = utcnow() - timedelta(days=keep_days)
    result = cast(
        "CursorResult[Any]",
        db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff)),
    )
    db.flush()
    return int(result.rowcount or 0)


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------
def session_is_revoked(db: Session, session_id: str) -> bool:
    revoked_at: datetime | None = db.execute(
        select(SessionToken.revoked_at).where(SessionToken.id == session_id)
    ).scalar_one_or_none()
    return revoked_at is not None


def count_active_sessions(db: Session, user_id: str) -> int:
    return int(
        db.execute(
            select(func.count(SessionToken.id)).where(
                SessionToken.user_id == user_id,
                SessionToken.revoked_at.is_(None),
                SessionToken.expires_at > utcnow(),
            )
        ).scalar_one()
    )


def revoke_sessions_for_user(db: Session, user_id: str) -> int:
    result = cast(
        "CursorResult[Any]",
        db.execute(
            update(SessionToken)
            .where(SessionToken.user_id == user_id, SessionToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        ),
    )
    db.flush()
    return int(result.rowcount or 0)
