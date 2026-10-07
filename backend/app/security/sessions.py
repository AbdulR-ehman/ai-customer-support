"""Server-side sessions: opaque bearer tokens stored as SHA-256 hashes.

Design notes
------------
* The cookie carries 256 bits of entropy from :mod:`secrets` (never a JWT, so a
  logout or password change is a real, immediate server-side revocation).
* Only the SHA-256 hash of the token is persisted, so a database leak does not
  hand out usable sessions.
* Every login creates a **new** session row (no session fixation) and, when the
  caller presents an existing session, that session is revoked first.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Any, cast

from sqlalchemy import delete, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.base import utcnow
from app.models.user import SessionToken, User

TOKEN_BYTES = 32
"""256 bits of entropy for the session cookie value."""


def generate_session_token() -> str:
    """Return a new random, URL-safe session token."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_session_token(token: str) -> str:
    """Hash a session token for storage/comparison (deterministic lookup key)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user: User,
    settings: Settings,
    *,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, SessionToken]:
    """Create a session for ``user`` and return ``(raw_token, row)``."""
    raw_token = generate_session_token()
    now = utcnow()
    row = SessionToken(
        token_hash=hash_session_token(raw_token),
        user_id=user.id,
        expires_at=now + timedelta(minutes=settings.session_expire_minutes),
        last_seen_at=now,
        client_ip=client_ip,
        user_agent=(user_agent or "")[:200] or None,
    )
    db.add(row)
    db.flush()
    return raw_token, row


def get_session_by_token(db: Session, raw_token: str | None) -> SessionToken | None:
    """Return the active session row for ``raw_token`` (None when unusable)."""
    if not raw_token or len(raw_token) > 512:
        return None
    row = db.execute(
        select(SessionToken).where(SessionToken.token_hash == hash_session_token(raw_token))
    ).scalar_one_or_none()
    if row is None or not row.is_active:
        return None
    return row


def touch_session(db: Session, row: SessionToken) -> None:
    """Record activity without extending the absolute expiry."""
    row.last_seen_at = utcnow()
    db.flush()


def revoke_session(db: Session, row: SessionToken) -> None:
    """Revoke a single session (logout)."""
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        db.flush()


def revoke_session_by_token(db: Session, raw_token: str | None) -> bool:
    """Revoke by raw token; returns True when an active session was revoked."""
    if not raw_token:
        return False
    result = cast(
        "CursorResult[Any]",
        db.execute(
            update(SessionToken)
            .where(
                SessionToken.token_hash == hash_session_token(raw_token),
                SessionToken.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        ),
    )
    db.flush()
    return bool(result.rowcount)


def revoke_all_user_sessions(
    db: Session, user_id: str, *, except_session_id: str | None = None
) -> int:
    """Revoke every session of a user (password change, account deletion)."""
    statement = update(SessionToken).where(
        SessionToken.user_id == user_id, SessionToken.revoked_at.is_(None)
    )
    if except_session_id:
        statement = statement.where(SessionToken.id != except_session_id)
    result = cast("CursorResult[Any]", db.execute(statement.values(revoked_at=utcnow())))
    db.flush()
    return int(result.rowcount or 0)


def purge_expired_sessions(db: Session, *, keep_days: int = 7) -> int:
    """Delete long-expired session rows (maintenance/cleanup script)."""
    cutoff = utcnow() - timedelta(days=keep_days)
    result = cast(
        "CursorResult[Any]",
        db.execute(delete(SessionToken).where(SessionToken.expires_at < cutoff)),
    )
    db.flush()
    return int(result.rowcount or 0)
