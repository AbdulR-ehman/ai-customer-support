"""Audit-trail and rate-limit counter persistence.

Rate limiting uses fixed windows stored in SQLite with a single atomic upsert, so
concurrent requests cannot double-spend the same slot. The SQL is SQLite-specific
by design (single-file deployment); moving to another server database would mean
swapping this one statement.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import case, delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.base import utcnow
from app.models.rate_limit import RateLimitCounter


@dataclass(frozen=True, slots=True)
class RateLimitOutcome:
    """Result of consuming one rate-limit slot."""

    allowed: bool
    count: int
    limit: int
    remaining: int
    retry_after: int
    window_seconds: int


def record_audit(
    db: Session,
    *,
    action: str,
    actor_user_id: str | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Append one audit entry. Rows are never updated or deleted by the app."""
    entry = AuditLog(
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        action=action[:60],
        target_type=(target_type or None),
        target_id=(str(target_id)[:64] if target_id else None),
        detail=(detail[:500] if detail else None),
        request_id=(request_id[:64] if request_id else None),
        ip_address=(ip_address[:64] if ip_address else None),
    )
    db.add(entry)
    db.flush()
    return entry


def list_audit(
    db: Session, *, limit: int, offset: int, action: str | None = None
) -> list[AuditLog]:
    statement = select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    if action:
        statement = statement.where(AuditLog.action == action)
    return list(db.execute(statement).scalars())


def count_audit(db: Session, *, action: str | None = None) -> int:
    statement = select(func.count(AuditLog.id))
    if action:
        statement = statement.where(AuditLog.action == action)
    return int(db.execute(statement).scalar_one())


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def rate_limit_hit(db: Session, *, key: str, limit: int, window_seconds: int) -> RateLimitOutcome:
    """Consume one slot in a fixed window, atomically.

    ``key`` is built by the caller from a scope plus an identity (user id or IP),
    never from raw user input.
    """
    now = utcnow()
    window_end = now + timedelta(seconds=window_seconds)
    statement = (
        sqlite_insert(RateLimitCounter)
        .values(key=key[:200], count=1, window_ends_at=window_end, updated_at=now)
        .on_conflict_do_update(
            index_elements=[RateLimitCounter.key],
            set_={
                "count": case(
                    (RateLimitCounter.window_ends_at <= now, 1),
                    else_=RateLimitCounter.count + 1,
                ),
                "window_ends_at": case(
                    (RateLimitCounter.window_ends_at <= now, window_end),
                    else_=RateLimitCounter.window_ends_at,
                ),
                "updated_at": now,
            },
        )
        .returning(RateLimitCounter.count, RateLimitCounter.window_ends_at)
    )
    count, stored_window_end = db.execute(statement).one()
    ends_at = _as_utc(stored_window_end)
    allowed = int(count) <= limit
    retry_after = 0
    if not allowed:
        retry_after = max(1, math.ceil((ends_at - now).total_seconds()))
    return RateLimitOutcome(
        allowed=allowed,
        count=int(count),
        limit=limit,
        remaining=max(0, limit - int(count)),
        retry_after=retry_after,
        window_seconds=window_seconds,
    )


def peek_rate_limit(db: Session, *, key: str, limit: int, window_seconds: int) -> RateLimitOutcome:
    """Inspect a counter without consuming a slot."""
    now = utcnow()
    row = db.get(RateLimitCounter, key[:200])
    if row is None or _as_utc(row.window_ends_at) <= now:
        return RateLimitOutcome(
            allowed=True,
            count=0,
            limit=limit,
            remaining=limit,
            retry_after=0,
            window_seconds=window_seconds,
        )
    count = int(row.count)
    allowed = count <= limit
    retry_after = (
        0 if allowed else max(1, math.ceil((_as_utc(row.window_ends_at) - now).total_seconds()))
    )
    return RateLimitOutcome(
        allowed=allowed,
        count=count,
        limit=limit,
        remaining=max(0, limit - count),
        retry_after=retry_after,
        window_seconds=window_seconds,
    )


def reset_rate_limit(db: Session, *, key: str) -> bool:
    result = cast(
        "CursorResult[Any]",
        db.execute(delete(RateLimitCounter).where(RateLimitCounter.key == key[:200])),
    )
    db.flush()
    return bool(result.rowcount)


def purge_expired_counters(db: Session, *, older_than_hours: int = 24) -> int:
    cutoff = utcnow() - timedelta(hours=older_than_hours)
    result = cast(
        "CursorResult[Any]",
        db.execute(delete(RateLimitCounter).where(RateLimitCounter.window_ends_at < cutoff)),
    )
    db.flush()
    return int(result.rowcount or 0)
