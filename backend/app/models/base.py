"""Shared SQLAlchemy plumbing: custom column types and reusable mixins."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

__all__ = [
    "Base",
    "TimestampMixin",
    "UTCDateTime",
    "UUIDStr",
    "new_uuid",
    "utcnow",
]


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def new_uuid() -> str:
    """Unguessable identifier for public resources."""
    return str(uuid.uuid4())


class UTCDateTime(TypeDecorator[datetime]):
    """Store datetimes as naive UTC, always return timezone-aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


#: 36-character UUID column type used for every public identifier.
UUIDStr = String(36)


class TimestampMixin:
    """``created_at`` / ``updated_at`` in UTC."""

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )
