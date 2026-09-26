"""Fixed-window rate-limit counters (SQLite-backed, no external service)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UTCDateTime, utcnow


class RateLimitCounter(Base):
    """One row per active bucket, e.g. ``chat:user:<uuid>:minute``.

    Fixed windows keep the implementation simple and predictable: the counter is
    reset when the window expires. Used per user, per IP and per route class.
    """

    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_ends_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )
