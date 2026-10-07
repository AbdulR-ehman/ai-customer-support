"""User, session and login-attempt models."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDStr, new_uuid, utcnow

if TYPE_CHECKING:  # pragma: no cover - typing only (import cycle at runtime)
    from app.models.conversation import Conversation, Feedback

ROLE_CUSTOMER = "customer"
ROLE_ADMIN = "admin"
ROLES: tuple[str, ...] = (ROLE_CUSTOMER, ROLE_ADMIN)


class User(Base, TimestampMixin):
    """A registered customer or administrator.

    The role is never accepted from a request body: it is assigned by the
    service layer (registration always creates ``customer``; only
    ``scripts/create_admin.py`` or an existing admin can create an admin).
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('customer', 'admin')", name="ck_users_role"),
        Index("ix_users_role_created", "role", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=ROLE_CUSTOMER)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    sessions: Mapped[list[SessionToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    conversations: Mapped[list[Conversation]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    feedback_entries: Mapped[list[Feedback]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def is_admin(self) -> bool:
        """Derived convenience flag - never settable from client input."""
        return self.role == ROLE_ADMIN

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.id} role={self.role}>"


class SessionToken(Base, TimestampMixin):
    """Server-side session. Only the SHA-256 hash of the cookie value is stored."""

    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_user_active", "user_id", "revoked_at", "expires_at"),)

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    user_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    client_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > utcnow()


class LoginAttempt(Base):
    """Authentication audit/throttling record.

    Stores the normalised email (an identifier, never a credential) and the
    client IP so lockouts and brute-force detection can be scoped per account and
    per IP. Passwords are never stored here.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (
        Index("ix_login_attempts_email_created", "email_normalized", "created_at"),
        Index("ix_login_attempts_ip_created", "ip_address", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email_normalized: Mapped[str | None] = mapped_column(String(320))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str | None] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )
