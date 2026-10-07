"""Audit-log model (append-only from the application's point of view)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UTCDateTime, UUIDStr, utcnow

#: Admin/system actions recorded in the audit trail.
AUDIT_DOCUMENT_UPLOAD = "document.upload"
AUDIT_DOCUMENT_DELETE = "document.delete"
AUDIT_DOCUMENT_REINDEX = "document.reindex"
AUDIT_DOCUMENT_VIEW = "document.view"
AUDIT_DOCUMENT_DOWNLOAD = "document.download"
AUDIT_USER_ROLE_CHANGE = "user.role_change"
AUDIT_USER_REGISTER = "user.register"
AUDIT_USER_LOGIN = "user.login"
AUDIT_USER_LOGIN_FAILED = "user.login_failed"
AUDIT_USER_LOGOUT = "user.logout"
AUDIT_USER_LOCKOUT = "user.lockout"
AUDIT_USER_PASSWORD_CHANGE = "user.password_change"
AUDIT_USER_DELETE = "user.delete"
AUDIT_ACCESS_DENIED = "access.denied"
AUDIT_RATE_LIMITED = "rate_limit.blocked"
AUDIT_INJECTION_BLOCKED = "guard.injection_blocked"
AUDIT_CONVERSATION_DELETE = "conversation.delete"


class AuditLog(Base):
    """Security-relevant event with actor, target and correlation id.

    The application never updates or deletes rows in this table.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_created", "created_at"),
        Index("ix_audit_logs_action_created", "action", "created_at"),
        Index("ix_audit_logs_actor_created", "actor_user_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[str | None] = mapped_column(
        UUIDStr, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_role: Mapped[str | None] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    #: Short, sanitised context. Never contains secrets or full message bodies.
    detail: Mapped[str | None] = mapped_column(String(500))
    request_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )
