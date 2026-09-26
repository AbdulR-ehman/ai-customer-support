"""Conversation, message, source-reference and feedback models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDStr, new_uuid, utcnow
from app.models.user import User

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
MESSAGE_ROLES: tuple[str, ...] = (ROLE_USER, ROLE_ASSISTANT)

RATING_UP = "up"
RATING_DOWN = "down"
RATINGS: tuple[str, ...] = (RATING_UP, RATING_DOWN)


class Conversation(Base, TimestampMixin):
    """One support thread owned by exactly one user."""

    __tablename__ = "conversations"
    __table_args__ = (Index("ix_conversations_user_updated", "user_id", "updated_at"),)

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(120), nullable=False, default="New conversation")
    message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_message_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    user: Mapped[User] = relationship(back_populates="conversations")
    messages: Mapped[list[Message]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Message.created_at",
    )

    def touch(self, *, message_delta: int = 1) -> None:
        """Keep the summary counters consistent with the message table."""
        now = utcnow()
        self.message_count = max(0, self.message_count + message_delta)
        self.last_message_at = now
        self.updated_at = now


class Message(Base):
    """A single user or assistant turn."""

    __tablename__ = "messages"
    __table_args__ = (
        CheckConstraint("role IN ('user', 'assistant')", name="ck_messages_role"),
        Index("ix_messages_conversation_created", "conversation_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    conversation_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    #: True when an input/output guard replaced the answer with a safe refusal.
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    provider: Mapped[str | None] = mapped_column(String(40))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    retrieval_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )

    conversation: Mapped[Conversation] = relationship(back_populates="messages")
    sources: Mapped[list[MessageSource]] = relationship(
        back_populates="message",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="MessageSource.position",
    )
    feedback_entries: Mapped[list[Feedback]] = relationship(
        back_populates="message", cascade="all, delete-orphan", passive_deletes=True
    )


class MessageSource(Base):
    """A citation shown under an assistant answer.

    Title and snippet are snapshotted so the citation stays readable even after
    the document is re-indexed. ``document_id`` cascades so that deleting a
    document also removes its citations.
    """

    __tablename__ = "message_sources"
    __table_args__ = (Index("ix_message_sources_message", "message_id", "position"),)

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    message_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    document_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Chunk id is a plain reference (no FK) so re-indexing never mutates history.
    chunk_id: Mapped[str | None] = mapped_column(UUIDStr)
    document_title: Mapped[str] = mapped_column(String(255), nullable=False)
    snippet: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    chunk_position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    message: Mapped[Message] = relationship(back_populates="sources")


class Feedback(Base, TimestampMixin):
    """One thumbs up/down (with optional comment) per user per message."""

    __tablename__ = "feedback"
    __table_args__ = (
        UniqueConstraint("message_id", "user_id", name="uq_feedback_message_user"),
        CheckConstraint("rating IN ('up', 'down')", name="ck_feedback_rating"),
        Index("ix_feedback_created", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    message_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rating: Mapped[str] = mapped_column(String(8), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(1000))

    message: Mapped[Message] = relationship(back_populates="feedback_entries")
    user: Mapped[User] = relationship(back_populates="feedback_entries")
