"""Conversation, message, source reference and feedback persistence.

Every lookup reachable from a customer-facing route is **scoped by owner** in
this module: a message belonging to someone else is simply not found, which lets
routers answer 404 instead of leaking the existence of the resource.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, selectinload

from app.models.base import utcnow
from app.models.conversation import (
    ROLE_ASSISTANT,
    ROLE_USER,
    Conversation,
    Feedback,
    Message,
    MessageSource,
)

MAX_TITLE_LENGTH = 120


@dataclass(frozen=True, slots=True)
class SourceInput:
    """Citation data captured at answer time."""

    document_id: str
    document_title: str
    snippet: str
    chunk_id: str | None
    score: float
    chunk_position: int


def build_title(question: str) -> str:
    """Derive a short conversation title from the first user message."""
    flat = " ".join(question.split())
    if not flat:
        return "New conversation"
    if len(flat) <= 60:
        return flat
    return f"{flat[:57].rstrip()}..."


def create_conversation(
    db: Session, *, user_id: str, title: str = "New conversation"
) -> Conversation:
    conversation = Conversation(
        user_id=user_id, title=title[:MAX_TITLE_LENGTH] or "New conversation"
    )
    db.add(conversation)
    db.flush()
    return conversation


def get_conversation(db: Session, conversation_id: str, *, user_id: str) -> Conversation | None:
    """Owner-scoped conversation lookup (returns None for other users)."""
    return db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id, Conversation.user_id == user_id
        )
    ).scalar_one_or_none()


def list_conversations(db: Session, *, user_id: str, limit: int, offset: int) -> list[Conversation]:
    return list(
        db.execute(
            select(Conversation)
            .where(Conversation.user_id == user_id)
            .order_by(Conversation.updated_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
    )


def count_conversations(db: Session, *, user_id: str) -> int:
    return int(
        db.execute(
            select(func.count(Conversation.id)).where(Conversation.user_id == user_id)
        ).scalar_one()
    )


def total_conversations(db: Session) -> int:
    """Platform-wide count (admin statistics only, never customer-facing)."""
    return int(db.execute(select(func.count(Conversation.id))).scalar_one())


def delete_conversation(db: Session, conversation: Conversation) -> None:
    """Hard-delete a conversation (messages, sources and feedback cascade)."""
    db.delete(conversation)
    db.flush()


def add_message(
    db: Session,
    *,
    conversation: Conversation,
    role: str,
    content: str,
    blocked: bool = False,
    provider: str | None = None,
    latency_ms: int | None = None,
    retrieval_count: int = 0,
) -> Message:
    """Persist one turn and keep the conversation summary counters in sync."""
    if role not in {ROLE_USER, ROLE_ASSISTANT}:  # pragma: no cover - defensive
        raise ValueError("invalid role")
    message = Message(
        conversation_id=conversation.id,
        role=role,
        content=content,
        blocked=blocked,
        provider=provider,
        latency_ms=latency_ms,
        retrieval_count=retrieval_count,
    )
    db.add(message)
    conversation.message_count += 1
    conversation.last_message_at = utcnow()
    conversation.updated_at = utcnow()
    db.flush()
    return message


def get_message_for_user(db: Session, message_id: str, *, user_id: str) -> Message | None:
    """Owner-scoped message lookup through its conversation."""
    return db.execute(
        select(Message)
        .join(Conversation, Conversation.id == Message.conversation_id)
        .where(Message.id == message_id, Conversation.user_id == user_id)
    ).scalar_one_or_none()


def list_messages(
    db: Session,
    *,
    conversation_id: str,
    limit: int | None = None,
    offset: int = 0,
) -> list[Message]:
    statement = (
        select(Message)
        .options(selectinload(Message.sources))
        .where(Message.conversation_id == conversation_id)
        .order_by(Message.created_at.asc(), Message.id.asc())
        .offset(offset)
    )
    if limit is not None:
        statement = statement.limit(limit)
    return list(db.execute(statement).scalars())


def recent_messages(db: Session, *, conversation_id: str, limit: int) -> list[Message]:
    """The most recent ``limit`` messages, returned oldest-first."""
    if limit <= 0:
        return []
    newest_first = list(
        db.execute(
            select(Message)
            .where(Message.conversation_id == conversation_id)
            .order_by(Message.created_at.desc(), Message.id.desc())
            .limit(limit)
        ).scalars()
    )
    return list(reversed(newest_first))


def count_messages(db: Session, *, conversation_id: str) -> int:
    return int(
        db.execute(
            select(func.count(Message.id)).where(Message.conversation_id == conversation_id)
        ).scalar_one()
    )


def add_sources(db: Session, *, message: Message, sources: Sequence[SourceInput]) -> None:
    """Attach citation snapshots to an answer.

    Title and snippet are snapshots so citations stay readable after
    re-indexing; ``document_id`` cascades, so deleting a document also removes
    its citations from history.
    """
    for position, source in enumerate(sources):
        db.add(
            MessageSource(
                message_id=message.id,
                document_id=source.document_id,
                chunk_id=source.chunk_id,
                document_title=source.document_title[:255],
                snippet=source.snippet,
                score=source.score,
                chunk_position=source.chunk_position,
                position=position,
            )
        )
    db.flush()


# --------------------------------------------------------------------------
# Feedback
# --------------------------------------------------------------------------
def get_feedback(db: Session, *, message_id: str, user_id: str) -> Feedback | None:
    return db.execute(
        select(Feedback).where(Feedback.message_id == message_id, Feedback.user_id == user_id)
    ).scalar_one_or_none()


def feedback_for_messages(
    db: Session, *, message_ids: Sequence[str], user_id: str
) -> dict[str, Feedback]:
    if not message_ids:
        return {}
    rows = db.execute(
        select(Feedback).where(
            Feedback.message_id.in_(list(message_ids)), Feedback.user_id == user_id
        )
    ).scalars()
    return {row.message_id: row for row in rows}


def upsert_feedback(
    db: Session, *, message_id: str, user_id: str, rating: str, comment: str | None
) -> Feedback:
    """One feedback row per user per message (unique constraint enforced in DB)."""
    existing = get_feedback(db, message_id=message_id, user_id=user_id)
    if existing is not None:
        existing.rating = rating
        existing.comment = comment
        db.flush()
        return existing
    row = Feedback(message_id=message_id, user_id=user_id, rating=rating, comment=comment)
    db.add(row)
    db.flush()
    return row


def delete_feedback(db: Session, *, message_id: str, user_id: str) -> bool:
    result = cast(
        "CursorResult[Any]",
        db.execute(
            delete(Feedback).where(Feedback.message_id == message_id, Feedback.user_id == user_id)
        ),
    )
    db.flush()
    return bool(result.rowcount)


def count_feedback(db: Session, *, rating: str | None = None) -> int:
    statement = select(func.count(Feedback.id))
    if rating:
        statement = statement.where(Feedback.rating == rating)
    return int(db.execute(statement).scalar_one())


def list_recent_feedback(db: Session, *, limit: int, offset: int) -> list[Feedback]:
    return list(
        db.execute(
            select(Feedback)
            .options(selectinload(Feedback.message))
            .order_by(Feedback.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
    )


def oldest_conversations(db: Session, *, before: datetime, limit: int) -> list[Conversation]:
    """Retention helper: conversations not touched since ``before``."""
    return list(
        db.execute(
            select(Conversation)
            .where(Conversation.updated_at < before)
            .order_by(Conversation.updated_at.asc())
            .limit(limit)
        ).scalars()
    )
