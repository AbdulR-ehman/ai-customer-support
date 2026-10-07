"""Model-to-schema serializers (single source of API response shapes)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.base import utcnow
from app.models.conversation import Feedback, Message, MessageSource
from app.models.document import Document, DocumentIngestionEvent
from app.models.user import User


def iso(value: datetime | None) -> str | None:
    """UTC ISO-8601 rendering; never leaks a local timezone."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=utcnow().tzinfo)
    return value.astimezone(utcnow().tzinfo).isoformat()


def user_out(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "created_at": iso(user.created_at),
    }


def source_out(source: MessageSource) -> dict[str, Any]:
    return {
        "document_id": source.document_id or "",
        "document_title": source.document_title,
        "snippet": source.snippet,
        "score": float(source.score or 0.0),
        "position": int(source.position or 0),
    }


def feedback_out(feedback: Feedback) -> dict[str, Any]:
    return {"rating": feedback.rating, "comment": feedback.comment}


def message_out(
    message: Message,
    *,
    feedback: Feedback | None = None,
) -> dict[str, Any]:
    return {
        "id": message.id,
        "role": message.role,
        "content": message.content,
        "created_at": iso(message.created_at) or "",
        "blocked": bool(message.blocked),
        "sources": [source_out(s) for s in (message.sources or [])],
        "feedback": feedback_out(feedback) if feedback else None,
    }


def conversation_out(conversation: Any) -> dict[str, Any]:
    return {
        "id": conversation.id,
        "title": conversation.title,
        "message_count": conversation.message_count,
        "created_at": iso(conversation.created_at) or "",
        "last_message_at": iso(conversation.last_message_at),
    }


def document_out(document: Document) -> dict[str, Any]:
    return {
        "id": document.id,
        "title": document.title,
        "original_filename": document.original_filename,
        "content_type": document.content_type,
        "source": document.source,
        "size_bytes": document.size_bytes,
        "status": document.status,
        "error_message": document.error_message,
        "chunk_count": document.chunk_count,
        "page_count": document.page_count,
        "created_at": iso(document.created_at) or "",
        "indexed_at": iso(document.indexed_at),
        "uploaded_by": document.uploaded_by,
    }


def ingestion_event_out(event: DocumentIngestionEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "status": event.status,
        "message": event.message,
        "chunk_count": event.chunk_count,
        "duration_ms": event.duration_ms,
        "created_at": iso(event.created_at) or "",
    }


__all__ = [
    "conversation_out",
    "document_out",
    "feedback_out",
    "ingestion_event_out",
    "iso",
    "message_out",
    "source_out",
    "user_out",
]
