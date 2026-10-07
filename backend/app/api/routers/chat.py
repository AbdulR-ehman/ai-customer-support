"""Customer chat, conversation history and feedback routes.

Every route depends on ``require_user``. Conversation and message lookups are
owner-scoped in the repository layer, so another customer's id returns 404 rather
than 403 and never confirms that the resource exists.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, DbDep, RequestMetaDep, SettingsDep
from app.api.serializers import conversation_out, feedback_out, message_out
from app.errors import ConflictError, InvalidInputError, NotFoundError
from app.logging_config import log_event
from app.models.audit import AUDIT_CONVERSATION_DELETE
from app.models.conversation import ROLE_ASSISTANT, Conversation
from app.repositories import conversations as conversations_repo
from app.repositories import system as system_repo
from app.schemas.chat import (
    MAX_OFFSET,
    MAX_PAGE_LIMIT,
    ChatRequest,
    ChatResponse,
    ConversationDetail,
    ConversationSummary,
    FeedbackOut,
    FeedbackRequest,
)
from app.services import chat as chat_service

logger = logging.getLogger("app.api.chat")

router = APIRouter(prefix="/api/chat", tags=["chat"])

#: Auto-created conversation titles, before the first question is known.
_NEW_TITLES: tuple[str, ...] = ("New conversation", "Support question", "Acme Support chat")


def _owned_conversation(db: Session, conversation_id: str, user_id: str) -> Conversation:
    """Owner-scoped lookup; 404 for foreign ids (no IDOR confirmation)."""
    conversation = conversations_repo.get_conversation(db, conversation_id, user_id=user_id)
    if conversation is None:
        raise NotFoundError()
    return conversation


@router.post("/conversations", response_model=ConversationSummary, status_code=201)
def create_conversation(
    db: DbDep, current: CurrentUser, settings: SettingsDep
) -> dict[str, object]:
    """Start an empty conversation without asking a question yet."""
    if (
        conversations_repo.count_conversations(db, user_id=current.id)
        >= settings.max_conversations_per_user
    ):
        raise ConflictError(
            "You have reached the maximum number of conversations. "
            "Please delete an old conversation to start a new one."
        )
    conversation = conversations_repo.create_conversation(
        db, user_id=current.id, title=_NEW_TITLES[0]
    )
    db.commit()
    return conversation_out(conversation)


@router.get("/conversations", response_model=list[ConversationSummary])
def list_conversations(
    db: DbDep,
    current: CurrentUser,
    limit: int = Query(default=20, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
) -> list[dict[str, object]]:
    """List the signed-in customer's conversations (owner-scoped, paginated)."""
    rows = conversations_repo.list_conversations(db, user_id=current.id, limit=limit, offset=offset)
    return [conversation_out(row) for row in rows]


@router.post("/messages", response_model=ChatResponse)
def send_message(
    payload: ChatRequest,
    db: DbDep,
    current: CurrentUser,
    settings: SettingsDep,
    meta: RequestMetaDep,
) -> ChatResponse:
    """Ask a question and receive a grounded, cited answer.

    The service performs its own per-user/per-IP chat throttling, so the limit is
    enforced in exactly one place regardless of the caller.
    """
    request_id, client_ip = meta
    is_new = payload.conversation_id is None
    conversation: Conversation
    if is_new:
        if (
            conversations_repo.count_conversations(db, user_id=current.id)
            >= settings.max_conversations_per_user
        ):
            raise ConflictError(
                "You have reached the maximum number of conversations. "
                "Please delete an old conversation to start a new one."
            )
        conversation = conversations_repo.create_conversation(
            db, user_id=current.id, title=_NEW_TITLES[0]
        )
    else:
        # ``is_new`` is False only when a conversation_id was supplied, but the
        # check is explicit (and not an ``assert``) so it survives ``python -O``.
        if payload.conversation_id is None:
            raise InvalidInputError("A conversation_id is required to continue a conversation.")
        conversation = _owned_conversation(db, payload.conversation_id, current.id)

    result = chat_service.ask(
        db,
        settings,
        user=current,
        conversation=conversation,
        question=payload.question,
        client_ip=client_ip,
        request_id=request_id,
    )
    return ChatResponse(
        conversation_id=result.conversation_id,
        conversation_title=result.conversation_title,
        conversation_is_new=is_new,
        user_message=message_out(result.user_message),
        assistant_message=message_out(result.assistant_message),
        grounded=result.grounded,
    )


@router.get("/conversations/{conversation_id}", response_model=ConversationDetail)
def get_conversation(
    conversation_id: str,
    db: DbDep,
    current: CurrentUser,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_LIMIT),
) -> dict[str, object]:
    """Return one conversation with its messages, sources and feedback."""
    conversation = _owned_conversation(db, conversation_id, current.id)
    rows = conversations_repo.list_messages(db, conversation_id=conversation_id, limit=limit)
    return {
        **conversation_out(conversation),
        "messages": [
            message_out(
                row,
                feedback=conversations_repo.get_feedback(db, message_id=row.id, user_id=current.id),
            )
            for row in rows
        ],
    }


@router.delete("/conversations/{conversation_id}", status_code=204)
def delete_conversation(
    conversation_id: str,
    db: DbDep,
    current: CurrentUser,
    meta: RequestMetaDep,
) -> Response:
    """Delete one of the customer's own conversations and all of its messages."""
    conversation = _owned_conversation(db, conversation_id, current.id)
    request_id, client_ip = meta
    system_repo.record_audit(
        db,
        action=AUDIT_CONVERSATION_DELETE,
        actor_user_id=current.id,
        actor_role=current.role,
        target_type="conversation",
        target_id=conversation_id,
        detail="customer deleted their conversation",
        request_id=request_id,
        ip_address=client_ip,
    )
    conversations_repo.delete_conversation(db, conversation)
    db.commit()
    log_event(
        logger,
        "conversation_deleted",
        user_id=current.id,
        conversation_id=conversation_id,
    )
    return Response(status_code=204)


@router.put("/messages/{message_id}/feedback", response_model=FeedbackOut)
def submit_feedback(
    message_id: str,
    payload: FeedbackRequest,
    db: DbDep,
    current: CurrentUser,
    settings: SettingsDep,
) -> dict[str, object]:
    """Create or update feedback on one of the customer's own answers."""
    message = conversations_repo.get_message_for_user(db, message_id, user_id=current.id)
    # One 404 for missing, foreign-owned, and non-assistant messages.
    if message is None or message.role != ROLE_ASSISTANT:
        raise NotFoundError()

    comment = payload.comment
    if comment is not None:
        comment = comment.strip()
        if len(comment) > settings.feedback_comment_max_chars:
            raise InvalidInputError(
                "Feedback comments are limited to "
                f"{settings.feedback_comment_max_chars} characters."
            )

    feedback = conversations_repo.upsert_feedback(
        db,
        message_id=message_id,
        user_id=current.id,
        rating=payload.rating,
        comment=comment or None,
    )
    db.commit()
    return feedback_out(feedback)


__all__ = ["router"]
