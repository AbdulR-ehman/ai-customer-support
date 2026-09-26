"""Chat orchestration.

Pipeline for one question::

    validate -> rate limit -> input guard -> persist question -> retrieve (BM25)
      -> mark untrusted chunks -> generate (mock provider, bounded concurrency)
      -> output guard -> persist answer + citations

Security-relevant behaviour
---------------------------
* The assistant is never called with more than ``MAX_CONTEXT_CHARS`` of context,
  ``MAX_HISTORY_MESSAGES`` of history, or a question longer than
  ``MAX_MESSAGE_CHARS``.
* A blocked question is stored with ``blocked=True`` and answered with a fixed,
  non-leaking refusal; the attempt is audited and logged.
* Any output that contains the canary, a secret, credential-shaped text or an
  internal path is discarded and replaced with a refusal.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.ai.base import AIContextChunk, AIMessage, AIRequest
from app.ai.factory import get_provider
from app.ai.guards import (
    INJECTION_REFUSAL,
    LEAK_REFUSAL,
    check_user_input,
    inspect_context_chunk,
    scan_output,
)
from app.ai.normalization import normalize_text
from app.ai.prompts import NOT_ENOUGH_INFORMATION, get_system_prompt, leaked_markers
from app.config import Settings
from app.errors import AIProviderError, ConflictError, InvalidInputError, ServiceUnavailableError
from app.knowledge.retrieval import RetrievedChunk, search_chunks
from app.logging_config import log_event
from app.models.audit import AUDIT_INJECTION_BLOCKED
from app.models.conversation import ROLE_ASSISTANT, ROLE_USER, Conversation, Message
from app.models.user import User
from app.repositories import conversations as conversations_repo
from app.repositories import system as system_repo
from app.repositories.conversations import SourceInput
from app.services.rate_limit import RateLimiter

logger = logging.getLogger("app.chat")

_ai_semaphore: threading.BoundedSemaphore | None = None
_ai_semaphore_size = 0
_semaphore_lock = threading.Lock()


@dataclass(slots=True)
class ChatResult:
    """Everything the API layer needs to render one exchange."""

    user_message: Message
    assistant_message: Message
    conversation_id: str = ""
    conversation_title: str = ""
    sources: list[SourceInput] = field(default_factory=list)
    blocked: bool = False
    grounded: bool = False
    query_terms: list[str] = field(default_factory=list)
    context_chunks: int = 0
    flagged_chunks: int = 0
    notes: list[str] = field(default_factory=list)


def _semaphore(size: int) -> threading.BoundedSemaphore:
    """Process-wide cap on concurrent provider calls."""
    global _ai_semaphore, _ai_semaphore_size
    with _semaphore_lock:
        if _ai_semaphore is None or _ai_semaphore_size != size:
            _ai_semaphore = threading.BoundedSemaphore(max(1, size))
            _ai_semaphore_size = size
        return _ai_semaphore


def validate_question(question: str, settings: Settings) -> str:
    """Reject empty, whitespace-only and oversized questions."""
    normalized = normalize_text(question, max_length=settings.max_message_chars + 1)
    if not normalized:
        raise InvalidInputError("Please enter a question before sending.")
    if len(normalized) > settings.max_message_chars:
        raise InvalidInputError(
            f"Your question is too long. Please keep it under "
            f"{settings.max_message_chars} characters."
        )
    return normalized


def ask(
    db: Session,
    settings: Settings,
    *,
    user: User,
    conversation: Conversation,
    question: str,
    client_ip: str | None = None,
    request_id: str | None = None,
    limiter: RateLimiter | None = None,
) -> ChatResult:
    """Answer one question inside ``conversation`` and persist the exchange."""
    limiter = limiter or RateLimiter(settings)
    cleaned_question = validate_question(question, settings)

    if conversations_repo.count_messages(db, conversation_id=conversation.id) >= (
        settings.max_messages_per_conversation
    ):
        raise ConflictError(
            "This conversation has reached its message limit. "
            "Please start a new conversation to keep chatting."
        )

    limiter.enforce_chat(db, user_id=user.id, client_ip=client_ip)

    history = conversations_repo.recent_messages(
        db, conversation_id=conversation.id, limit=settings.max_history_messages
    )
    verdict = check_user_input(cleaned_question)
    if not verdict.blocked:
        previous_questions = [message.content for message in history if message.role == ROLE_USER]
        if previous_questions:
            # Split-across-messages attacks only become visible when combined.
            combined = f"{previous_questions[-1]}\n{cleaned_question}"
            verdict = check_user_input(combined)

    if verdict.blocked:
        return _refuse_question(
            db,
            conversation=conversation,
            user=user,
            question=cleaned_question,
            reason=verdict.reason,
            request_id=request_id,
            client_ip=client_ip,
        )

    if conversation.title in DEFAULT_TITLES:
        # Title the conversation from its first real question (plain text, escaped).
        conversation.title = title_from_question(cleaned_question)

    user_message = conversations_repo.add_message(
        db, conversation=conversation, role=ROLE_USER, content=cleaned_question
    )

    chunks, terms = _retrieve(db, settings, question=cleaned_question, history=history)
    result = _answer(
        db,
        settings,
        user=user,
        conversation=conversation,
        user_message=user_message,
        chunks=chunks,
        terms=terms,
        request_id=request_id,
        client_ip=client_ip,
    )
    result.conversation_id = conversation.id
    result.conversation_title = conversation.title
    return result


#: Generic titles used until the first question can title the conversation.
DEFAULT_TITLES: frozenset[str] = frozenset(
    {"New conversation", "Support question", "Acme Support chat"}
)
MAX_TITLE_CHARS = 80

#: A follow-up is only "short and elliptical" when it has very few search terms.
MAX_FOLLOWUP_TERMS = 3
MAX_FOLLOWUP_CHARS = 60


def title_from_question(question: str) -> str:
    """Build a short, safe conversation title from the first question."""
    flat = " ".join(question.split()).strip(" ?.!,")
    if not flat:
        return "New conversation"
    if len(flat) > MAX_TITLE_CHARS:
        flat = flat[:MAX_TITLE_CHARS].rstrip()
    return flat


def _retrieve(
    db: Session,
    settings: Settings,
    *,
    question: str,
    history: list[Message],
) -> tuple[list[RetrievedChunk], list[str]]:
    """BM25 search, with one history-assisted retry for follow-up questions."""
    chunks, terms = search_chunks(
        db.connection(),
        question,
        top_k=settings.retrieval_top_k,
        min_score=settings.retrieval_min_score,
        max_context_chars=settings.max_context_chars,
    )
    if chunks:
        return chunks, terms

    # History-assisted retry, only for genuine short follow-ups ("and shipping?").
    # A longer, self-contained question that found nothing means we genuinely do
    # not know; retrying with the previous question would let an unrelated question
    # inherit an earlier answer, which is how hallucinations appear.
    if len(terms) <= MAX_FOLLOWUP_TERMS and len(question) <= MAX_FOLLOWUP_CHARS:
        previous = [message.content for message in history if message.role == ROLE_USER]
        if previous:
            retry_chunks, retry_terms = search_chunks(
                db.connection(),
                f"{previous[-1]} {question}",
                top_k=settings.retrieval_top_k,
                min_score=settings.retrieval_min_score,
                max_context_chars=settings.max_context_chars,
            )
            if retry_chunks:
                return retry_chunks, sorted({*terms, *retry_terms})
    return [], terms


def _refuse_question(
    db: Session,
    *,
    conversation: Conversation,
    user: User,
    question: str,
    reason: str,
    request_id: str | None,
    client_ip: str | None,
) -> ChatResult:
    """Store the attempt and answer with a fixed refusal. Nothing is executed."""
    user_message = conversations_repo.add_message(
        db, conversation=conversation, role=ROLE_USER, content=question, blocked=True
    )
    assistant_message = conversations_repo.add_message(
        db,
        conversation=conversation,
        role=ROLE_ASSISTANT,
        content=INJECTION_REFUSAL,
        blocked=True,
        provider="guard",
        latency_ms=0,
        retrieval_count=0,
    )
    system_repo.record_audit(
        db,
        action=AUDIT_INJECTION_BLOCKED,
        actor_user_id=user.id,
        actor_role=user.role,
        target_type="conversation",
        target_id=conversation.id,
        detail=f"blocked input ({reason})",
        request_id=request_id,
        ip_address=client_ip,
    )
    db.commit()
    log_event(logger, "prompt_injection_blocked", reason=reason, user_id=user.id)
    return ChatResult(
        user_message=user_message,
        assistant_message=assistant_message,
        conversation_id=conversation.id,
        conversation_title=conversation.title,
        blocked=True,
        grounded=False,
        notes=["input_guard", reason],
    )


def _answer(
    db: Session,
    settings: Settings,
    *,
    user: User,
    conversation: Conversation,
    user_message: Message,
    chunks: list[RetrievedChunk],
    terms: list[str],
    request_id: str | None,
    client_ip: str | None,
) -> ChatResult:
    """Generate, guard and persist the assistant answer."""
    context_chunks: list[AIContextChunk] = []
    flagged = 0
    for chunk in chunks:
        verdict = inspect_context_chunk(chunk.content)
        if verdict.blocked:
            flagged += 1
            log_event(
                logger,
                "untrusted_chunk_flagged",
                document_id=chunk.document_id,
                reason=verdict.reason,
            )
        context_chunks.append(
            AIContextChunk(
                chunk_id=chunk.chunk_id,
                source_label=chunk.document_title,
                text=chunk.content,
                score=chunk.score,
                flagged=verdict.blocked,
            )
        )

    history_messages = tuple(
        AIMessage(role=message.role, content=message.content[:600])
        for message in conversations_repo.recent_messages(
            db, conversation_id=conversation.id, limit=settings.max_history_messages
        )
        if message.id != user_message.id
    )

    system_prompt = get_system_prompt(settings)
    request = AIRequest(
        question=user_message.content,
        system_prompt=system_prompt,
        context_chunks=tuple(context_chunks),
        history=history_messages,
        max_response_chars=settings.max_response_chars,
    )

    provider = get_provider()
    semaphore = _semaphore(settings.max_concurrent_ai)
    if not semaphore.acquire(blocking=False):
        raise ServiceUnavailableError(
            "The assistant is handling a lot of requests right now. Please try again shortly."
        )
    started = time.perf_counter()
    try:
        response = provider.generate(request)
    except (InvalidInputError, ConflictError, ServiceUnavailableError):
        raise
    except Exception as exc:
        log_event(logger, "ai_provider_failure", error_type=type(exc).__name__)
        raise AIProviderError(
            "The assistant is temporarily unavailable. Please try again."
        ) from exc
    finally:
        semaphore.release()
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if elapsed_ms / 1000 > settings.ai_timeout_seconds:
        raise AIProviderError("The assistant took too long to respond. Please try again.")

    scan = scan_output(
        response.text,
        canary=settings.resolved_canary_token,
        secret_values=(settings.resolved_secret_key,),
        system_prompt=leaked_markers(system_prompt),
        max_length=settings.max_response_chars,
    )
    leak_detected = any(
        marker in scan.leaks
        for marker in (
            "canary_token",
            "secret_value",
            "system_prompt",
            "secret_shape",
            "internal_path",
        )
    )
    answer_text = LEAK_REFUSAL if leak_detected else scan.text
    if not answer_text:
        answer_text = NOT_ENOUGH_INFORMATION

    assistant_message = conversations_repo.add_message(
        db,
        conversation=conversation,
        role=ROLE_ASSISTANT,
        content=answer_text,
        blocked=leak_detected,
        provider=response.provider,
        latency_ms=elapsed_ms,
        retrieval_count=len(context_chunks),
    )

    sources = _build_sources(chunks, response.used_chunk_ids) if response.grounded else []
    if sources:
        conversations_repo.add_sources(db, message=assistant_message, sources=sources)

    if leak_detected:
        system_repo.record_audit(
            db,
            action=AUDIT_INJECTION_BLOCKED,
            actor_user_id=user.id,
            actor_role=user.role,
            target_type="message",
            target_id=assistant_message.id,
            detail=f"output guard redacted: {','.join(scan.leaks)}",
            request_id=request_id,
            ip_address=client_ip,
        )
        log_event(logger, "output_guard_triggered", leaks=",".join(scan.leaks), user_id=user.id)

    db.commit()
    log_event(
        logger,
        "chat_answered",
        user_id=user.id,
        conversation_id=conversation.id,
        grounded=response.grounded,
        context_chunks=len(context_chunks),
        flagged_chunks=flagged,
        source_count=len(sources),
        latency_ms=elapsed_ms,
    )
    return ChatResult(
        user_message=user_message,
        assistant_message=assistant_message,
        sources=sources,
        blocked=False,
        grounded=response.grounded,
        query_terms=terms,
        context_chunks=len(context_chunks),
        flagged_chunks=flagged,
        notes=response.notes,
    )


def _build_sources(
    chunks: list[RetrievedChunk], used_chunk_ids: tuple[str, ...]
) -> list[SourceInput]:
    """Map the chunks the provider actually used into citation snapshots."""
    chunks_used = (
        [chunk for chunk in chunks if chunk.chunk_id in set(used_chunk_ids)]
        if used_chunk_ids
        else chunks
    )
    return [
        SourceInput(
            document_id=chunk.document_id,
            document_title=chunk.document_title,
            snippet=chunk.snippet,
            chunk_id=chunk.chunk_id,
            score=chunk.score,
            chunk_position=0,
        )
        for chunk in chunks_used
    ]
