"""Chat, conversation and feedback schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from app.schemas.base import RequestModel, ResponseModel

#: Hard ceiling; the configurable per-deployment limit is enforced in the service.
MAX_QUESTION_CHARS = 20_000
MAX_COMMENT_CHARS = 5000
MAX_PAGE_LIMIT = 100
MAX_OFFSET = 10_000


class ChatRequest(RequestModel):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    conversation_id: str | None = Field(default=None, max_length=64)


class SourceOut(ResponseModel):
    document_id: str
    document_title: str
    snippet: str
    score: float
    position: int


class FeedbackOut(ResponseModel):
    rating: Literal["up", "down"]
    comment: str | None = None


class MessageOut(ResponseModel):
    id: str
    role: Literal["user", "assistant"]
    content: str
    created_at: str
    blocked: bool = False
    sources: list[SourceOut] = Field(default_factory=list)
    feedback: FeedbackOut | None = None


class ConversationSummary(ResponseModel):
    id: str
    title: str
    message_count: int
    created_at: str
    last_message_at: str | None = None


class ConversationDetail(ConversationSummary):
    messages: list[MessageOut] = Field(default_factory=list)


class ChatResponse(ResponseModel):
    conversation_id: str
    conversation_title: str
    conversation_is_new: bool
    user_message: MessageOut
    assistant_message: MessageOut
    grounded: bool


class FeedbackRequest(RequestModel):
    rating: Literal["up", "down"]
    comment: str | None = Field(default=None, max_length=MAX_COMMENT_CHARS)

    @field_validator("comment", mode="before")
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value
