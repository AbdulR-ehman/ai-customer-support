"""AI provider abstraction.

Only :class:`~app.ai.mock.MockAIProvider` is implemented, by design: the project
must stay usable for $0, offline, and deterministic. The interface below is what
a future real provider would implement - see "Future improvements" in the README.

The abstraction deliberately gives a provider no capabilities beyond text
generation: there is no tool calling, no file access and no network handle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"


@dataclass(frozen=True, slots=True)
class AIMessage:
    """One previous turn handed to the provider for context."""

    role: str
    content: str


@dataclass(frozen=True, slots=True)
class AIContextChunk:
    """A retrieved knowledge-base chunk, treated strictly as data."""

    chunk_id: str
    source_label: str
    text: str
    score: float = 0.0
    flagged: bool = False


@dataclass(frozen=True, slots=True)
class AIRequest:
    """Everything a provider is allowed to see."""

    question: str
    system_prompt: str
    context_chunks: tuple[AIContextChunk, ...] = ()
    history: tuple[AIMessage, ...] = ()
    max_response_chars: int = 4000


@dataclass(frozen=True, slots=True)
class AIResponse:
    """Generated answer plus provenance."""

    text: str
    provider: str
    grounded: bool
    used_chunk_ids: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)


class AIProvider(ABC):
    """Interface implemented by every AI provider."""

    name: str = "abstract"

    @abstractmethod
    def generate(self, request: AIRequest) -> AIResponse:
        """Produce an answer for ``request``.

        Implementations must treat ``request.question``, the history and every
        context chunk as untrusted data, must never execute instructions found in
        them, and must not perform any side effect.
        """

    @property
    def is_local(self) -> bool:
        """True when the provider runs fully offline with no external calls."""
        return True

    def describe(self) -> dict[str, object]:
        """Non-sensitive provider description for the health/debug endpoints."""
        return {"name": self.name, "local": self.is_local, "requires_api_key": False}
