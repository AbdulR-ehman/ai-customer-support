"""The only AI provider: a deterministic, offline, template-based mock.

Why this is injection-proof
---------------------------
The mock never interprets, plans, or obeys anything. It:

1. splits the retrieved chunks into sentences,
2. keeps the sentences that overlap the question's own search terms,
3. drops any sentence that the guards flag as instruction-like, and
4. writes the answer from fixed templates around those literal sentences.

There is no code path where text from the question or the context becomes an
instruction, a command, a URL fetch, or a side effect. The answer is a pure
function of the request, so the whole application is testable and reproducible
offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.ai.base import AIContextChunk, AIProvider, AIRequest, AIResponse
from app.ai.guards import inspect_context_chunk
from app.ai.prompts import CLARIFICATION_REQUEST, NOT_ENOUGH_INFORMATION, SUPPORT_EMAIL
from app.knowledge.retrieval import extract_query_terms

SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n{1,}")
MIN_FACT_LENGTH = 25
MAX_FACT_LENGTH = 400
MAX_FACTS = 4
MAX_SENTENCES_PER_CHUNK = 3

FOLLOW_UP_CLOSING = f"If you need account-specific help, contact Acme Support at {SUPPORT_EMAIL}."

VAGUE_QUESTIONS: frozenset[str] = frozenset(
    {
        "help",
        "hi",
        "hello",
        "hey",
        "support",
        "question",
        "info",
        "information",
        "can you help me",
        "i need help",
        "help me",
        "anyone",
        "need help",
    }
)


@dataclass(frozen=True, slots=True)
class _Fact:
    """A literal sentence taken from a knowledge-base chunk."""

    text: str
    source_label: str
    chunk_id: str
    score: float


class MockAIProvider(AIProvider):
    """Deterministic offline provider grounded strictly in retrieved context."""

    name = "mock"

    def generate(self, request: AIRequest) -> AIResponse:
        facts = self._select_facts(request)

        if not request.context_chunks:
            terms = extract_query_terms(request.question)
            if self._is_vague(request.question, terms):
                return AIResponse(
                    text=CLARIFICATION_REQUEST,
                    provider=self.name,
                    grounded=False,
                    notes=["no_context", "clarification_requested"],
                )
            return AIResponse(
                text=NOT_ENOUGH_INFORMATION,
                provider=self.name,
                grounded=False,
                notes=["no_context", "insufficient_information"],
            )

        if not facts:
            return AIResponse(
                text=NOT_ENOUGH_INFORMATION,
                provider=self.name,
                grounded=False,
                notes=["no_usable_facts", "insufficient_information"],
            )

        answer = self._compose(facts, max_chars=request.max_response_chars)
        return AIResponse(
            text=answer,
            provider=self.name,
            grounded=True,
            used_chunk_ids=tuple(dict.fromkeys(fact.chunk_id for fact in facts)),
            notes=["deterministic", "facts_from_context"],
        )

    # ------------------------------------------------------------- internals
    def _select_facts(self, request: AIRequest) -> list[_Fact]:
        terms = extract_query_terms(request.question)
        facts: list[_Fact] = []
        seen: set[str] = set()

        for chunk in request.context_chunks:
            for sentence, overlap in self._sentences(chunk, terms):
                key = sentence.lower()[:120]
                if key in seen:
                    continue
                seen.add(key)
                facts.append(
                    _Fact(
                        text=sentence,
                        source_label=chunk.source_label,
                        chunk_id=chunk.chunk_id,
                        score=overlap + chunk.score,
                    )
                )

        facts.sort(key=lambda fact: fact.score, reverse=True)
        return facts[:MAX_FACTS]

    def _sentences(self, chunk: AIContextChunk, terms: list[str]) -> list[tuple[str, float]]:
        """Split a chunk into candidate facts, dropping instruction-like text."""
        results: list[tuple[str, float]] = []
        for raw in SENTENCE_SPLIT_RE.split(chunk.text):
            sentence = " ".join(raw.split()).strip().strip("-*|#\t")
            if len(sentence) < MIN_FACT_LENGTH:
                continue
            if len(sentence) > MAX_FACT_LENGTH:
                sentence = self._truncate(sentence, MAX_FACT_LENGTH)
            # Defence in depth: never quote instruction-like content back.
            if inspect_context_chunk(sentence).blocked:
                continue
            lowered = sentence.lower()
            overlap = sum(1 for term in terms if term in lowered)
            if terms and overlap == 0:
                continue
            results.append((sentence, float(overlap)))
            if len(results) >= MAX_SENTENCES_PER_CHUNK:
                break
        return results

    def _compose(self, facts: list[_Fact], *, max_chars: int) -> str:
        if len(facts) == 1:
            fact = facts[0]
            first = fact.text[0].lower() + fact.text[1:] if fact.text else fact.text
            answer = f"According to the Acme Support knowledge base, {first}"
            answer = f"{answer}\n\nSource: {fact.source_label}"
        else:
            lines = ["According to the Acme Support knowledge base:"]
            lines.extend(f"- {fact.text} (source: {fact.source_label})" for fact in facts)
            lines.append("")
            lines.append(FOLLOW_UP_CLOSING)
            answer = "\n".join(lines)

        return self._truncate(answer, max_chars) if len(answer) > max_chars else answer

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        window = text[: max(1, limit - 3)]
        boundary = max(window.rfind(". "), window.rfind("\n"))
        window = window[: boundary + 1] if boundary > limit // 2 else window.rstrip()
        return f"{window}..."

    @staticmethod
    def _is_vague(question: str, terms: list[str]) -> bool:
        stripped = question.strip()
        if len(stripped) <= 3:
            return True
        lowered = stripped.lower().strip(" ?.!,")
        if lowered in VAGUE_QUESTIONS:
            return True
        return not terms
