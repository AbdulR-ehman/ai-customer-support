"""Deterministic, paragraph-aware chunking.

Chunks are built from paragraph boundaries first and only hard-split when a
single paragraph exceeds the chunk size. Consecutive chunks overlap by
``overlap`` characters (snapped to a word boundary) so answers that straddle a
boundary are still retrievable.

The function is pure and deterministic: the same input always produces exactly
the same chunks, which is what makes re-indexing idempotent.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.ai.normalization import normalize_text


@dataclass(frozen=True, slots=True)
class TextChunk:
    """One retrievable slice of a document."""

    position: int
    content: str
    char_count: int

    @property
    def preview(self) -> str:
        """Short single-line preview used for source references."""
        flattened = " ".join(self.content.split())
        return flattened[:200]


def _tail_overlap(text: str, overlap: int) -> str:
    """Return the trailing ``overlap`` characters snapped to a word boundary."""
    if overlap <= 0 or not text:
        return ""
    tail = text[-overlap:]
    if len(text) > overlap and not text[-overlap - 1].isspace():
        parts = tail.split(maxsplit=1)
        if len(parts) == 2:
            tail = parts[1]
    return tail.strip()


def _split_long_paragraph(paragraph: str, chunk_size: int, overlap: int) -> list[str]:
    """Sliding window over a paragraph that is longer than one chunk."""
    pieces: list[str] = []
    start = 0
    length = len(paragraph)
    while start < length:
        end = min(start + chunk_size, length)
        window = paragraph[start:end]
        if end < length:
            # Prefer to break on whitespace so words are not torn in half.
            boundary = window.rfind(" ")
            if boundary > chunk_size // 2:
                window = window[:boundary]
                end = start + boundary
        window = window.strip()
        if window:
            pieces.append(window)
        next_start = end - overlap
        start = next_start if next_start > start else end
    return pieces


def chunk_text(
    text: str,
    *,
    chunk_size: int,
    overlap: int,
    max_chunks: int | None = None,
) -> list[TextChunk]:
    """Split ``text`` into overlapping chunks with stable positions."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >= 0 and smaller than chunk_size")

    normalized = normalize_text(text)
    if not normalized:
        return []

    paragraphs = [part for part in (p.strip() for p in normalized.split("\n\n")) if part]
    raw_chunks: list[str] = []
    current = ""

    for paragraph in paragraphs:
        if len(paragraph) > chunk_size:
            if current:
                raw_chunks.append(current)
                current = ""
            raw_chunks.extend(_split_long_paragraph(paragraph, chunk_size, overlap))
            continue

        if not current:
            current = paragraph
            continue

        candidate = f"{current}\n\n{paragraph}"
        if len(candidate) <= chunk_size:
            current = candidate
            continue

        raw_chunks.append(current)
        prefix = _tail_overlap(current, overlap)
        merged = f"{prefix}\n\n{paragraph}" if prefix else paragraph
        current = merged if len(merged) <= chunk_size else paragraph

    if current:
        raw_chunks.append(current)

    chunks: list[TextChunk] = []
    for position, content in enumerate(raw_chunks):
        if max_chunks is not None and position >= max_chunks:
            break
        stripped = content.strip()
        if not stripped:
            continue
        chunks.append(TextChunk(position=position, content=stripped, char_count=len(stripped)))
    return chunks
