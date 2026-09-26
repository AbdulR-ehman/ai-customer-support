"""BM25 retrieval over the FTS5 index - zero-cost, offline, no embeddings.

Query safety
------------
The user question is **never** inserted into SQL and **never** passed to FTS5 as
raw syntax. It is normalised, reduced to ``[a-z0-9]+`` tokens, filtered against a
stop-word list, and only then reassembled into an FTS5 expression built purely
from our own tokens. Anything that could carry FTS syntax - quotes, ``*``,
parentheses, ``:``, ``NEAR``/``AND``/``OR``, backslashes - has already been
removed, so the expression cannot be broken or injected into.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.ai.normalization import normalize_text
from app.knowledge.indexing import FTS_TABLE

TOKEN_RE = re.compile(r"[a-z0-9]+")
MAX_QUERY_TERMS = 12
MAX_QUERY_LENGTH = 400
CANDIDATE_MULTIPLIER = 4
SNIPPET_WIDTH = 240

#: A chunk must match at least this fraction of the question's search terms.
#: Without it, a four-term question with a single incidental keyword match
#: ("warranty void policy Atlantis" matching only "policy") scores just high
#: enough to be treated as relevant, and the assistant answers an unrelated
#: question. A one-term question always has full coverage, so this only tightens
#: multi-term questions.
MIN_TERM_COVERAGE = 0.3

#: Short high-frequency words that would otherwise match most chunks.
STOPWORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "the",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "do",
        "does",
        "did",
        "of",
        "to",
        "in",
        "on",
        "at",
        "for",
        "and",
        "or",
        "but",
        "if",
        "then",
        "than",
        "that",
        "this",
        "these",
        "those",
        "it",
        "its",
        "as",
        "by",
        "with",
        "without",
        "from",
        "into",
        "about",
        "over",
        "what",
        "which",
        "who",
        "whom",
        "whose",
        "when",
        "where",
        "why",
        "how",
        "can",
        "could",
        "will",
        "would",
        "shall",
        "should",
        "may",
        "might",
        "i",
        "me",
        "my",
        "mine",
        "we",
        "our",
        "you",
        "your",
        "yours",
        "they",
        "them",
        "their",
        "he",
        "she",
        "his",
        "her",
        "have",
        "has",
        "had",
        "please",
        "tell",
        "give",
        "want",
        "need",
        "get",
        "got",
        "there",
        "here",
        "just",
        "also",
        "any",
        "all",
        "some",
        "not",
        "no",
        "yes",
        "am",
        "us",
        "so",
        "too",
        "very",
        "much",
        "many",
        "more",
        "most",
    }
)

MATCH_SQL = text(
    f"""
    SELECT f.chunk_id         AS chunk_id,
           f.document_id      AS document_id,
           f.title            AS title,
           f.content          AS content,
           bm25({FTS_TABLE})  AS bm25_score,
           d.original_filename AS filename
    FROM {FTS_TABLE} AS f
    JOIN documents AS d ON d.id = f.document_id
    WHERE {FTS_TABLE} MATCH :query
      AND d.status = 'indexed'
    ORDER BY bm25_score
    LIMIT :limit
    """
)


@dataclass(slots=True)
class RetrievedChunk:
    """One ranked knowledge-base chunk."""

    chunk_id: str
    document_id: str
    document_title: str
    filename: str
    content: str
    score: float
    bm25_score: float
    matched_terms: list[str] = field(default_factory=list)

    @property
    def snippet(self) -> str:
        return make_snippet(self.content, self.matched_terms)

    def source_label(self) -> str:
        """Human-readable label used in citations and prompt data blocks."""
        return self.document_title or self.filename


def extract_query_terms(question: str) -> list[str]:
    """Reduce a question to safe search terms."""
    normalized = normalize_text(question, max_length=MAX_QUERY_LENGTH).lower()
    tokens = TOKEN_RE.findall(normalized)
    terms: list[str] = []
    for token in tokens:
        if len(token) < 2 or token in STOPWORDS:
            continue
        if token.isdigit() and len(token) < 3:
            continue
        if token not in terms:
            terms.append(token)
    # If stop-word removal emptied the query, fall back to the raw tokens so the
    # assistant still has a chance to find something.
    if not terms:
        terms = [token for token in tokens if len(token) >= 2]
    return terms[:MAX_QUERY_TERMS]


def build_fts_query(terms: list[str]) -> str | None:
    """Build a safe FTS5 expression from pre-sanitised terms.

    Prefix matching (``term*``) is used so "refund" also finds "refunds", while
    the strict ``[a-z0-9]+`` allow-list guarantees no FTS operator can survive.
    """
    safe_terms = [term for term in terms if TOKEN_RE.fullmatch(term)]
    if not safe_terms:
        return None
    return " OR ".join(f"{term}*" for term in safe_terms)


def _matched_terms(terms: list[str], content_lower: str) -> list[str]:
    words = set(TOKEN_RE.findall(content_lower))
    return [term for term in terms if term in words or any(w.startswith(term) for w in words)]


def _coverage(terms: list[str], content_lower: str) -> float:
    if not terms:
        return 0.0
    return len(_matched_terms(terms, content_lower)) / len(terms)


def make_snippet(content: str, terms: list[str], *, width: int = SNIPPET_WIDTH) -> str:
    """Return a readable excerpt centred on the best-matching window."""
    flat = " ".join(content.split())
    if len(flat) <= width:
        return flat
    lowered = flat.lower()
    best_position = 0
    best_hits = -1
    stride = max(1, width // 4)
    for start in range(0, max(1, len(flat) - width), stride):
        window = lowered[start : start + width]
        hits = sum(1 for term in terms if term in window)
        if hits > best_hits:
            best_hits = hits
            best_position = start
            if terms and hits == len(terms):
                break
    snippet = flat[best_position : best_position + width].strip()
    prefix = "..." if best_position > 0 else ""
    suffix = "..." if best_position + width < len(flat) else ""
    return f"{prefix}{snippet}{suffix}"


def search_chunks(
    connection: Connection,
    question: str,
    *,
    top_k: int,
    min_score: float,
    max_context_chars: int | None = None,
) -> tuple[list[RetrievedChunk], list[str]]:
    """Search the knowledge base.

    Returns ``(chunks, query_terms)``. Chunks are ordered by relevance and are
    empty when nothing relevant is found - the caller must then answer that it
    does not have enough information instead of guessing.
    """
    terms = extract_query_terms(question)
    query = build_fts_query(terms)
    if query is None:
        return [], terms

    limit = max(top_k, top_k * CANDIDATE_MULTIPLIER)
    rows = connection.execute(MATCH_SQL, {"query": query, "limit": limit}).mappings().all()

    scored: list[RetrievedChunk] = []
    for rank, row in enumerate(rows):
        content = str(row["content"] or "")
        lowered = content.lower()
        coverage = _coverage(terms, lowered)
        if coverage <= 0.0 or coverage < MIN_TERM_COVERAGE:
            continue
        score = round(0.85 * coverage + 0.15 * (1.0 / (1.0 + rank)), 4)
        if score < min_score:
            continue
        scored.append(
            RetrievedChunk(
                chunk_id=str(row["chunk_id"]),
                document_id=str(row["document_id"]),
                document_title=str(row["title"] or row["filename"] or "Untitled document"),
                filename=str(row["filename"] or ""),
                content=content,
                score=score,
                bm25_score=float(row["bm25_score"] or 0.0),
                matched_terms=_matched_terms(terms, lowered),
            )
        )

    scored.sort(key=lambda chunk: chunk.score, reverse=True)
    if max_context_chars is None:
        return scored[:top_k], terms

    # Fill the context budget, preferring breadth across documents.
    selected: list[RetrievedChunk] = []
    per_document: dict[str, int] = {}
    budget = max_context_chars
    for chunk in scored:
        if len(selected) >= top_k or budget <= 0:
            break
        if per_document.get(chunk.document_id, 0) >= 2:
            continue
        if len(chunk.content) > budget:
            continue
        selected.append(chunk)
        per_document[chunk.document_id] = per_document.get(chunk.document_id, 0) + 1
        budget -= len(chunk.content)
    return selected, terms
