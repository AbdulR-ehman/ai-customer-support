"""SQLite FTS5 index management for the knowledge base.

A contentless-by-convention FTS5 table mirrors the chunk table: it stores the
chunk/document ids (unindexed) plus the searchable title and content. The
application keeps it in sync inside the *same transaction* as the chunk rows, so
re-indexing either fully succeeds or fully rolls back.

All statements are parameterised; no SQL is ever built from user input.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

FTS_TABLE = "document_chunks_fts"

#: unicode61 with diacritic folding keeps "café" findable as "cafe".
TOKENIZER = "unicode61 remove_diacritics 2"

CREATE_FTS_SQL = f"""
CREATE VIRTUAL TABLE IF NOT EXISTS {FTS_TABLE} USING fts5(
    chunk_id UNINDEXED,
    document_id UNINDEXED,
    title,
    content,
    tokenize="{TOKENIZER}"
)
"""

INSERT_CHUNK_SQL = text(
    f"INSERT INTO {FTS_TABLE} (chunk_id, document_id, title, content) "
    "VALUES (:chunk_id, :document_id, :title, :content)"
)
DELETE_DOCUMENT_SQL = text(f"DELETE FROM {FTS_TABLE} WHERE document_id = :document_id")
DELETE_CHUNK_SQL = text(f"DELETE FROM {FTS_TABLE} WHERE chunk_id = :chunk_id")
COUNT_SQL = text(f"SELECT COUNT(*) FROM {FTS_TABLE}")
CLEAR_SQL = text(f"DELETE FROM {FTS_TABLE}")
OPTIMIZE_SQL = text(f"INSERT INTO {FTS_TABLE}({FTS_TABLE}) VALUES('optimize')")


def ensure_fts_table(connection: Connection) -> None:
    """Create the FTS5 virtual table when it does not exist yet."""
    connection.execute(text(CREATE_FTS_SQL))


def index_chunks(connection: Connection, rows: Sequence[tuple[str, str, str, str]]) -> int:
    """Insert ``(chunk_id, document_id, title, content)`` rows. Returns the count."""
    if not rows:
        return 0
    payload: list[dict[str, Any]] = [
        {"chunk_id": chunk_id, "document_id": document_id, "title": title, "content": content}
        for chunk_id, document_id, title, content in rows
    ]
    connection.execute(INSERT_CHUNK_SQL, payload)
    return len(payload)


def delete_document_from_index(connection: Connection, document_id: str) -> int:
    """Remove every indexed chunk of a document (used before re-indexing)."""
    result = connection.execute(DELETE_DOCUMENT_SQL, {"document_id": document_id})
    return int(result.rowcount or 0)


def delete_chunks_from_index(connection: Connection, chunk_ids: Iterable[str]) -> int:
    removed = 0
    for chunk_id in chunk_ids:
        result = connection.execute(DELETE_CHUNK_SQL, {"chunk_id": chunk_id})
        removed += int(result.rowcount or 0)
    return removed


def clear_index(connection: Connection) -> int:
    result = connection.execute(CLEAR_SQL)
    return int(result.rowcount or 0)


def optimize_index(connection: Connection) -> None:
    """Compact the FTS index (run after large re-indexing jobs)."""
    connection.execute(OPTIMIZE_SQL)


def count_indexed_chunks(connection: Connection) -> int:
    return int(connection.execute(COUNT_SQL).scalar_one())


def rebuild_index(connection: Connection, rows: Sequence[tuple[str, str, str, str]]) -> int:
    """Drop every entry and re-insert the given rows (maintenance command)."""
    clear_index(connection)
    return index_chunks(connection, rows)
