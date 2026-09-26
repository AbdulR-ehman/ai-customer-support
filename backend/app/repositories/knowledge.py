"""Document, chunking and ingestion-event persistence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, selectinload

from app.models.base import utcnow
from app.models.document import (
    SOURCE_UPLOAD,
    STATUS_FAILED,
    STATUS_INDEXED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    Document,
    DocumentChunk,
    DocumentIngestionEvent,
)


@dataclass(frozen=True, slots=True)
class ChunkInput:
    """One chunk to persist."""

    position: int
    content: str
    is_flagged: bool = False
    flag_reason: str | None = None

    @property
    def char_count(self) -> int:
        return len(self.content)


def create_document(
    db: Session,
    *,
    title: str,
    original_filename: str,
    stored_filename: str,
    content_type: str,
    content_hash: str,
    size_bytes: int,
    source: str = SOURCE_UPLOAD,
    uploaded_by: str | None = None,
) -> Document:
    document = Document(
        title=title[:255] or original_filename,
        original_filename=original_filename[:255],
        stored_filename=stored_filename,
        content_type=content_type[:120],
        content_hash=content_hash,
        size_bytes=size_bytes,
        source=source,
        uploaded_by=uploaded_by,
        status=STATUS_PENDING,
    )
    db.add(document)
    db.flush()
    return document


def get_document(db: Session, document_id: str) -> Document | None:
    return db.get(Document, document_id)


def get_document_with_chunks(db: Session, document_id: str) -> Document | None:
    return db.execute(
        select(Document)
        .options(selectinload(Document.chunks), selectinload(Document.events))
        .where(Document.id == document_id)
    ).scalar_one_or_none()


def get_document_by_hash(db: Session, content_hash: str) -> Document | None:
    """Used to make ingestion idempotent (unique content hash)."""
    return db.execute(
        select(Document).where(Document.content_hash == content_hash)
    ).scalar_one_or_none()


def list_documents(
    db: Session, *, limit: int, offset: int, status: str | None = None
) -> list[Document]:
    statement = select(Document).order_by(Document.created_at.desc()).offset(offset).limit(limit)
    if status:
        statement = statement.where(Document.status == status)
    return list(db.execute(statement).scalars())


def count_documents(db: Session, *, status: str | None = None) -> int:
    statement = select(func.count(Document.id))
    if status:
        statement = statement.where(Document.status == status)
    return int(db.execute(statement).scalar_one())


def set_status(
    db: Session,
    document: Document,
    status: str,
    *,
    error_message: str | None = None,
    chunk_count: int | None = None,
    page_count: int | None = None,
) -> None:
    document.status = status
    document.error_message = error_message[:500] if error_message else None
    if chunk_count is not None:
        document.chunk_count = chunk_count
    if page_count is not None:
        document.page_count = page_count
    if status == STATUS_INDEXED:
        document.indexed_at = utcnow()
    db.flush()


def record_event(
    db: Session,
    document: Document,
    *,
    status: str,
    message: str | None = None,
    chunk_count: int | None = None,
    duration_ms: int | None = None,
) -> DocumentIngestionEvent:
    event = DocumentIngestionEvent(
        document_id=document.id,
        status=status,
        message=(message[:500] if message else None),
        chunk_count=chunk_count,
        duration_ms=duration_ms,
    )
    db.add(event)
    db.flush()
    return event


def list_events(db: Session, *, document_id: str, limit: int = 20) -> list[DocumentIngestionEvent]:
    return list(
        db.execute(
            select(DocumentIngestionEvent)
            .where(DocumentIngestionEvent.document_id == document_id)
            .order_by(DocumentIngestionEvent.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def list_recent_events(db: Session, *, limit: int = 50) -> list[DocumentIngestionEvent]:
    return list(
        db.execute(
            select(DocumentIngestionEvent)
            .options(selectinload(DocumentIngestionEvent.document))
            .order_by(DocumentIngestionEvent.created_at.desc())
            .limit(limit)
        ).scalars()
    )


def replace_chunks(db: Session, document: Document, chunks: Sequence[ChunkInput]) -> int:
    """Atomically replace every chunk of a document (re-index idempotency).

    The delete and the inserts run inside the caller's transaction, so a failure
    leaves the previous index intact.
    """
    db.execute(delete(DocumentChunk).where(DocumentChunk.document_id == document.id))
    for chunk in chunks:
        db.add(
            DocumentChunk(
                document_id=document.id,
                position=chunk.position,
                content=chunk.content,
                char_count=chunk.char_count,
                is_flagged=chunk.is_flagged,
                flag_reason=chunk.flag_reason,
            )
        )
    document.chunk_count = len(chunks)
    db.flush()
    return len(chunks)


def list_chunks(db: Session, *, document_id: str, limit: int = 200) -> list[DocumentChunk]:
    return list(
        db.execute(
            select(DocumentChunk)
            .where(DocumentChunk.document_id == document_id)
            .order_by(DocumentChunk.position.asc())
            .limit(limit)
        ).scalars()
    )


def chunks_by_ids(db: Session, chunk_ids: Sequence[str]) -> dict[str, DocumentChunk]:
    if not chunk_ids:
        return {}
    rows = db.execute(select(DocumentChunk).where(DocumentChunk.id.in_(list(chunk_ids)))).scalars()
    return {row.id: row for row in rows}


def documents_by_ids(db: Session, document_ids: Sequence[str]) -> dict[str, Document]:
    if not document_ids:
        return {}
    rows = db.execute(select(Document).where(Document.id.in_(list(document_ids)))).scalars()
    return {row.id: row for row in rows}


def delete_document(db: Session, document: Document) -> None:
    """Delete a document; chunks, ingestion events and citations cascade."""
    db.delete(document)
    db.flush()


def all_chunk_rows(db: Session) -> list[tuple[str, str, str, str]]:
    """``(chunk_id, document_id, title, content)`` for a full index rebuild."""
    rows = db.execute(
        select(DocumentChunk.id, DocumentChunk.document_id, Document.title, DocumentChunk.content)
        .join(Document, Document.id == DocumentChunk.document_id)
        .where(Document.status == STATUS_INDEXED)
        .order_by(DocumentChunk.document_id, DocumentChunk.position)
    ).all()
    return [(str(a), str(b), str(c), str(d)) for a, b, c, d in rows]


def total_chunks(db: Session) -> int:
    return int(db.execute(select(func.count(DocumentChunk.id))).scalar_one())


def flagged_chunks(db: Session) -> int:
    return int(
        db.execute(
            select(func.count(DocumentChunk.id)).where(DocumentChunk.is_flagged.is_(True))
        ).scalar_one()
    )


def knowledge_stats(db: Session) -> dict[str, int]:
    return {
        "documents": count_documents(db),
        "documents_indexed": count_documents(db, status=STATUS_INDEXED),
        "documents_pending": count_documents(db, status=STATUS_PENDING),
        "documents_processing": count_documents(db, status=STATUS_PROCESSING),
        "documents_failed": count_documents(db, status=STATUS_FAILED),
        "chunks": total_chunks(db),
        "chunks_flagged": flagged_chunks(db),
    }
