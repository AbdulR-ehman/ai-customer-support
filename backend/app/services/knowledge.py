"""Knowledge-base ingestion, re-indexing and deletion.

Every ingestion follows the same pipeline:

    validate -> store -> extract -> clean -> chunk -> flag -> persist -> index FTS

and is idempotent: the SHA-256 content hash is unique, so re-uploading the same
file returns the existing document instead of creating a duplicate. Re-indexing
replaces the chunks of a document inside one transaction, so the index is either
fully updated or left untouched.

Endpoints that call this service are synchronous, so FastAPI runs them in its
threadpool: extraction never blocks the event loop.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.guards import inspect_context_chunk
from app.config import Settings
from app.errors import ConflictError, InvalidInputError, NotFoundError
from app.knowledge import indexing
from app.knowledge.chunking import chunk_text
from app.knowledge.cleaning import ensure_meaningful_text
from app.knowledge.extraction import extract_text
from app.knowledge.uploads import (
    resolve_storage_path,
    safe_error_message,
    validate_upload,
)
from app.logging_config import log_event
from app.models.document import (
    SOURCE_SEED,
    SOURCE_UPLOAD,
    STATUS_FAILED,
    STATUS_INDEXED,
    STATUS_PROCESSING,
    Document,
)
from app.repositories import knowledge as knowledge_repo
from app.repositories.knowledge import ChunkInput

logger = logging.getLogger("app.knowledge")

MAX_CHUNKS_PER_DOCUMENT = 5000

#: Wall-clock budget for one extraction run (PDF bombs, huge text files).
EXTRACTION_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Outcome of one ingestion attempt."""

    document: Document
    created: bool
    chunk_count: int
    flagged_chunks: int
    message: str


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_file(path: Path, data: bytes) -> None:
    """Write the uploaded bytes with a fixed extension under the upload root."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def ingest_bytes(
    db: Session,
    settings: Settings,
    *,
    raw_filename: str | None,
    content_type: str | None,
    data: bytes,
    uploaded_by: str | None,
    title: str | None = None,
    source: str = SOURCE_UPLOAD,
) -> IngestResult:
    """Ingest an in-memory document (used by uploads and by the seed script)."""
    info = validate_upload(
        raw_filename=raw_filename,
        content_type=content_type,
        data=data,
        max_bytes=settings.max_upload_bytes,
    )

    content_hash = _hash_bytes(data)
    existing = knowledge_repo.get_document_by_hash(db, content_hash)
    if existing is not None:
        # Idempotent ingestion: identical content is never stored twice.
        log_event(logger, "ingestion_duplicate", document_id=existing.id)
        return IngestResult(
            document=existing,
            created=False,
            chunk_count=existing.chunk_count,
            flagged_chunks=0,
            message="This document has already been ingested; the existing copy was kept.",
        )

    if knowledge_repo.count_documents(db) >= settings.max_documents:
        raise ConflictError(
            f"The knowledge base already holds the maximum of {settings.max_documents} "
            "documents. Please delete a document before uploading another."
        )

    document = knowledge_repo.create_document(
        db,
        title=title or info.original_filename,
        original_filename=info.original_filename,
        stored_filename=info.stored_filename,
        content_type=info.content_type,
        content_hash=content_hash,
        size_bytes=info.size_bytes,
        source=source,
        uploaded_by=uploaded_by,
    )
    knowledge_repo.record_event(db, document, status=STATUS_PROCESSING, message="upload accepted")
    db.commit()

    storage_path = resolve_storage_path(settings.upload_dir_path, info.stored_filename)
    started = time.perf_counter()
    try:
        _write_file(storage_path, data)
        return _process_document(db, settings, document, started=started, data=data)
    except Exception as exc:
        _fail_document(db, document, exc, storage_path=storage_path, started=started)
        raise


def ingest_from_path(
    db: Session,
    settings: Settings,
    path: Path,
    *,
    uploaded_by: str | None = None,
    title: str | None = None,
) -> IngestResult:
    """Ingest a document from disk (used by the seeding script)."""
    if not path.is_file():
        raise NotFoundError(f"Knowledge-base file not found: {path.name}")
    data = path.read_bytes()
    if len(data) > settings.max_upload_bytes:
        raise InvalidInputError(
            f"{path.name} exceeds the {settings.max_upload_mb} MB upload limit."
        )
    return ingest_bytes(
        db,
        settings,
        raw_filename=path.name,
        content_type="application/pdf" if path.suffix.lower() == ".pdf" else "text/plain",
        data=data,
        uploaded_by=uploaded_by,
        title=title or path.stem.replace("_", " ").replace("-", " "),
        source=SOURCE_SEED,
    )


def serve_uploaded_bytes(settings: Settings, document: Document) -> Path:
    """Resolve an uploaded document path for an admin-only download."""
    return resolve_storage_path(settings.upload_dir_path, document.stored_filename)


def _fail_document(
    db: Session, document: Document, exc: Exception, *, storage_path: Path | None, started: float
) -> None:
    """Mark a document as failed with a sanitised reason and remove the file."""
    if isinstance(exc, (InvalidInputError, ConflictError)):
        safe_reason = safe_error_message(exc, fallback="The document could not be processed.")
    else:
        logger.exception("ingestion failed for document %s", document.id)
        safe_reason = "Processing failed due to an unexpected error."
    knowledge_repo.set_status(db, document, STATUS_FAILED, error_message=safe_reason)
    knowledge_repo.record_event(
        db,
        document,
        status=STATUS_FAILED,
        message=safe_reason,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    db.commit()
    if storage_path is not None and storage_path.exists():
        try:
            storage_path.unlink()
        except OSError:  # pragma: no cover - filesystem race
            logger.warning("could not remove failed upload for document %s", document.id)


def _process_document(
    db: Session,
    settings: Settings,
    document: Document,
    *,
    started: float,
    data: bytes,
) -> IngestResult:
    """Extract, clean, chunk, flag and index a document."""
    extraction = extract_text(
        document.original_filename,
        document.content_type,
        data,
        max_chars=settings.max_extracted_chars,
        max_pdf_pages=settings.max_pdf_pages,
        timeout_seconds=EXTRACTION_TIMEOUT_SECONDS,
    )
    text = ensure_meaningful_text(extraction.text)

    chunks = chunk_text(
        text,
        chunk_size=settings.chunk_size_chars,
        overlap=settings.chunk_overlap_chars,
        max_chunks=MAX_CHUNKS_PER_DOCUMENT,
    )
    if not chunks:
        raise InvalidInputError("No usable text could be extracted from this document.")

    inputs: list[ChunkInput] = []
    flagged = 0
    for chunk in chunks:
        verdict = inspect_context_chunk(chunk.content)
        if verdict.blocked:
            flagged += 1
        inputs.append(
            ChunkInput(
                position=chunk.position,
                content=chunk.content,
                is_flagged=verdict.blocked,
                flag_reason=(verdict.reason[:200] if verdict.blocked else None),
            )
        )

    # Chunks and the FTS mirror are replaced inside one transaction.
    knowledge_repo.replace_chunks(db, document, inputs)
    connection = db.connection()
    indexing.ensure_fts_table(connection)
    indexing.delete_document_from_index(connection, document.id)
    stored_chunks = knowledge_repo.list_chunks(
        db, document_id=document.id, limit=MAX_CHUNKS_PER_DOCUMENT + 1
    )
    indexing.index_chunks(
        connection,
        [(row.id, document.id, document.title, row.content) for row in stored_chunks],
    )
    if flagged:
        indexing.optimize_index(connection)

    knowledge_repo.set_status(
        db,
        document,
        STATUS_INDEXED,
        chunk_count=len(stored_chunks),
        page_count=extraction.page_count,
    )
    knowledge_repo.record_event(
        db,
        document,
        status=STATUS_INDEXED,
        message=(
            f"indexed {len(stored_chunks)} chunk(s)"
            + (f"; {flagged} flagged as untrusted instructions" if flagged else "")
        ),
        chunk_count=len(stored_chunks),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    db.commit()

    log_event(
        logger,
        "document_indexed",
        document_id=document.id,
        chunk_count=len(stored_chunks),
        flagged_chunks=flagged,
        kind=extraction.kind,
        truncated=extraction.truncated,
    )
    return IngestResult(
        document=document,
        created=True,
        chunk_count=len(stored_chunks),
        flagged_chunks=flagged,
        message=f"Indexed {len(stored_chunks)} chunk(s) from {document.original_filename}.",
    )


def reindex_document(db: Session, settings: Settings, document: Document) -> IngestResult:
    """Re-run the pipeline for a stored document (idempotent)."""
    storage_path = resolve_storage_path(settings.upload_dir_path, document.stored_filename)
    if not storage_path.is_file():
        knowledge_repo.set_status(
            db, document, STATUS_FAILED, error_message="The stored file is no longer available."
        )
        knowledge_repo.record_event(
            db, document, status=STATUS_FAILED, message="stored file missing"
        )
        db.commit()
        raise NotFoundError("The stored file for this document is no longer available.")

    started = time.perf_counter()
    knowledge_repo.set_status(db, document, STATUS_PROCESSING)
    knowledge_repo.record_event(
        db, document, status=STATUS_PROCESSING, message="re-index requested"
    )
    db.commit()
    try:
        return _process_document(
            db, settings, document, started=started, data=storage_path.read_bytes()
        )
    except Exception as exc:
        _fail_document(db, document, exc, storage_path=None, started=started)
        raise


def delete_document(db: Session, settings: Settings, document: Document) -> None:
    """Remove a document from the database, the FTS index and the filesystem."""
    connection = db.connection()
    indexing.ensure_fts_table(connection)
    indexing.delete_document_from_index(connection, document.id)
    stored_filename = document.stored_filename
    knowledge_repo.delete_document(db, document)
    db.commit()

    storage_path = resolve_storage_path(settings.upload_dir_path, stored_filename)
    if storage_path.is_file():
        try:
            storage_path.unlink()
        except OSError:  # pragma: no cover - filesystem race
            logger.warning("could not remove stored file for a deleted document")
    log_event(logger, "document_deleted", document_id=document.id)


def rebuild_index(db: Session, settings: Settings) -> int:
    """Rebuild the whole FTS index from the chunk table (maintenance command)."""
    connection = db.connection()
    indexing.ensure_fts_table(connection)
    count = indexing.rebuild_index(connection, knowledge_repo.all_chunk_rows(db))
    indexing.optimize_index(connection)
    db.commit()
    log_event(logger, "index_rebuilt", chunk_count=count)
    return count
