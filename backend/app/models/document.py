"""Knowledge-base document, chunk and ingestion-event models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDStr, new_uuid, utcnow

STATUS_PENDING = "pending"
STATUS_PROCESSING = "processing"
STATUS_INDEXED = "indexed"
STATUS_FAILED = "failed"
DOCUMENT_STATUSES: tuple[str, ...] = (
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_INDEXED,
    STATUS_FAILED,
)

SOURCE_UPLOAD = "upload"
SOURCE_SEED = "seed"

ALLOWED_EXTENSIONS: tuple[str, ...] = (".txt", ".md", ".pdf")


class Document(Base, TimestampMixin):
    """An uploaded/imported knowledge-base file.

    ``stored_filename`` is a random UUID-based name; the user-supplied filename
    is kept sanitised, as metadata only, and is never used on the filesystem.
    """

    __tablename__ = "documents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'processing', 'indexed', 'failed')", name="ck_documents_status"
        ),
        Index("ix_documents_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False, default="text/plain")
    source: Mapped[str] = mapped_column(String(20), nullable=False, default=SOURCE_UPLOAD)
    #: SHA-256 of the raw bytes - unique, which makes ingestion idempotent.
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    page_count: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=STATUS_PENDING)
    error_message: Mapped[str | None] = mapped_column(String(500))
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indexed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    uploaded_by: Mapped[str | None] = mapped_column(
        UUIDStr, ForeignKey("users.id", ondelete="SET NULL")
    )

    chunks: Mapped[list[DocumentChunk]] = relationship(
        back_populates="document",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DocumentChunk.position",
    )
    events: Mapped[list[DocumentIngestionEvent]] = relationship(
        back_populates="document",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DocumentIngestionEvent.created_at",
    )

    @property
    def is_searchable(self) -> bool:
        return self.status == STATUS_INDEXED and self.chunk_count > 0


class DocumentChunk(Base):
    """A retrievable slice of a document. Mirrored into the FTS5 index."""

    __tablename__ = "document_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "position", name="uq_document_chunks_position"),
        Index("ix_document_chunks_document", "document_id", "position"),
    )

    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)
    document_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Set when the chunk looks like it is trying to instruct an AI system.
    is_flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    flag_reason: Mapped[str | None] = mapped_column(String(200))

    document: Mapped[Document] = relationship(back_populates="chunks")


class DocumentIngestionEvent(Base):
    """Append-only ingestion history shown in the admin UI."""

    __tablename__ = "document_ingestion_events"
    __table_args__ = (Index("ix_ingestion_events_document", "document_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(
        UUIDStr, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str | None] = mapped_column(String(500))
    chunk_count: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )

    document: Mapped[Document] = relationship(back_populates="events")
