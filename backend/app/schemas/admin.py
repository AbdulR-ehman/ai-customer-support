"""Admin schemas: documents, statistics and the audit log."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.schemas.base import ResponseModel

MAX_PAGE_LIMIT = 100
MAX_OFFSET = 10_000

DocumentStatus = Literal["pending", "processing", "indexed", "failed"]


class DocumentOut(ResponseModel):
    id: str
    title: str
    original_filename: str
    content_type: str
    source: Literal["upload", "seed"]
    size_bytes: int
    status: DocumentStatus
    error_message: str | None = None
    chunk_count: int
    page_count: int | None = None
    created_at: str
    indexed_at: str | None = None
    uploaded_by: str | None = None


class IngestionEventOut(ResponseModel):
    id: int
    status: str
    message: str | None = None
    chunk_count: int | None = None
    duration_ms: int | None = None
    created_at: str


class DocumentDetail(DocumentOut):
    events: list[IngestionEventOut] = Field(default_factory=list)


class UploadResponse(ResponseModel):
    document: DocumentOut
    created: bool
    chunk_count: int
    flagged_chunks: int
    message: str


class KnowledgeStatsOut(ResponseModel):
    documents: int
    documents_indexed: int
    documents_pending: int
    documents_processing: int
    documents_failed: int
    chunks: int
    chunks_flagged: int


class StatsOut(ResponseModel):
    users: int
    admins: int
    conversations: int
    feedback_total: int
    feedback_up: int
    feedback_down: int
    audit_entries: int
    knowledge: KnowledgeStatsOut


class AuditEntryOut(ResponseModel):
    id: int
    action: str
    actor_user_id: str | None = None
    actor_role: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    detail: str | None = None
    request_id: str | None = None
    ip_address: str | None = None
    created_at: str


class PageMeta(ResponseModel):
    total: int
    limit: int
    offset: int


class DocumentListOut(ResponseModel):
    items: list[DocumentOut]
    page: PageMeta


class AuditListOut(ResponseModel):
    items: list[AuditEntryOut]
    page: PageMeta


class OperationResponse(ResponseModel):
    message: str
    chunks: int | None = None
