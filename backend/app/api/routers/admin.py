"""Admin routes: knowledge-base management, dashboard statistics and audit log.

Every route depends on ``require_admin``; a customer token receives 403 before any
data is read. Admin actions are recorded in the append-only audit log.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, Query, Request, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import CurrentAdmin, DbDep, LimiterDep, RequestMetaDep, SettingsDep
from app.api.serializers import document_out, ingestion_event_out, iso
from app.errors import NotFoundError
from app.knowledge.uploads import read_limited
from app.logging_config import log_event
from app.models.audit import (
    AUDIT_DOCUMENT_DELETE,
    AUDIT_DOCUMENT_REINDEX,
    AUDIT_DOCUMENT_UPLOAD,
)
from app.models.conversation import RATING_DOWN, RATING_UP
from app.models.document import DOCUMENT_STATUSES, Document
from app.repositories import conversations as conversations_repo
from app.repositories import knowledge as knowledge_repo
from app.repositories import system as system_repo
from app.repositories import users as users_repo
from app.schemas.admin import (
    MAX_OFFSET,
    MAX_PAGE_LIMIT,
    AuditEntryOut,
    AuditListOut,
    DocumentDetail,
    DocumentListOut,
    DocumentOut,
    OperationResponse,
    PageMeta,
    StatsOut,
    UploadResponse,
)
from app.services import knowledge as knowledge_service

logger = logging.getLogger("app.api.admin")

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _document_or_404(db: Session, document_id: str) -> Document:
    document = knowledge_repo.get_document(db, document_id)
    if document is None:
        raise NotFoundError()
    return document


@router.get("/stats", response_model=StatsOut)
def dashboard_stats(db: DbDep, admin: CurrentAdmin) -> StatsOut:
    """Basic portfolio-level statistics (no secrets, no conversation content)."""
    del admin
    return StatsOut(
        users=users_repo.count_users(db),
        admins=users_repo.count_users(db, role="admin"),
        conversations=conversations_repo.total_conversations(db),
        feedback_total=conversations_repo.count_feedback(db),
        feedback_up=conversations_repo.count_feedback(db, rating=RATING_UP),
        feedback_down=conversations_repo.count_feedback(db, rating=RATING_DOWN),
        audit_entries=system_repo.count_audit(db),
        knowledge=knowledge_repo.knowledge_stats(db),
    )


@router.get("/documents", response_model=DocumentListOut)
def list_documents(
    db: DbDep,
    admin: CurrentAdmin,
    limit: int = Query(default=25, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    status: str | None = Query(default=None),
) -> dict[str, object]:
    """Paginated knowledge documents with ingestion status."""
    del admin
    if status is not None and status not in DOCUMENT_STATUSES:
        raise NotFoundError()
    items = knowledge_repo.list_documents(db, limit=limit, offset=offset, status=status)
    return {
        "items": [document_out(item) for item in items],
        "page": PageMeta(
            total=knowledge_repo.count_documents(db, status=status),
            limit=limit,
            offset=offset,
        ).model_dump(),
    }


@router.get("/documents/{document_id}", response_model=DocumentDetail)
def get_document(
    document_id: str, db: DbDep, admin: CurrentAdmin, meta: RequestMetaDep
) -> dict[str, object]:
    """Document metadata plus its ingestion history (audit-logged)."""
    del admin
    document = _document_or_404(db, document_id)
    events = knowledge_repo.list_events(db, document_id=document_id, limit=25)
    request_id, client_ip = meta
    system_repo.record_audit(
        db,
        action="document.view",
        actor_role="admin",
        target_type="document",
        target_id=document_id,
        detail="admin viewed document metadata",
        request_id=request_id,
        ip_address=client_ip,
    )
    db.commit()
    return {
        **document_out(document),
        "events": [ingestion_event_out(event) for event in events],
    }


@router.post("/documents", response_model=UploadResponse, status_code=201)
async def upload_document(
    request: Request,
    db: DbDep,
    admin: CurrentAdmin,
    settings: SettingsDep,
    limiter: LimiterDep,
    meta: RequestMetaDep,
    file: UploadFile = File(...),
) -> dict[str, object]:
    """Ingest an uploaded TXT, Markdown or PDF document.

    The file is read with a streaming cap, validated (name, extension, MIME,
    magic bytes) and then processed by the ingestion pipeline. Duplicate content
    is detected by SHA-256 and never stored twice.
    """
    del request
    limiter.enforce_upload(db, user_id=admin.id)
    limiter.enforce_global(db, identity=admin.id)

    data = read_limited(file.file, settings.max_upload_bytes)
    result = knowledge_service.ingest_bytes(
        db,
        settings,
        raw_filename=file.filename,
        content_type=file.content_type,
        data=data,
        uploaded_by=admin.id,
    )

    request_id, client_ip = meta
    if result.created:
        system_repo.record_audit(
            db,
            action=AUDIT_DOCUMENT_UPLOAD,
            actor_user_id=admin.id,
            actor_role=admin.role,
            target_type="document",
            target_id=result.document.id,
            detail=f"uploaded {result.document.original_filename}",
            request_id=request_id,
            ip_address=client_ip,
        )
        db.commit()

    return {
        "document": DocumentOut(**document_out(result.document)).model_dump(),
        "created": result.created,
        "chunk_count": result.chunk_count,
        "flagged_chunks": result.flagged_chunks,
        "message": result.message,
    }


@router.post("/documents/{document_id}/reindex", response_model=OperationResponse)
def reindex_document(
    document_id: str,
    db: DbDep,
    admin: CurrentAdmin,
    settings: SettingsDep,
    limiter: LimiterDep,
    meta: RequestMetaDep,
) -> dict[str, object]:
    """Re-run extraction and indexing for a document (idempotent)."""
    limiter.enforce_admin_write(db, user_id=admin.id, scope="reindex")
    document = _document_or_404(db, document_id)

    request_id, client_ip = meta
    system_repo.record_audit(
        db,
        action=AUDIT_DOCUMENT_REINDEX,
        actor_user_id=admin.id,
        actor_role=admin.role,
        target_type="document",
        target_id=document_id,
        detail="admin requested re-index",
        request_id=request_id,
        ip_address=client_ip,
    )
    db.commit()

    result = knowledge_service.reindex_document(db, settings, document)
    return {"message": result.message, "chunks": result.chunk_count}


@router.delete("/documents/{document_id}", response_model=OperationResponse)
def delete_document(
    document_id: str,
    db: DbDep,
    admin: CurrentAdmin,
    settings: SettingsDep,
    limiter: LimiterDep,
    meta: RequestMetaDep,
) -> dict[str, object]:
    """Delete a document, its chunks, its FTS entries and the stored file."""
    limiter.enforce_admin_write(db, user_id=admin.id, scope="delete")
    document = _document_or_404(db, document_id)
    request_id, client_ip = meta

    system_repo.record_audit(
        db,
        action=AUDIT_DOCUMENT_DELETE,
        actor_user_id=admin.id,
        actor_role=admin.role,
        target_type="document",
        target_id=document_id,
        detail="admin deleted document",
        request_id=request_id,
        ip_address=client_ip,
    )
    db.commit()

    knowledge_service.delete_document(db, settings, document)
    log_event(logger, "admin_document_deleted", admin_id=admin.id, document_id=document_id)
    return {"message": "The document and its index entries were deleted.", "chunks": None}


@router.get("/audit", response_model=AuditListOut)
def list_audit_log(
    db: DbDep,
    admin: CurrentAdmin,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    action: str | None = Query(default=None, max_length=60),
) -> dict[str, object]:
    """Read-only view of the append-only audit trail."""
    del admin
    items = system_repo.list_audit(db, limit=limit, offset=offset, action=action)
    return {
        "items": [
            AuditEntryOut(
                id=row.id,
                action=row.action,
                actor_user_id=row.actor_user_id,
                actor_role=row.actor_role,
                target_type=row.target_type,
                target_id=row.target_id,
                detail=row.detail,
                request_id=row.request_id,
                ip_address=row.ip_address,
                created_at=iso(row.created_at) or "",
            ).model_dump()
            for row in items
        ],
        "page": PageMeta(
            total=system_repo.count_audit(db, action=action),
            limit=limit,
            offset=offset,
        ).model_dump(),
    }


__all__ = ["router"]
