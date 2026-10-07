"""ORM models for Acme Support AI.

Import order matters: importing :mod:`app.models.user` first means every module
that references ``User`` (and the modules ``User`` references by string name) is
registered in the SQLAlchemy class registry before mappers are configured.
"""

from app.models.audit import AuditLog
from app.models.conversation import (
    RATING_DOWN,
    RATING_UP,
    RATINGS,
    ROLE_ASSISTANT,
    ROLE_USER,
    Conversation,
    Feedback,
    Message,
    MessageSource,
)
from app.models.document import (
    ALLOWED_EXTENSIONS,
    DOCUMENT_STATUSES,
    SOURCE_SEED,
    SOURCE_UPLOAD,
    STATUS_FAILED,
    STATUS_INDEXED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    Document,
    DocumentChunk,
    DocumentIngestionEvent,
)
from app.models.rate_limit import RateLimitCounter
from app.models.user import (
    ROLE_ADMIN,
    ROLE_CUSTOMER,
    ROLES,
    LoginAttempt,
    SessionToken,
    User,
)

__all__ = [
    "ALLOWED_EXTENSIONS",
    "DOCUMENT_STATUSES",
    "RATINGS",
    "RATING_DOWN",
    "RATING_UP",
    "ROLES",
    "ROLE_ADMIN",
    "ROLE_ASSISTANT",
    "ROLE_CUSTOMER",
    "ROLE_USER",
    "SOURCE_SEED",
    "SOURCE_UPLOAD",
    "STATUS_FAILED",
    "STATUS_INDEXED",
    "STATUS_PENDING",
    "STATUS_PROCESSING",
    "AuditLog",
    "Conversation",
    "Document",
    "DocumentChunk",
    "DocumentIngestionEvent",
    "Feedback",
    "LoginAttempt",
    "Message",
    "MessageSource",
    "RateLimitCounter",
    "SessionToken",
    "User",
]
