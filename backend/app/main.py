"""FastAPI application factory and ASGI entry point.

Startup order matters:

1. validate configuration (Pydantic Settings refuses unsafe/placeholder values);
2. configure structured, redacting logging;
3. create runtime directories and the database engine;
4. create the schema and the FTS5 index;
5. verify the configured AI provider is the supported offline mock.

Middleware is added bottom-up so the outermost layer is the security headers.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.ai.factory import build_provider
from app.api.routers import admin, auth, chat, health
from app.config import Settings, get_settings
from app.db import dispose_engine, init_engine
from app.errors import install_exception_handlers
from app.knowledge import indexing
from app.logging_config import configure_logging, log_event
from app.middleware.body_limit import BodySizeLimitMiddleware
from app.middleware.csrf import CsrfMiddleware
from app.middleware.request_context import RequestContextMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

# Importing the models package registers every mapper before create_all runs.
from app.models import Document, DocumentChunk  # noqa: F401  (mapper registration)
from app.models.base import Base

logger = logging.getLogger("app.main")

#: Routes reachable without a session. The route-protection test asserts that
#: every registered route is either here or carries an auth dependency.
PUBLIC_ROUTES: frozenset[str] = frozenset(
    {
        "/health",
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/csrf",
    }
)


def create_schema(settings: Settings) -> None:
    """Create tables and the FTS5 index for a fresh database."""

    engine = init_engine(settings)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        indexing.ensure_fts_table(connection)
        indexing.optimize_index(connection)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Validate configuration, prepare storage and log a masked startup summary."""
    settings: Settings = app.state.settings
    app_logger = configure_logging(settings)
    settings.ensure_runtime_dirs()
    create_schema(settings)
    provider = build_provider(settings)

    log_event(
        app_logger,
        "application_started",
        environment=settings.app_env,
        ai_provider=provider.name,
        host=settings.host,
        port=settings.port,
        docs_enabled=settings.docs_enabled,
        database_kind="sqlite" if settings.database_url_sync.startswith("sqlite") else "other",
        allowed_origin_count=len(settings.allowed_origins_list),
    )
    try:
        yield
    finally:
        log_event(app_logger, "application_stopping")
        dispose_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Exposed so tests can construct isolated instances."""
    active = settings or get_settings()
    app = FastAPI(
        title=active.app_name,
        version="1.0.0",
        lifespan=lifespan,
        # Docs/OpenAPI are development-only (section 19 of the requirements).
        docs_url="/docs" if active.docs_enabled else None,
        redoc_url="/redoc" if active.docs_enabled else None,
        openapi_url="/openapi.json" if active.docs_enabled else None,
    )
    app.state.settings = active

    install_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(chat.router)
    app.include_router(admin.router)

    # Middleware is applied in reverse: the last added runs first.
    app.add_middleware(SecurityHeadersMiddleware, enabled=active.security_headers_enabled)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=active.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", active.csrf_header_name, "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=active.allowed_hosts_list)
    app.add_middleware(CsrfMiddleware, settings=active)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=active.max_request_body_bytes)
    app.add_middleware(RequestContextMiddleware)

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover - manual invocation
    import uvicorn

    _settings = get_settings()
    # Loopback only: this app is never intended to be exposed directly.
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=_settings.port,
        reload=False,
        log_config=None,
    )
