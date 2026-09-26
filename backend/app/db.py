"""Database engine, session factory and SQLite hardening.

SQLite runs with ``PRAGMA foreign_keys=ON`` and WAL journaling. Every request
gets its own session which is always closed; multi-step writes use an explicit
transaction that rolls back on failure.
"""

from __future__ import annotations

import logging
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import Settings

logger = logging.getLogger("app.db")


class Base(DeclarativeBase):
    """Declarative base for every ORM model."""


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _configure_sqlite_connection(dbapi_connection: Any, _record: Any) -> None:
    """Per-connection PRAGMAs. Applied to every pooled connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        # WAL is a no-op (and harmless) for in-memory databases.
        cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


def init_engine(settings: Settings) -> Engine:
    """Create the process-wide engine and session factory."""
    global _engine, _session_factory

    url = settings.database_url_sync
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        # Sessions are used from FastAPI's threadpool: allow cross-thread use and
        # give SQLite a generous lock timeout instead of failing immediately.
        connect_args = {"check_same_thread": False, "timeout": 15.0}

    _engine = create_engine(
        url,
        echo=settings.sql_echo,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    if url.startswith("sqlite"):
        event.listen(_engine, "connect", _configure_sqlite_connection)

    _session_factory = sessionmaker(
        bind=_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        class_=Session,
    )
    logger.debug("database engine initialised")
    return _engine


def get_engine() -> Engine:
    """Return the initialised engine, creating it from settings if necessary."""
    if _engine is None:
        from app.config import get_settings

        return init_engine(get_settings())
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the session factory, creating it from settings if necessary."""
    if _session_factory is None:
        get_engine()
    if _session_factory is None:  # pragma: no cover - init_engine always sets it
        raise RuntimeError("Database session factory could not be initialised")
    return _session_factory


def dispose_engine() -> None:
    """Dispose the engine and reset module state (test teardown)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request-scoped session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for background jobs and scripts."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_database() -> bool:
    """Return True when the database answers a trivial query."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # pragma: no cover - environmental failure
        logger.exception("database health check failed")
        return False


def sqlite_supports_fts5() -> bool:
    """Verify FTS5 availability at startup (retrieval depends on it)."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_probe USING fts5(x)"))
            connection.execute(text("DROP TABLE IF EXISTS _fts5_probe"))
            connection.commit()
        return True
    except Exception:  # pragma: no cover - sqlite built without FTS5
        logger.exception("SQLite build has no FTS5 support")
        return False
