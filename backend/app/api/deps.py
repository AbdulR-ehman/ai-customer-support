"""Reusable FastAPI dependencies.

Every protected route depends on :func:`require_user` or :func:`require_admin`;
there is no route that infers privileges from its own path or payload.

Authorisation failures return 404 for other users' resources (never 403) so the
API does not confirm that a foreign resource exists.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.errors import AuthenticationError, NotFoundError, PermissionDeniedError
from app.models.user import ROLE_ADMIN, SessionToken, User
from app.security.csrf import (
    build_csrf_token,
    generate_preauth_nonce,
    preauth_identity,
    session_identity,
)
from app.security.sessions import get_session_by_token, touch_session
from app.services.rate_limit import RateLimiter
from app.utils.network import client_ip as resolve_client_ip


def get_app_settings(request: Request) -> Settings:
    """Return the settings the running app was actually built with.

    The app stores its own settings on ``app.state``. Reading them here (rather
    than re-creating a process-wide ``Settings``) guarantees that dependencies,
    middleware and routes all sign and verify with the *same* secret, which is
    essential for CSRF validation and for tests that inject their own settings.
    """
    app_settings = getattr(request.app.state, "settings", None)
    if isinstance(app_settings, Settings):
        return app_settings
    return get_settings()


DbDep = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_app_settings)]

_limiter: RateLimiter | None = None


def get_limiter(request: Request) -> RateLimiter:
    """Process-wide rate limiter (SQLite-backed counters).

    The limiter is rebuilt whenever the app's settings object changes, so a test
    that injects tight limits really gets those limits.
    """
    global _limiter
    settings = get_app_settings(request)
    if _limiter is None or _limiter.settings is not settings:
        _limiter = RateLimiter(settings)
    return _limiter


LimiterDep = Annotated[RateLimiter, Depends(get_limiter)]


def issue_preauth_csrf(settings: Settings) -> tuple[str, str]:
    """Create a fresh pre-authentication CSRF pair ``(nonce, token)``.

    The middleware derives the identity as ``preauth_identity(nonce)``, so the
    token must be signed with exactly that same identity string.
    """
    nonce = generate_preauth_nonce()
    token = build_csrf_token(settings.resolved_secret_key, preauth_identity(nonce))
    return nonce, token


def csrf_token_for_session(settings: Settings, session_cookie_value: str) -> str:
    """The CSRF token bound to an existing session cookie."""
    return build_csrf_token(settings.resolved_secret_key, session_identity(session_cookie_value))


def get_current_user(
    request: Request, db: DbDep, settings: SettingsDep
) -> tuple[User, SessionToken | None]:
    """Resolve the authenticated user from the session cookie, or raise 401."""
    raw_token = request.cookies.get(settings.cookie_name)
    if not raw_token:
        raise AuthenticationError()
    session = get_session_by_token(db, raw_token)
    if session is None or not session.is_active:
        raise AuthenticationError()
    from app.models.base import utcnow

    if session.expires_at is not None and session.expires_at <= utcnow():
        raise AuthenticationError()
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError()
    touch_session(db, session)
    db.commit()
    return user, session


CurrentUserDep = Annotated[tuple[User, SessionToken | None], Depends(get_current_user)]


def require_user(request: Request, current: CurrentUserDep) -> User:
    """Any authenticated user."""
    user, _session = current
    return user


def require_admin(current: CurrentUserDep) -> User:
    """Authenticated administrators only (enforced server-side)."""
    user, _session = current
    if user.role != ROLE_ADMIN:
        raise PermissionDeniedError()
    return user


def session_token(request: Request, settings: SettingsDep) -> str | None:
    """The raw session cookie value (needed to bind the CSRF token)."""
    return request.cookies.get(settings.cookie_name)


CurrentUser = Annotated[User, Depends(require_user)]
CurrentAdmin = Annotated[User, Depends(require_admin)]
SessionCookieDep = Annotated[str | None, Depends(session_token)]


def get_request_meta(request: Request, settings: SettingsDep) -> tuple[str | None, str | None]:
    """``(request_id, client_ip)`` for audit records and logging."""
    from app.middleware.request_context import current_request_id

    return current_request_id(), resolve_client_ip(request, settings)


RequestMetaDep = Annotated[tuple[str | None, str | None], Depends(get_request_meta)]


def require_found(resource: object | None) -> object:
    """Raise a non-leaking 404 when an owner-scoped lookup misses."""
    if resource is None:
        raise NotFoundError()
    return resource


__all__ = [
    "CurrentAdmin",
    "CurrentUser",
    "CurrentUserDep",
    "DbDep",
    "LimiterDep",
    "RequestMetaDep",
    "SessionCookieDep",
    "SettingsDep",
    "csrf_token_for_session",
    "get_limiter",
    "get_request_meta",
    "issue_preauth_csrf",
    "require_admin",
    "require_found",
    "require_user",
]
