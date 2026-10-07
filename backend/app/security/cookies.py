"""Cookie helpers.

Session cookies are HttpOnly + SameSite so JavaScript can never read the session
token, and ``COOKIE_SECURE`` is configurable because plain-HTTP localhost
development cannot set the Secure flag.

The CSRF cookie holds only the *identity half* of the double-submit token (a
random nonce); the token itself is returned in the response body of
``GET /api/auth/csrf`` and echoed back through the ``X-CSRF-Token`` header.
"""

from __future__ import annotations

from fastapi import Response

from app.config import Settings
from app.security.csrf import CSRF_COOKIE_NAME


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    """Attach the session cookie to a response."""
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=settings.session_expire_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    """Expire the session cookie immediately (logout)."""
    response.delete_cookie(
        key=settings.cookie_name,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


def set_csrf_cookie(response: Response, settings: Settings, nonce: str) -> None:
    """Store the pre-authentication CSRF nonce."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=nonce,
        max_age=settings.session_expire_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_csrf_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )
