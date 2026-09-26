"""CSRF enforcement middleware.

Every state-changing request (POST/PUT/PATCH/DELETE) must carry a valid
``X-CSRF-Token`` header:

* authenticated requests are bound to the session cookie value (which is
  HttpOnly, so a cross-site script cannot read it);
* pre-authentication requests (login/registration) are bound to a random
  ``acme_csrf`` cookie issued by ``GET /api/auth/csrf``.

Validation is a constant-time HMAC comparison, needs no database access, and
rejects unsafe methods that arrive without any CSRF context at all.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import Settings
from app.errors import error_envelope
from app.security.csrf import (
    CSRF_COOKIE_NAME,
    UNSAFE_METHODS,
    preauth_identity,
    session_identity,
    validate_csrf_token,
)

logger = logging.getLogger("app.csrf")

CSRF_ERROR_MESSAGE = (
    "Your security token is missing or expired. Please refresh the page and try again."
)


class CsrfMiddleware(BaseHTTPMiddleware):
    """Reject unsafe requests that fail double-submit validation."""

    def __init__(self, app: object, *, settings: Settings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._settings = settings

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method.upper() not in UNSAFE_METHODS:
            return await call_next(request)

        settings = self._settings
        session_cookie = request.cookies.get(settings.cookie_name)
        if session_cookie:
            identity = session_identity(session_cookie)
        else:
            nonce = request.cookies.get(CSRF_COOKIE_NAME)
            if not nonce:
                return self._reject(request, reason="no_csrf_context")
            identity = preauth_identity(nonce)

        provided = request.headers.get(settings.csrf_header_name)
        if not validate_csrf_token(settings.resolved_secret_key, identity, provided):
            return self._reject(request, reason="invalid_token")

        return await call_next(request)

    def _reject(self, request: Request, *, reason: str) -> JSONResponse:
        logger.warning(
            "csrf_rejected path=%s method=%s reason=%s",
            request.url.path,
            request.method,
            reason,
        )
        response = JSONResponse(
            status_code=403,
            content=error_envelope("csrf_failed", CSRF_ERROR_MESSAGE),
        )
        response.headers["Cache-Control"] = "no-store"
        return response
