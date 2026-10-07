"""Request correlation and access logging middleware.

Every request gets a validated request id (from the ``X-Request-ID`` header when
the client supplies a safe one, otherwise a fresh UUID). The id is bound to the
logging context, returned to the client, and included in every log line emitted
while handling the request.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.logging_config import get_request_id, set_log_user, set_request_id

logger = logging.getLogger("app.request")

REQUEST_ID_HEADER = "X-Request-ID"
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

#: Paths that are too noisy / low value to log at INFO on every hit.
QUIET_PATHS: frozenset[str] = frozenset({"/health", "/favicon.ico"})


def _clean_request_id(value: str | None) -> str:
    """Accept only short, safe request ids; otherwise generate a new one."""
    if value and _SAFE_REQUEST_ID_RE.match(value):
        return value
    return uuid.uuid4().hex


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind a request id and log one structured line per request."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = _clean_request_id(request.headers.get(REQUEST_ID_HEADER))
        set_request_id(request_id)
        set_log_user(None)
        request.state.request_id = request_id
        started = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.perf_counter() - started) * 1000)
            logger.exception(
                "request_failed",
                extra={
                    "event": "request_failed",
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                },
            )
            raise

        duration_ms = int((time.perf_counter() - started) * 1000)
        response.headers[REQUEST_ID_HEADER] = request_id
        if request.url.path not in QUIET_PATHS:
            logger.info(
                "request",
                extra={
                    "event": "request",
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client": _client_hint(request),
                },
            )
        return response


def _client_hint(request: Request) -> str:
    """Coarse client marker for logs (never a full IP in the message body)."""
    forwarded = request.client.host if request.client else "-"
    return forwarded


def current_request_id() -> str:
    """Convenience re-export used by routers and services."""
    return get_request_id()
