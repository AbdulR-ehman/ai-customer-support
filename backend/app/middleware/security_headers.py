"""Security response headers.

Applied to every response (HTML, JSON, errors alike). The header set follows the
OWASP secure-headers guidance, adapted for an application that renders a
React SPA and never embeds user content as HTML:

* ``Content-Security-Policy`` - strict; no inline or third-party scripts.
* ``X-Content-Type-Options`` - ``nosniff``: uploaded files can never be sniffed
  into an executable type.
* ``X-Frame-Options`` / ``frame-ancestors`` - the app cannot be framed (clickjacking).
* ``Referrer-Policy`` - no referrer leakage to third parties.
* ``Permissions-Policy`` - browser features the app does not need are disabled.
* ``Cache-Control: no-store`` on API responses so authenticated data is not cached.

HSTS is intentionally NOT sent by default: it only makes sense behind HTTPS in
production (see docs/SECURITY.md, "production hardening checklist").
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "worker-src 'self'"
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}

#: Response headers that must never be advertised.
STRIPPED_HEADERS: tuple[str, ...] = ("Server", "X-Powered-By")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add hardening headers and mark API responses as uncacheable."""

    def __init__(self, app: object, *, enabled: bool = True) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._enabled = enabled

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        if self._enabled:
            for header, value in SECURITY_HEADERS.items():
                response.headers.setdefault(header, value)
        for header in STRIPPED_HEADERS:
            if header in response.headers:
                del response.headers[header]
        if request.url.path.startswith("/api") or request.url.path == "/health":
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
        return response
