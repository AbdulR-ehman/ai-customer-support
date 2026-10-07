"""CSRF protection: signed double-submit token.

The browser sends the token in :data:`CSRF_HEADER` (``X-CSRF-Token``) while the
identity half stays in a cookie the attacker's origin cannot read:

* authenticated request -> identity is the **HttpOnly** session cookie value;
* pre-authentication (login/register) -> identity is a random ``acme_csrf``
  cookie issued by ``GET /api/auth/csrf``.

The token is ``HMAC-SHA256(secret, "csrf:v1:<identity>")`` encoded URL-safe, so
it is stateless, cannot be forged without the server secret, and needs no
database lookup during validation. Comparison is constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

CSRF_COOKIE_NAME = "acme_csrf"
CSRF_HEADER = "X-CSRF-Token"
_PREFIX = "csrf:v1:"
PREAUTH_IDENTITY = "preauth"

#: Methods that require a CSRF token.
UNSAFE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def generate_preauth_nonce() -> str:
    """Random nonce stored in the non-HttpOnly pre-auth CSRF cookie."""
    return secrets.token_urlsafe(24)


def _sign(secret: str, identity: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), f"{_PREFIX}{identity}".encode(), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def build_csrf_token(secret: str, identity: str) -> str:
    """Build the token for an identity (session cookie value or pre-auth nonce)."""
    return _sign(secret, identity)


def session_identity(session_cookie_value: str) -> str:
    return f"session:{session_cookie_value}"


def preauth_identity(nonce: str) -> str:
    return f"{PREAUTH_IDENTITY}:{nonce}"


def validate_csrf_token(secret: str, identity: str, provided: str | None) -> bool:
    """Constant-time validation of a submitted CSRF token."""
    if not provided or len(provided) > 512:
        return False
    expected = _sign(secret, identity)
    return hmac.compare_digest(expected, provided.strip())
