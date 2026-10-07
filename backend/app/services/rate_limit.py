"""Rate limiting and abuse protection.

Named scopes map to environment-configurable limits. Identities (user ids, IP
addresses) are hashed before they are used in a counter key, so the rate-limit
table does not accumulate raw IP addresses.

Every rejection raises :class:`app.errors.RateLimitedError`, which produces HTTP
429 with a ``Retry-After`` header and a friendly, non-leaking message.
"""

from __future__ import annotations

import hashlib
import logging

from sqlalchemy.orm import Session

from app.config import Settings
from app.errors import RateLimitedError
from app.logging_config import log_event
from app.repositories import system as system_repo
from app.repositories.system import RateLimitOutcome

logger = logging.getLogger("app.rate_limit")

MINUTE = 60
HOUR = 3600
DAY = 86400


def _identity_key(scope: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"{scope}:{digest}"


class RateLimiter:
    """Small facade over the counter table with named scopes."""

    def __init__(self, settings: Settings) -> None:
        #: Kept public so callers can detect a settings change and rebuild.
        self.settings = settings

    @property
    def _settings(self) -> Settings:
        return self.settings

    # ------------------------------------------------------------- primitives
    def consume(
        self, db: Session, *, scope: str, identity: str, limit: int, window_seconds: int
    ) -> RateLimitOutcome:
        if not self._settings.rate_limit_enabled:
            return RateLimitOutcome(
                allowed=True,
                count=0,
                limit=limit,
                remaining=limit,
                retry_after=0,
                window_seconds=window_seconds,
            )
        return system_repo.rate_limit_hit(
            db,
            key=_identity_key(scope, identity),
            limit=limit,
            window_seconds=window_seconds,
        )

    def enforce(
        self,
        db: Session,
        *,
        scope: str,
        identity: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitOutcome:
        outcome = self.consume(
            db, scope=scope, identity=identity, limit=limit, window_seconds=window_seconds
        )
        if not outcome.allowed:
            log_event(
                logger,
                "rate_limit_blocked",
                scope=scope,
                limit=limit,
                window_seconds=window_seconds,
                window="user" if scope.endswith(":user") else "identity",
            )
            raise RateLimitedError(outcome.retry_after, scope=scope)
        return outcome

    # ------------------------------------------------------------------ scopes
    def enforce_chat(self, db: Session, *, user_id: str, client_ip: str | None) -> None:
        """Chat is limited per user (short and daily window) and per IP."""
        s = self._settings
        self.enforce(
            db,
            scope="chat:user:minute",
            identity=user_id,
            limit=s.rate_limit_chat_per_minute,
            window_seconds=MINUTE,
        )
        self.enforce(
            db,
            scope="chat:user:day",
            identity=user_id,
            limit=s.rate_limit_chat_per_day,
            window_seconds=DAY,
        )
        if client_ip:
            self.enforce(
                db,
                scope="chat:ip:minute",
                identity=client_ip,
                limit=max(1, s.rate_limit_chat_per_minute * 3),
                window_seconds=MINUTE,
            )

    def enforce_login(self, db: Session, *, client_ip: str | None, email: str) -> None:
        s = self._settings
        if client_ip:
            self.enforce(
                db,
                scope="login:ip:minute",
                identity=client_ip,
                limit=s.rate_limit_login_per_minute,
                window_seconds=MINUTE,
            )
        self.enforce(
            db,
            scope="login:account:minute",
            identity=email.strip().lower(),
            limit=s.rate_limit_login_per_minute,
            window_seconds=MINUTE,
        )

    def enforce_register(self, db: Session, *, client_ip: str | None) -> None:
        s = self._settings
        if client_ip:
            self.enforce(
                db,
                scope="register:ip:hour",
                identity=client_ip,
                limit=s.rate_limit_register_per_hour,
                window_seconds=HOUR,
            )

    def enforce_upload(self, db: Session, *, user_id: str) -> None:
        self.enforce(
            db,
            scope="upload:user:hour",
            identity=user_id,
            limit=self._settings.rate_limit_upload_per_hour,
            window_seconds=HOUR,
        )

    def enforce_admin_write(self, db: Session, *, user_id: str, scope: str) -> None:
        self.enforce(
            db,
            scope=f"admin:{scope}:user:hour",
            identity=user_id,
            limit=self._settings.rate_limit_upload_per_hour,
            window_seconds=HOUR,
        )

    def enforce_global(self, db: Session, *, identity: str) -> None:
        self.enforce(
            db,
            scope="global:identity:minute",
            identity=identity,
            limit=self._settings.rate_limit_global_per_minute,
            window_seconds=MINUTE,
        )

    def enforce_password_change(self, db: Session, *, user_id: str) -> None:
        self.enforce(
            db,
            scope="password:user:hour",
            identity=user_id,
            limit=self._settings.rate_limit_login_per_minute,
            window_seconds=HOUR,
        )
