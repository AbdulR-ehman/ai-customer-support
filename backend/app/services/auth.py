"""Authentication service: registration, login, sessions and password changes.

Anti-enumeration design
-----------------------
* Login failures (unknown email, wrong password, locked account, disabled
  account) all return the *same* generic error, and the unknown-email path still
  performs a dummy Argon2 verification so response timing matches.
* Registration is "soft": an email that already exists produces the same status
  code and response shape as a successful sign-up, and the password is hashed
  either way, so the endpoint cannot be used to test whether an address is
  registered. Real account creation is still audited.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import NoReturn

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.errors import AuthenticationError, InvalidInputError
from app.logging_config import log_event
from app.models.audit import (
    AUDIT_USER_DELETE,
    AUDIT_USER_LOCKOUT,
    AUDIT_USER_LOGIN,
    AUDIT_USER_LOGIN_FAILED,
    AUDIT_USER_PASSWORD_CHANGE,
    AUDIT_USER_REGISTER,
)
from app.models.user import ROLE_CUSTOMER, SessionToken, User
from app.repositories import system as system_repo
from app.repositories import users as users_repo
from app.security import sessions as session_service
from app.security.passwords import (
    dummy_verify,
    enforce_password_policy,
    hash_password,
    verify_password,
)

logger = logging.getLogger("app.auth")

GENERIC_LOGIN_ERROR = "The email address or password is incorrect."
GENERIC_REGISTER_MESSAGE = (
    "If that email address is available, your Acme account has been created. "
    "You can now sign in. If you already had an account, please sign in instead."
)
ACCOUNT_DISABLED_ERROR = "This account is not available."


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Successful authentication."""

    user: User
    session_token: str
    session: SessionToken


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    """Registration outcome (``created`` is intentionally not exposed to clients)."""

    created: bool
    user: User | None
    message: str = GENERIC_REGISTER_MESSAGE


def register_user(
    db: Session,
    settings: Settings,
    *,
    email: str,
    password: str,
    display_name: str | None = None,
    request_id: str | None = None,
    client_ip: str | None = None,
) -> RegistrationResult:
    """Create a customer account.

    The role is hard-coded to ``customer``: it is never taken from client input,
    which is what makes privilege escalation by mass assignment impossible.
    """
    normalized = users_repo.normalize_email(email)
    enforce_password_policy(
        password,
        min_length=settings.password_min_length,
        max_length=settings.password_max_length,
        email=normalized,
        display_name=display_name,
    )

    # Always hash: identical work on both branches keeps response timing comparable.
    password_hash = hash_password(password)

    existing = users_repo.get_user_by_email(db, normalized)
    if existing is not None:
        log_event(logger, "registration_soft_duplicate", account="existing")
        system_repo.record_audit(
            db,
            action=AUDIT_USER_REGISTER,
            actor_user_id=existing.id,
            actor_role=existing.role,
            target_type="user",
            target_id=existing.id,
            detail="duplicate registration attempt ignored",
            request_id=request_id,
            ip_address=client_ip,
        )
        return RegistrationResult(created=False, user=None)

    try:
        user = users_repo.create_user(
            db,
            email=normalized,
            password_hash=password_hash,
            role=ROLE_CUSTOMER,
            display_name=display_name,
        )
    except IntegrityError:
        # Concurrent duplicate sign-up: behave exactly like the soft-duplicate path.
        db.rollback()
        return RegistrationResult(created=False, user=None)

    system_repo.record_audit(
        db,
        action=AUDIT_USER_REGISTER,
        actor_user_id=user.id,
        actor_role=user.role,
        target_type="user",
        target_id=user.id,
        detail="customer account created",
        request_id=request_id,
        ip_address=client_ip,
    )
    log_event(logger, "user_registered", user_id=user.id)
    return RegistrationResult(created=True, user=user)


def _record_failure(
    db: Session,
    *,
    email: str,
    client_ip: str | None,
    action: str = "generic",
    user: User | None = None,
    detail: str = "invalid credentials",
) -> NoReturn:
    """Persist failure bookkeeping, then raise the generic login error.

    The counters, the lockout and the audit entry must survive the 401. Raising
    without committing would roll them back, which silently disables
    brute-force protection, so the transaction is committed here explicitly.
    """
    users_repo.record_login_attempt(
        db, email=email, ip_address=client_ip, success=False, reason=action
    )
    system_repo.record_audit(
        db,
        action=action if action.startswith("user.") else AUDIT_USER_LOGIN_FAILED,
        actor_user_id=user.id if user is not None else None,
        actor_role=user.role if user is not None else None,
        target_type="user",
        target_id=user.id if user is not None else None,
        detail=detail,
        ip_address=client_ip,
    )
    db.commit()
    raise AuthenticationError(GENERIC_LOGIN_ERROR)


def authenticate(
    db: Session,
    settings: Settings,
    *,
    email: str,
    password: str,
    request_id: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> LoginResult:
    """Verify credentials and start a new session, or raise the generic error."""
    normalized = users_repo.normalize_email(email)
    user = users_repo.get_user_by_email(db, normalized)

    if user is None:
        dummy_verify(password)
        log_event(logger, "login_failed", reason="unknown_account")
        _record_failure(
            db,
            email=normalized,
            client_ip=client_ip,
            action="unknown_account",
            detail="login attempt for an unknown address",
        )

    if user.is_locked:
        log_event(logger, "login_failed", reason="locked", user_id=user.id)
        _record_failure(
            db,
            email=normalized,
            client_ip=client_ip,
            action="locked",
            user=user,
            detail="login attempt while the account was locked",
        )

    if not user.is_active:
        dummy_verify(password)
        log_event(logger, "login_failed", reason="inactive", user_id=user.id)
        _record_failure(
            db,
            email=normalized,
            client_ip=client_ip,
            action="inactive",
            user=user,
            detail="login attempt on a disabled account",
        )

    is_valid, replacement = verify_password(password, user.password_hash)
    if not is_valid:
        locked = users_repo.register_failed_login(
            db,
            user,
            max_attempts=settings.login_max_failed_attempts,
            lockout_minutes=settings.login_lockout_minutes,
        )
        log_event(
            logger,
            "login_failed",
            reason="bad_password_locked" if locked else "bad_password",
            user_id=user.id,
        )
        _record_failure(
            db,
            email=normalized,
            client_ip=client_ip,
            action=AUDIT_USER_LOCKOUT if locked else AUDIT_USER_LOGIN_FAILED,
            user=user,
            detail=("account locked after repeated failures" if locked else "invalid credentials"),
        )

    if replacement:
        # Transparent upgrade when Argon2 parameters have been strengthened.
        users_repo.set_password(db, user, replacement)

    users_repo.update_last_login(db, user)
    users_repo.record_login_attempt(
        db, email=normalized, ip_address=client_ip, success=True, reason="ok"
    )
    token, session = session_service.create_session(
        db, user, settings, client_ip=client_ip, user_agent=user_agent
    )
    system_repo.record_audit(
        db,
        action=AUDIT_USER_LOGIN,
        actor_user_id=user.id,
        actor_role=user.role,
        target_type="user",
        target_id=user.id,
        detail="login succeeded",
        request_id=request_id,
        ip_address=client_ip,
    )
    log_event(logger, "login_succeeded", user_id=user.id)
    return LoginResult(user=user, session_token=token, session=session)


def logout(
    db: Session,
    *,
    session_token: str | None,
    user: User | None,
    request_id: str | None = None,
    client_ip: str | None = None,
) -> bool:
    """Server-side logout: the session row is revoked, not just the cookie."""
    revoked = session_service.revoke_session_by_token(db, session_token)
    if user is not None:
        system_repo.record_audit(
            db,
            action=AUDIT_USER_LOGIN,
            actor_user_id=user.id,
            actor_role=user.role,
            target_type="session",
            detail="logout",
            request_id=request_id,
            ip_address=client_ip,
        )
    log_event(logger, "logout", revoked=revoked, user_id=user.id if user else "-")
    return revoked


def change_password(
    db: Session,
    settings: Settings,
    *,
    user: User,
    current_password: str,
    new_password: str,
    keep_session_id: str | None = None,
    request_id: str | None = None,
    client_ip: str | None = None,
) -> int:
    """Change a password and invalidate every other session."""
    if not verify_password(current_password, user.password_hash)[0]:
        log_event(logger, "password_change_failed", user_id=user.id)
        raise AuthenticationError("The current password is incorrect.")

    if verify_password(new_password, user.password_hash)[0]:
        raise InvalidInputError("The new password must be different from the current one.")

    enforce_password_policy(
        new_password,
        min_length=settings.password_min_length,
        max_length=settings.password_max_length,
        email=user.email,
        display_name=user.display_name,
    )
    users_repo.set_password(db, user, hash_password(new_password))
    revoked = session_service.revoke_all_user_sessions(
        db, user.id, except_session_id=keep_session_id
    )
    system_repo.record_audit(
        db,
        action=AUDIT_USER_PASSWORD_CHANGE,
        actor_user_id=user.id,
        actor_role=user.role,
        target_type="user",
        target_id=user.id,
        detail=f"password changed; {revoked} other session(s) revoked",
        request_id=request_id,
        ip_address=client_ip,
    )
    log_event(logger, "password_changed", user_id=user.id, revoked_sessions=revoked)
    return revoked


def delete_account(
    db: Session,
    *,
    user: User,
    request_id: str | None = None,
    client_ip: str | None = None,
) -> None:
    """Delete the account and cascade its conversations, messages and sessions."""
    user_id = user.id
    session_service.revoke_all_user_sessions(db, user_id)
    system_repo.record_audit(
        db,
        action=AUDIT_USER_DELETE,
        actor_role=user.role,
        target_type="user",
        target_id=user_id,
        detail="self-service account deletion",
        request_id=request_id,
        ip_address=client_ip,
    )
    users_repo.delete_user(db, user)
    log_event(logger, "account_deleted", user_id=user_id)
