"""Authentication, session and account routes.

All state-changing requests are protected by :class:`CsrfMiddleware`; this router
only issues and consumes the tokens. Login and registration return the same
generic errors for unknown accounts, wrong passwords and locked accounts so the
API never confirms whether an email exists.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app.api.deps import (
    CurrentUserDep,
    DbDep,
    LimiterDep,
    RequestMetaDep,
    SessionCookieDep,
    SettingsDep,
    csrf_token_for_session,
    issue_preauth_csrf,
)
from app.api.serializers import user_out
from app.schemas.auth import (
    AuthResponse,
    ChangePasswordRequest,
    CsrfResponse,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    RegisterResponse,
)
from app.security.cookies import (
    clear_csrf_cookie,
    clear_session_cookie,
    set_csrf_cookie,
    set_session_cookie,
)
from app.services import auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

#: Public (unauthenticated) auth routes, used by the route-protection audit test.
PUBLIC_AUTH_PATHS: frozenset[str] = frozenset(
    {"/api/auth/register", "/api/auth/login", "/api/auth/csrf"}
)

#: Returned verbatim whether or not the address was actually created, so
#: registration cannot be used to discover which emails are registered.
GENERIC_SIGNUP_MESSAGE = (
    "If that address can be registered, it now has an account. Sign in to continue."
)


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(
    payload: RegisterRequest,
    response: Response,
    db: DbDep,
    settings: SettingsDep,
    limiter: LimiterDep,
    meta: RequestMetaDep,
) -> RegisterResponse:
    """Create a customer account. The role is never accepted from the client."""
    request_id, client_ip = meta
    limiter.enforce_register(db, client_ip=client_ip)
    limiter.enforce_global(db, identity=client_ip or "anonymous")

    auth_service.register_user(
        db,
        settings,
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
        request_id=request_id,
        client_ip=client_ip,
    )
    db.commit()

    # Issue a pre-auth CSRF pair so the client can immediately sign in.
    nonce, _token = issue_preauth_csrf(settings)
    set_csrf_cookie(response, settings, nonce)
    # A brand-new account and a duplicate signup get byte-identical responses
    # (same status, same body) so this endpoint cannot be used to enumerate
    # which email addresses are already registered.
    return RegisterResponse(message=GENERIC_SIGNUP_MESSAGE)


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbDep,
    settings: SettingsDep,
    limiter: LimiterDep,
    meta: RequestMetaDep,
) -> AuthResponse:
    """Verify credentials and start a server-side session."""
    request_id, client_ip = meta
    limiter.enforce_login(db, client_ip=client_ip, email=payload.email)
    limiter.enforce_global(db, identity=client_ip or "anonymous")

    result = auth_service.authenticate(
        db,
        settings,
        email=payload.email,
        password=payload.password,
        request_id=request_id,
        client_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()

    set_session_cookie(response, settings, result.session_token)
    # The authenticated CSRF identity is derived from the HttpOnly session cookie.
    token = csrf_token_for_session(settings, result.session_token)
    return AuthResponse(user=user_out(result.user), message="Signed in.", csrf_token=token)


@router.get("/csrf", response_model=CsrfResponse)
def csrf(response: Response, settings: SettingsDep) -> CsrfResponse:
    """Issue a pre-authentication CSRF nonce cookie and its signed token."""
    nonce, token = issue_preauth_csrf(settings)
    set_csrf_cookie(response, settings, nonce)
    return CsrfResponse(csrf_token=token)


@router.get("/session", response_model=AuthResponse)
def current_session(
    current: CurrentUserDep,
    settings: SettingsDep,
    session_cookie: SessionCookieDep,
) -> AuthResponse:
    """Return the signed-in user and a fresh session-bound CSRF token."""
    user, _session = current
    token = csrf_token_for_session(settings, session_cookie) if session_cookie else ""
    return AuthResponse(user=user_out(user), message=None, csrf_token=token)


@router.post("/logout", response_model=MessageResponse)
def logout_route(
    response: Response,
    db: DbDep,
    settings: SettingsDep,
    current: CurrentUserDep,
    session_cookie: SessionCookieDep,
    meta: RequestMetaDep,
) -> MessageResponse:
    """Revoke the server-side session and clear both cookies."""
    user, _session = current
    request_id, client_ip = meta
    auth_service.logout(
        db,
        session_token=session_cookie,
        user=user,
        request_id=request_id,
        client_ip=client_ip,
    )
    db.commit()
    clear_session_cookie(response, settings)
    clear_csrf_cookie(response, settings)
    return MessageResponse(message="You have been signed out.")


@router.post("/password", response_model=MessageResponse)
def change_password_route(
    payload: ChangePasswordRequest,
    db: DbDep,
    settings: SettingsDep,
    current: CurrentUserDep,
    limiter: LimiterDep,
    meta: RequestMetaDep,
) -> MessageResponse:
    """Change the password; every other session is revoked immediately."""
    user, session = current
    request_id, client_ip = meta
    limiter.enforce_password_change(db, user_id=user.id)
    limiter.enforce_global(db, identity=user.id)

    auth_service.change_password(
        db,
        settings,
        user=user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        keep_session_id=session.id if session is not None else None,
        request_id=request_id,
        client_ip=client_ip,
    )
    db.commit()
    return MessageResponse(message="Your password was updated and other sessions were signed out.")


@router.delete("/account", response_model=MessageResponse)
def delete_account_route(
    response: Response,
    db: DbDep,
    settings: SettingsDep,
    current: CurrentUserDep,
    meta: RequestMetaDep,
) -> MessageResponse:
    """Delete the account and cascade its conversations and sessions."""
    user, _session = current
    request_id, client_ip = meta
    auth_service.delete_account(db, user=user, request_id=request_id, client_ip=client_ip)
    db.commit()
    clear_session_cookie(response, settings)
    clear_csrf_cookie(response, settings)
    return MessageResponse(message="Your account and its data have been deleted.")


__all__ = ["GENERIC_SIGNUP_MESSAGE", "PUBLIC_AUTH_PATHS", "router"]
