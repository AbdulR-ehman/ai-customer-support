"""Application error types and global exception handlers.

Every error returned to a client uses one stable JSON envelope::

    {"error": {"code": "...", "message": "...", "request_id": "...", "details": [...]}}

Internal details (stack traces, SQL, file paths, library versions, configuration
values) are never included in a response; they stay in the server log correlated
by the request id.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.logging_config import get_request_id, log_event, sanitize_for_log

logger = logging.getLogger("app.errors")

GENERIC_MESSAGE = "An unexpected error occurred. Please try again."


class AppError(Exception):
    """Base class for every deliberate, client-safe application error."""

    status_code: int = 500
    code: str = "internal_error"
    message: str = GENERIC_MESSAGE

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
        details: list[dict[str, Any]] | None = None,
        log_level: int = logging.WARNING,
        log_context: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.headers = dict(headers or {})
        self.details = details or []
        self.log_level = log_level
        self.log_context = dict(log_context or {})
        super().__init__(self.message)


class InvalidInputError(AppError):
    """Malformed or unacceptable input (never echoes internals)."""

    status_code = 422
    code = "invalid_input"
    message = "The submitted data is not valid."


class AuthenticationError(AppError):
    status_code = 401
    code = "unauthenticated"
    message = "Authentication is required."


class PermissionDeniedError(AppError):
    status_code = 403
    code = "forbidden"
    message = "You do not have permission to perform this action."


class NotFoundError(AppError):
    """Also used instead of 403 for another user's resources (anti-IDOR)."""

    status_code = 404
    code = "not_found"
    message = "The requested resource was not found."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    message = "The request conflicts with the current state."


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"
    message = "The submitted content is too large."


class UnsupportedMediaTypeError(AppError):
    status_code = 415
    code = "unsupported_media_type"
    message = "The submitted file type is not supported."


class ContentPolicyError(AppError):
    """Blocked by an input guard (prompt injection, abuse, policy)."""

    status_code = 400
    code = "blocked_content"
    message = "That request cannot be processed."


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"
    message = "Too many requests. Please slow down and try again shortly."

    def __init__(self, retry_after: int, *, scope: str = "global") -> None:
        super().__init__(
            headers={"Retry-After": str(max(1, int(retry_after)))},
            log_level=logging.INFO,
            log_context={"rate_limit_scope": scope, "retry_after": retry_after},
        )


class ServiceUnavailableError(AppError):
    status_code = 503
    code = "service_unavailable"
    message = "The service is temporarily unavailable. Please try again shortly."


class AIProviderError(ServiceUnavailableError):
    code = "ai_provider_error"
    message = "The assistant is temporarily unavailable. Please try again shortly."


class RetrievalError(ServiceUnavailableError):
    code = "retrieval_error"
    message = "Knowledge search is temporarily unavailable. Please try again shortly."


class ConfigurationError(AppError):
    """Unstartable configuration - surfaced at startup, not to end users."""

    status_code = 500
    code = "configuration_error"
    message = "The service is not correctly configured."


# --------------------------------------------------------------------------
# Response envelope
# --------------------------------------------------------------------------
_STATUS_CODES: dict[int, tuple[str, str]] = {
    400: ("bad_request", "The request could not be processed."),
    401: ("unauthenticated", "Authentication is required."),
    403: ("forbidden", "You do not have permission to perform this action."),
    404: ("not_found", "The requested resource was not found."),
    405: ("method_not_allowed", "That HTTP method is not allowed for this endpoint."),
    406: ("not_acceptable", "The requested response format is not available."),
    408: ("timeout", "The request took too long to process."),
    409: ("conflict", "The request conflicts with the current state."),
    413: ("payload_too_large", "The submitted content is too large."),
    415: ("unsupported_media_type", "The submitted file type is not supported."),
    422: ("invalid_input", "The submitted data is not valid."),
    429: ("rate_limited", "Too many requests. Please slow down and try again shortly."),
    500: ("internal_error", GENERIC_MESSAGE),
    501: ("not_implemented", "That capability is not available."),
    503: ("service_unavailable", "The service is temporarily unavailable."),
    504: ("timeout", "The request took too long to process."),
}

MAX_VALIDATION_DETAILS = 20


def error_envelope(
    code: str,
    message: str,
    *,
    details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the single error shape used by every endpoint."""
    body: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "request_id": get_request_id(),
        }
    }
    if details:
        body["error"]["details"] = details
    return body


def _json_error(
    status_code: int,
    code: str,
    message: str,
    *,
    headers: dict[str, str] | None = None,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    response = JSONResponse(
        status_code=status_code,
        content=error_envelope(code, message, details=details),
    )
    response.headers["Cache-Control"] = "no-store"
    for key, value in (headers or {}).items():
        response.headers[key] = value
    return response


def _validation_details(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Report which fields failed and why, without echoing submitted values."""
    details: list[dict[str, Any]] = []
    for error in exc.errors()[:MAX_VALIDATION_DETAILS]:
        location = [
            str(part) for part in error.get("loc", ()) if str(part) not in ("body", "query")
        ]
        details.append(
            {
                "field": ".".join(location) or "request",
                "code": str(error.get("type", "invalid")),
                "message": sanitize_for_log(error.get("msg", "Invalid value"), max_length=200),
            }
        )
    return details


def install_exception_handlers(app: FastAPI) -> None:
    """Register the global handlers."""

    @app.exception_handler(AppError)
    async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        log_event(
            logger,
            "app_error",
            level=exc.log_level,
            error_code=exc.code,
            status=exc.status_code,
            path=request.url.path,
            method=request.method,
            **exc.log_context,
        )
        return _json_error(exc.status_code, exc.code, exc.message, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        log_event(
            logger,
            "request_validation_failed",
            level=logging.INFO,
            status=422,
            path=request.url.path,
            method=request.method,
            issue_count=len(exc.errors()),
        )
        return _json_error(
            422,
            "invalid_input",
            "The submitted data is not valid.",
            details=_validation_details(exc),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, message = _STATUS_CODES.get(
            exc.status_code, ("http_error", "The request could not be completed.")
        )
        if exc.status_code >= 500:
            log_event(
                logger,
                "http_exception",
                level=logging.ERROR,
                status=exc.status_code,
                path=request.url.path,
                method=request.method,
            )
        return _json_error(exc.status_code, code, message)

    @app.exception_handler(TimeoutError)
    async def _handle_timeout(request: Request, exc: TimeoutError) -> JSONResponse:
        log_event(
            logger,
            "request_timeout",
            level=logging.WARNING,
            status=504,
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
        )
        return _json_error(504, "timeout", "The request took too long to process.")

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # The stack trace goes to the server log only, never to the client.
        log_event(
            logger,
            "unhandled_exception",
            level=logging.ERROR,
            status=500,
            path=request.url.path,
            method=request.method,
            error_type=type(exc).__name__,
            error_detail=sanitize_for_log(exc, max_length=200),
        )
        logger.debug("unhandled exception detail", exc_info=exc)
        return _json_error(500, "internal_error", GENERIC_MESSAGE)
