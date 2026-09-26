"""Structured logging with mandatory secret redaction.

Console output is human readable (``key=value``) or JSON, the rotating file
handler always writes JSON. A redaction filter runs on **every** record so that
passwords, tokens, hashes, cookies and API-key-shaped strings never reach a log
sink, no matter which logger produced them.

Untrusted input (user questions, filenames, document titles...) must be passed
through :func:`sanitize_for_log` before being interpolated into a log message,
which neutralises newlines/control characters and prevents log injection.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import Settings

# --------------------------------------------------------------------------
# Request correlation
# --------------------------------------------------------------------------
_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
_user_id_var: ContextVar[str] = ContextVar("user_id", default="-")


def set_request_id(request_id: str) -> None:
    """Bind the current request id to the logging context."""
    _request_id_var.set(request_id or "-")


def get_request_id() -> str:
    """Return the request id bound to the current context (``-`` when unbound)."""
    return _request_id_var.get()


def set_log_user(user_id: str | None) -> None:
    """Bind the acting user id (never an email or a name) to the log context."""
    _user_id_var.set(user_id or "-")


def get_log_user() -> str:
    return _user_id_var.get()


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------
_REDACTION = "<redacted>"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # key: value / key=value / "key": "value" for sensitive key names
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|secret_key|token|access_token|refresh_token"
        r"|api[_-]?key|apikey|authorization|auth|cookie|set-cookie|session|session_id"
        r"|csrf[_-]?token|canary[_-]?token)\b(\"?\s*[:=]\s*\"?)([^\s\"',;)}\]]+)"
    ),
    # argon2 / bcrypt / scrypt hashes
    re.compile(r"\$(argon2(?:id|i|d)?|2[aby]|scrypt)\$[^\s\"']+"),
    # provider-style API keys
    re.compile(r"\b(?:sk|pk|rk|ghp|xox[baprs])[-_][A-Za-z0-9_\-]{12,}\b"),
    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"),
    # Bearer / Basic credentials
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"),
    # secrets embedded in URLs
    re.compile(r"(?i)([?&](?:token|key|secret|password|sig|signature)=)[^&\s]+"),
)


def redact_text(text: str) -> str:
    """Mask anything that looks like a credential inside ``text``."""
    if not text:
        return text
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups == 3:
            redacted = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTION}", redacted)
        elif pattern.groups == 2 or pattern.groups == 1:
            redacted = pattern.sub(lambda m: f"{m.group(1)}{_REDACTION}", redacted)
        else:
            redacted = pattern.sub(_REDACTION, redacted)
    return redacted


def sanitize_for_log(value: object, max_length: int = 300) -> str:
    """Make untrusted text safe to embed in a log line.

    Removes newlines/tabs/control characters (log-injection defence), redacts
    credentials, and truncates to ``max_length`` characters.
    """
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    text = redact_text(text)
    if len(text) > max_length:
        return f"{text[:max_length]}...(truncated)"
    return text


class RedactionFilter(logging.Filter):
    """Rewrites every record so that secrets cannot leave the process."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive, never break logging
            return True
        redacted = redact_text(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


_RESERVED_ATTRS: frozenset[str] = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()
) | {"message", "asctime", "taskName", "structured"}


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    """Return the non-standard ``extra=`` fields attached to a record."""
    extras: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _RESERVED_ATTRS or key.startswith("_"):
            continue
        extras[key] = redact_text(value) if isinstance(value, str) else value
    return extras


class JsonFormatter(logging.Formatter):
    """One JSON object per line - the format used by the rotating log file."""

    def __init__(self, service: str = "acme-support-ai") -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "service": self._service,
            "request_id": get_request_id(),
            "user_id": get_log_user(),
            "module": record.module,
            "line": record.lineno,
            "msg": redact_text(record.getMessage()),
        }
        payload.update(_extras(record))
        if record.exc_info and record.exc_info[0] is not None:
            payload["error"] = redact_text(f"{record.exc_info[0].__name__}: {record.exc_info[1]}")
            if record.levelno <= logging.DEBUG:
                payload["traceback"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=False)


class KeyValueFormatter(logging.Formatter):
    """Compact ``key=value`` console format for humans."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, tz=UTC).strftime("%H:%M:%S")
        parts = [
            stamp,
            f"{record.levelname:<8}",
            record.name,
            f"[{get_request_id()}]",
            redact_text(record.getMessage()),
        ]
        for key, value in _extras(record).items():
            rendered = sanitize_for_log(value, max_length=200)
            if " " in rendered:
                rendered = f'"{rendered}"'
            parts.append(f"{key}={rendered}")
        line = " ".join(parts)
        if record.exc_info and record.exc_info[0] is not None:
            line += "\n" + redact_text(self.formatException(record.exc_info))
        return line


def configure_logging(settings: Settings) -> logging.Logger:
    """Configure root logging. Idempotent: safe to call repeatedly in tests."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    level = getattr(logging, settings.log_level.strip().upper(), logging.INFO)
    root.setLevel(level)

    console = logging.StreamHandler(stream=sys.stderr)
    console.setFormatter(
        JsonFormatter(settings.app_name) if settings.log_json else KeyValueFormatter()
    )
    console.addFilter(RedactionFilter())
    root.addHandler(console)

    try:
        settings.log_dir_path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            Path(settings.log_dir_path) / "app.log",
            maxBytes=settings.log_file_max_bytes,
            backupCount=settings.log_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(JsonFormatter(settings.app_name))
        file_handler.addFilter(RedactionFilter())
        root.addHandler(file_handler)
    except OSError as exc:  # pragma: no cover - unwritable disk is environmental
        root.warning("file logging disabled: %s", sanitize_for_log(exc))

    # Uvicorn installs its own handlers; funnel everything through root instead
    # so that redaction and correlation ids apply uniformly.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("multipart").setLevel(logging.WARNING)

    return logging.getLogger("app")


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Emit a structured, redacted audit-style event."""
    logger.log(level, event, extra={"event": event, **fields})
