"""Application configuration.

All runtime configuration is read from environment variables (optionally via a
project-root ``.env`` file) and validated by Pydantic v2. Invalid or unsafe
configuration aborts startup with a clear message instead of failing later.

Nothing in this module may ever log a secret value.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> backend/app -> backend -> <project root>
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
ENV_FILE: Path = PROJECT_ROOT / ".env"

DEV_LIKE_ENVS: frozenset[str] = frozenset({"development", "dev", "local", "test", "testing"})

# Values that must never be accepted as a real secret outside development.
PLACEHOLDER_SECRETS: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "change_me",
        "secret",
        "secret-key",
        "your-secret-key",
        "placeholder",
        "test",
        "dev",
        "password",
    }
)

# The only supported AI provider. See docs/SECURITY.md and the README.
SUPPORTED_AI_PROVIDERS: frozenset[str] = frozenset({"mock"})


class Settings(BaseSettings):
    """Validated application settings."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ app
    app_name: str = "Acme Support AI"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    # ----------------------------------------------------------- ai provider
    ai_provider: str = "mock"

    # ------------------------------------------------------------- database
    database_url: str = "sqlite:///./storage/app.db"
    sql_echo: bool = False

    # ------------------------------------------------------------- security
    secret_key: str = ""
    canary_token: str = ""
    allowed_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    allowed_hosts: str = "127.0.0.1,localhost,testserver"
    trusted_proxies: str = ""
    enable_docs_in_dev: bool = True
    security_headers_enabled: bool = True

    # --------------------------------------------------- sessions / cookies
    session_expire_minutes: int = Field(default=120, ge=5, le=60 * 24 * 30)
    cookie_name: str = "acme_session"
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    csrf_header_name: str = "X-CSRF-Token"

    # ------------------------------------------------------------- passwords
    password_min_length: int = Field(default=10, ge=10, le=64)
    password_max_length: int = Field(default=128, ge=64, le=1024)
    login_max_failed_attempts: int = Field(default=5, ge=3, le=50)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)

    # -------------------------------------------------------- knowledge base
    upload_dir: str = "storage/uploads"
    max_upload_mb: int = Field(default=5, ge=1, le=100)
    max_pdf_pages: int = Field(default=200, ge=1, le=5000)
    max_extracted_chars: int = Field(default=500_000, ge=1_000, le=10_000_000)
    max_documents: int = Field(default=200, ge=1, le=100_000)
    chunk_size_chars: int = Field(default=1000, ge=200, le=8000)
    chunk_overlap_chars: int = Field(default=150, ge=0, le=4000)
    processing_mode: str = "threadpool"

    # -------------------------------------------------------------- retrieval
    retrieval_top_k: int = Field(default=5, ge=1, le=50)
    retrieval_min_score: float = Field(default=0.05, ge=0.0, le=1.0)
    max_context_chars: int = Field(default=6000, ge=500, le=100_000)
    retrieval_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    # ----------------------------------------------------------- ai behaviour
    max_message_chars: int = Field(default=2000, ge=50, le=20_000)
    max_response_chars: int = Field(default=4000, ge=200, le=40_000)
    max_history_messages: int = Field(default=10, ge=0, le=100)
    max_conversations_per_user: int = Field(default=100, ge=1, le=10_000)
    max_messages_per_conversation: int = Field(default=200, ge=2, le=10_000)
    max_concurrent_ai: int = Field(default=4, ge=1, le=100)
    ai_timeout_seconds: float = Field(default=10.0, gt=0, le=120)

    # ---------------------------------------------------------- rate limiting
    rate_limit_enabled: bool = True
    rate_limit_chat_per_minute: int = Field(default=15, ge=1, le=10_000)
    rate_limit_chat_per_day: int = Field(default=300, ge=1, le=100_000)
    rate_limit_login_per_minute: int = Field(default=10, ge=1, le=10_000)
    rate_limit_register_per_hour: int = Field(default=10, ge=1, le=10_000)
    rate_limit_upload_per_hour: int = Field(default=30, ge=1, le=10_000)
    rate_limit_global_per_minute: int = Field(default=600, ge=1, le=1_000_000)
    #: Must stay >= max_upload_bytes: multipart framing adds overhead. The
    #: upload handler still enforces the exact per-file limit while streaming.
    max_request_body_bytes: int = Field(default=6 * 1024 * 1024, ge=4096, le=100 * 1024 * 1024)

    # ---------------------------------------------------- privacy / retention
    feedback_comment_max_chars: int = Field(default=1000, ge=10, le=5000)
    retention_days: int = Field(default=0, ge=0, le=3650)

    # --------------------------------------------------------------- logging
    log_level: str = "INFO"
    log_dir: str = "logs"
    log_file_max_bytes: int = Field(default=5 * 1024 * 1024, ge=64 * 1024)
    log_backup_count: int = Field(default=3, ge=1, le=50)
    log_json: bool = True

    # ----------------------------------------------------------- validators
    @field_validator("app_env", "log_level", "upload_dir", "log_dir", mode="before")
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("cookie_samesite", mode="before")
    @classmethod
    def _validate_samesite(cls, value: object) -> object:
        """Normalise COOKIE_SAMESITE; an unknown value aborts startup."""
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized not in {"lax", "strict", "none"}:
                raise ValueError("COOKIE_SAMESITE must be one of: lax, strict, none")
            return normalized
        return value

    @field_validator("processing_mode")
    @classmethod
    def _validate_processing_mode(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"threadpool", "inline"}:
            raise ValueError("PROCESSING_MODE must be one of: threadpool, inline")
        return normalized

    @field_validator("ai_provider")
    @classmethod
    def _validate_ai_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in SUPPORTED_AI_PROVIDERS:
            supported = ", ".join(sorted(SUPPORTED_AI_PROVIDERS))
            raise ValueError(
                f"Unsupported AI_PROVIDER {value!r}: this project is zero-cost and offline, "
                f"so the only supported provider is: {supported}."
            )
        return normalized

    @field_validator("secret_key")
    @classmethod
    def _strip_secret(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _validate_consistency(self) -> Settings:
        if self.chunk_overlap_chars >= self.chunk_size_chars:
            raise ValueError("CHUNK_OVERLAP_CHARS must be smaller than CHUNK_SIZE_CHARS")
        if self.max_context_chars < self.chunk_size_chars:
            raise ValueError("MAX_CONTEXT_CHARS must be >= CHUNK_SIZE_CHARS")
        if self.max_request_body_bytes < self.max_upload_bytes:
            raise ValueError(
                "MAX_REQUEST_BODY_BYTES must be >= MAX_UPLOAD_MB (multipart encoding adds overhead)"
            )
        if "*" in self.allowed_origins_list:
            raise ValueError("ALLOWED_ORIGINS must not contain '*' because cookies are sent")
        if self.cookie_samesite == "none" and not self.cookie_secure:
            raise ValueError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true")
        if not self.is_dev:
            if self.secret_key.lower() in PLACEHOLDER_SECRETS or len(self.secret_key) < 32:
                raise ValueError(
                    "SECRET_KEY is missing, a placeholder, or shorter than 32 characters. "
                    "Non-development environments must supply a strong secret. Generate one "
                    "with: python scripts/generate_secret.py"
                )
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE must be true outside development (HTTPS only)")
        return self

    # --------------------------------------------------------------- derived
    @property
    def is_dev(self) -> bool:
        """True when running in a development-like environment."""
        return self.app_env.strip().lower() in DEV_LIKE_ENVS

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are development-only."""
        return self.is_dev and self.enable_docs_in_dev

    @property
    def allowed_origins_list(self) -> list[str]:
        return _split_csv(self.allowed_origins)

    @property
    def allowed_hosts_list(self) -> list[str]:
        return _split_csv(self.allowed_hosts) or ["127.0.0.1", "localhost"]

    @property
    def trusted_proxies_list(self) -> list[str]:
        return _split_csv(self.trusted_proxies)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def upload_dir_path(self) -> Path:
        return self._resolve(self.upload_dir)

    @property
    def log_dir_path(self) -> Path:
        return self._resolve(self.log_dir)

    @property
    def database_url_sync(self) -> str:
        """Absolute SQLAlchemy URL (relative SQLite paths resolved to the root)."""
        url = self.database_url.strip()
        prefix = "sqlite:///"
        if url.startswith(prefix):
            raw_path = url[len(prefix) :]
            if raw_path.startswith("./"):
                raw_path = raw_path[2:]
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = PROJECT_ROOT / candidate
            return f"{prefix}{candidate.as_posix()}"
        return url

    @property
    def resolved_secret_key(self) -> str:
        """The effective secret; a random one is generated in dev when missing."""
        if self.secret_key:
            return self.secret_key
        cached = getattr(self, "_ephemeral_secret", None)
        if cached is None:
            cached = secrets.token_urlsafe(48)
            object.__setattr__(self, "_ephemeral_secret", cached)
        return str(cached)

    @property
    def resolved_canary_token(self) -> str:
        """Canary planted in the system prompt to detect prompt leakage.

        Generated once per process when CANARY_TOKEN is not configured, so it is
        unique in production and never a real secret.
        """
        if self.canary_token:
            return self.canary_token
        cached = getattr(self, "_ephemeral_canary", None)
        if cached is None:
            cached = f"CANARY-{secrets.token_hex(16)}"
            object.__setattr__(self, "_ephemeral_canary", cached)
        return str(cached)

    def _resolve(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else PROJECT_ROOT / path

    def ensure_runtime_dirs(self) -> None:
        """Create runtime directories (never served directly by the app)."""
        for directory in (self.upload_dir_path, self.log_dir_path, PROJECT_ROOT / "storage"):
            directory.mkdir(parents=True, exist_ok=True)

    def safe_summary(self) -> dict[str, object]:
        """Config summary that is safe to log: secret values are masked."""
        return {
            "app_env": self.app_env,
            "ai_provider": self.ai_provider,
            "database_url": self.database_url_sync,
            "allowed_origins": self.allowed_origins_list,
            "allowed_hosts": self.allowed_hosts_list,
            "trust_forwarded_for": bool(self.trusted_proxies_list),
            "docs_enabled": self.docs_enabled,
            "cookie_secure": self.cookie_secure,
            "rate_limit_enabled": self.rate_limit_enabled,
            "max_upload_mb": self.max_upload_mb,
            "max_message_chars": self.max_message_chars,
            "secret_key": "<set>" if self.secret_key else "<generated-ephemeral>",
            "canary_token": "<set>" if self.canary_token else "<generated-ephemeral>",
        }


def _split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached process-wide settings object."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the settings cache (used by tests after changing the environment)."""
    get_settings.cache_clear()
