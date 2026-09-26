"""Dump the exact bytes of the security headers returned by the app.

Useful when a header looks correct in the terminal but fails a strict equality
check (a homoglyph or a stray character is invisible in normal output).

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\dump_response_headers.py
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

BASE = pathlib.Path(tempfile.mkdtemp(prefix="acme-hdr-"))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.db import dispose_engine  # noqa: E402
from app.main import create_app, create_schema  # noqa: E402

INTERESTING = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
)


def main() -> int:
    settings = Settings(
        app_env="test",
        ai_provider="mock",
        database_url=f"sqlite:///{(BASE / 'hdr.db').as_posix()}",
        upload_dir=str(BASE / "uploads"),
        log_dir=str(BASE / "logs"),
        secret_key="header-dump-test-secret-0123456789-abcd",
    )
    settings.ensure_runtime_dirs()
    dispose_engine()
    create_schema(settings)

    with TestClient(create_app(settings)) as client:
        response = client.get("/health")

    print(f"status: {response.status_code}")
    for name, value in response.headers.items():
        if name.lower() in INTERESTING:
            escaped = "".join(ch if 32 <= ord(ch) < 127 else f"\\x{ord(ch):02x}" for ch in value)
            print(f"{name}: {escaped}")
    dispose_engine()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
