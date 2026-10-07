"""Liveness endpoint.

The response body is intentionally minimal: only a status word. It never exposes a
version, filesystem path, database URL, or any other configuration detail.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.schemas.base import ResponseModel

router = APIRouter(tags=["health"])


class HealthOut(ResponseModel):
    """Public health payload - no version, no paths, no configuration."""

    status: str


@router.get("/health", response_model=HealthOut)
def health() -> dict[str, str]:
    return {"status": "ok"}


__all__ = ["router"]
