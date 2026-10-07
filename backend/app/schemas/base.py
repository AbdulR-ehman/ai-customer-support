"""Pydantic v2 request/response schemas.

Every request model is strict: ``extra="forbid"`` rejects unknown fields
(mass-assignment protection), lengths are capped, and no schema ever accepts
privilege fields such as ``role``, ``is_admin`` or ``id``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RequestModel(BaseModel):
    """Base for every inbound request body."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ResponseModel(BaseModel):
    """Base for every outbound response body."""

    model_config = ConfigDict(extra="forbid")
