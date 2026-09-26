"""Authentication and account schemas."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator

from app.schemas.base import RequestModel, ResponseModel

#: Deliberately conservative address check; normalization happens server-side.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
MAX_EMAIL_LENGTH = 254
MAX_NAME_LENGTH = 80


class RegisterRequest(RequestModel):
    email: str = Field(min_length=3, max_length=MAX_EMAIL_LENGTH)
    password: str = Field(min_length=1, max_length=128)
    display_name: str | None = Field(default=None, max_length=MAX_NAME_LENGTH)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, value: str) -> str:
        candidate = value.strip()
        if not EMAIL_RE.match(candidate):
            raise ValueError("Enter a valid email address.")
        return candidate.lower()

    @field_validator("display_name", mode="before")
    @classmethod
    def _empty_name_to_none(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return value


class LoginRequest(RequestModel):
    email: str = Field(min_length=3, max_length=MAX_EMAIL_LENGTH)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, value: str) -> str:
        candidate = value.strip()
        if not EMAIL_RE.match(candidate):
            # Same generic behaviour as a bad address: no enumeration hints.
            raise ValueError("Enter a valid email address.")
        return candidate.lower()


class ChangePasswordRequest(RequestModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class UserOut(ResponseModel):
    id: str
    email: str
    display_name: str | None = None
    role: Literal["customer", "admin"]
    created_at: str | None = None


class AuthResponse(ResponseModel):
    user: UserOut
    message: str | None = None
    csrf_token: str


class RegisterResponse(ResponseModel):
    message: str


class MessageResponse(ResponseModel):
    message: str


class CsrfResponse(ResponseModel):
    csrf_token: str
