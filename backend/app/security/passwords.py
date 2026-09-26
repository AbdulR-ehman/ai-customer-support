"""Password hashing (Argon2id) and password policy enforcement.

Passwords are only ever handled as plain text inside a request and never
persisted, logged, or included in an audit record. Verification uses a fixed
dummy hash for unknown accounts so that login timing does not reveal whether an
email exists (user-enumeration resistance).
"""

from __future__ import annotations

import hmac
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.errors import InvalidInputError

#: OWASP-recommended Argon2id defaults (argon2-cffi: time=3, memory=64 MiB, lanes=4).
_hasher = PasswordHasher()

#: Pre-computed dummy hash used to equalise verification time for unknown users.
_DUMMY_HASH = _hasher.hash("acme-support-dummy-password-value")

#: A small selection of heavily-used passwords. Not a substitute for a breach
#: list, but it stops the obvious ones for a portfolio-scale deployment.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password12",
        "password123",
        "password1234",
        "passw0rd",
        "p@ssw0rd",
        "p@ssword123",
        "1234567890",
        "12345678",
        "123456789",
        "12345678910",
        "qwertyuiop",
        "qwerty123",
        "qwertyuiop123",
        "iloveyou",
        "letmein",
        "letmein123",
        "welcome",
        "welcome1",
        "welcome123",
        "admin",
        "admin123",
        "administrator",
        "root",
        "toor",
        "guest",
        "guest123",
        "changeme",
        "changeme123",
        "secret",
        "secret123",
        "default",
        "temp1234",
        "abcd1234",
        "abcd12345",
        "a1b2c3d4e5",
        "abc123456",
        "qazwsxedc",
        "monkey123",
        "dragon123",
        "football",
        "baseball",
        "superman",
        "batman123",
        "trustno1",
        "master123",
        "sunshine",
        "princess",
        "shadow123",
        "michael123",
        "!qaz2wsx",
        "1qaz2wsx",
        "zaq12wsx",
        "asdfghjkl",
        "asdf1234",
        "zxcvbnm123",
        "1q2w3e4r5t",
        "1q2w3e4r",
        "q1w2e3r4",
        "qwerty12345",
        "password!234",
        "support123",
        "customer123",
        "acme1234",
        "acmesupport",
        "letmeinplease",
        "nopassword",
        "mypassword",
        "mypassword123",
        "securepassword",
        "p@ssword1",
        "hello12345",
        "money12345",
        "freedom123",
        "whatever1",
        "trustme123",
        "test123456",
        "testing123",
        "testtest123",
        "aaaaaaa111",
        "aaaaaaaaaa",
        "0123456789",
        "987654321",
        "1111111111",
        "2222222222",
        "123123123123",
    }
)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Verify ``password`` against ``password_hash``.

    Returns ``(is_valid, replacement_hash)``. ``replacement_hash`` is set when
    the stored hash uses outdated parameters and should be upgraded.
    """
    try:
        _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, None
    if _hasher.check_needs_rehash(password_hash):
        return True, _hasher.hash(password)
    return True, None


def dummy_verify(password: str) -> None:
    """Burn the same time as a real verification (unknown-account path)."""
    try:
        _hasher.verify(_DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return


def password_strength_issues(
    password: str,
    *,
    min_length: int,
    max_length: int,
    email: str | None = None,
    display_name: str | None = None,
) -> list[str]:
    """Return a list of policy violations (empty when the password is fine)."""
    issues: list[str] = []
    normalized = unicodedata.normalize("NFKC", password)

    if len(normalized) < min_length:
        issues.append(f"must be at least {min_length} characters long")
    if len(normalized) > max_length:
        issues.append(f"must be at most {max_length} characters long")
    if normalized.strip() != normalized or not normalized.strip():
        issues.append("must not be empty or padded with whitespace")
    if normalized.lower() in COMMON_PASSWORDS:
        issues.append("is too common and easily guessed")
    if len(set(normalized)) <= 2:
        issues.append("must use a wider variety of characters")

    lowered = normalized.lower()
    if len(lowered) >= min_length and lowered in {
        "abcdefghij",
        "1234567890",
        "qwertyuiop",
        "asdfghjkl;",
    }:
        issues.append("must not be a simple keyboard or numeric sequence")

    if email:
        local_part = email.split("@", 1)[0].strip().lower()
        if len(local_part) >= 4 and local_part in lowered:
            issues.append("must not contain your email address")
        domain = email.split("@", 1)[1].strip().lower() if "@" in email else ""
        if len(domain) >= 6 and domain in lowered:
            issues.append("must not contain your email domain")
    if display_name:
        name = display_name.strip().lower()
        if len(name) >= 4 and name in lowered:
            issues.append("must not contain your name")

    return issues


def enforce_password_policy(
    password: str,
    *,
    min_length: int,
    max_length: int,
    email: str | None = None,
    display_name: str | None = None,
) -> str:
    """Validate and return the password, or raise a client-safe error."""
    issues = password_strength_issues(
        password,
        min_length=min_length,
        max_length=max_length,
        email=email,
        display_name=display_name,
    )
    if issues:
        # The reason describes the policy only; it never echoes the password.
        raise InvalidInputError(
            "The password does not meet the security requirements: " + "; ".join(issues) + ".",
            details=[
                {"field": "password", "code": "weak_password", "message": issue} for issue in issues
            ],
        )
    return password


def constant_time_compare(left: str, right: str) -> bool:
    """Compare two values without leaking timing information."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
