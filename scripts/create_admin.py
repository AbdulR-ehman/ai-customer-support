"""Create the first Acme Support administrator.

The password is never hard-coded and never has a default. It is read either
interactively with :func:`getpass` or from the ``ACME_ADMIN_PASSWORD``
environment variable (useful for CI). The password is hashed with Argon2id
immediately and is never printed, logged, or stored in plain text.

Usage (from the project root):
    .\\.venv\\Scripts\\python.exe scripts\\create_admin.py --email admin@example.com
    $env:ACME_ADMIN_PASSWORD = "..."; .\\.venv\\Scripts\\python.exe scripts\\create_admin.py --email admin@example.com
"""

from __future__ import annotations

import argparse
import getpass
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import get_settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.errors import InvalidInputError  # noqa: E402
from app.main import create_schema  # noqa: E402
from app.models.user import ROLE_ADMIN  # noqa: E402
from app.repositories import users as users_repo  # noqa: E402
from app.security.passwords import (  # noqa: E402
    enforce_password_policy,
    hash_password,
)

PASSWORD_ENV_VAR = "ACME_ADMIN_PASSWORD"


def read_password(settings: object) -> str:
    """Get the password from the environment or an interactive prompt."""
    from_env = os.environ.get(PASSWORD_ENV_VAR, "")
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        raise SystemExit(
            "No terminal available for the password prompt. Set the "
            f"{PASSWORD_ENV_VAR} environment variable instead."
        )
    first = getpass.getpass("Admin password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise SystemExit("The passwords did not match.")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or update an Acme Support administrator account."
    )
    parser.add_argument("--email", required=True, help="Admin email address (created if missing).")
    parser.add_argument(
        "--promote-existing",
        action="store_true",
        help=(
            "If the account already exists, promote it to admin and reset its "
            "password instead of refusing."
        ),
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    create_schema(settings)

    normalized = users_repo.normalize_email(args.email)
    password = read_password(settings)
    try:
        # The same policy customers face; no admin exemption.
        enforce_password_policy(
            password,
            min_length=settings.password_min_length,
            max_length=settings.password_max_length,
            email=normalized,
        )
    except InvalidInputError as exc:
        print(f"Password rejected: {exc}", file=sys.stderr)
        return 2

    password_hash = hash_password(password)
    # Drop the plaintext as early as possible.
    del password

    with session_scope() as db:
        existing = users_repo.get_user_by_email(db, normalized)
        if existing is not None:
            if not args.promote_existing:
                print(
                    "An account with that address already exists. Re-run with "
                    "--promote-existing to promote it and reset its password.",
                    file=sys.stderr,
                )
                return 3
            existing.role = ROLE_ADMIN
            existing.is_active = True
            users_repo.set_password(db, existing, password_hash)
            action = "promoted"
            user_id = existing.id
        else:
            user = users_repo.create_user(
                db,
                email=normalized,
                password_hash=password_hash,
                role=ROLE_ADMIN,
                display_name="Acme Support Admin",
            )
            action = "created"
            user_id = user.id

    print(f"Administrator {action}: {normalized} (id {user_id})")
    print("Sign in at the login page with that address and your new password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
