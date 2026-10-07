"""Shared pytest fixtures.

Every test runs against an isolated temporary SQLite database and with outbound
network access blocked, so an accidental external call fails the suite instead
of silently reaching the internet.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

CUSTOMER_PASSWORD = "Lantern-Meadow-Quartz-8821"
ADMIN_PASSWORD = "Harbour-Violet-Cinder-5507"

#: Knowledge seeded into the test index so chat answers can be grounded.
SEED_DOCUMENTS: dict[str, bytes] = {
    "refund-policy.md": (
        b"# Acme Support Refund Policy\n\n"
        b"Acme Support accepts refunds within 30 days of purchase. "
        b"Refunds are issued to the original payment method.\n\n"
        b"Acme Support does not offer refunds after the 30 day window.\n"
    ),
    "shipping.txt": (
        b"Acme Support Shipping\n\n"
        b"Standard Acme Support shipping takes 3 to 5 business days. "
        b"Express shipping takes 1 to 2 business days.\n"
    ),
    "support-hours.md": (
        b"Acme Support hours\n\n"
        b"Acme Support standard support hours are Monday to Friday, "
        b"09:00 to 18:00 US Eastern Time.\n"
    ),
}


class NetworkBlockedError(RuntimeError):
    """Raised when a test tries to open a real network connection."""


@pytest.fixture(autouse=True, scope="session")
def block_outbound_network() -> Iterator[None]:
    """Fail any test that attempts a real outbound connection.

    ``AI_PROVIDER=mock`` must never call out, so this turns a silent regression
    into a loud test failure. Loopback and ``socketpair`` are allowed because
    asyncio creates an internal self-pipe through them; only connections that
    would leave the machine are blocked.
    """
    real_socket = socket.socket
    real_create_connection = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo

    def _is_local(address: object) -> bool:
        """True when the address stays on this machine (or has no host)."""
        if not isinstance(address, tuple) or not address:
            return True
        host = address[0]
        if not isinstance(host, str) or not host:
            return True
        if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}:
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            # A hostname other than localhost is treated as external.
            return False

    def _blocked(*args: object, **kwargs: object) -> None:
        raise NetworkBlockedError(
            "Outbound network access is blocked in tests; mock mode must be offline."
        )

    def guarded_connect(self: object, address: object) -> None:
        if _is_local(address):
            return real_socket.connect(self, address)  # type: ignore[arg-type]
        _blocked()

    def guarded_connect_ex(self: object, address: object) -> int:
        if _is_local(address):
            return real_socket.connect_ex(self, address)  # type: ignore[arg-type]
        _blocked()

    class _GuardedSocket(real_socket):  # type: ignore[misc, valid-type]
        connect = guarded_connect
        connect_ex = guarded_connect_ex

    socket.socket = _GuardedSocket  # type: ignore[assignment]

    def guarded_create_connection(address: object, *args: object, **kwargs: object) -> object:
        if not _is_local(address):
            _blocked()
        return real_create_connection(address, *args, **kwargs)  # type: ignore[arg-type]

    def guarded_getaddrinfo(host: object, port: object, *args: object, **kwargs: object) -> object:
        if not _is_local((host, port)):
            _blocked()
        return real_getaddrinfo(host, port, *args, **kwargs)  # type: ignore[arg-type]

    socket.create_connection = guarded_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket = real_socket  # type: ignore[assignment]
        socket.create_connection = real_create_connection  # type: ignore[assignment]
        socket.getaddrinfo = real_getaddrinfo  # type: ignore[assignment]


@pytest.fixture(scope="session")
def settings(tmp_path_factory: pytest.TempPathFactory) -> Iterator[object]:
    """Session settings bound to a temporary database and upload directory."""
    from app.config import Settings

    base = tmp_path_factory.mktemp("acme-test")
    config = Settings(
        app_env="test",
        ai_provider="mock",
        database_url=f"sqlite:///{(base / 'test.db').as_posix()}",
        upload_dir=str(base / "uploads"),
        log_dir=str(base / "logs"),
        secret_key="test-only-secret-key-0123456789-abcdefghij",
        # The session database is shared by every test, so fixed-window counters
        # would otherwise accumulate and throttle unrelated later tests. Rate
        # limiting is exercised explicitly, on an isolated database, in the
        # security suite; a single feature toggle keeps the default suite clean.
        rate_limit_enabled=False,
    )
    config.ensure_runtime_dirs()
    yield config


@pytest.fixture(scope="session", autouse=True)
def prepared_database(settings: object) -> Iterator[None]:
    """Create the schema, FTS index and seed documents once per session."""
    from app.db import dispose_engine, session_scope
    from app.main import create_schema
    from app.services import knowledge as knowledge_service

    create_schema(settings)
    with session_scope() as db:
        for filename, data in SEED_DOCUMENTS.items():
            content_type = "text/markdown" if filename.endswith(".md") else "text/plain"
            knowledge_service.ingest_bytes(
                db,
                settings,
                raw_filename=filename,
                content_type=content_type,
                data=data,
                uploaded_by=None,
            )

    yield

    # Leave no open handles behind for the coverage/reporting step.
    dispose_engine()


@pytest.fixture
def db(settings: object) -> Iterator[object]:
    """A request-style database session bound to the test database."""
    from app.db import get_session_factory

    session = get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client(settings: object) -> Iterator[object]:
    """A TestClient with the app lifespan running (schema is already created)."""
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def preauth_token(client: object) -> object:
    """Return a callable that issues a fresh pre-authentication CSRF token.

    Every pre-authentication response rotates the nonce cookie, so a test that
    performs several pre-auth POSTs must fetch a new token before each one.
    """

    def issue() -> str:
        return client.get("/api/auth/csrf").json()["csrf_token"]

    return issue


def _unique_email(prefix: str) -> str:
    """A per-test unique address (tests share one session-scoped database)."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}@example.test"


def _create_user(
    email: str,
    password: str,
    role: str,
) -> str:
    from app.db import session_scope
    from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER
    from app.repositories import users as users_repo
    from app.security.passwords import hash_password

    with session_scope() as db:
        user = users_repo.create_user(
            db,
            email=email,
            password_hash=hash_password(password),
            role=ROLE_ADMIN if role == "admin" else ROLE_CUSTOMER,
            display_name=f"Test {role.title()}",
        )
        return user.id


@pytest.fixture
def customer(client: object, preauth_token: object) -> dict[str, str]:
    """A registered + signed-in customer, with an authenticated CSRF header."""
    email = _unique_email("customer")
    password = CUSTOMER_PASSWORD
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert response.status_code == 201, response.text

    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert login.status_code == 200, login.text
    return {
        "id": login.json()["user"]["id"],
        "email": email,
        "password": password,
        "csrf": login.json()["csrf_token"],
    }


@pytest.fixture
def auth_headers(customer: dict[str, str]) -> dict[str, str]:
    """Authenticated CSRF header for the signed-in customer."""
    return {"X-CSRF-Token": customer["csrf"]}


@pytest.fixture
def admin(client: object, preauth_token: object) -> dict[str, str]:
    """A signed-in administrator account.

    Cookies are cleared first so the login happens in a genuine pre-authentication
    context: with an existing session cookie the CSRF middleware binds tokens to
    that session instead of the pre-auth nonce, and a pre-auth token is rejected.
    """
    email = _unique_email("admin")
    password = ADMIN_PASSWORD
    _create_user(email, password, role="admin")

    client.cookies.clear()
    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert login.status_code == 200, login.text
    return {
        "id": login.json()["user"]["id"],
        "email": email,
        "password": password,
        "csrf": login.json()["csrf_token"],
    }


@pytest.fixture
def admin_headers(admin: dict[str, str]) -> dict[str, str]:
    """Authenticated CSRF header for the signed-in administrator."""
    return {"X-CSRF-Token": admin["csrf"]}


@pytest.fixture
def second_client(settings: object) -> Iterator[object]:
    """A second, independent TestClient (its own cookie jar).

    One client can only hold one signed-in identity, so a test that needs both a
    customer and an administrator uses a second client rather than re-logging in
    and losing the first session.
    """
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(settings)) as other:
        yield other


def _sign_in(client: object, email: str, password: str) -> tuple[str, str]:
    """Register (if needed), sign in, and return ``(csrf_token, session_cookie)``."""
    client.cookies.clear()
    token = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"], client.cookies.get("acme_session") or ""


@pytest.fixture
def customer_on(client: object, second_client: object) -> dict[str, str]:
    """A signed-in customer on the *second* client (leaves ``client`` free)."""
    email = _unique_email("alt-customer")
    _create_user(email, CUSTOMER_PASSWORD, role="customer")
    csrf, _session = _sign_in(second_client, email, CUSTOMER_PASSWORD)
    return {"id": "", "email": email, "password": CUSTOMER_PASSWORD, "csrf": csrf}


@pytest.fixture
def other_customer(client: object) -> dict[str, str]:
    """Credentials for a second, independent customer (IDOR tests).

    The account is created directly in the database and is **not** signed in:
    the TestClient keeps one cookie jar, so a test must call ``login_as`` to
    become this user and thereby become a different owner than the original.
    """
    email = _unique_email("other")
    user_id = _create_user(email, CUSTOMER_PASSWORD, role="customer")
    return {"id": user_id, "email": email, "password": CUSTOMER_PASSWORD}
