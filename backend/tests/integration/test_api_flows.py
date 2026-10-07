"""Integration tests: registration, login, chat, history, feedback, admin flows."""

from __future__ import annotations

import uuid

import pytest
from tests.conftest import CUSTOMER_PASSWORD


def test_health_is_minimal_and_public(client: object) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    # No version, path, or configuration detail may leak.
    assert set(response.json()) == {"status"}


def test_registration_then_login_and_logout(client: object, preauth_token: object) -> None:
    email = f"flow-{uuid.uuid4().hex[:10]}@example.test"

    registered = client.post(
        "/api/auth/register",
        json={"email": email, "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert registered.status_code == 201

    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert login.status_code == 200
    body = login.json()
    assert body["user"]["role"] == "customer"
    csrf = body["csrf_token"]

    session = client.get("/api/auth/session")
    assert session.status_code == 200
    assert session.json()["user"]["email"] == email

    logged_out = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logged_out.status_code == 200

    # The session row was revoked, so the old cookie no longer authenticates.
    assert client.get("/api/chat/conversations").status_code == 401


def test_duplicate_registration_is_indistinguishable(client: object, preauth_token: object) -> None:
    """A repeated sign-up must not reveal that the address already exists."""
    email = f"dupe-{uuid.uuid4().hex[:10]}@example.test"

    first = client.post(
        "/api/auth/register",
        json={"email": email, "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert first.status_code == 201

    second = client.post(
        "/api/auth/register",
        json={"email": email, "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert second.status_code == first.status_code
    assert second.json() == first.json()


def test_chat_returns_grounded_answer_with_sources(
    client: object, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/chat/messages",
        json={"question": "What is your refund policy?"},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["grounded"] is True
    assert body["conversation_is_new"] is True
    assert "30 days" in body["assistant_message"]["content"]

    sources = body["assistant_message"]["sources"]
    assert sources, "a grounded answer must cite at least one source"
    assert sources[0]["document_title"]
    assert sources[0]["snippet"]


def test_chat_admits_when_information_is_missing(
    client: object, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/chat/messages",
        json={"question": "What is the Galactic Senate quorum rule for Mars?"},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["grounded"] is False
    assert "enough information" in body["assistant_message"]["content"].lower()
    assert body["assistant_message"]["sources"] == []


def test_conversation_history_survives_a_reload(
    client: object, auth_headers: dict[str, str]
) -> None:
    first = client.post(
        "/api/chat/messages",
        json={"question": "How long does standard shipping take?"},
        headers=auth_headers,
    )
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]

    # A "reload" is a fresh request with the same session cookie.
    listing = client.get("/api/chat/conversations")
    assert conversation_id in {item["id"] for item in listing.json()}

    detail = client.get(f"/api/chat/conversations/{conversation_id}")
    assert detail.status_code == 200
    messages = detail.json()["messages"]
    assert [m["role"] for m in messages] == ["user", "assistant"]

    # Continuing the same conversation appends to the same history.
    follow_up = client.post(
        "/api/chat/messages",
        json={
            "question": "What are your support hours?",
            "conversation_id": conversation_id,
        },
        headers=auth_headers,
    )
    assert follow_up.status_code == 200, follow_up.text
    assert follow_up.json()["conversation_id"] == conversation_id
    assert follow_up.json()["conversation_is_new"] is False

    after = client.get(f"/api/chat/conversations/{conversation_id}")
    assert len(after.json()["messages"]) == 4


def test_feedback_is_saved_and_can_be_updated(client: object, auth_headers: dict[str, str]) -> None:
    chat = client.post(
        "/api/chat/messages",
        json={"question": "What is your refund policy?"},
        headers=auth_headers,
    )
    assert chat.status_code == 200, chat.text
    message_id = chat.json()["assistant_message"]["id"]

    first = client.put(
        f"/api/chat/messages/{message_id}/feedback",
        json={"rating": "up"},
        headers=auth_headers,
    )
    assert first.status_code == 200
    assert first.json() == {"rating": "up", "comment": None}

    updated = client.put(
        f"/api/chat/messages/{message_id}/feedback",
        json={"rating": "down", "comment": "Not what I asked."},
        headers=auth_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["rating"] == "down"

    detail = client.get(f"/api/chat/conversations/{chat.json()['conversation_id']}")
    assert detail.json()["messages"][1]["feedback"]["rating"] == "down"


def test_customer_can_delete_own_conversation(client: object, auth_headers: dict[str, str]) -> None:
    chat = client.post(
        "/api/chat/messages",
        json={"question": "What is your refund policy?"},
        headers=auth_headers,
    )
    conversation_id = chat.json()["conversation_id"]

    deleted = client.request(
        "DELETE", f"/api/chat/conversations/{conversation_id}", headers=auth_headers
    )
    assert deleted.status_code == 204
    assert client.get(f"/api/chat/conversations/{conversation_id}").status_code == 404


def test_account_deletion_removes_the_session(
    client: object, customer: dict[str, str], auth_headers: dict[str, str]
) -> None:
    response = client.request("DELETE", "/api/auth/account", headers=auth_headers)
    assert response.status_code == 200
    assert client.get("/api/chat/conversations").status_code == 401


@pytest.mark.parametrize("question", ["", "   "])
def test_blank_questions_are_rejected(
    client: object, auth_headers: dict[str, str], question: str
) -> None:
    response = client.post("/api/chat/messages", json={"question": question}, headers=auth_headers)
    assert response.status_code in {422, 400}


def test_admin_can_upload_reindex_and_delete_a_document(
    client: object, admin_headers: dict[str, str]
) -> None:
    upload = client.post(
        "/api/admin/documents",
        files={
            "file": (
                "returns-policy.md",
                b"# Returns\n\nReturns are accepted within 21 days of delivery.\n",
                "text/markdown",
            )
        },
        headers=admin_headers,
    )
    assert upload.status_code == 201, upload.text
    payload = upload.json()
    assert payload["created"] is True
    assert payload["chunk_count"] >= 1
    document_id = payload["document"]["id"]

    reindexed = client.post(f"/api/admin/documents/{document_id}/reindex", headers=admin_headers)
    assert reindexed.status_code == 200
    assert reindexed.json()["chunks"] == payload["chunk_count"]

    deleted = client.request("DELETE", f"/api/admin/documents/{document_id}", headers=admin_headers)
    assert deleted.status_code == 200
    assert client.get(f"/api/admin/documents/{document_id}").status_code == 404


def test_duplicate_upload_is_deduplicated(client: object, admin_headers: dict[str, str]) -> None:
    body = b"# Duplicate\n\nThe duplicate window is 5 business days.\n"

    first = client.post(
        "/api/admin/documents",
        files={"file": ("dup.md", body, "text/markdown")},
        headers=admin_headers,
    )
    assert first.status_code == 201
    assert first.json()["created"] is True

    second = client.post(
        "/api/admin/documents",
        files={"file": ("different-name.md", body, "text/markdown")},
        headers=admin_headers,
    )
    assert second.status_code == 201
    assert second.json()["created"] is False
    assert second.json()["document"]["id"] == first.json()["document"]["id"]


def test_admin_dashboard_and_audit_log(client: object, admin_headers: dict[str, str]) -> None:
    stats = client.get("/api/admin/stats")
    assert stats.status_code == 200, stats.text
    body = stats.json()
    assert body["users"] >= 1
    assert body["knowledge"]["documents"] >= 1

    audit = client.get("/api/admin/audit?limit=20")
    assert audit.status_code == 200
    assert isinstance(audit.json()["items"], list)


def test_password_change_invalidates_other_sessions(
    client: object, customer: dict[str, str], preauth_token: object
) -> None:
    """Changing the password revokes every other session, including old cookies."""
    # Session A is the one created by the ``customer`` fixture. Keep its raw
    # cookie so it can be replayed after the password change.
    session_a = client.cookies.get("acme_session")
    assert session_a

    # Sign out and back in to create session B (a "second browser").
    logout = client.post("/api/auth/logout", headers={"X-CSRF-Token": customer["csrf"]})
    assert logout.status_code == 200
    client.cookies.clear()

    login = client.post(
        "/api/auth/login",
        json={"email": customer["email"], "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert login.status_code == 200, login.text
    session_b_csrf = login.json()["csrf_token"]
    session_b = client.cookies.get("acme_session")
    assert session_b and session_b != session_a

    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": CUSTOMER_PASSWORD,
            "new_password": "Cobalt-Meridian-Quill-6620",
        },
        headers={"X-CSRF-Token": session_b_csrf},
    )
    assert changed.status_code == 200, changed.text

    # Session B (the one that changed the password) stays signed in.
    assert client.get("/api/chat/conversations").status_code == 200

    # Session A is revoked server-side, so replaying its cookie fails.
    client.cookies.clear()
    client.cookies.set("acme_session", session_a)
    assert client.get("/api/chat/conversations").status_code == 401

    # The old password no longer works; the new one does.
    client.cookies.clear()
    stale = client.post(
        "/api/auth/login",
        json={"email": customer["email"], "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert stale.status_code == 401

    with_new = client.post(
        "/api/auth/login",
        json={"email": customer["email"], "password": "Cobalt-Meridian-Quill-6620"},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert with_new.status_code == 200


def test_login_lockout_after_repeated_failures(
    client: object, preauth_token: object, settings: object
) -> None:
    email = f"lock-{uuid.uuid4().hex[:10]}@example.test"
    client.post(
        "/api/auth/register",
        json={"email": email, "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )

    for _ in range(settings.login_max_failed_attempts + 1):
        response = client.post(
            "/api/auth/login",
            json={"email": email, "password": "Wrong-Password-Value-11"},
            headers={"X-CSRF-Token": preauth_token()},
        )
        assert response.status_code == 401

    # The correct password is refused while locked, with an identical error.
    locked = client.post(
        "/api/auth/login",
        json={"email": email, "password": CUSTOMER_PASSWORD},
        headers={"X-CSRF-Token": preauth_token()},
    )
    assert locked.status_code == 401
    assert "incorrect" in locked.json()["error"]["message"].lower()
