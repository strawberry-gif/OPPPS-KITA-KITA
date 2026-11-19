from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.api


def _unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"


def test_login_returns_bearer_token_and_profile(client, credentials):
    email, password, full_name, role = credentials["admin"]
    response = client.post(
        "/api/auth/login", data={"username": email, "password": password}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    assert payload["access_token"]
    assert payload["expires_in"] > 0
    assert payload["user"]["email"] == email
    assert payload["user"]["role"] == role
    assert payload["user"]["full_name"] == full_name


def test_login_is_case_insensitive_for_email(client, credentials):
    email, password, _, _ = credentials["analyst"]
    response = client.post(
        "/api/auth/login", data={"username": email.upper(), "password": password}
    )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == email


def test_login_rejects_unknown_email(client):
    response = client.post(
        "/api/auth/login",
        data={"username": "nobody@test.local", "password": "Whatever123!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_login_rejects_wrong_password(client, credentials):
    email, _, _, _ = credentials["admin"]
    response = client.post(
        "/api/auth/login", data={"username": email, "password": "WrongPassword123!"}
    )
    assert response.status_code == 401


def test_me_requires_authentication(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_me_returns_current_user(client, analyst_headers):
    response = client.get("/api/auth/me", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_disabled_account_cannot_login(client, admin_headers):
    email = _unique_email("disabled")
    created = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": email,
            "full_name": "Disabled User",
            "password": "DisabledPass123!",
            "role": "viewer",
        },
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]

    deactivated = client.patch(
        f"/api/users/{user_id}", headers=admin_headers, json={"is_active": False}
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["is_active"] is False

    login = client.post(
        "/api/auth/login",
        data={"username": email, "password": "DisabledPass123!"},
    )
    assert login.status_code == 403
    assert "disabled" in login.json()["detail"].lower()

    # Restore so the account does not linger in a disabled state.
    client.patch(
        f"/api/users/{user_id}", headers=admin_headers, json={"is_active": True}
    )


def test_password_change_invalidates_old_password(client, admin_headers):
    email = _unique_email("rotate")
    old_password = "OldPassword123!"
    new_password = "NewPassword456!"
    created = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": email,
            "full_name": "Password Rotation",
            "password": old_password,
            "role": "analyst",
        },
    )
    assert created.status_code == 201, created.text

    login = client.post(
        "/api/auth/login", data={"username": email, "password": old_password}
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    changed = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": old_password, "new_password": new_password},
    )
    assert changed.status_code == 200, changed.text

    old_login = client.post(
        "/api/auth/login", data={"username": email, "password": old_password}
    )
    assert old_login.status_code == 401
    new_login = client.post(
        "/api/auth/login", data={"username": email, "password": new_password}
    )
    assert new_login.status_code == 200


def test_password_change_requires_correct_current_password(client, analyst_headers):
    response = client.post(
        "/api/auth/change-password",
        headers=analyst_headers,
        json={
            "current_password": "DefinitelyWrong123!",
            "new_password": "AnotherPassword123!",
        },
    )
    assert response.status_code == 400


def test_password_change_requires_new_password_to_differ(client, analyst_headers, credentials):
    password = credentials["analyst"][1]
    response = client.post(
        "/api/auth/change-password",
        headers=analyst_headers,
        json={"current_password": password, "new_password": password},
    )
    assert response.status_code == 422


def test_user_management_is_admin_only(client, analyst_headers, viewer_headers):
    for headers in (analyst_headers, viewer_headers):
        listed = client.get("/api/users", headers=headers)
        assert listed.status_code == 403
        created = client.post(
            "/api/users",
            headers=headers,
            json={
                "email": _unique_email("forbidden"),
                "full_name": "Forbidden",
                "password": "ForbiddenPass123!",
                "role": "viewer",
            },
        )
        assert created.status_code == 403


def test_admin_can_create_and_update_users(client, admin_headers):
    email = _unique_email("created")
    created = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": email,
            "full_name": "Created By Test",
            "password": "CreatedPass123!",
            "role": "viewer",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["email"] == email
    assert body["role"] == "viewer"
    assert "hashed_password" not in body

    duplicate = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": email,
            "full_name": "Duplicate",
            "password": "CreatedPass123!",
            "role": "viewer",
        },
    )
    assert duplicate.status_code == 409

    promoted = client.patch(
        f"/api/users/{body['id']}", headers=admin_headers, json={"role": "analyst"}
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "analyst"

    listed = client.get("/api/users", headers=admin_headers)
    assert listed.status_code == 200
    assert any(row["email"] == email for row in listed.json())


def test_admin_cannot_deactivate_or_demote_self(client, admin_headers, user_ids, credentials):
    admin_id = user_ids[credentials["admin"][0]]
    deactivate = client.patch(
        f"/api/users/{admin_id}", headers=admin_headers, json={"is_active": False}
    )
    assert deactivate.status_code == 422

    demote = client.patch(
        f"/api/users/{admin_id}", headers=admin_headers, json={"role": "viewer"}
    )
    assert demote.status_code == 422


def test_assignees_endpoint_lists_active_users(client, viewer_headers):
    response = client.get("/api/users/assignees", headers=viewer_headers)
    assert response.status_code == 200
    rows = response.json()
    assert rows
    assert {"id", "full_name", "email"} <= set(rows[0])


def test_user_validation_rejects_short_password_and_bad_role(client, admin_headers):
    short = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": _unique_email("short"),
            "full_name": "Short",
            "password": "short",
            "role": "viewer",
        },
    )
    assert short.status_code == 422
    assert short.json()["detail"] == "Request validation failed"

    bad_role = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": _unique_email("badrole"),
            "full_name": "Bad Role",
            "password": "ValidPassword123!",
            "role": "superuser",
        },
    )
    assert bad_role.status_code == 422


def test_login_throttle_blocks_after_repeated_failures(client, credentials):
    email, _, _, _ = credentials["viewer"]
    for _ in range(8):
        response = client.post(
            "/api/auth/login", data={"username": email, "password": "WrongPass123!"}
        )
        assert response.status_code == 401
    blocked = client.post(
        "/api/auth/login", data={"username": email, "password": "WrongPass123!"}
    )
    assert blocked.status_code == 429
    assert "too many" in blocked.json()["detail"].lower()
