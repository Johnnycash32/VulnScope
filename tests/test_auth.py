from __future__ import annotations

from fastapi.testclient import TestClient


def test_register_login_and_me(client: TestClient) -> None:
    email = "alice@example.com"
    password = "password123"

    register = client.post(
        "/auth/register",
        json={"email": email, "password": password, "full_name": "Alice"},
    )
    assert register.status_code == 201, register.text
    assert register.json()["access_token"]

    login = client.post("/auth/login", data={"username": email, "password": password})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    me = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["email"] == email
    assert body["full_name"] == "Alice"
    assert body["role"] == "user"


def test_duplicate_email_rejected(client: TestClient) -> None:
    payload = {"email": "bob@example.com", "password": "password123", "full_name": "Bob"}
    first = client.post("/auth/register", json=payload)
    assert first.status_code == 201, first.text

    duplicate = client.post("/auth/register", json=payload)
    assert duplicate.status_code == 409, duplicate.text


def test_login_with_wrong_password_rejected(client: TestClient) -> None:
    client.post(
        "/auth/register",
        json={"email": "carol@example.com", "password": "password123", "full_name": "Carol"},
    )
    bad = client.post(
        "/auth/login",
        data={"username": "carol@example.com", "password": "wrong-password"},
    )
    assert bad.status_code == 401, bad.text


def test_password_min_length_enforced(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"email": "short@example.com", "password": "short", "full_name": "Short"},
    )
    assert response.status_code == 422, response.text