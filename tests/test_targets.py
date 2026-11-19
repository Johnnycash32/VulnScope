from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient


class FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _create_target(client: TestClient, headers: dict[str, str], url: str) -> dict[str, Any]:
    response = client.post(
        "/targets",
        json={"url": url, "verification_method": "file"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_target_returns_token_and_instructions(
    client: TestClient, register: Any
) -> None:
    reg = register()
    data = _create_target(client, reg["headers"], "https://93.184.216.34")

    assert data["target_id"] > 0
    assert len(data["token"]) >= 16
    assert data["verification_url"].endswith(f"{data['token']}.txt")
    assert data["instructions"]
    assert data["token"] in data["instructions"]


def test_targets_require_authentication(client: TestClient) -> None:
    response = client.get("/targets")
    assert response.status_code == 401, response.text


def test_verify_fails_with_mocked_404(
    client: TestClient, register: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = register()
    data = _create_target(client, reg["headers"], "https://93.184.216.34")
    target_id = data["target_id"]

    monkeypatch.setattr(
        "app.services.ownership._fetch",
        lambda url: FakeResponse(404, "not found"),
    )

    response = client.post(f"/targets/{target_id}/verify", headers=reg["headers"])
    assert response.status_code == 400, response.text
    assert "verification" in response.json()["detail"].lower()


def test_verify_succeeds_with_matching_body(
    client: TestClient, register: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = register()
    data = _create_target(client, reg["headers"], "https://93.184.216.34")
    target_id = data["target_id"]
    token = data["token"]

    monkeypatch.setattr(
        "app.services.ownership._fetch",
        lambda url: FakeResponse(200, token),
    )

    response = client.post(f"/targets/{target_id}/verify", headers=reg["headers"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verified_at"] is not None
    assert body["verification_token"] == token


def test_verify_rejects_loopback_url_ssrf(
    client: TestClient, register: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = register()
    data = _create_target(client, reg["headers"], "http://127.0.0.1")
    target_id = data["target_id"]

    def _fail(url: str) -> None:
        raise AssertionError("network fetch must not be attempted for blocked host")

    monkeypatch.setattr("app.services.ownership._fetch", _fail)

    response = client.post(f"/targets/{target_id}/verify", headers=reg["headers"])
    assert response.status_code == 400, response.text
    assert "ssrf" in response.json()["detail"].lower()


def test_users_only_see_their_own_targets(
    client: TestClient, register: Any
) -> None:
    first = register(email="first@example.com")
    second = register(email="second@example.com")

    _create_target(client, first["headers"], "https://93.184.216.34")

    listing = client.get("/targets", headers=second["headers"])
    assert listing.status_code == 200, listing.text
    assert listing.json() == []

    own = client.get("/targets", headers=first["headers"])
    assert len(own.json()) == 1


def test_verify_not_found_for_other_users_target(
    client: TestClient, register: Any
) -> None:
    owner = register(email="owner@example.com")
    intruder = register(email="intruder@example.com")

    data = _create_target(client, owner["headers"], "https://93.184.216.34")

    response = client.post(
        f"/targets/{data['target_id']}/verify",
        headers=intruder["headers"],
    )
    assert response.status_code == 404, response.text