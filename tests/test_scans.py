from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.models.scan import Scan
from app.models.target import Target
from app.services import tasks


class FakeZAPClient:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: int = 30):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

    def spider_scan(self, url: str) -> str:
        return "spider-1"

    def spider_status(self, scan_id: str) -> str:
        return "100"

    def active_scan(self, url: str) -> str:
        return "scan-1"

    def active_scan_status(self, scan_id: str) -> str:
        return "100"

    def alerts(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        return [
            {
                "name": "Cross-Site Scripting (XSS)",
                "risk": "High",
                "confidence": "High",
                "description": "Reflected XSS detected",
                "solution": "Encode untrusted output",
                "evidence": "http://example.com/search?q=<script>",
            },
            {
                "name": "Insecure Cookie",
                "risk": "Low",
                "confidence": "Medium",
                "description": "Cookie without Secure flag",
                "solution": "Set the Secure flag",
                "evidence": "Set-Cookie: session=abc",
            },
        ]


def test_run_zap_scan_saves_vulnerabilities(
    client: TestClient,
    register: Any,
    db_session: SessionLocal,
    session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "ZAPClient", FakeZAPClient)
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "get_cve_data", lambda keyword: [])
    tasks.celery_app.conf.broker_url = "memory://"
    tasks.celery_app.conf.result_backend = "cache+memory://"

    reg = register()
    headers = reg["headers"]

    target = client.post(
        "/targets",
        json={"url": "https://93.184.216.34", "verification_method": "file"},
        headers=headers,
    )
    assert target.status_code == 201, target.text
    target_id = target.json()["target_id"]

    row = db_session.get(Target, target_id)
    assert row is not None
    row.verified_at = datetime.now(UTC)
    db_session.commit()

    created = client.post(f"/scans/{target_id}", headers=headers)
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]

    result = tasks.run_zap_scan.run(scan_id, "https://93.184.216.34")
    assert result["status"] == "completed"
    assert result["vulnerabilities"] == 2

    scan = db_session.get(Scan, scan_id)
    assert scan is not None
    assert scan.status == "completed"
    assert scan.completed_at is not None
    assert len(scan.vulnerabilities) == 2

    names = {v.name for v in scan.vulnerabilities}
    assert names == {"Cross-Site Scripting (XSS)", "Insecure Cookie"}
    risks = {v.risk for v in scan.vulnerabilities}
    assert risks == {"High", "Low"}

    # New CVE/remediation columns are present (populated when NVD/KB match).
    for v in scan.vulnerabilities:
        assert hasattr(v, "cve_id")
        assert hasattr(v, "cvss_score")
        assert hasattr(v, "cvss_severity")
        assert hasattr(v, "remediation_code")


def test_scan_auto_verifies_unverified_target(
    client: TestClient, register: Any
) -> None:
    reg = register()
    headers = reg["headers"]

    target = client.post(
        "/targets",
        json={"url": "https://93.184.216.34", "verification_method": "file"},
        headers=headers,
    )
    assert target.status_code == 201
    target_id = target.json()["target_id"]

    created = client.post(f"/scans/{target_id}", headers=headers)
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "pending"


def test_scan_requires_auth(client: TestClient) -> None:
    response = client.post("/scans/1")
    assert response.status_code == 401, response.text


def test_scan_not_found_for_other_users_target(
    client: TestClient, register: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks, "ZAPClient", FakeZAPClient)
    monkeypatch.setattr(tasks, "SessionLocal", SessionLocal)

    owner = register(email="owner@example.com")
    intruder = register(email="intruder@example.com")

    target = client.post(
        "/targets",
        json={"url": "https://93.184.216.34", "verification_method": "file"},
        headers=owner["headers"],
    )
    assert target.status_code == 201
    target_id = target.json()["target_id"]

    created = client.post(f"/scans/{target_id}", headers=intruder["headers"])
    assert created.status_code == 404, created.text
