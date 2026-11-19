from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.routes import reports
from app.db.session import SessionLocal
from app.models.scan import Scan, Vulnerability
from app.models.target import Target
from app.models.user import User


def _seed_scan(db: SessionLocal, user_id: int) -> int:
    target = Target(
        user_id=user_id,
        url="https://93.184.216.34",
        verification_token="test-token",
        verification_method="file",
        verified_at=datetime.now(UTC),
    )
    db.add(target)
    db.flush()
    scan = Scan(target_id=target.id, status="completed", completed_at=datetime.now(UTC))
    db.add(scan)
    db.flush()

    db.add(
        Vulnerability(
            scan_id=scan.id,
            name="Cross-Site Scripting (XSS)",
            risk="High",
            confidence="High",
            description="Reflected XSS detected",
            solution="Encode output",
            evidence="<script>alert(1)</script>",
            cve_id="CVE-2021-1234",
            cvss_score=7.1,
            cvss_severity="High",
            remediation_code="Escape user input before rendering.",
        )
    )
    db.commit()
    return scan.id


def test_report_returns_pdf(
    client: TestClient,
    register: Any,
    db_session: SessionLocal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reports, "_render_pdf", lambda html: b"%PDF-1.4 fake")

    reg = register()
    headers = reg["headers"]

    user = db_session.scalar(select(User).where(User.email == "user@example.com"))
    if user is None:
        pytest.skip("registered user not found in test db")

    scan_id = _seed_scan(db_session, user.id)

    resp = client.get(f"/scans/{scan_id}/report", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-1.4 fake")
    assert f'filename="vulnscope-scan-{scan_id}.pdf"' in resp.headers["content-disposition"]


def test_report_requires_auth(client: TestClient) -> None:
    resp = client.get("/scans/1/report")
    assert resp.status_code == 401, resp.text


def test_report_not_found(client: TestClient, register: Any) -> None:
    reg = register()
    headers = reg["headers"]
    resp = client.get("/scans/99999/report", headers=headers)
    assert resp.status_code == 404, resp.text
