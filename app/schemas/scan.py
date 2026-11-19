from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    name: str
    risk: str
    confidence: str | None
    description: str | None
    solution: str | None
    evidence: str | None
    cve_id: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    cvss_details: dict[str, Any] | None
    cwes: list[str] | None
    references: list[dict[str, str]] | None
    vendor_advisories: list[dict[str, str]] | None
    exploit_available: bool
    published_date: datetime | None
    last_modified_date: datetime | None
    remediation_code: str | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: str
    created_at: datetime
    completed_at: datetime | None
    vulnerabilities: list[VulnerabilityOut] = []