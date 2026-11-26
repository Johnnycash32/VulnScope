from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.scan import Scan, Vulnerability
from app.models.target import Target
from app.models.user import User
from app.schemas.scan import ScanOut
from app.services import tasks

router = APIRouter(prefix="/scans", tags=["scans"])


def _vuln_key(v: Vulnerability) -> tuple[str, str | None]:
    """Generate a unique key for a vulnerability for comparison."""
    return (v.name, v.cve_id)


def _compare_vulns(
    old_vulns: list[Vulnerability], new_vulns: list[Vulnerability]
) -> dict[str, list[dict]]:
    """Compare two vulnerability lists and return added, removed, changed."""
    old_map = {_vuln_key(v): v for v in old_vulns}
    new_map = {_vuln_key(v): v for v in new_vulns}

    added = []
    removed = []
    changed = []

    for key, new_v in new_map.items():
        if key not in old_map:
            added.append({
                "name": new_v.name,
                "cve_id": new_v.cve_id,
                "risk": new_v.risk,
                "cvss_score": new_v.cvss_score,
                "cvss_severity": new_v.cvss_severity,
            })
        else:
            old_v = old_map[key]
            # Check for changes in risk, CVSS, etc.
            changes = []
            if old_v.risk != new_v.risk:
                changes.append(f"Risk: {old_v.risk} -> {new_v.risk}")
            if old_v.cvss_score != new_v.cvss_score:
                changes.append(f"CVSS: {old_v.cvss_score} -> {new_v.cvss_score}")
            if old_v.cvss_severity != new_v.cvss_severity:
                changes.append(f"CVSS Severity: {old_v.cvss_severity} -> {new_v.cvss_severity}")
            if old_v.exploit_available != new_v.exploit_available:
                old_exploit = "Yes" if old_v.exploit_available else "No"
                new_exploit = "Yes" if new_v.exploit_available else "No"
                changes.append(f"Exploit available: {old_exploit} -> {new_exploit}")
            if changes:
                changed.append({
                    "name": new_v.name,
                    "cve_id": new_v.cve_id,
                    "changes": changes,
                    "old_risk": old_v.risk,
                    "new_risk": new_v.risk,
                })

    for key, old_v in old_map.items():
        if key not in new_map:
            removed.append({
                "name": old_v.name,
                "cve_id": old_v.cve_id,
                "risk": old_v.risk,
                "cvss_score": old_v.cvss_score,
                "cvss_severity": old_v.cvss_severity,
            })

    return {"added": added, "removed": removed, "changed": changed}


@router.post(
    "/{target_id}",
    response_model=ScanOut,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    target_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    target = db.scalar(
        select(Target).where(Target.id == target_id, Target.user_id == user.id)
    )
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )
    if target.verified_at is None:
        target.verified_at = datetime.now(UTC)
        db.add(target)
        db.commit()

    scan = Scan(target_id=target.id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    tasks.run_zap_scan.delay(scan.id, target.url)
    return scan


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = db.scalar(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == scan_id, Target.user_id == user.id)
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return scan


@router.get("/{scan_id}/compare", status_code=status.HTTP_200_OK)
def compare_scans(
    scan_id: int,
    baseline_scan_id: int = Query(..., description="Scan ID to compare against"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Compare two scans for the same target and show differences."""
    # Get current scan
    scan = db.scalar(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == scan_id, Target.user_id == user.id)
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get baseline scan
    baseline = db.scalar(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == baseline_scan_id, Target.user_id == user.id)
    )
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline scan not found")

    # Ensure same target
    if scan.target_id != baseline.target_id:
        raise HTTPException(status_code=400, detail="Scans must be for the same target")

    comparison = _compare_vulns(list(baseline.vulnerabilities), list(scan.vulnerabilities))

    return {
        "scan_id": scan.id,
        "baseline_scan_id": baseline.id,
        "target_id": scan.target_id,
        "target_url": scan.target.url if scan.target else "",
        "summary": {
            "baseline_total": len(baseline.vulnerabilities),
            "current_total": len(scan.vulnerabilities),
            "added": len(comparison["added"]),
            "removed": len(comparison["removed"]),
            "changed": len(comparison["changed"]),
        },
        "details": comparison,
    }