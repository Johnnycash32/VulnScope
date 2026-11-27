from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.scan import Scan
from app.models.target import Target

router = APIRouter(prefix="/scans", tags=["reports"])

_template_env = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def _render_pdf(html: str) -> bytes:
    """Render HTML to PDF bytes via WeasyPrint.

    WeasyPrint is imported lazily here because it needs system libraries
    (cairo/pango) that are present in Docker but not in every local dev env.
    """
    from weasyprint import HTML  # noqa: PLC0415

    return HTML(string=html).write_pdf()


def _serialize_vuln(v) -> dict[str, Any]:
    """Serialize vulnerability with enriched CVE data."""
    import json as json_module

    cvss_details = None
    if v.cvss_details:
        with contextlib.suppress(json_module.JSONDecodeError):
            cvss_details = json_module.loads(v.cvss_details)

    references = None
    if v.references:
        with contextlib.suppress(json_module.JSONDecodeError):
            references = json_module.loads(v.references)

    vendor_advisories = None
    if v.vendor_advisories:
        with contextlib.suppress(json_module.JSONDecodeError):
            vendor_advisories = json_module.loads(v.vendor_advisories)

    cwes = None
    if v.cwes:
        cwes = [c.strip() for c in v.cwes.split(",") if c.strip()]

    return {
        "id": v.id,
        "name": v.name,
        "risk": v.risk,
        "confidence": v.confidence,
        "description": v.description,
        "solution": v.solution,
        "evidence": v.evidence,
        "cve_id": v.cve_id,
        "cvss_score": v.cvss_score,
        "cvss_severity": v.cvss_severity,
        "cvss_vector": v.cvss_vector,
        "cvss_details": cvss_details,
        "cwes": cwes,
        "references": references,
        "vendor_advisories": vendor_advisories,
        "exploit_available": v.exploit_available,
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
        "remediation_code": v.remediation_code,
    }


@router.get("/{scan_id}/report", status_code=status.HTTP_200_OK)
def get_scan_report(
    scan_id: int,
    format: str = Query("pdf", pattern="^(pdf|html|json)$"),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
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

    template = _template_env.get_template("report.html")
    vulnerabilities_data = [_serialize_vuln(v) for v in scan.vulnerabilities]

    # Add parsed data to vulnerability objects for template
    for v in scan.vulnerabilities:
        if v.cvss_details:
            try:
                v.cvss_details = json.loads(v.cvss_details)
            except json.JSONDecodeError:
                v.cvss_details = None
        if v.references:
            try:
                v.references = json.loads(v.references)
            except json.JSONDecodeError:
                v.references = None
        if v.vendor_advisories:
            try:
                v.vendor_advisories = json.loads(v.vendor_advisories)
            except json.JSONDecodeError:
                v.vendor_advisories = None

    html = template.render(
        scan=scan,
        target_url=scan.target.url if scan.target else "",
        vulnerabilities=list(scan.vulnerabilities),
    )

    if format == "html":
        return HTMLResponse(content=html)

    if format == "json":
        report_data = {
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "target_url": scan.target.url if scan.target else "",
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message,
            "generated_at": datetime.now(UTC).isoformat(),
            "vulnerabilities": vulnerabilities_data,
        }
        return JSONResponse(content=report_data)

    # Default: PDF
    pdf_bytes = _render_pdf(html)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vulnscope-scan-{scan_id}.pdf"'
        },
    )


@router.get("/{scan_id}/report/summary", status_code=status.HTTP_200_OK)
def get_scan_summary(
    scan_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get a quick summary of scan findings for dashboards."""
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

    vulns = list(scan.vulnerabilities)
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    cve_count = 0
    exploit_count = 0

    for v in vulns:
        risk_counts[v.risk] = risk_counts.get(v.risk, 0) + 1
        if v.cve_id:
            cve_count += 1
        if v.exploit_available:
            exploit_count += 1

    return {
        "scan_id": scan.id,
        "target_url": scan.target.url if scan.target else "",
        "status": scan.status,
        "total_vulnerabilities": len(vulns),
        "risk_breakdown": risk_counts,
        "cve_enriched_count": cve_count,
        "exploit_available_count": exploit_count,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
