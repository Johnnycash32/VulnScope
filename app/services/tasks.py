from __future__ import annotations

import json
import time
from datetime import UTC, datetime

# Import every model module so all cross-module relationship targets are
# registered with SQLAlchemy's registry before mapper configuration.
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.scan import Scan, Vulnerability
from app.models.target import Target  # noqa: F401  register Target for mapper config
from app.models.user import User  # noqa: F401  resolve Target.user relationship target
from app.services.cve_client import get_cve_data
from app.services.remediation import get_remediation
from app.services.zap_client import ZAPClient
from app.worker import celery_app


def _wait_for_zap(status_fn, scan_id: str, zap: ZAPClient, max_wait: int = 900) -> None:
    interval = 5
    elapsed = 0
    while elapsed < max_wait:
        if status_fn(scan_id) == "100":
            return
        time.sleep(interval)
        elapsed += interval
    raise TimeoutError(f"ZAP scan {scan_id} did not complete within {max_wait}s")


def _parse_iso_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except ValueError:
        return None


@celery_app.task(bind=True, name="run_zap_scan")
def run_zap_scan(self, scan_id: int, target_url: str) -> dict:
    """Run a ZAP spider + active scan for a target and persist findings."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"error": "scan not found"}

        scan.status = "running"
        db.add(scan)
        db.commit()

        settings = get_settings()
        zap = ZAPClient(
            base_url=settings.zap_api_url,
            api_key=settings.zap_api_key,
        )

        spider_id = zap.spider_scan(target_url)
        _wait_for_zap(zap.spider_status, spider_id, zap)

        active_scan_id = zap.active_scan(target_url)
        _wait_for_zap(zap.active_scan_status, active_scan_id, zap)

        found_alerts = zap.alerts(scan_id=active_scan_id)

        for alert in found_alerts:
            alert_name = alert.get("name", "") or ""
            cve_id = None
            cvss_score = None
            cvss_severity = None
            cvss_vector = None
            cvss_details = None
            cwes = None
            references = None
            vendor_advisories = None
            exploit_available = False
            published_date = None
            last_modified_date = None
            remediation_code = None

            try:
                cve_results = get_cve_data(alert_name)
                if cve_results:
                    cve = cve_results[0]
                    cve_id = cve.get("cve_id")
                    cvss_score = cve.get("cvss_score")
                    cvss_severity = cve.get("cvss_severity")
                    cvss_vector = cve.get("cvss_vector")
                    cvss_details = cve.get("cvss_details")
                    cwes = cve.get("cwes")
                    references = cve.get("references")
                    vendor_advisories = cve.get("vendor_advisories")
                    exploit_available = cve.get("exploit_available", False)
                    published_date = _parse_iso_datetime(cve.get("published_date"))
                    last_modified_date = _parse_iso_datetime(cve.get("last_modified_date"))
            except Exception:  # noqa: BLE001
                pass

            try:
                remediation = get_remediation(alert_name)
                if remediation:
                    remediation_code = remediation.get("advice")
            except Exception:  # noqa: BLE001
                pass

            # Normalize values to match DB check constraints. NVD returns
            # cvss_severity uppercase (e.g. "MEDIUM"); ZAP returns risk as
            # "Informational" which we map to "Info".
            risk = alert.get("risk", "Info") or "Info"
            if risk == "Informational":
                risk = "Info"
            cvss_severity = cvss_severity.title() if cvss_severity else None

            vulnerability = Vulnerability(
                scan_id=scan.id,
                name=alert_name,
                risk=risk,
                confidence=str(alert.get("confidence") or ""),
                description=alert.get("description"),
                solution=alert.get("solution"),
                evidence=alert.get("evidence"),
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                cvss_details=json.dumps(cvss_details) if cvss_details else None,
                cwes=", ".join(cwes) if cwes else None,
                references=json.dumps(references) if references else None,
                vendor_advisories=json.dumps(vendor_advisories) if vendor_advisories else None,
                exploit_available=exploit_available,
                published_date=published_date,
                last_modified_date=last_modified_date,
                remediation_code=remediation_code,
            )
            db.add(vulnerability)

        scan.status = "completed"
        scan.completed_at = datetime.now(UTC)
        db.add(scan)
        db.commit()

        return {
            "scan_id": scan.id,
            "status": "completed",
            "vulnerabilities": len(found_alerts),
        }
    except Exception as exc:  # noqa: BLE001
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                msg = str(exc) or exc.__class__.__name__
                low = msg.lower()
                if "resolve" in low or "connection" in low or "name or service" in low:
                    scan.error_message = "Target unreachable by ZAP (DNS/network error)"
                elif "ssl" in low or "handshake" in low or "certificate" in low:
                    scan.error_message = "SSL/TLS handshake failed"
                elif "timeout" in low or "timed out" in low:
                    scan.error_message = "Scan timed out (target too slow or WAF blocking)"
                else:
                    scan.error_message = f"Scan failed: {msg[:300]}"
                db.add(scan)
                db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        raise
    finally:
        db.close()