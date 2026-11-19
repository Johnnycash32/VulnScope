from __future__ import annotations

import time
from datetime import datetime
from functools import lru_cache
from typing import Any

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD allows max 5 requests per 30 seconds without an API key.
# Space requests at least 6 seconds apart to stay under the limit.
_RATE_LIMIT_INTERVAL = 6.0
_last_request_time: float = 0.0


def _rate_limit() -> None:
    """Ensure we do not exceed NVD's unauthenticated rate limit."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _RATE_LIMIT_INTERVAL:
        time.sleep(_RATE_LIMIT_INTERVAL - elapsed)
    _last_request_time = time.time()


def _parse_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    return None


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            if desc.get("lang") == "en":
                cwes.append(desc.get("value", "") or "")
    return cwes


def _extract_references(cve: dict[str, Any]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for ref in cve.get("references", []) or []:
        url = ref.get("url", "") or ""
        if not url:
            continue
        tags = ref.get("tags", []) or []
        refs.append({"url": url, "tags": ", ".join(tags)})
    return refs


def _extract_vendor_advisories(cve: dict[str, Any]) -> list[dict[str, str]]:
    advisories: list[dict[str, str]] = []
    for ref in cve.get("references", []) or []:
        tags = ref.get("tags", []) or []
        if any(t.lower() in {"vendor-advisory", "patch", "third-party-advisory"} for t in tags):
            advisories.append({
                "url": ref.get("url", "") or "",
                "source": ref.get("source", "") or "",
                "tags": ", ".join(tags),
            })
    return advisories


def _check_exploit_availability(cve: dict[str, Any]) -> bool:
    # Check references for exploit-related tags
    for ref in cve.get("references", []) or []:
        tags = ref.get("tags", []) or []
        if any(t.lower() in {"exploit", "exploit-db", "metasploit"} for t in tags):
            return True
    # Check CISA KEV (Known Exploited Vulnerabilities) - would need separate API
    return False


def _extract_cvss_details(metrics: dict[str, Any]) -> dict[str, Any]:
    """Extract detailed CVSS vector and metrics."""
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, []) or []
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {}) or {}
            metric = metric_list[0]
            return {
                "vector": cvss_data.get("vectorString"),
                "base_score": cvss_data.get("baseScore"),
                "base_severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
                "attack_vector": cvss_data.get("attackVector"),
                "attack_complexity": cvss_data.get("attackComplexity"),
                "privileges_required": cvss_data.get("privilegesRequired"),
                "user_interaction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
                "exploitability_score": metric.get("exploitabilityScore"),
                "impact_score": metric.get("impactScore"),
            }
    return {}


@lru_cache(maxsize=128)
def get_cve_data(keyword: str) -> list[dict[str, Any]]:
    """Search the NVD REST API for CVEs matching a keyword.

    Returns a list of dicts with enriched CVE data including:
    cve_id, description, cvss_score, cvss_severity, cvss_vector, cwes,
    references, vendor_advisories, exploit_available, published_date,
    last_modified_date, cvss_details.
    On any network/API failure, returns an empty list so callers can degrade gracefully.
    Results are cached in memory so repeated lookups do not hit NVD again.
    """
    _rate_limit()
    try:
        response = requests.get(
            NVD_BASE_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=20,
        )
        response.raise_for_status()
    except requests.RequestException:
        return []

    try:
        data = response.json()
    except ValueError:
        return []

    results: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id", "") or ""

        description = ""
        for desc in cve.get("descriptions", []) or []:
            if desc.get("lang") == "en":
                description = desc.get("value", "") or ""
                break

        metrics = cve.get("metrics", {}) or {}
        cvss_details = _extract_cvss_details(metrics)
        cvss_score = cvss_details.get("base_score")
        cvss_severity = cvss_details.get("base_severity") or "Info"

        published = _parse_datetime(cve.get("published"))
        last_modified = _parse_datetime(cve.get("lastModified"))

        results.append(
            {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_details.get("vector"),
                "cvss_details": cvss_details,
                "cwes": _extract_cwes(cve),
                "references": _extract_references(cve),
                "vendor_advisories": _extract_vendor_advisories(cve),
                "exploit_available": _check_exploit_availability(cve),
                "published_date": published.isoformat() if published else None,
                "last_modified_date": last_modified.isoformat() if last_modified else None,
            }
        )

    return results


@lru_cache(maxsize=128)
def get_cve_by_id(cve_id: str) -> dict[str, Any] | None:
    """Fetch a single CVE by ID with full details."""
    _rate_limit()
    try:
        response = requests.get(
            f"{NVD_BASE_URL}",
            params={"cveId": cve_id.upper()},
            timeout=20,
        )
        response.raise_for_status()
    except requests.RequestException:
        return None

    try:
        data = response.json()
    except ValueError:
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get("cve", {}) or {}
    metrics = cve.get("metrics", {}) or {}
    cvss_details = _extract_cvss_details(metrics)

    description = ""
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            description = desc.get("value", "") or ""
            break

    published = _parse_datetime(cve.get("published"))
    last_modified = _parse_datetime(cve.get("lastModified"))

    return {
        "cve_id": cve.get("id", "") or "",
        "description": description,
        "cvss_score": cvss_details.get("base_score"),
        "cvss_severity": cvss_details.get("base_severity") or "Info",
        "cvss_vector": cvss_details.get("vector"),
        "cvss_details": cvss_details,
        "cwes": _extract_cwes(cve),
        "references": _extract_references(cve),
        "vendor_advisories": _extract_vendor_advisories(cve),
        "exploit_available": _check_exploit_availability(cve),
        "published_date": published.isoformat() if published else None,
        "last_modified_date": last_modified.isoformat() if last_modified else None,
    }
