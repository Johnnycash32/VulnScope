from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any


def _compute_grade(status: str, days: int | None, proto: str, bits: int) -> str:
    """Assign a basic SSL grade (A+, A, B, C, F) from cert health, protocol, key."""
    if status in ("error", "expired"):
        return "F"
    if days is not None and days < 0:
        return "F"
    grade = "A"
    if "TLSv1.3" in proto:
        grade = "A+"
    elif "TLSv1.2" in proto:
        grade = "A"
    elif "TLSv1.1" in proto or "TLSv1.0" in proto:
        grade = "C"
    elif "SSL" in proto:
        return "F"
    if bits and bits < 128 and grade in ("A", "A+"):
        grade = "B"
    if days is not None and days < 14 and grade in ("A+", "A"):
        grade = "B"
    return grade


def check_certificate(domain: str) -> dict[str, Any]:
    """Fetch SSL/TLS certificate info for a domain using stdlib only.

    Returns a dict with: domain, issuer, expiry_date, status, days_remaining,
    ssl_grade, error.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "issuer": None,
        "expiry_date": None,
        "status": "unknown",
        "days_remaining": None,
        "ssl_grade": "—",
        "error": None,
    }

    # Strip scheme if present so socket.connect works
    host = domain.replace("https://", "").replace("http://", "").split("/")[0]
    port = 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock, \
             ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert: dict[str, Any] = ssock.getpeercert()
                proto = ssock.version() or ""
                bits = 0
                try:
                    ciph = ssock.cipher()
                    if ciph:
                        bits = ciph[2] or 0
                except Exception:  # noqa: BLE001
                    bits = 0

        # Parse issuer (list of tuples -> dict)
        issuer_raw = cert.get("issuer", ())
        issuer_parts: list[str] = []
        for component in issuer_raw:
            for key, value in component:
                issuer_parts.append(f"{key}={value}")
        result["issuer"] = ", ".join(issuer_parts) or None

        # Parse expiry date
        not_after = cert.get("notAfter")
        if not_after:
            # Format example: 'Sep 15 12:00:00 2026 GMT'
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            result["expiry_date"] = expiry

            now = datetime.now(UTC)
            delta = expiry - now
            result["days_remaining"] = delta.days

            if delta.days < 0:
                result["status"] = "expired"
            elif delta.days <= 14:
                result["status"] = "expiring_soon"
            else:
                result["status"] = "valid"

        result["ssl_grade"] = _compute_grade(
            result["status"], result["days_remaining"], proto, bits
        )

    except ssl.SSLCertVerificationError as exc:
        result["status"] = "error"
        result["error"] = f"Certificate verification failed: {exc}"
    except socket.gaierror as exc:
        result["status"] = "error"
        result["error"] = f"DNS resolution failed: {exc}"
    except TimeoutError as exc:
        result["status"] = "error"
        result["error"] = f"Connection timed out: {exc}"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = f"Connection error: {exc}"
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(exc)

    return result
