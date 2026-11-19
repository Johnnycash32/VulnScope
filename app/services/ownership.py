from __future__ import annotations

import ipaddress
import secrets
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import dns.resolver
import httpx

if TYPE_CHECKING:
    from app.models.target import Target

_HTTP_SCHEMES = frozenset({"http", "https"})
_FETCH_TIMEOUT = 10.0
_DNS_TIMEOUT = 10.0


class SSRFBlocked(Exception):
    """Raised when a URL fails the SSRF guard."""


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str | None = None


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def extract_host(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname:
        return parsed.hostname
    fallback = urlparse("//" + url)
    return fallback.hostname or url


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
    )


def _reject_if_disallowed(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    if _is_disallowed_ip(ip):
        raise SSRFBlocked(f"resolves to non-public address {ip_str}")


def _resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return [info[4][0] for info in infos]


def assert_public_url(url: str) -> None:
    """Reject non-http(s) schemes and hosts that resolve to non-public addresses.

    This must be called before every outbound fetch to enforce the SSRF guard.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _HTTP_SCHEMES:
        raise SSRFBlocked(f"scheme not allowed: {scheme or '(none)'}")

    host = parsed.hostname
    if not host:
        raise SSRFBlocked("missing host")

    try:
        literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = (
            ipaddress.ip_address(host)
        )
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        _reject_if_disallowed(str(literal_ip))
        return

    for ip_str in _resolve_host(host):
        _reject_if_disallowed(ip_str)


def build_file_urls(target: Target) -> list[str]:
    host = extract_host(target.url)
    token = target.verification_token
    return [f"https://{host}/{token}.txt", f"http://{host}/{token}.txt"]


def _resolve_dns_txt(record_name: str) -> list[str]:
    """Resolve DNS TXT records for a given name."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = _DNS_TIMEOUT
        resolver.lifetime = _DNS_TIMEOUT
        answers = resolver.resolve(record_name, "TXT")
        return [str(rdata) for rdata in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.exception.DNSException,
    ):
        return []


def build_verification_instructions(target: Target) -> tuple[str, str]:
    """Return (verification_url, human_instructions) for a target."""
    host = extract_host(target.url)
    token = target.verification_token
    if target.verification_method == "dns":
        verification_url = f"_vulnscope.{host}"
        instructions = (
            f"Create a DNS TXT record named '_vulnscope.{host}' with the exact value: {token}. "
            "Then trigger verification."
        )
        return verification_url, instructions

    verification_url = f"https://{host}/{token}.txt"
    instructions = (
        f"Publish a text file at '{verification_url}' (served over HTTPS, HTTP is also tried) "
        f"whose entire body is exactly: {token}. Then trigger verification."
    )
    return verification_url, instructions


def _fetch(url: str) -> httpx.Response:
    with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
        return client.get(url)


def _verify_dns(target: Target) -> VerificationResult:
    """Verify ownership via DNS TXT record."""
    host = extract_host(target.url)
    token = target.verification_token
    record_name = f"_vulnscope.{host}"

    txt_records = _resolve_dns_txt(record_name)
    if not txt_records:
        return VerificationResult(ok=False, reason=f"no TXT records found for {record_name}")

    # TXT records come back with quotes, strip them
    for record in txt_records:
        cleaned = record.strip('"')
        if cleaned == token:
            return VerificationResult(ok=True)

    return VerificationResult(ok=False, reason="token mismatch in DNS TXT record")


def verify_ownership(target: Target) -> VerificationResult:
    if target.verification_method == "dns":
        return _verify_dns(target)

    reason = "verification failed"
    for url in build_file_urls(target):
        try:
            assert_public_url(url)
        except SSRFBlocked as exc:
            return VerificationResult(ok=False, reason=f"ssrf_blocked: {exc}")

        try:
            response = _fetch(url)
        except httpx.HTTPError as exc:
            reason = f"request failed: {exc}"
            continue

        if response.status_code != 200:
            reason = f"unexpected status {response.status_code} from {url}"
            continue

        if response.text.strip() != target.verification_token:
            reason = "token mismatch"
            continue

        return VerificationResult(ok=True)

    return VerificationResult(ok=False, reason=reason)