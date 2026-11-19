from __future__ import annotations

from typing import Any

import requests


class ZAPClient:
    """Thin wrapper around the OWASP ZAP JSON API.

    ZAP is expected to run in daemon mode without authentication unless
    ZAP_API_KEY is explicitly configured.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _params(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.api_key:
            params["apikey"] = self.api_key
        if extra:
            params.update(extra)
        return params

    def _get(self, path: str, params: dict[str, str] | None = None) -> Any:
        url = f"{self.base_url}{path}"
        response = requests.get(
            url, params=self._params(params), timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()

    def spider_scan(self, url: str) -> str:
        data = self._get("/JSON/spider/action/scan/", {"url": url})
        return str(data.get("scan", ""))

    def spider_status(self, scan_id: str) -> str:
        data = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
        return str(data.get("status", "0"))

    def active_scan(self, url: str) -> str:
        data = self._get(
            "/JSON/ascan/action/scan/",
            {"url": url, "recurse": "true"},
        )
        return str(data.get("scan", ""))

    def active_scan_status(self, scan_id: str) -> str:
        data = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return str(data.get("status", "0"))

    def alerts(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, str] = {}
        if scan_id:
            params["scanId"] = scan_id
        data = self._get("/JSON/core/view/alerts/", params)
        return data.get("alerts", [])