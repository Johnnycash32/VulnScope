from __future__ import annotations

from typing import Any

import pytest

from app.services import cve_client


class FakeResponse:
    def __init__(self, json_data: dict[str, Any], status_code: int = 200) -> None:
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise AssertionError(f"bad status {self.status_code}")

    def json(self) -> dict[str, Any]:
        return self._json


def _nvd_payload() -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-1234",
                    "descriptions": [
                        {"lang": "en", "value": "A reflected XSS in example app."},
                        {"lang": "es", "value": "Descripcion en espanol"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.1,
                                    "baseSeverity": "High",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }


def test_get_cve_data_parses_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_get(url: str, params: dict[str, Any], timeout: int) -> FakeResponse:
        captured["url"] = url
        captured["params"] = params
        return FakeResponse(_nvd_payload())

    monkeypatch.setattr(cve_client.requests, "get", fake_get)
    # Clear the lru_cache so the call actually runs.
    cve_client.get_cve_data.cache_clear()

    results = cve_client.get_cve_data("Cross Site Scripting")

    assert captured["url"] == cve_client.NVD_BASE_URL
    assert captured["params"]["keywordSearch"] == "Cross Site Scripting"
    assert len(results) == 1
    item = results[0]
    assert item["cve_id"] == "CVE-2021-1234"
    assert item["description"] == "A reflected XSS in example app."
    assert item["cvss_score"] == 7.1
    assert item["cvss_severity"] == "High"


def test_get_cve_data_graceful_on_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> FakeResponse:
        raise cve_client.requests.RequestException("boom")

    monkeypatch.setattr(cve_client.requests, "get", fake_get)
    cve_client.get_cve_data.cache_clear()

    results = cve_client.get_cve_data("anything")
    assert results == []


def test_get_cve_data_graceful_on_bad_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadJsonResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            raise ValueError("no json")

    monkeypatch.setattr(cve_client.requests, "get", lambda *a, **k: BadJsonResponse())
    cve_client.get_cve_data.cache_clear()

    results = cve_client.get_cve_data("anything")
    assert results == []
