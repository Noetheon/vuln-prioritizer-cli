from __future__ import annotations

import json
from pathlib import Path

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider


class FakeResponse:
    def __init__(self, json_data: dict | None = None, status_code: int = 200) -> None:
        self._json_data = json_data or {}
        self.status_code = status_code

    def json(self) -> dict:
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error = requests.HTTPError(f"{self.status_code} error")
            error.response = self
            raise error


def test_nvd_parse_payload_prefers_v40_and_collects_metadata() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [
                        {"lang": "de", "value": "Deutsch"},
                        {"lang": "en", "value": "English description"},
                    ],
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-79"}]},
                    ],
                    "references": [{"url": "https://example.com/advisory"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                            }
                        ],
                        "cvssMetricV40": [
                            {
                                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                            }
                        ],
                    },
                }
            }
        ]
    }

    parsed = NvdProvider.parse_payload("CVE-2026-0001", payload)

    assert parsed.description == "English description"
    assert parsed.cvss_base_score == 9.8
    assert parsed.cvss_severity == "CRITICAL"
    assert parsed.cwes == ["CWE-79"]
    assert parsed.references == ["https://example.com/advisory"]


def test_nvd_fetch_many_handles_missing_results() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return FakeResponse({"vulnerabilities": []}, status_code=200)

    provider = NvdProvider(session=Session())
    results, warnings = provider.fetch_many(["CVE-2026-0001"])

    assert warnings == []
    assert results["CVE-2026-0001"].cvss_base_score is None


def test_nvd_uses_cache_on_second_fetch(tmp_path: Path) -> None:
    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.calls += 1
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": "Cached NVD record"}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "baseScore": 8.8,
                                                "baseSeverity": "HIGH",
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                }
            )

    session = Session()
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    provider = NvdProvider(session=session, cache=cache)

    first_results, first_warnings = provider.fetch_many(["CVE-2026-1111"])
    second_results, second_warnings = provider.fetch_many(["CVE-2026-1111"])

    assert first_warnings == []
    assert second_warnings == []
    assert first_results["CVE-2026-1111"].description == "Cached NVD record"
    assert second_results["CVE-2026-1111"].description == "Cached NVD record"
    assert session.calls == 1


def test_epss_fetch_many_parses_batch_payload() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return FakeResponse(
                {
                    "data": [
                        {
                            "cve": "CVE-2021-44228",
                            "epss": "0.973",
                            "percentile": "0.999",
                            "date": "2026-04-18",
                        }
                    ]
                }
            )

    provider = EpssProvider(session=Session())
    results, warnings = provider.fetch_many(["CVE-2021-44228"])

    assert warnings == []
    assert results["CVE-2021-44228"].epss == 0.973
    assert results["CVE-2021-44228"].percentile == 0.999


def test_kev_fetch_many_from_offline_json(tmp_path: Path) -> None:
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "dateAdded": "2021-12-10",
                        "requiredAction": "Patch now",
                        "dueDate": "2021-12-24",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    provider = KevProvider()
    results, warnings = provider.fetch_many(
        ["CVE-2021-44228", "CVE-2024-3094"],
        offline_file=kev_file,
    )

    assert warnings == []
    assert results["CVE-2021-44228"].in_kev is True
    assert results["CVE-2024-3094"].in_kev is False


def test_kev_uses_mirror_when_primary_feed_fails() -> None:
    class Session:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            if "cisa.gov" in url:
                raise requests.RequestException("primary feed unavailable")
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2023-44487",
                            "vendorProject": "IETF",
                            "product": "HTTP/2",
                        }
                    ]
                }
            )

    provider = KevProvider(session=Session())
    results, warnings = provider.fetch_many(["CVE-2023-44487"])

    assert warnings == []
    assert results["CVE-2023-44487"].in_kev is True
