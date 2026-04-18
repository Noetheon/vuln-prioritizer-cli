from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vuln_prioritizer.cli import app
from vuln_prioritizer.models import AttackData, EpssData, KevData, NvdData
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner = CliRunner()


def test_cli_end_to_end_with_mocked_providers(monkeypatch, tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "report.md"
    input_file.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")

    def fake_nvd_fetch_many(self, cve_ids):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": NvdData(
                    cve_id="CVE-2021-44228",
                    description="Log4Shell",
                    cvss_base_score=10.0,
                    cvss_severity="CRITICAL",
                ),
                "CVE-2023-44487": NvdData(
                    cve_id="CVE-2023-44487",
                    description="HTTP/2 Rapid Reset",
                    cvss_base_score=7.5,
                    cvss_severity="HIGH",
                ),
            },
            [],
        )

    def fake_epss_fetch_many(self, cve_ids):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": EpssData(
                    cve_id="CVE-2021-44228",
                    epss=0.97,
                    percentile=0.999,
                ),
                "CVE-2023-44487": EpssData(
                    cve_id="CVE-2023-44487",
                    epss=0.42,
                    percentile=0.91,
                ),
            },
            [],
        )

    def fake_kev_fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": KevData(cve_id="CVE-2021-44228", in_kev=True),
                "CVE-2023-44487": KevData(cve_id="CVE-2023-44487", in_kev=False),
            },
            [],
        )

    def fake_attack_fetch_many(self, cve_ids, enabled, offline_file=None):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": AttackData(
                    cve_id="CVE-2021-44228",
                    attack_techniques=["T1190"],
                    attack_tactics=["Initial Access"],
                )
            },
            [],
        )

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)
    monkeypatch.setattr(AttackProvider, "fetch_many", fake_attack_fetch_many)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "markdown",
        ],
    )

    assert result.exit_code == 0
    assert "CVE-2021-44228" in result.stdout
    assert output_file.exists()
    assert "# Vulnerability Prioritization Report" in output_file.read_text(encoding="utf-8")


def test_cli_rejects_output_with_table_format(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(tmp_path / "report.txt"),
            "--format",
            "table",
        ],
    )

    assert result.exit_code == 2
    assert "--output cannot be used together with --format table." in result.stdout


def test_cli_explain_end_to_end_with_mocked_providers(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "explain.json"

    def fake_nvd_fetch_many(self, cve_ids):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": NvdData(
                    cve_id="CVE-2021-44228",
                    description="Log4Shell",
                    cvss_base_score=10.0,
                    cvss_severity="CRITICAL",
                    published="2021-12-10T10:15:09.143",
                )
            },
            [],
        )

    def fake_epss_fetch_many(self, cve_ids):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": EpssData(
                    cve_id="CVE-2021-44228",
                    epss=0.97,
                    percentile=0.999,
                )
            },
            [],
        )

    def fake_kev_fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": KevData(
                    cve_id="CVE-2021-44228",
                    in_kev=True,
                    vendor_project="Apache",
                    product="Log4j",
                )
            },
            [],
        )

    def fake_attack_fetch_many(self, cve_ids, enabled, offline_file=None):  # noqa: ANN001
        return ({}, [])

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)
    monkeypatch.setattr(AttackProvider, "fetch_many", fake_attack_fetch_many)

    result = runner.invoke(
        app,
        [
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "Explanation for CVE-2021-44228" in result.stdout
    assert output_file.exists()
    assert '"priority_label": "Critical"' in output_file.read_text(encoding="utf-8")
