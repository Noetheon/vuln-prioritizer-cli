from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vuln_prioritizer.cli import app
from vuln_prioritizer.models import AttackData, EpssData, KevData, NvdData
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner = CliRunner()


def test_cli_analyze_end_to_end_with_mocked_providers(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "report.md"
    _install_fake_providers(monkeypatch)

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
    assert "Vulnerability Prioritization" in result.stdout
    assert "Total input rows: 4" in result.stdout
    assert output_file.exists()
    report = output_file.read_text(encoding="utf-8")
    assert "# Vulnerability Prioritization Report" in report
    assert "- Findings shown: 4" in report
    assert "- NVD hits: 4/4" in report
    assert "## ATT&CK Context Summary" in report


def test_cli_analyze_supports_priority_threshold_filters_and_sorting(
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "report.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--priority",
            "high",
            "--min-epss",
            "0.40",
            "--sort-by",
            "cve",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert [item["cve_id"] for item in payload["findings"]] == [
        "CVE-2023-44487",
        "CVE-2024-3094",
    ]
    assert payload["metadata"]["filtered_out_count"] == 2
    assert payload["metadata"]["active_filters"] == ["priority=High", "min-epss>=0.400"]
    assert payload["attack_summary"]["mapped_cves"] == 0


def test_cli_analyze_supports_kev_only_and_min_cvss(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "filtered.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--kev-only",
            "--min-cvss",
            "7.0",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert [item["cve_id"] for item in payload["findings"]] == ["CVE-2021-44228"]
    assert payload["metadata"]["active_filters"] == ["kev-only", "min-cvss>=7.0"]


def test_cli_compare_table_mode(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--sort-by",
            "cve",
        ],
    )

    assert result.exit_code == 0
    assert "CVSS-only vs Enriched Prioritization" in result.stdout
    assert "Changed rows:" in result.stdout
    assert "Unchanged rows:" in result.stdout


def test_cli_compare_json_export(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "compare.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--priority",
            "high",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert "comparisons" in payload
    assert payload["metadata"]["active_filters"] == ["priority=High"]
    assert any(item["changed"] for item in payload["comparisons"])
    assert payload["attack_summary"]["mapped_cves"] == 0


def test_cli_analyze_supports_custom_policy_thresholds(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "policy.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--high-epss-threshold",
            "0.30",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2024-0004")
    assert finding["priority_label"] == "High"
    assert payload["metadata"]["policy_overrides"] == ["high-epss=0.300"]


def test_cli_rejects_invalid_policy_thresholds(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--high-epss-threshold",
            "0.30",
            "--medium-epss-threshold",
            "0.35",
        ],
    )

    assert result.exit_code == 2
    assert "EPSS thresholds must descend" in result.stdout


def test_cli_compare_rejects_output_with_table_format(tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--output",
            str(tmp_path / "compare.txt"),
            "--format",
            "table",
        ],
    )

    assert result.exit_code == 2
    assert "--output cannot be used together with --format table." in result.stdout


def test_cli_explain_end_to_end_with_mocked_providers(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "explain.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--offline-attack-file",
            str(tmp_path / "attack.csv"),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "Explanation for CVE-2021-44228" in result.stdout
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["finding"]["priority_label"] == "Critical"
    assert payload["comparison"]["cvss_only_label"] == "Critical"
    assert payload["attack"]["attack_note"] == "Representative demo mapping note."
    assert payload["metadata"]["attack_source"] == "local-csv"


def _write_input_file(tmp_path: Path) -> Path:
    input_file = tmp_path / "cves.txt"
    input_file.write_text(
        "\n".join(
            [
                "CVE-2021-44228",
                "CVE-2023-44487",
                "CVE-2024-3094",
                "CVE-2024-0004",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return input_file


def _install_fake_providers(monkeypatch) -> None:  # noqa: ANN001
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
                "CVE-2024-3094": NvdData(
                    cve_id="CVE-2024-3094",
                    description="XZ Utils backdoor",
                    cvss_base_score=5.0,
                    cvss_severity="MEDIUM",
                ),
                "CVE-2024-0004": NvdData(
                    cve_id="CVE-2024-0004",
                    description="Synthetic medium case",
                    cvss_base_score=8.0,
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
                "CVE-2024-3094": EpssData(
                    cve_id="CVE-2024-3094",
                    epss=0.45,
                    percentile=0.88,
                ),
                "CVE-2024-0004": EpssData(
                    cve_id="CVE-2024-0004",
                    epss=0.30,
                    percentile=0.66,
                ),
            },
            [],
        )

    def fake_kev_fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001
        return (
            {
                "CVE-2021-44228": KevData(cve_id="CVE-2021-44228", in_kev=True),
                "CVE-2023-44487": KevData(cve_id="CVE-2023-44487", in_kev=False),
                "CVE-2024-3094": KevData(cve_id="CVE-2024-3094", in_kev=False),
                "CVE-2024-0004": KevData(cve_id="CVE-2024-0004", in_kev=False),
            },
            [],
        )

    def fake_attack_fetch_many(  # noqa: ANN001
        self,
        cve_ids,
        *,
        enabled,
        source="none",
        mapping_file=None,
        technique_metadata_file=None,
        offline_file=None,
    ):
        return (
            {
                "CVE-2021-44228": AttackData(
                    cve_id="CVE-2021-44228",
                    mapped=enabled,
                    source="local-csv" if enabled else source,
                    attack_relevance="Medium" if enabled else "Unmapped",
                    attack_rationale=(
                        "Legacy local ATT&CK CSV context is available for this CVE."
                        if enabled
                        else "No ATT&CK context was provided for this CVE."
                    ),
                    attack_techniques=["T1190"],
                    attack_tactics=["Initial Access"],
                    attack_note="Representative demo mapping note.",
                )
            }
            if enabled
            else {},
            {
                "source": "local-csv" if enabled else "none",
                "mapping_file": (
                    str(mapping_file or offline_file) if (mapping_file or offline_file) else None
                ),
                "technique_metadata_file": (
                    str(technique_metadata_file) if technique_metadata_file is not None else None
                ),
                "source_version": None,
                "attack_version": None,
                "domain": None,
                "mapping_framework": None,
                "mapping_framework_version": None,
            },
            [],
        )

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)
    monkeypatch.setattr(AttackProvider, "fetch_many", fake_attack_fetch_many)
