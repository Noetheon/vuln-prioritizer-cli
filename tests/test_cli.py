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
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "data" / "input_fixtures"
ATTACK_ROOT = Path(__file__).resolve().parents[1] / "data" / "attack"


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


def test_cli_compare_rejects_sarif_format(tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    assert "compare supports only --format json, markdown, table." in result.stdout


def test_cli_explain_rejects_sarif_format() -> None:
    result = runner.invoke(
        app,
        [
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    assert "explain supports only --format json, markdown, table." in result.stdout


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


def test_cli_analyze_sarif_export_and_fail_on(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "results.sarif"
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
            "sarif",
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "vuln-prioritizer"
    assert len(payload["runs"][0]["results"]) == 4


def test_cli_data_status_shows_cache_and_attack_metadata(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "data",
            "status",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--attack-mapping-file",
            str(ATTACK_ROOT / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(ATTACK_ROOT / "attack_techniques_enterprise_16.1_subset.json"),
        ],
    )

    assert result.exit_code == 0
    assert "Data Status" in result.stdout
    assert "Cache directory:" in result.stdout
    assert "ATT&CK source:" in result.stdout
    assert "ATT&CK version:" in result.stdout


def test_cli_report_html_renders_from_analysis_json(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    analysis_file = tmp_path / "analysis.json"
    html_file = tmp_path / "report.html"
    _install_fake_providers(monkeypatch)

    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(analysis_file),
            "--format",
            "json",
        ],
    )

    assert analyze_result.exit_code == 0

    html_result = runner.invoke(
        app,
        [
            "report",
            "html",
            "--input",
            str(analysis_file),
            "--output",
            str(html_file),
        ],
    )

    assert html_result.exit_code == 0
    html = html_file.read_text(encoding="utf-8")
    assert "<h1>vuln-prioritizer Executive Report</h1>" in html
    assert "CVE-2021-44228" in html


def test_cli_analyze_supports_trivy_vex_asset_context_and_custom_policy(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "scanner-analysis.json"
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,exposure,environment,owner,business_service",
                '"image","ghcr.io/acme/demo-app:1.0.0 (alpine 3.19)",'
                '"api-gateway","critical","internet-facing","prod",'
                '"platform-team","customer-login"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "profiles:",
                "  prod-urgent:",
                "    narrative_only: false",
                "    enterprise_escalation: true",
                "    internet_facing_boost: true",
                "    prod_asset_boost: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "trivy_report.json"),
            "--input-format",
            "trivy-json",
            "--asset-context",
            str(asset_context_file),
            "--vex-file",
            str(FIXTURE_ROOT / "openvex_statements.json"),
            "--policy-file",
            str(policy_file),
            "--policy-profile",
            "prod-urgent",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["metadata"]["input_format"] == "trivy-json"
    assert payload["metadata"]["policy_profile"] == "prod-urgent"
    assert payload["metadata"]["suppressed_by_vex"] == 1
    assert payload["metadata"]["under_investigation_count"] == 1
    assert payload["metadata"]["source_stats"] == {"trivy-json": 3}
    assert payload["metadata"]["schema_version"] == "1.0.0"

    finding_ids = [item["cve_id"] for item in payload["findings"]]
    assert "CVE-2023-34362" not in finding_ids
    assert finding_ids == ["CVE-2024-3094", "CVE-2024-4577"]

    top_finding = payload["findings"][0]
    assert top_finding["highest_asset_criticality"] == "critical"
    assert top_finding["asset_count"] == 1
    assert (
        top_finding["context_recommendation"]
        == "Escalate validation and remediation because context indicates "
        "internet-facing exposure, production environment."
    )


def test_cli_analyze_show_suppressed_keeps_vex_hidden_findings_visible(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "show-suppressed.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "trivy_report.json"),
            "--input-format",
            "trivy-json",
            "--vex-file",
            str(FIXTURE_ROOT / "openvex_statements.json"),
            "--show-suppressed",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["active_filters"] == ["show-suppressed"]

    suppressed = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2023-34362")
    assert suppressed["suppressed_by_vex"] is True
    assert suppressed["provenance"]["vex_statuses"] == {"not_affected": 1}


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
