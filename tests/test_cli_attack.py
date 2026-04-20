from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vuln_prioritizer.cli import app
from vuln_prioritizer.models import EpssData, KevData, NvdData
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner = CliRunner()

ATTACK_MAPPING_FILE = Path("data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json")
ATTACK_METADATA_FILE = Path("data/attack/attack_techniques_enterprise_16.1_subset.json")


def test_cli_analyze_supports_ctid_attack_source(monkeypatch, tmp_path: Path) -> None:
    input_file = tmp_path / "attack.txt"
    input_file.write_text(
        "CVE-2023-34362\nCVE-2024-4577\nCVE-2024-3094\n",
        encoding="utf-8",
    )
    output_file = tmp_path / "attack-report.json"
    _install_fake_network_providers(monkeypatch)

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
            "--attack-source",
            "ctid-json",
            "--attack-mapping-file",
            str(ATTACK_MAPPING_FILE),
            "--attack-technique-metadata-file",
            str(ATTACK_METADATA_FILE),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["attack_source"] == "ctid-mappings-explorer"
    assert payload["attack_summary"]["mapped_cves"] == 2
    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2023-34362")
    assert finding["attack_mapped"] is True
    assert finding["attack_relevance"] == "High"
    assert finding["attack_techniques"][0] == "T1190"


def test_cli_attack_coverage_json_works_offline(tmp_path: Path) -> None:
    output_file = tmp_path / "coverage.json"

    result = runner.invoke(
        app,
        [
            "attack",
            "coverage",
            "--input",
            "data/sample_cves_mixed.txt",
            "--attack-mapping-file",
            str(ATTACK_MAPPING_FILE),
            "--attack-technique-metadata-file",
            str(ATTACK_METADATA_FILE),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"]["mapped_cves"] == 3
    assert payload["summary"]["unmapped_cves"] == 2
    assert payload["metadata"]["source"] == "ctid-mappings-explorer"


def test_cli_attack_navigator_layer_exports_json(tmp_path: Path) -> None:
    output_file = tmp_path / "navigator.json"

    result = runner.invoke(
        app,
        [
            "attack",
            "navigator-layer",
            "--input",
            "data/sample_cves_attack.txt",
            "--attack-mapping-file",
            str(ATTACK_MAPPING_FILE),
            "--attack-technique-metadata-file",
            str(ATTACK_METADATA_FILE),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["domain"] == "enterprise-attack"
    assert payload["techniques"]
    assert payload["techniques"][0]["score"] >= 1


def _install_fake_network_providers(monkeypatch) -> None:  # noqa: ANN001
    def fake_nvd_fetch_many(self, cve_ids):  # noqa: ANN001
        return (
            {
                cve_id: NvdData(
                    cve_id=cve_id,
                    description=f"Synthetic description for {cve_id}",
                    cvss_base_score=8.0 if cve_id != "CVE-2024-3094" else 5.0,
                    cvss_severity="HIGH" if cve_id != "CVE-2024-3094" else "MEDIUM",
                    cvss_version="3.1",
                )
                for cve_id in cve_ids
            },
            [],
        )

    def fake_epss_fetch_many(self, cve_ids):  # noqa: ANN001
        return (
            {cve_id: EpssData(cve_id=cve_id, epss=0.42, percentile=0.9) for cve_id in cve_ids},
            [],
        )

    def fake_kev_fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001
        return ({cve_id: KevData(cve_id=cve_id, in_kev=False) for cve_id in cve_ids}, [])

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)
