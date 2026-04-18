from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.models import AnalysisContext, PrioritizedFinding
from vuln_prioritizer.reporter import generate_markdown_report, write_output


def test_markdown_report_contains_headers_and_na(tmp_path: Path) -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2024-0001",
        description=None,
        cvss_base_score=None,
        cvss_severity=None,
        epss=None,
        epss_percentile=None,
        in_kev=False,
        attack_techniques=[],
        priority_label="Low",
        priority_rank=4,
        rationale="FIRST EPSS data is unavailable.",
        recommended_action="Document the finding.",
    )
    context = AnalysisContext(
        input_path="data/sample_cves.txt",
        output_path="report.md",
        output_format="markdown",
        generated_at="2026-04-18T00:00:00+00:00",
        attack_enabled=False,
        warnings=[],
        total_input=1,
        valid_input=1,
        findings_count=1,
        counts_by_priority={"Low": 1},
        data_sources=["NVD", "EPSS", "KEV"],
    )

    report = generate_markdown_report([finding], context)

    assert "# Vulnerability Prioritization Report" in report
    assert "## Findings" in report
    assert "| CVE ID | Description | CVSS | Severity | EPSS |" in report
    assert "N.A." in report

    output_file = tmp_path / "report.md"
    write_output(output_file, report)
    assert output_file.read_text(encoding="utf-8") == report
