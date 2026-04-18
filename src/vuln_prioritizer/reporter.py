"""Report generation and terminal rendering."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.models import AnalysisContext, AttackData, EpssData, KevData, NvdData, PrioritizedFinding


def render_findings_table(findings: list[PrioritizedFinding]) -> Table:
    """Build the Rich table shown in the terminal."""
    table = Table(title="Vulnerability Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Priority")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Description", overflow="fold")

    for finding in findings:
        table.add_row(
            finding.cve_id,
            finding.priority_label,
            format_score(finding.cvss_base_score, digits=1),
            format_score(finding.epss, digits=3),
            "Yes" if finding.in_kev else "No",
            truncate_text(finding.description or "N.A.", 100),
        )

    return table


def generate_markdown_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown report."""
    summary_lines = [
        "# Vulnerability Prioritization Report",
        "",
        "## Run Metadata",
        f"- Generated at: `{context.generated_at}`",
        f"- Input file: `{context.input_path}`",
        f"- Output format: `{context.output_format}`",
        f"- ATT&CK context enabled: `{'yes' if context.attack_enabled else 'no'}`",
        "",
        "## Data Sources",
    ]
    summary_lines.extend(f"- {source}" for source in context.data_sources)

    summary_lines.extend(
        [
            "",
            "## Methodology",
            "- Critical: KEV or (EPSS >= 0.70 and CVSS >= 7.0)",
            "- High: EPSS >= 0.40 or CVSS >= 9.0",
            "- Medium: CVSS >= 7.0 or EPSS >= 0.10",
            "- Low: all remaining CVEs",
            "",
            "## Summary",
            f"- Total input rows: {context.total_input}",
            f"- Valid unique CVEs: {context.valid_input}",
            f"- Findings generated: {context.findings_count}",
        ]
    )
    for label in ("Critical", "High", "Medium", "Low"):
        summary_lines.append(f"- {label}: {context.counts_by_priority.get(label, 0)}")

    summary_lines.extend(["", "## Warnings"])
    if context.warnings:
        summary_lines.extend(f"- {warning}" for warning in context.warnings)
    else:
        summary_lines.append("- None")

    summary_lines.extend(
        [
            "",
            "## Findings",
            "",
            "| CVE ID | Description | CVSS | Severity | EPSS | EPSS Percentile | KEV | ATT&CK Techniques | Priority | Rationale | Recommended Action |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for finding in findings:
        summary_lines.append(
            "| "
            + " | ".join(
                [
                    finding.cve_id,
                    escape_pipes(finding.description or "N.A."),
                    format_score(finding.cvss_base_score, digits=1),
                    escape_pipes(finding.cvss_severity or "N.A."),
                    format_score(finding.epss, digits=3),
                    format_score(finding.epss_percentile, digits=3),
                    "Yes" if finding.in_kev else "No",
                    escape_pipes(", ".join(finding.attack_techniques) or "N.A."),
                    finding.priority_label,
                    escape_pipes(finding.rationale),
                    escape_pipes(finding.recommended_action),
                ]
            )
            + " |"
        )

    return "\n".join(summary_lines) + "\n"


def generate_json_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON export."""
    payload = {
        "metadata": context.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def write_output(path: Path, content: str) -> None:
    """Write report content to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def render_explain_view(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
) -> Group:
    """Build a detailed terminal view for one CVE."""
    signal_table = Table(title=f"Explanation for {finding.cve_id}", show_header=False)
    signal_table.add_column("Field", style="bold cyan")
    signal_table.add_column("Value")
    signal_table.add_row("Priority", finding.priority_label)
    signal_table.add_row("CVSS", format_score(finding.cvss_base_score, digits=1))
    signal_table.add_row("CVSS Severity", finding.cvss_severity or "N.A.")
    signal_table.add_row("EPSS", format_score(finding.epss, digits=3))
    signal_table.add_row("EPSS Percentile", format_score(finding.epss_percentile, digits=3))
    signal_table.add_row("In KEV", "Yes" if finding.in_kev else "No")
    signal_table.add_row("Published", nvd.published or "N.A.")
    signal_table.add_row("Last Modified", nvd.last_modified or "N.A.")
    signal_table.add_row("CWEs", comma_or_na(nvd.cwes))
    signal_table.add_row("ATT&CK Techniques", comma_or_na(attack.attack_techniques))
    signal_table.add_row("ATT&CK Tactics", comma_or_na(attack.attack_tactics))
    signal_table.add_row("KEV Vendor", kev.vendor_project or "N.A.")
    signal_table.add_row("KEV Product", kev.product or "N.A.")
    signal_table.add_row("KEV Required Action", kev.required_action or "N.A.")
    signal_table.add_row("KEV Due Date", kev.due_date or "N.A.")

    description_panel = Panel(normalize_whitespace(nvd.description or "N.A."), title="Description")
    rationale_panel = Panel(normalize_whitespace(finding.rationale), title="Rationale")
    action_panel = Panel(normalize_whitespace(finding.recommended_action), title="Recommended Action")

    references = nvd.references[:10]
    references_panel = Panel(
        "\n".join(f"- {reference}" for reference in references) if references else "N.A.",
        title="References (first 10)",
    )

    return Group(signal_table, description_panel, rationale_panel, action_panel, references_panel)


def generate_explain_markdown(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    context: AnalysisContext,
) -> str:
    """Render a single-CVE detailed Markdown explanation."""
    lines = [
        f"# CVE Explanation: {finding.cve_id}",
        "",
        "## Run Metadata",
        f"- Generated at: `{context.generated_at}`",
        f"- Output format: `{context.output_format}`",
        f"- ATT&CK context enabled: `{'yes' if context.attack_enabled else 'no'}`",
        f"- Cache enabled: `{'yes' if context.cache_enabled else 'no'}`",
    ]
    if context.cache_dir:
        lines.append(f"- Cache directory: `{context.cache_dir}`")

    lines.extend(
        [
            "",
            "## Signals",
            f"- Priority: `{finding.priority_label}`",
            f"- CVSS: `{format_score(finding.cvss_base_score, 1)}`",
            f"- CVSS Severity: `{finding.cvss_severity or 'N.A.'}`",
            f"- EPSS: `{format_score(finding.epss, 3)}`",
            f"- EPSS Percentile: `{format_score(finding.epss_percentile, 3)}`",
            f"- In KEV: `{'yes' if finding.in_kev else 'no'}`",
            f"- Published: `{nvd.published or 'N.A.'}`",
            f"- Last Modified: `{nvd.last_modified or 'N.A.'}`",
            f"- CWEs: {comma_or_na(nvd.cwes)}",
            f"- ATT&CK Techniques: {comma_or_na(attack.attack_techniques)}",
            f"- ATT&CK Tactics: {comma_or_na(attack.attack_tactics)}",
            "",
            "## Description",
            normalize_whitespace(nvd.description or "N.A."),
            "",
            "## Rationale",
            normalize_whitespace(finding.rationale),
            "",
            "## Recommended Action",
            normalize_whitespace(finding.recommended_action),
            "",
            "## KEV Metadata",
            f"- Vendor/Project: `{kev.vendor_project or 'N.A.'}`",
            f"- Product: `{kev.product or 'N.A.'}`",
            f"- Date Added: `{kev.date_added or 'N.A.'}`",
            f"- Required Action: `{kev.required_action or 'N.A.'}`",
            f"- Due Date: `{kev.due_date or 'N.A.'}`",
            "",
            "## References",
        ]
    )
    if nvd.references:
        lines.extend(f"- {reference}" for reference in nvd.references[:20])
    else:
        lines.append("- N.A.")
    return "\n".join(lines) + "\n"


def generate_explain_json(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    context: AnalysisContext,
) -> str:
    """Render a single-CVE detailed JSON explanation."""
    payload = {
        "metadata": context.model_dump(),
        "finding": finding.model_dump(),
        "nvd": nvd.model_dump(),
        "epss": epss.model_dump(),
        "kev": kev.model_dump(),
        "attack": attack.model_dump(),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def format_score(value: float | None, digits: int) -> str:
    """Format numeric output or return N.A."""
    if value is None:
        return "N.A."
    return f"{value:.{digits}f}"


def truncate_text(value: str, limit: int) -> str:
    """Keep long descriptions compact in the terminal view."""
    value = normalize_whitespace(value)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def escape_pipes(value: str) -> str:
    """Escape Markdown table separators."""
    return normalize_whitespace(value).replace("|", "\\|").strip()


def normalize_whitespace(value: str) -> str:
    """Flatten multi-line values for console and Markdown rendering."""
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def comma_or_na(values: list[str]) -> str:
    """Render lists consistently."""
    return ", ".join(values) if values else "N.A."
