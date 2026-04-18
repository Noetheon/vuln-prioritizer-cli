"""Report generation and terminal rendering."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    ComparisonFinding,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
)


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


def render_compare_table(comparisons: list[ComparisonFinding]) -> Table:
    """Build the Rich comparison table shown in the terminal."""
    table = Table(title="CVSS-only vs Enriched Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("CVSS-only")
    table.add_column("Enriched")
    table.add_column("Change")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Reason", overflow="fold")

    for row in comparisons:
        table.add_row(
            row.cve_id,
            row.cvss_only_label,
            row.enriched_label,
            format_change(row.delta_rank),
            format_score(row.cvss_base_score, digits=1),
            format_score(row.epss, digits=3),
            "Yes" if row.in_kev else "No",
            truncate_text(row.change_reason, 110),
        )

    return table


def render_summary_panel(
    context: AnalysisContext,
    *,
    mode: str = "analyze",
    changed_count: int | None = None,
) -> Panel:
    """Render the shared terminal summary panel."""
    lines = [
        f"Total input rows: {context.total_input}",
        f"Valid unique CVEs: {context.valid_input}",
        f"Findings shown: {context.findings_count}",
        f"Filtered out: {context.filtered_out_count}",
        f"NVD hits: {context.nvd_hits}/{context.valid_input}",
        f"EPSS hits: {context.epss_hits}/{context.valid_input}",
        f"KEV hits: {context.kev_hits}/{context.valid_input}",
    ]
    if context.attack_enabled:
        lines.append(f"ATT&CK hits: {context.attack_hits}/{context.valid_input}")

    if mode == "compare" and changed_count is not None:
        unchanged_count = max(context.findings_count - changed_count, 0)
        lines.extend(
            [
                f"Changed rows: {changed_count}",
                f"Unchanged rows: {unchanged_count}",
            ]
        )

    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"{label}: {context.counts_by_priority.get(label, 0)}")

    if context.active_filters:
        lines.append("Active filters: " + ", ".join(context.active_filters))
    if context.policy_overrides:
        lines.append("Policy overrides: " + ", ".join(context.policy_overrides))

    return Panel("\n".join(lines), title="Summary")


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
    ]
    if context.attack_mapping_file:
        summary_lines.append(f"- ATT&CK mapping file: `{context.attack_mapping_file}`")

    summary_lines.extend(["", "## Data Sources"])
    summary_lines.extend(f"- {source}" for source in context.data_sources)

    summary_lines.extend(
        [
            "",
            "## Methodology",
        ]
    )
    summary_lines.extend(f"- {line}" for line in context.priority_policy.methodology_lines())

    summary_lines.extend(
        [
            "",
            "## Summary",
            f"- Total input rows: {context.total_input}",
            f"- Valid unique CVEs: {context.valid_input}",
            f"- Findings shown: {context.findings_count}",
            f"- Filtered out: {context.filtered_out_count}",
            f"- NVD hits: {context.nvd_hits}/{context.valid_input}",
            f"- EPSS hits: {context.epss_hits}/{context.valid_input}",
            f"- KEV hits: {context.kev_hits}/{context.valid_input}",
        ]
    )
    if context.attack_enabled:
        summary_lines.append(f"- ATT&CK hits: {context.attack_hits}/{context.valid_input}")
    for label in ("Critical", "High", "Medium", "Low"):
        summary_lines.append(f"- {label}: {context.counts_by_priority.get(label, 0)}")

    summary_lines.extend(["- Active filters: " + format_filters(context.active_filters)])
    summary_lines.extend(["- Policy overrides: " + format_filters(context.policy_overrides)])

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
            "| CVE ID | Description | CVSS | Severity | EPSS | EPSS Percentile "
            "| KEV | ATT&CK Techniques | Priority | Rationale | Recommended Action |",
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


def generate_compare_markdown(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown comparison report."""
    changed_count = sum(1 for row in comparisons if row.changed)
    lines = [
        "# Vulnerability Priority Comparison Report",
        "",
        "## Run Metadata",
        f"- Generated at: `{context.generated_at}`",
        f"- Input file: `{context.input_path}`",
        f"- Output format: `{context.output_format}`",
        f"- ATT&CK context enabled: `{'yes' if context.attack_enabled else 'no'}`",
    ]
    if context.attack_mapping_file:
        lines.append(f"- ATT&CK mapping file: `{context.attack_mapping_file}`")

    lines.extend(
        [
            "",
            "## Baselines",
            "- CVSS-only: Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low otherwise",
            "- Enriched thresholds:",
        ]
    )
    lines.extend(f"  - {line}" for line in context.priority_policy.methodology_lines()[:3])

    lines.extend(["", "## Data Sources"])
    lines.extend(f"- {source}" for source in context.data_sources)
    lines.extend(
        [
            "",
            "## Summary",
            f"- Total input rows: {context.total_input}",
            f"- Valid unique CVEs: {context.valid_input}",
            f"- Findings shown: {context.findings_count}",
            f"- Filtered out: {context.filtered_out_count}",
            f"- Changed rows: {changed_count}",
            f"- Unchanged rows: {max(context.findings_count - changed_count, 0)}",
            f"- NVD hits: {context.nvd_hits}/{context.valid_input}",
            f"- EPSS hits: {context.epss_hits}/{context.valid_input}",
            f"- KEV hits: {context.kev_hits}/{context.valid_input}",
            f"- Active filters: {format_filters(context.active_filters)}",
            f"- Policy overrides: {format_filters(context.policy_overrides)}",
        ]
    )
    if context.attack_enabled:
        lines.append(f"- ATT&CK hits: {context.attack_hits}/{context.valid_input}")

    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"- Enriched {label}: {context.counts_by_priority.get(label, 0)}")

    lines.extend(["", "## Warnings"])
    if context.warnings:
        lines.extend(f"- {warning}" for warning in context.warnings)
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Comparison",
            "",
            "| CVE ID | Description | CVSS-only | Enriched | Delta | Changed | CVSS | EPSS "
            "| KEV | Reason |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for row in comparisons:
        lines.append(
            "| "
            + " | ".join(
                [
                    row.cve_id,
                    escape_pipes(row.description or "N.A."),
                    row.cvss_only_label,
                    row.enriched_label,
                    escape_pipes(format_change(row.delta_rank)),
                    "Yes" if row.changed else "No",
                    format_score(row.cvss_base_score, digits=1),
                    format_score(row.epss, digits=3),
                    "Yes" if row.in_kev else "No",
                    escape_pipes(row.change_reason),
                ]
            )
            + " |"
        )

    return "\n".join(lines) + "\n"


def generate_compare_json(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON comparison export."""
    payload = {
        "metadata": context.model_dump(),
        "comparisons": [row.model_dump() for row in comparisons],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def write_output(path: Path, content: str) -> None:
    """Write report content to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized_content = content if content.endswith("\n") else content + "\n"
    path.write_text(normalized_content, encoding="utf-8")


def render_explain_view(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    comparison: ComparisonFinding | None = None,
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
    signal_table.add_row("ATT&CK Note", attack.attack_note or "N.A.")
    signal_table.add_row("KEV Vendor", kev.vendor_project or "N.A.")
    signal_table.add_row("KEV Product", kev.product or "N.A.")
    signal_table.add_row("KEV Required Action", kev.required_action or "N.A.")
    signal_table.add_row("KEV Due Date", kev.due_date or "N.A.")
    if comparison is not None:
        signal_table.add_row("CVSS-only Baseline", comparison.cvss_only_label)
        signal_table.add_row("Delta vs Baseline", format_change(comparison.delta_rank))

    description_panel = Panel(
        normalize_whitespace(nvd.description or "N.A."),
        title="Description",
    )
    rationale_panel = Panel(normalize_whitespace(finding.rationale), title="Rationale")
    comparison_panel = Panel(
        normalize_whitespace(comparison.change_reason if comparison is not None else "N.A."),
        title="Comparison",
    )
    action_panel = Panel(
        normalize_whitespace(finding.recommended_action), title="Recommended Action"
    )

    references = nvd.references[:10]
    references_panel = Panel(
        "\n".join(f"- {reference}" for reference in references) if references else "N.A.",
        title="References (first 10)",
    )

    return Group(
        signal_table,
        description_panel,
        rationale_panel,
        comparison_panel,
        action_panel,
        references_panel,
    )


def generate_explain_markdown(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    context: AnalysisContext,
    comparison: ComparisonFinding | None = None,
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
    if context.attack_mapping_file:
        lines.append(f"- ATT&CK mapping file: `{context.attack_mapping_file}`")
    lines.append(f"- Policy overrides: `{format_filters(context.policy_overrides)}`")

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
            f"- ATT&CK Note: {attack.attack_note or 'N.A.'}",
            "",
            "## Description",
            normalize_whitespace(nvd.description or "N.A."),
            "",
            "## Rationale",
            normalize_whitespace(finding.rationale),
            "",
            "## Comparison",
            f"- CVSS-only Baseline: `{comparison.cvss_only_label if comparison else 'N.A.'}`",
            (
                f"- Enriched Priority: `"
                f"{comparison.enriched_label if comparison else finding.priority_label}`"
            ),
            (
                f"- Delta vs Baseline: `"
                f"{format_change(comparison.delta_rank) if comparison else 'N.A.'}`"
            ),
            normalize_whitespace(comparison.change_reason if comparison is not None else "N.A."),
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
    comparison: ComparisonFinding | None = None,
) -> str:
    """Render a single-CVE detailed JSON explanation."""
    payload = {
        "metadata": context.model_dump(),
        "finding": finding.model_dump(),
        "nvd": nvd.model_dump(),
        "epss": epss.model_dump(),
        "kev": kev.model_dump(),
        "attack": attack.model_dump(),
        "comparison": comparison.model_dump() if comparison is not None else None,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def format_score(value: float | None, digits: int) -> str:
    """Format numeric output or return N.A."""
    if value is None:
        return "N.A."
    return f"{value:.{digits}f}"


def format_change(delta_rank: int) -> str:
    """Render the comparison delta for terminal and Markdown output."""
    if delta_rank > 0:
        return f"Up {delta_rank}"
    if delta_rank < 0:
        return f"Down {abs(delta_rank)}"
    return "No change"


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


def format_filters(active_filters: list[str]) -> str:
    """Render filters consistently across Markdown and terminal output."""
    return ", ".join(active_filters) if active_filters else "None"
