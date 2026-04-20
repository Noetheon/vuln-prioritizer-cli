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
    AttackMapping,
    AttackSummary,
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
    table.add_column("ATT&CK")
    table.add_column("Attack Relevance")
    table.add_column("Description", overflow="fold")

    for finding in findings:
        table.add_row(
            finding.cve_id,
            finding.priority_label,
            format_score(finding.cvss_base_score, digits=1),
            format_score(finding.epss, digits=3),
            "Yes" if finding.in_kev else "No",
            _format_attack_indicator(finding.attack_mapped, len(finding.attack_technique_details)),
            finding.attack_relevance,
            truncate_text(finding.description or "N.A.", 90),
        )

    return table


def render_compare_table(comparisons: list[ComparisonFinding]) -> Table:
    """Build the Rich comparison table shown in the terminal."""
    table = Table(title="CVSS-only vs Enriched Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("CVSS-only")
    table.add_column("Enriched")
    table.add_column("ATT&CK")
    table.add_column("Relevance")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Reason", overflow="fold")

    for row in comparisons:
        table.add_row(
            row.cve_id,
            row.cvss_only_label,
            row.enriched_label,
            _format_attack_indicator(row.attack_mapped, row.mapped_technique_count),
            row.attack_relevance,
            format_score(row.cvss_base_score, digits=1),
            format_score(row.epss, digits=3),
            "Yes" if row.in_kev else "No",
            truncate_text(row.change_reason, 100),
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
        lines.extend(
            [
                f"ATT&CK source: {context.attack_source}",
                f"ATT&CK hits: {context.attack_hits}/{context.valid_input}",
                f"Mapped CVEs shown: {context.attack_summary.mapped_cves}",
                f"Unmapped CVEs shown: {context.attack_summary.unmapped_cves}",
            ]
        )
        if context.mapping_framework_version:
            lines.append(f"Mapping version: {context.mapping_framework_version}")
        if context.attack_version:
            lines.append(f"ATT&CK version: {context.attack_version}")

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
    lines = [
        "# Vulnerability Prioritization Report",
        "",
        "## Run Metadata",
    ]
    lines.extend(_run_metadata_lines(context))
    lines.extend(["", "## Data Sources"])
    lines.extend(f"- {source}" for source in context.data_sources)
    lines.extend(["", "## Methodology"])
    lines.extend(f"- {line}" for line in context.priority_policy.methodology_lines())
    lines.extend(_attack_methodology_lines(context))
    lines.extend(["", "## Summary"])
    lines.extend(_summary_lines(context))
    lines.extend(["", "## ATT&CK Context Summary"])
    lines.extend(_attack_summary_lines(context.attack_summary, context.attack_enabled))
    lines.extend(["", "## Warnings"])
    lines.extend(_warning_lines(context.warnings))
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | "
            "KEV | ATT&CK | Attack Relevance | Priority | Rationale | Recommended Action |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    finding.cve_id,
                    escape_pipes(finding.description or "N.A."),
                    format_score(finding.cvss_base_score, digits=1),
                    escape_pipes(finding.cvss_severity or "N.A."),
                    escape_pipes(finding.cvss_version or "N.A."),
                    format_score(finding.epss, digits=3),
                    format_score(finding.epss_percentile, digits=3),
                    "Yes" if finding.in_kev else "No",
                    escape_pipes(
                        _format_attack_indicator(
                            finding.attack_mapped,
                            len(finding.attack_technique_details),
                        )
                    ),
                    escape_pipes(finding.attack_relevance),
                    finding.priority_label,
                    escape_pipes(finding.rationale),
                    escape_pipes(finding.recommended_action),
                ]
            )
            + " |"
        )

    lines.extend(["", "## ATT&CK-mapped CVEs", ""])
    if any(finding.attack_mapped for finding in findings):
        lines.extend(
            [
                "| CVE ID | Mapping Types | Techniques | Tactics | Capability Groups "
                "| ATT&CK Note |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            if not finding.attack_mapped:
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        finding.cve_id,
                        escape_pipes(", ".join(_mapping_types(finding.attack_mappings)) or "N.A."),
                        escape_pipes(", ".join(finding.attack_techniques) or "N.A."),
                        escape_pipes(", ".join(finding.attack_tactics) or "N.A."),
                        escape_pipes(
                            ", ".join(_capability_groups(finding.attack_mappings)) or "N.A."
                        ),
                        escape_pipes(finding.attack_note or "N.A."),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No mapped CVEs were included in this export.")

    return "\n".join(lines) + "\n"


def generate_json_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON export."""
    payload = {
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
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
    ]
    lines.extend(_run_metadata_lines(context))
    lines.extend(
        [
            "",
            "## Baselines",
            "- CVSS-only: Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low otherwise",
            "- Enriched thresholds:",
        ]
    )
    lines.extend(f"- {line}" for line in context.priority_policy.methodology_lines())
    lines.extend(_attack_methodology_lines(context))
    lines.extend(["", "## Data Sources"])
    lines.extend(f"- {source}" for source in context.data_sources)
    lines.extend(["", "## Summary"])
    lines.extend(_summary_lines(context))
    lines.append(f"- Changed rows: {changed_count}")
    lines.append(f"- Unchanged rows: {max(context.findings_count - changed_count, 0)}")
    lines.extend(["", "## ATT&CK Context Summary"])
    lines.extend(_attack_summary_lines(context.attack_summary, context.attack_enabled))
    lines.extend(["", "## Warnings"])
    lines.extend(_warning_lines(context.warnings))
    lines.extend(
        [
            "",
            "## Comparison",
            "",
            "| CVE ID | Description | CVSS-only | Enriched | ATT&CK | Attack Relevance | "
            "Delta | Changed | CVSS | EPSS | KEV | Reason |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
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
                    escape_pipes(
                        _format_attack_indicator(
                            row.attack_mapped,
                            row.mapped_technique_count,
                        )
                    ),
                    escape_pipes(row.attack_relevance),
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
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
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
    signal_table.add_row("CVSS Version", finding.cvss_version or "N.A.")
    signal_table.add_row("EPSS", format_score(finding.epss, digits=3))
    signal_table.add_row("EPSS Percentile", format_score(finding.epss_percentile, digits=3))
    signal_table.add_row("In KEV", "Yes" if finding.in_kev else "No")
    signal_table.add_row("Published", nvd.published or "N.A.")
    signal_table.add_row("Last Modified", nvd.last_modified or "N.A.")
    signal_table.add_row("CWEs", comma_or_na(nvd.cwes))
    signal_table.add_row("ATT&CK Source", attack.source)
    signal_table.add_row("ATT&CK Relevance", attack.attack_relevance)
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

    mappings_table = Table(title="ATT&CK Mappings")
    mappings_table.add_column("Type")
    mappings_table.add_column("Technique")
    mappings_table.add_column("Tactics")
    mappings_table.add_column("Capability Group")

    if attack.mappings:
        tactics_by_id = {
            technique.attack_object_id: comma_or_na(technique.tactics)
            for technique in attack.techniques
        }
        for mapping in attack.mappings:
            mappings_table.add_row(
                mapping.mapping_type or "N.A.",
                f"{mapping.attack_object_id} {mapping.attack_object_name or ''}".strip(),
                tactics_by_id.get(mapping.attack_object_id, "N.A."),
                mapping.capability_group or "N.A.",
            )
    else:
        mappings_table.add_row("N.A.", "No CTID mapping", "N.A.", "N.A.")

    description_panel = Panel(
        normalize_whitespace(nvd.description or "N.A."),
        title="Description",
    )
    rationale_panel = Panel(normalize_whitespace(finding.rationale), title="Rationale")
    attack_panel = Panel(
        normalize_whitespace(attack.attack_rationale or "No ATT&CK rationale available."),
        title="ATT&CK Context",
    )
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
        mappings_table,
        description_panel,
        rationale_panel,
        attack_panel,
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
    ]
    lines.extend(_run_metadata_lines(context))
    lines.extend(
        [
            "",
            "## Signals",
            f"- Priority: `{finding.priority_label}`",
            f"- CVSS: `{format_score(finding.cvss_base_score, 1)}`",
            f"- CVSS Severity: `{finding.cvss_severity or 'N.A.'}`",
            f"- CVSS Version: `{finding.cvss_version or 'N.A.'}`",
            f"- EPSS: `{format_score(finding.epss, 3)}`",
            f"- EPSS Percentile: `{format_score(finding.epss_percentile, 3)}`",
            f"- In KEV: `{'yes' if finding.in_kev else 'no'}`",
            f"- Published: `{nvd.published or 'N.A.'}`",
            f"- Last Modified: `{nvd.last_modified or 'N.A.'}`",
            f"- CWEs: {comma_or_na(nvd.cwes)}",
            f"- ATT&CK Source: `{attack.source}`",
            f"- ATT&CK Relevance: `{attack.attack_relevance}`",
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
            "## ATT&CK Context",
            normalize_whitespace(attack.attack_rationale or "No ATT&CK rationale available."),
            "",
            "| Mapping Type | Technique | Tactics | Capability Group | Comments |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    if attack.mappings:
        tactics_by_id = {
            technique.attack_object_id: comma_or_na(technique.tactics)
            for technique in attack.techniques
        }
        for mapping in attack.mappings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_pipes(mapping.mapping_type or "N.A."),
                        escape_pipes(
                            f"{mapping.attack_object_id} {mapping.attack_object_name or ''}".strip()
                        ),
                        escape_pipes(tactics_by_id.get(mapping.attack_object_id, "N.A.")),
                        escape_pipes(mapping.capability_group or "N.A."),
                        escape_pipes(mapping.comments or "N.A."),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| N.A. | No CTID mapping | N.A. | N.A. | N.A. |")

    lines.extend(
        [
            "",
            "## Comparison",
            f"- CVSS-only Baseline: `{comparison.cvss_only_label if comparison else 'N.A.'}`",
            "- Enriched Priority: `"
            f"{comparison.enriched_label if comparison else finding.priority_label}`",
            "- Delta vs Baseline: `"
            f"{format_change(comparison.delta_rank) if comparison else 'N.A.'}`",
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
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
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


def _run_metadata_lines(context: AnalysisContext) -> list[str]:
    lines = [
        f"- Generated at: `{context.generated_at}`",
        f"- Input file: `{context.input_path}`",
        f"- Output format: `{context.output_format}`",
        f"- ATT&CK context enabled: `{'yes' if context.attack_enabled else 'no'}`",
        f"- ATT&CK source: `{context.attack_source}`",
        f"- Cache enabled: `{'yes' if context.cache_enabled else 'no'}`",
    ]
    if context.output_path:
        lines.append(f"- Output path: `{context.output_path}`")
    if context.cache_dir:
        lines.append(f"- Cache directory: `{context.cache_dir}`")
    if context.attack_mapping_file:
        lines.append(f"- ATT&CK mapping file: `{context.attack_mapping_file}`")
    if context.attack_technique_metadata_file:
        lines.append(
            f"- ATT&CK technique metadata file: `{context.attack_technique_metadata_file}`"
        )
    if context.mapping_framework:
        lines.append(f"- ATT&CK mapping framework: `{context.mapping_framework}`")
    if context.mapping_framework_version:
        lines.append(f"- ATT&CK mapping framework version: `{context.mapping_framework_version}`")
    if context.attack_version:
        lines.append(f"- ATT&CK version: `{context.attack_version}`")
    if context.attack_domain:
        lines.append(f"- ATT&CK domain: `{context.attack_domain}`")
    lines.append(f"- Policy overrides: `{format_filters(context.policy_overrides)}`")
    return lines


def _summary_lines(context: AnalysisContext) -> list[str]:
    lines = [
        f"- Total input rows: {context.total_input}",
        f"- Valid unique CVEs: {context.valid_input}",
        f"- Findings shown: {context.findings_count}",
        f"- Filtered out: {context.filtered_out_count}",
        f"- NVD hits: {context.nvd_hits}/{context.valid_input}",
        f"- EPSS hits: {context.epss_hits}/{context.valid_input}",
        f"- KEV hits: {context.kev_hits}/{context.valid_input}",
        f"- ATT&CK hits: {context.attack_hits}/{context.valid_input}",
    ]
    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"- {label}: {context.counts_by_priority.get(label, 0)}")
    lines.append(f"- Active filters: {format_filters(context.active_filters)}")
    return lines


def _attack_methodology_lines(context: AnalysisContext) -> list[str]:
    if not context.attack_enabled:
        return ["- ATT&CK context was disabled for this run."]
    return [
        "- ATT&CK context is sourced from explicit local files only.",
        "- No heuristic or LLM-generated CVE-to-ATT&CK mapping is performed.",
        "- ATT&CK relevance is reported separately and does not change the primary priority score.",
    ]


def _attack_summary_lines(summary: AttackSummary, enabled: bool) -> list[str]:
    if not enabled:
        return ["ATT&CK context was disabled for this export."]

    lines = [
        f"- CVEs with ATT&CK mappings: {summary.mapped_cves}",
        f"- Unmapped CVEs: {summary.unmapped_cves}",
        "- Mapping type distribution: " + _format_distribution(summary.mapping_type_distribution),
        "- Technique distribution: " + _format_distribution(summary.technique_distribution),
        "- Tactic distribution: " + _format_distribution(summary.tactic_distribution),
        "- ATT&CK mappings are imported from explicit local CTID or local CSV files only.",
    ]
    return lines


def _warning_lines(warnings: list[str]) -> list[str]:
    if warnings:
        return [f"- {warning}" for warning in warnings]
    return ["- None"]


def _format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "None"
    return ", ".join(
        f"{key}: {value}"
        for key, value in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    )


def _format_attack_indicator(mapped: bool, technique_count: int) -> str:
    if not mapped:
        return "Unmapped"
    return f"{technique_count} technique(s)"


def _mapping_types(mappings: list[AttackMapping]) -> list[str]:
    values: list[str] = []
    for mapping in mappings:
        if mapping.mapping_type and mapping.mapping_type not in values:
            values.append(mapping.mapping_type)
    return values


def _capability_groups(mappings: list[AttackMapping]) -> list[str]:
    values: list[str] = []
    for mapping in mappings:
        if mapping.capability_group and mapping.capability_group not in values:
            values.append(mapping.capability_group)
    return values
