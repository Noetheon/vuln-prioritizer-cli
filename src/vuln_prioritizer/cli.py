"""Typer-based command line interface."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import typer
from dotenv import load_dotenv
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    DATA_SOURCES,
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.inputs import (
    InputLoader,
    build_inline_input,
    load_asset_context_file,
    load_vex_files,
)
from vuln_prioritizer.models import (
    AnalysisContext,
    AssetContextRecord,
    AttackData,
    AttackSummary,
    ContextPolicyProfile,
    EnrichmentResult,
    EpssData,
    KevData,
    NvdData,
    ParsedInput,
    PrioritizedFinding,
    PriorityPolicy,
    VexStatement,
)
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider
from vuln_prioritizer.reporter import (
    generate_compare_json,
    generate_compare_markdown,
    generate_explain_json,
    generate_explain_markdown,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_sarif_report,
    render_compare_table,
    render_explain_view,
    render_findings_table,
    render_summary_panel,
    write_output,
)
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService
from vuln_prioritizer.services.contextualization import (
    aggregate_provenance,
    load_context_profile,
)
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id

app = typer.Typer(help="Prioritize known CVEs with NVD, EPSS, KEV, and ATT&CK context.")
attack_app = typer.Typer(help="Validate and summarize local ATT&CK mapping files.")
data_app = typer.Typer(help="Inspect cache state and local data-source metadata.")
report_app = typer.Typer(help="Render secondary report formats from exported analysis JSON.")
app.add_typer(attack_app, name="attack")
app.add_typer(data_app, name="data")
app.add_typer(report_app, name="report")
console = Console()


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    table = "table"


class PriorityFilter(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class SortBy(str, Enum):
    priority = "priority"
    epss = "epss"
    cvss = "cvss"
    cve = "cve"


class AttackSource(str, Enum):
    none = "none"
    local_csv = "local-csv"
    ctid_json = "ctid-json"


class InputFormat(str, Enum):
    auto = "auto"
    cve_list = "cve-list"
    trivy_json = "trivy-json"
    grype_json = "grype-json"
    cyclonedx_json = "cyclonedx-json"
    spdx_json = "spdx-json"
    dependency_check_json = "dependency-check-json"
    github_alerts_json = "github-alerts-json"


class PolicyProfile(str, Enum):
    default = "default"
    enterprise = "enterprise"
    conservative = "conservative"


class TargetKind(str, Enum):
    generic = "generic"
    image = "image"
    repository = "repository"
    filesystem = "filesystem"
    host = "host"


PRIORITY_LABELS = {
    PriorityFilter.critical: "Critical",
    PriorityFilter.high: "High",
    PriorityFilter.medium: "Medium",
    PriorityFilter.low: "Low",
}


@app.callback()
def callback() -> None:
    """CLI entrypoint."""


@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.markdown, "--format"),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    fail_on: PriorityFilter | None = typer.Option(None, "--fail-on"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Analyze a CVE list and produce a prioritized terminal view and optional report."""
    load_dotenv()
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="analyze",
        format=format,
        allowed_formats={
            OutputFormat.markdown,
            OutputFormat.json,
            OutputFormat.sarif,
            OutputFormat.table,
        },
    )

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
        input_format=input_format,
        no_attack=no_attack,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=offline_attack_file,
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        policy=_build_priority_policy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        ),
        policy_profile=policy_profile,
        policy_file=policy_file,
        asset_context=asset_context,
        target_kind=target_kind.value,
        target_ref=target_ref,
        vex_files=vex_file or [],
        show_suppressed=show_suppressed,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )

    console.print(render_findings_table(findings))
    console.print(render_summary_panel(context))
    _print_warnings(context.warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_markdown_report(findings, context))
        elif format == OutputFormat.json:
            write_output(output, generate_json_report(findings, context))
        elif format == OutputFormat.sarif:
            write_output(output, generate_sarif_report(findings, context))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")
    if fail_on is not None:
        _handle_fail_on(findings, fail_on)


@app.command()
def compare(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.markdown, "--format"),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Compare a CVSS-only baseline with the enriched prioritization result."""
    load_dotenv()
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="compare",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
        input_format=input_format,
        no_attack=no_attack,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=offline_attack_file,
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        policy=_build_priority_policy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        ),
        policy_profile=policy_profile,
        policy_file=policy_file,
        asset_context=asset_context,
        target_kind=target_kind.value,
        target_ref=target_ref,
        vex_files=vex_file or [],
        show_suppressed=show_suppressed,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )

    prioritizer = PrioritizationService()
    comparisons = prioritizer.build_comparison(findings, sort_by=sort_by.value)
    changed_count = sum(1 for row in comparisons if row.changed)

    console.print(render_compare_table(comparisons))
    console.print(render_summary_panel(context, mode="compare", changed_count=changed_count))
    _print_warnings(context.warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_compare_markdown(comparisons, context))
        elif format == OutputFormat.json:
            write_output(output, generate_compare_json(comparisons, context))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@app.command()
def explain(
    cve: str = typer.Option(..., "--cve"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Explain the prioritization result for a single CVE."""
    load_dotenv()
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="explain",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    normalized_cve = normalize_cve_id(cve)
    if normalized_cve is None:
        console.print(f"[red]Input validation failed:[/red] Invalid CVE identifier: {cve!r}")
        raise typer.Exit(code=2)

    policy = _build_priority_policy(
        critical_epss_threshold=critical_epss_threshold,
        critical_cvss_threshold=critical_cvss_threshold,
        high_epss_threshold=high_epss_threshold,
        high_cvss_threshold=high_cvss_threshold,
        medium_epss_threshold=medium_epss_threshold,
        medium_cvss_threshold=medium_cvss_threshold,
    )
    context_profile = _load_context_profile_or_exit(policy_profile, policy_file)
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        _resolve_attack_options(
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
        )
    )
    asset_records = _load_asset_records_or_exit(asset_context)
    vex_statements = _load_vex_statements_or_exit(vex_file or [])
    parsed_input = build_inline_input(
        normalized_cve,
        target_kind=target_kind.value,
        target_ref=target_ref,
        asset_records=asset_records,
        vex_statements=vex_statements,
    )
    findings, counts, enrichment = _build_findings(
        parsed_input.unique_cves,
        policy=policy,
        parsed_input=parsed_input,
        context_profile=context_profile,
        attack_enabled=attack_enabled,
        attack_source=resolved_attack_source,
        attack_mapping_file=resolved_mapping_file,
        attack_technique_metadata_file=resolved_metadata_file,
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    if not show_suppressed:
        findings = [finding for finding in findings if not finding.suppressed_by_vex]

    if not findings:
        console.print("[red]No finding could be generated for the requested CVE.[/red]")
        raise typer.Exit(code=1)

    finding = findings[0]
    nvd = enrichment.nvd.get(normalized_cve, NvdData(cve_id=normalized_cve))
    epss = enrichment.epss.get(normalized_cve, EpssData(cve_id=normalized_cve))
    kev = enrichment.kev.get(normalized_cve, KevData(cve_id=normalized_cve, in_kev=False))
    attack = enrichment.attack.get(normalized_cve, AttackData(cve_id=normalized_cve))
    warnings = enrichment.warnings
    comparison = PrioritizationService(policy=policy).build_comparison([finding])[0]

    context = AnalysisContext(
        input_path=f"inline:{normalized_cve}",
        output_path=str(output) if output else None,
        output_format=format.value,
        generated_at=iso_utc_now(),
        attack_enabled=attack_enabled,
        attack_source=enrichment.attack_source,
        attack_mapping_file=enrichment.attack_mapping_file,
        attack_technique_metadata_file=enrichment.attack_technique_metadata_file,
        attack_source_version=enrichment.attack_source_version,
        attack_version=enrichment.attack_version,
        attack_domain=enrichment.attack_domain,
        mapping_framework=enrichment.mapping_framework,
        mapping_framework_version=enrichment.mapping_framework_version,
        warnings=warnings,
        total_input=1,
        valid_input=1,
        occurrences_count=parsed_input.total_rows,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        attack_hits=_count_attack_hits(enrichment),
        suppressed_by_vex=sum(1 for item in findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in findings if item.under_investigation),
        attack_summary=_build_attack_summary_from_findings([finding]),
        policy_overrides=policy.override_descriptions(),
        priority_policy=policy,
        policy_profile=context_profile.name,
        policy_file=str(policy_file) if policy_file else None,
        counts_by_priority=counts,
        source_stats=parsed_input.source_stats,
        input_format=parsed_input.input_format,
        data_sources=_build_data_sources(enrichment),
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    console.print(render_explain_view(finding, nvd, epss, kev, attack, comparison))
    _print_warnings(warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output,
                generate_explain_markdown(
                    finding,
                    nvd,
                    epss,
                    kev,
                    attack,
                    context,
                    comparison,
                ),
            )
        elif format == OutputFormat.json:
            write_output(
                output,
                generate_explain_json(
                    finding,
                    nvd,
                    epss,
                    kev,
                    attack,
                    context,
                    comparison,
                ),
            )
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@attack_app.command("validate")
def attack_validate(
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
) -> None:
    """Validate local ATT&CK mapping and metadata files."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="attack validate",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    result = _validate_attack_inputs(
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )

    console.print(_render_attack_validation_panel(result))
    _print_warnings(result["warnings"])

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, _generate_attack_validation_markdown(result))
        elif format == OutputFormat.json:
            write_output(output, json.dumps(result, indent=2, sort_keys=True))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@attack_app.command("coverage")
def attack_coverage(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
) -> None:
    """Show ATT&CK coverage for a local CVE list."""
    _validate_output_mode(format, output)
    _validate_command_formats(
        command_name="attack coverage",
        format=format,
        allowed_formats={OutputFormat.markdown, OutputFormat.json, OutputFormat.table},
    )

    cve_ids, total_input_rows, parser_warnings = _read_input_cves(input, max_cves=max_cves)
    attack_items, metadata, warnings = _load_attack_only(
        cve_ids,
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )
    summary = AttackEnrichmentService().summarize(attack_items)
    warnings = parser_warnings + warnings

    console.print(_render_attack_coverage_table(attack_items))
    console.print(
        Panel(
            "\n".join(
                [
                    f"Total input rows: {total_input_rows}",
                    f"Valid unique CVEs: {len(cve_ids)}",
                    f"Mapped CVEs: {summary.mapped_cves}",
                    f"Unmapped CVEs: {summary.unmapped_cves}",
                    f"ATT&CK source: {metadata['source']}",
                    "Mapping type distribution: "
                    + _format_distribution(summary.mapping_type_distribution),
                    "Technique distribution: "
                    + _format_distribution(summary.technique_distribution),
                    "Tactic distribution: " + _format_distribution(summary.tactic_distribution),
                ]
            ),
            title="ATT&CK Coverage",
        )
    )
    _print_warnings(warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output,
                _generate_attack_coverage_markdown(
                    input_path=str(input),
                    attack_items=attack_items,
                    summary=summary,
                    metadata=metadata,
                    warnings=warnings,
                ),
            )
        elif format == OutputFormat.json:
            write_output(
                output,
                json.dumps(
                    {
                        "metadata": {
                            "input_path": str(input),
                            **metadata,
                        },
                        "summary": summary.model_dump(),
                        "items": [item.model_dump() for item in attack_items],
                        "warnings": warnings,
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@attack_app.command("navigator-layer")
def attack_navigator_layer(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
) -> None:
    """Export an ATT&CK Navigator layer from local mapping coverage."""
    cve_ids, _, parser_warnings = _read_input_cves(input, max_cves=max_cves)
    attack_items, metadata, warnings = _load_attack_only(
        cve_ids,
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )
    layer = AttackEnrichmentService().build_navigator_layer(attack_items)
    write_output(output, json.dumps(layer, indent=2, sort_keys=True))
    console.print(
        Panel(
            "\n".join(
                [
                    f"Input file: {input}",
                    f"Output file: {output}",
                    f"ATT&CK source: {metadata['source']}",
                    f"Mapped techniques: {len(layer['techniques'])}",
                ]
            ),
            title="Navigator Layer",
        )
    )
    _print_warnings(parser_warnings + warnings)
    console.print(f"[green]Wrote navigator layer to {output}[/green]")


@data_app.command("status")
def data_status(
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
) -> None:
    """Show cache status and local metadata versions."""
    cache = FileCache(cache_dir, cache_ttl_hours)
    lines = [
        f"Cache directory: {cache_dir}",
        f"Cache TTL (hours): {cache_ttl_hours}",
        f"NVD latest cached at: {cache.latest_cached_at('nvd') or 'N.A.'}",
        f"EPSS latest cached at: {cache.latest_cached_at('epss') or 'N.A.'}",
        f"KEV latest cached at: {cache.latest_cached_at('kev') or 'N.A.'}",
        f"KEV mode: {'offline file' if offline_kev_file else 'live/cache'}",
    ]
    if attack_mapping_file is not None:
        validation = _validate_attack_inputs(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        lines.extend(
            [
                f"ATT&CK source: {validation['source']}",
                f"ATT&CK mapping file: {validation['mapping_file']}",
                f"ATT&CK source version: {validation['source_version'] or 'N.A.'}",
                f"ATT&CK version: {validation['attack_version'] or 'N.A.'}",
                f"ATT&CK domain: {validation['domain'] or 'N.A.'}",
            ]
        )
    console.print(Panel("\n".join(lines), title="Data Status"))


@report_app.command("html")
def report_html(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
) -> None:
    """Render a static HTML report from an analysis JSON export."""
    payload = json.loads(input.read_text(encoding="utf-8"))
    write_output(output, generate_html_report(payload))
    console.print(f"[green]Wrote html output to {output}[/green]")


def _prepare_analysis(
    *,
    input_path: Path,
    output: Path | None,
    format: OutputFormat,
    input_format: InputFormat,
    no_attack: bool,
    attack_source: AttackSource,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_attack_file: Path | None,
    priority_filters: list[PriorityFilter] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    sort_by: SortBy,
    policy: PriorityPolicy,
    policy_profile: str,
    policy_file: Path | None,
    asset_context: Path | None,
    target_kind: str,
    target_ref: str | None,
    vex_files: list[Path],
    show_suppressed: bool,
    max_cves: int | None,
    offline_kev_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
) -> tuple[list[PrioritizedFinding], AnalysisContext]:
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        _resolve_attack_options(
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
        )
    )
    try:
        asset_records = _load_asset_records_or_exit(asset_context)
        vex_statements = _load_vex_statements_or_exit(vex_files)
        parsed_input = InputLoader().load(
            input_path,
            input_format=input_format.value,
            max_cves=max_cves,
            target_kind=target_kind,
            target_ref=target_ref,
            asset_records=asset_records,
            vex_statements=vex_statements,
        )
    except ValidationError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    cve_ids = parsed_input.unique_cves
    context_profile = _load_context_profile_or_exit(policy_profile, policy_file)
    all_findings, _, enrichment = _build_findings(
        cve_ids,
        policy=policy,
        parsed_input=parsed_input,
        context_profile=context_profile,
        attack_enabled=attack_enabled,
        attack_source=resolved_attack_source,
        attack_mapping_file=resolved_mapping_file,
        attack_technique_metadata_file=resolved_metadata_file,
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
        nvd_api_key_env=nvd_api_key_env,
        no_cache=no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )

    if not all_findings:
        console.print("[red]No findings could be generated from the provided CVEs.[/red]")
        raise typer.Exit(code=1)

    prioritizer = PrioritizationService(policy=policy)
    normalized_priority_filters = _normalize_priority_filters(priority_filters)
    filtered_findings = prioritizer.filter_findings(
        all_findings,
        priorities=normalized_priority_filters,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        show_suppressed=show_suppressed,
    )
    findings = prioritizer.sort_findings(filtered_findings, sort_by=sort_by.value)
    warnings = parsed_input.warnings + enrichment.warnings

    context = AnalysisContext(
        input_path=str(input_path),
        output_path=str(output) if output else None,
        output_format=format.value,
        generated_at=iso_utc_now(),
        input_format=parsed_input.input_format,
        attack_enabled=attack_enabled,
        attack_source=enrichment.attack_source,
        attack_mapping_file=enrichment.attack_mapping_file,
        attack_technique_metadata_file=enrichment.attack_technique_metadata_file,
        attack_source_version=enrichment.attack_source_version,
        attack_version=enrichment.attack_version,
        attack_domain=enrichment.attack_domain,
        mapping_framework=enrichment.mapping_framework,
        mapping_framework_version=enrichment.mapping_framework_version,
        warnings=warnings,
        total_input=parsed_input.total_rows,
        valid_input=len(cve_ids),
        occurrences_count=len(parsed_input.occurrences),
        findings_count=len(findings),
        filtered_out_count=max(len(all_findings) - len(findings), 0),
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        attack_hits=_count_attack_hits(enrichment),
        suppressed_by_vex=sum(1 for item in all_findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in all_findings if item.under_investigation),
        attack_summary=_build_attack_summary_from_findings(findings),
        active_filters=_build_active_filters(
            priority_filters=priority_filters,
            kev_only=kev_only,
            min_cvss=min_cvss,
            min_epss=min_epss,
            show_suppressed=show_suppressed,
        ),
        policy_overrides=policy.override_descriptions(),
        priority_policy=policy,
        policy_profile=context_profile.name,
        policy_file=str(policy_file) if policy_file else None,
        counts_by_priority=prioritizer.count_by_priority(findings),
        source_stats=parsed_input.source_stats,
        data_sources=_build_data_sources(enrichment),
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    return findings, context


def _build_findings(
    cve_ids: list[str],
    *,
    policy: PriorityPolicy,
    parsed_input: ParsedInput,
    context_profile: ContextPolicyProfile,
    attack_enabled: bool,
    attack_source: str,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_kev_file: Path | None,
    offline_attack_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
) -> tuple[list[PrioritizedFinding], dict[str, int], EnrichmentResult]:
    enricher = EnrichmentService(
        nvd_api_key_env=nvd_api_key_env,
        use_cache=not no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    enrichment = enricher.enrich(
        cve_ids,
        attack_enabled=attack_enabled,
        attack_source=attack_source,
        offline_kev_file=offline_kev_file,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=offline_attack_file,
    )
    enrichment.parsed_input = parsed_input
    provenance_by_cve = aggregate_provenance(parsed_input.unique_cves, parsed_input.occurrences)

    prioritizer = PrioritizationService(policy=policy)
    findings, counts = prioritizer.prioritize(
        cve_ids,
        nvd_data=enrichment.nvd,
        epss_data=enrichment.epss,
        kev_data=enrichment.kev,
        attack_data=enrichment.attack,
        provenance_by_cve=provenance_by_cve,
        context_profile=context_profile,
    )
    return findings, counts, enrichment


def _validate_output_mode(format: OutputFormat, output: Path | None) -> None:
    if format == OutputFormat.table and output is not None:
        console.print(
            "[red]Input validation failed:[/red] "
            "--output cannot be used together with --format table."
        )
        raise typer.Exit(code=2)


def _validate_command_formats(
    *,
    command_name: str,
    format: OutputFormat,
    allowed_formats: set[OutputFormat],
) -> None:
    if format in allowed_formats:
        return

    supported = ", ".join(
        item.value for item in sorted(allowed_formats, key=lambda item: item.value)
    )
    console.print(
        f"[red]Input validation failed:[/red] {command_name} supports only --format {supported}."
    )
    raise typer.Exit(code=2)


def _normalize_priority_filters(priority_filters: list[PriorityFilter] | None) -> set[str]:
    if not priority_filters:
        return set()
    return {PRIORITY_LABELS[item] for item in priority_filters}


def _build_active_filters(
    *,
    priority_filters: list[PriorityFilter] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    show_suppressed: bool = False,
) -> list[str]:
    active_filters: list[str] = []

    if priority_filters:
        ordered_labels = []
        for item in priority_filters:
            label = PRIORITY_LABELS[item]
            if label not in ordered_labels:
                ordered_labels.append(label)
        active_filters.append("priority=" + ",".join(ordered_labels))
    if kev_only:
        active_filters.append("kev-only")
    if min_cvss is not None:
        active_filters.append(f"min-cvss>={min_cvss:.1f}")
    if min_epss is not None:
        active_filters.append(f"min-epss>={min_epss:.3f}")
    if show_suppressed:
        active_filters.append("show-suppressed")

    return active_filters


def _build_priority_policy(
    *,
    critical_epss_threshold: float,
    critical_cvss_threshold: float,
    high_epss_threshold: float,
    high_cvss_threshold: float,
    medium_epss_threshold: float,
    medium_cvss_threshold: float,
) -> PriorityPolicy:
    try:
        return PriorityPolicy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        )
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _resolve_attack_options(
    *,
    no_attack: bool,
    attack_source: AttackSource,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_attack_file: Path | None,
) -> tuple[bool, str, Path | None, Path | None]:
    if no_attack:
        return False, AttackSource.none.value, None, None

    if attack_source == AttackSource.none:
        if offline_attack_file is not None:
            return True, AttackSource.local_csv.value, offline_attack_file, None
        if attack_mapping_file is not None:
            return (
                True,
                AttackSource.ctid_json.value,
                attack_mapping_file,
                attack_technique_metadata_file,
            )
        return False, AttackSource.none.value, None, None

    if attack_source == AttackSource.local_csv:
        return True, attack_source.value, attack_mapping_file or offline_attack_file, None

    return (
        True,
        attack_source.value,
        attack_mapping_file or offline_attack_file,
        attack_technique_metadata_file,
    )


def _count_nvd_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.nvd.values() if _has_nvd_content(item))


def _count_epss_hits(enrichment: EnrichmentResult) -> int:
    return sum(
        1
        for item in enrichment.epss.values()
        if item.epss is not None or item.percentile is not None or item.date is not None
    )


def _count_kev_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.kev.values() if item.in_kev)


def _count_attack_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.attack.values() if item.mapped)


def _build_attack_summary_from_findings(findings: list[PrioritizedFinding]) -> AttackSummary:
    attack_items = [
        AttackData(
            cve_id=finding.cve_id,
            mapped=finding.attack_mapped,
            mappings=finding.attack_mappings,
            techniques=finding.attack_technique_details,
            attack_techniques=finding.attack_techniques,
            attack_tactics=finding.attack_tactics,
            attack_relevance=finding.attack_relevance,
        )
        for finding in findings
    ]
    return AttackEnrichmentService().summarize(attack_items)


def _build_data_sources(enrichment: EnrichmentResult) -> list[str]:
    sources = list(DATA_SOURCES)
    if enrichment.attack_source == "ctid-mappings-explorer":
        sources.append("CTID Mappings Explorer (local JSON artifact)")
    elif enrichment.attack_source == "local-csv":
        sources.append("Local ATT&CK CSV mapping")
    parsed_input = enrichment.parsed_input
    if parsed_input.source_stats:
        sources.append("Input formats: " + ", ".join(sorted(parsed_input.source_stats)))
    return sources


def _has_nvd_content(item: NvdData) -> bool:
    return any(
        [
            item.description is not None,
            item.cvss_base_score is not None,
            item.cvss_severity is not None,
            item.cvss_version is not None,
            item.published is not None,
            item.last_modified is not None,
            bool(item.cwes),
            bool(item.references),
        ]
    )


def _print_warnings(warnings: list[str]) -> None:
    if warnings:
        console.print(
            Panel(
                "\n".join(f"- {warning}" for warning in warnings),
                title="Warnings",
                border_style="yellow",
            )
        )


def _validate_attack_inputs(
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> dict:
    warnings: list[str] = []
    metadata: dict[str, str | None]
    mapping_count = 0
    unique_cves = 0
    technique_count = 0

    if attack_source == AttackSource.ctid_json.value:
        mappings_by_cve, mapping_metadata, mapping_warnings = CtidMappingsProvider().load(
            attack_mapping_file
        )
        warnings.extend(mapping_warnings)
        mapping_count = sum(len(items) for items in mappings_by_cve.values())
        unique_cves = len(mappings_by_cve)
        metadata = {
            "source": "ctid-mappings-explorer",
            "mapping_file": str(attack_mapping_file),
            "technique_metadata_file": (
                str(attack_technique_metadata_file)
                if attack_technique_metadata_file is not None
                else None
            ),
            "source_version": mapping_metadata.get("mapping_framework_version")
            or mapping_metadata.get("mapping_version"),
            "attack_version": mapping_metadata.get("attack_version"),
            "domain": mapping_metadata.get("domain"),
            "mapping_framework": mapping_metadata.get("mapping_framework"),
            "mapping_framework_version": mapping_metadata.get("mapping_framework_version"),
        }
        if attack_technique_metadata_file is not None:
            techniques, technique_metadata, technique_warnings = AttackMetadataProvider().load(
                attack_technique_metadata_file
            )
            warnings.extend(technique_warnings)
            technique_count = len(techniques)
            metadata["attack_version"] = (
                technique_metadata.get("attack_version") or metadata["attack_version"]
            )
            metadata["domain"] = technique_metadata.get("domain") or metadata["domain"]
    else:
        provider = AttackProvider()
        results, metadata, provider_warnings = provider.fetch_many(
            [],
            enabled=True,
            source=attack_source,
            mapping_file=attack_mapping_file,
            technique_metadata_file=attack_technique_metadata_file,
        )
        warnings.extend(provider_warnings)
        mapping_count = sum(1 for item in results.values() if item.mapped)
        unique_cves = len(results)

    return {
        "source": metadata["source"],
        "mapping_file": metadata["mapping_file"],
        "technique_metadata_file": metadata.get("technique_metadata_file"),
        "source_version": metadata.get("source_version"),
        "attack_version": metadata.get("attack_version"),
        "domain": metadata.get("domain"),
        "mapping_framework": metadata.get("mapping_framework"),
        "mapping_framework_version": metadata.get("mapping_framework_version"),
        "mapping_count": mapping_count,
        "unique_cves": unique_cves,
        "technique_count": technique_count,
        "warnings": warnings,
    }


def _render_attack_validation_panel(result: dict) -> Panel:
    lines = [
        f"ATT&CK source: {result['source']}",
        f"Mapping file: {result['mapping_file']}",
        f"Technique metadata file: {result['technique_metadata_file'] or 'N.A.'}",
        f"Unique CVEs in mapping: {result['unique_cves']}",
        f"Total mapping objects: {result['mapping_count']}",
        f"Technique metadata entries: {result['technique_count']}",
        f"Source version: {result['source_version'] or 'N.A.'}",
        f"ATT&CK version: {result['attack_version'] or 'N.A.'}",
        f"Domain: {result['domain'] or 'N.A.'}",
    ]
    return Panel("\n".join(lines), title="ATT&CK Validation")


def _generate_attack_validation_markdown(result: dict) -> str:
    lines = [
        "# ATT&CK Validation",
        "",
        f"- ATT&CK source: `{result['source']}`",
        f"- Mapping file: `{result['mapping_file']}`",
        f"- Technique metadata file: `{result['technique_metadata_file'] or 'N.A.'}`",
        f"- Unique CVEs in mapping: {result['unique_cves']}",
        f"- Total mapping objects: {result['mapping_count']}",
        f"- Technique metadata entries: {result['technique_count']}",
        f"- Source version: `{result['source_version'] or 'N.A.'}`",
        f"- ATT&CK version: `{result['attack_version'] or 'N.A.'}`",
        f"- Domain: `{result['domain'] or 'N.A.'}`",
        "",
        "## Warnings",
    ]
    if result["warnings"]:
        lines.extend(f"- {warning}" for warning in result["warnings"])
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _read_input_cves(input_path: Path, *, max_cves: int | None) -> tuple[list[str], int, list[str]]:
    try:
        parsed_input = InputLoader().load(input_path, input_format="auto", max_cves=max_cves)
    except ValidationError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    return parsed_input.unique_cves, parsed_input.total_rows, parsed_input.warnings


def _load_asset_records_or_exit(
    asset_context: Path | None,
) -> dict[tuple[str, str], AssetContextRecord]:
    try:
        return load_asset_context_file(asset_context)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _load_vex_statements_or_exit(vex_files: list[Path]) -> list[VexStatement]:
    try:
        return load_vex_files(vex_files)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _load_context_profile_or_exit(
    policy_profile: str,
    policy_file: Path | None,
) -> ContextPolicyProfile:
    try:
        return load_context_profile(policy_profile, policy_file)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _handle_fail_on(findings: list[PrioritizedFinding], fail_on: PriorityFilter) -> None:
    threshold = PRIORITY_LABELS[fail_on]
    ordered = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    if any(ordered[finding.priority_label] <= ordered[threshold] for finding in findings):
        raise typer.Exit(code=1)


def _load_attack_only(
    cve_ids: list[str],
    *,
    attack_source: str,
    attack_mapping_file: Path,
    attack_technique_metadata_file: Path | None,
) -> tuple[list[AttackData], dict[str, str | None], list[str]]:
    provider = AttackProvider()
    attack_data, metadata, warnings = provider.fetch_many(
        cve_ids,
        enabled=True,
        source=attack_source,
        mapping_file=attack_mapping_file,
        technique_metadata_file=attack_technique_metadata_file,
    )
    items = [attack_data.get(cve_id, AttackData(cve_id=cve_id)) for cve_id in cve_ids]
    return items, metadata, warnings


def _render_attack_coverage_table(attack_items: list[AttackData]) -> Table:
    table = Table(title="ATT&CK Coverage", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Mapped")
    table.add_column("Relevance")
    table.add_column("Techniques")
    table.add_column("Tactics")
    table.add_column("Mapping Types")

    for item in attack_items:
        table.add_row(
            item.cve_id,
            "Yes" if item.mapped else "No",
            item.attack_relevance,
            ", ".join(item.attack_techniques) or "N.A.",
            ", ".join(item.attack_tactics) or "N.A.",
            ", ".join(item.mapping_types) or "N.A.",
        )
    return table


def _generate_attack_coverage_markdown(
    *,
    input_path: str,
    attack_items: list[AttackData],
    summary: AttackSummary,
    metadata: dict[str, str | None],
    warnings: list[str],
) -> str:
    lines = [
        "# ATT&CK Coverage",
        "",
        f"- Input file: `{input_path}`",
        f"- ATT&CK source: `{metadata['source']}`",
        f"- Mapping file: `{metadata['mapping_file']}`",
        f"- Technique metadata file: `{metadata.get('technique_metadata_file') or 'N.A.'}`",
        f"- Mapped CVEs: {summary.mapped_cves}",
        f"- Unmapped CVEs: {summary.unmapped_cves}",
        "- Mapping type distribution: " + _format_distribution(summary.mapping_type_distribution),
        "- Technique distribution: " + _format_distribution(summary.technique_distribution),
        "- Tactic distribution: " + _format_distribution(summary.tactic_distribution),
        "",
        "## Items",
        "",
        "| CVE ID | Mapped | Relevance | Techniques | Tactics | Mapping Types |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in attack_items:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.cve_id,
                    "Yes" if item.mapped else "No",
                    item.attack_relevance,
                    ", ".join(item.attack_techniques) or "N.A.",
                    ", ".join(item.attack_tactics) or "N.A.",
                    ", ".join(item.mapping_types) or "N.A.",
                ]
            )
            + " |"
        )
    lines.extend(["", "## Warnings"])
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "None"
    return ", ".join(
        f"{key}: {value}"
        for key, value in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    )


def main() -> None:
    """Entrypoint used by the console script."""
    app()


if __name__ == "__main__":
    main()
