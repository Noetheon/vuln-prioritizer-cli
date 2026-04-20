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

from vuln_prioritizer.config import (
    DATA_SOURCES,
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    AttackSummary,
    EnrichmentResult,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityPolicy,
)
from vuln_prioritizer.parser import parse_input_file
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider
from vuln_prioritizer.reporter import (
    generate_compare_json,
    generate_compare_markdown,
    generate_explain_json,
    generate_explain_markdown,
    generate_json_report,
    generate_markdown_report,
    render_compare_table,
    render_explain_view,
    render_findings_table,
    render_summary_panel,
    write_output,
)
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id

app = typer.Typer(help="Prioritize known CVEs with NVD, EPSS, KEV, and ATT&CK context.")
attack_app = typer.Typer(help="Validate and summarize local ATT&CK mapping files.")
app.add_typer(attack_app, name="attack")
console = Console()


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
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

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
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
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


@app.command()
def compare(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: OutputFormat = typer.Option(OutputFormat.markdown, "--format"),
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

    findings, context = _prepare_analysis(
        input_path=input,
        output=output,
        format=format,
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
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        _resolve_attack_options(
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
        )
    )
    findings, counts, enrichment = _build_findings(
        [normalized_cve],
        policy=policy,
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
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        attack_hits=_count_attack_hits(enrichment),
        attack_summary=_build_attack_summary_from_findings([finding]),
        policy_overrides=policy.override_descriptions(),
        priority_policy=policy,
        counts_by_priority=counts,
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


def _prepare_analysis(
    *,
    input_path: Path,
    output: Path | None,
    format: OutputFormat,
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
        items, parser_warnings, total_input_rows = parse_input_file(input_path, max_cves=max_cves)
    except ValidationError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    cve_ids = [item.cve_id for item in items]
    all_findings, _, enrichment = _build_findings(
        cve_ids,
        policy=policy,
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
    )
    findings = prioritizer.sort_findings(filtered_findings, sort_by=sort_by.value)
    warnings = parser_warnings + enrichment.warnings

    context = AnalysisContext(
        input_path=str(input_path),
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
        total_input=total_input_rows,
        valid_input=len(cve_ids),
        findings_count=len(findings),
        filtered_out_count=max(len(all_findings) - len(findings), 0),
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        attack_hits=_count_attack_hits(enrichment),
        attack_summary=_build_attack_summary_from_findings(findings),
        active_filters=_build_active_filters(
            priority_filters=priority_filters,
            kev_only=kev_only,
            min_cvss=min_cvss,
            min_epss=min_epss,
        ),
        policy_overrides=policy.override_descriptions(),
        priority_policy=policy,
        counts_by_priority=prioritizer.count_by_priority(findings),
        data_sources=_build_data_sources(enrichment),
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    return findings, context


def _build_findings(
    cve_ids: list[str],
    *,
    policy: PriorityPolicy,
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

    prioritizer = PrioritizationService(policy=policy)
    findings, counts = prioritizer.prioritize(
        cve_ids,
        nvd_data=enrichment.nvd,
        epss_data=enrichment.epss,
        kev_data=enrichment.kev,
        attack_data=enrichment.attack,
    )
    return findings, counts, enrichment


def _validate_output_mode(format: OutputFormat, output: Path | None) -> None:
    if format == OutputFormat.table and output is not None:
        console.print(
            "[red]Input validation failed:[/red] "
            "--output cannot be used together with --format table."
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
        items, parser_warnings, total_input_rows = parse_input_file(input_path, max_cves=max_cves)
    except ValidationError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    return [item.cve_id for item in items], total_input_rows, parser_warnings


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
