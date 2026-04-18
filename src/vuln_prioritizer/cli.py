"""Typer-based command line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from vuln_prioritizer.config import (
    DATA_SOURCES,
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    EnrichmentResult,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
)
from vuln_prioritizer.parser import parse_input_file
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
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id

app = typer.Typer(help="Prioritize known CVEs with NVD, EPSS, and KEV context.")
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
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
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
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
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
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
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
        priority_filters=priority,
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sort_by=sort_by,
        max_cves=max_cves,
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
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

    attack_enabled = bool(not no_attack and offline_attack_file is not None)
    findings, counts, enrichment = _build_findings(
        [normalized_cve],
        attack_enabled=attack_enabled,
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

    context = AnalysisContext(
        input_path=f"inline:{normalized_cve}",
        output_path=str(output) if output else None,
        output_format=format.value,
        generated_at=iso_utc_now(),
        attack_enabled=attack_enabled,
        warnings=warnings,
        total_input=1,
        valid_input=1,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        counts_by_priority=counts,
        data_sources=DATA_SOURCES,
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    console.print(render_explain_view(finding, nvd, epss, kev, attack))
    _print_warnings(warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output, generate_explain_markdown(finding, nvd, epss, kev, attack, context)
            )
        elif format == OutputFormat.json:
            write_output(
                output,
                generate_explain_json(finding, nvd, epss, kev, attack, context),
            )
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def _prepare_analysis(
    *,
    input_path: Path,
    output: Path | None,
    format: OutputFormat,
    no_attack: bool,
    priority_filters: list[PriorityFilter] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    sort_by: SortBy,
    max_cves: int | None,
    offline_kev_file: Path | None,
    offline_attack_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
) -> tuple[list[PrioritizedFinding], AnalysisContext]:
    attack_enabled = bool(not no_attack and offline_attack_file is not None)

    try:
        items, parser_warnings, total_input_rows = parse_input_file(input_path, max_cves=max_cves)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    cve_ids = [item.cve_id for item in items]
    all_findings, _, enrichment = _build_findings(
        cve_ids,
        attack_enabled=attack_enabled,
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

    prioritizer = PrioritizationService()
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
        warnings=warnings,
        total_input=total_input_rows,
        valid_input=len(cve_ids),
        findings_count=len(findings),
        filtered_out_count=max(len(all_findings) - len(findings), 0),
        nvd_hits=_count_nvd_hits(enrichment),
        epss_hits=_count_epss_hits(enrichment),
        kev_hits=_count_kev_hits(enrichment),
        active_filters=_build_active_filters(
            priority_filters=priority_filters,
            kev_only=kev_only,
            min_cvss=min_cvss,
            min_epss=min_epss,
        ),
        counts_by_priority=prioritizer.count_by_priority(findings),
        data_sources=DATA_SOURCES,
        cache_enabled=not no_cache,
        cache_dir=str(cache_dir) if not no_cache else None,
    )

    return findings, context


def _build_findings(
    cve_ids: list[str],
    *,
    attack_enabled: bool,
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
        offline_kev_file=offline_kev_file,
        offline_attack_file=offline_attack_file,
    )

    prioritizer = PrioritizationService()
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


def _has_nvd_content(item: NvdData) -> bool:
    return any(
        [
            item.description is not None,
            item.cvss_base_score is not None,
            item.cvss_severity is not None,
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


def main() -> None:
    """Entrypoint used by the console script."""
    app()


if __name__ == "__main__":
    main()
