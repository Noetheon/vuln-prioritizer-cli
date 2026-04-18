"""Pydantic models for the CLI."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base model with frozen instances and forbidden extra fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class InputItem(StrictModel):
    cve_id: str


class NvdData(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    published: str | None = None
    last_modified: str | None = None
    cwes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class EpssData(StrictModel):
    cve_id: str
    epss: float | None = None
    percentile: float | None = None
    date: str | None = None


class KevData(StrictModel):
    cve_id: str
    in_kev: bool = False
    vendor_project: str | None = None
    product: str | None = None
    date_added: str | None = None
    required_action: str | None = None
    due_date: str | None = None


class AttackData(StrictModel):
    cve_id: str
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    attack_note: str | None = None


class PrioritizedFinding(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    attack_techniques: list[str] = Field(default_factory=list)
    priority_label: str
    priority_rank: int
    rationale: str
    recommended_action: str


class EnrichmentResult(BaseModel):
    nvd: dict[str, NvdData] = Field(default_factory=dict)
    epss: dict[str, EpssData] = Field(default_factory=dict)
    kev: dict[str, KevData] = Field(default_factory=dict)
    attack: dict[str, AttackData] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class AnalysisContext(BaseModel):
    input_path: str
    output_path: str | None = None
    output_format: str
    generated_at: str
    attack_enabled: bool = False
    warnings: list[str] = Field(default_factory=list)
    total_input: int = 0
    valid_input: int = 0
    findings_count: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    data_sources: list[str] = Field(default_factory=list)
    cache_enabled: bool = False
    cache_dir: str | None = None
