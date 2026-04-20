"""Pydantic models for the CLI."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    cvss_version: str | None = None
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


class AttackMapping(StrictModel):
    capability_id: str
    attack_object_id: str
    attack_object_name: str | None = None
    mapping_type: str | None = None
    capability_group: str | None = None
    capability_description: str | None = None
    comments: str | None = None
    references: list[str] = Field(default_factory=list)


class AttackTechnique(StrictModel):
    attack_object_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None
    revoked: bool = False
    deprecated: bool = False


class AttackSummary(StrictModel):
    mapped_cves: int = 0
    unmapped_cves: int = 0
    mapping_type_distribution: dict[str, int] = Field(default_factory=dict)
    technique_distribution: dict[str, int] = Field(default_factory=dict)
    tactic_distribution: dict[str, int] = Field(default_factory=dict)


class AttackData(StrictModel):
    cve_id: str
    mapped: bool = False
    source: str = "none"
    source_version: str | None = None
    attack_version: str | None = None
    domain: str | None = None
    mappings: list[AttackMapping] = Field(default_factory=list)
    techniques: list[AttackTechnique] = Field(default_factory=list)
    mapping_types: list[str] = Field(default_factory=list)
    capability_groups: list[str] = Field(default_factory=list)
    attack_relevance: str = "Unmapped"
    attack_rationale: str | None = None
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    attack_note: str | None = None


class PriorityPolicy(StrictModel):
    critical_epss_threshold: float = 0.70
    critical_cvss_threshold: float = 7.0
    high_epss_threshold: float = 0.40
    high_cvss_threshold: float = 9.0
    medium_epss_threshold: float = 0.10
    medium_cvss_threshold: float = 7.0

    @model_validator(mode="after")
    def validate_thresholds(self) -> PriorityPolicy:
        for field_name in (
            "critical_epss_threshold",
            "high_epss_threshold",
            "medium_epss_threshold",
        ):
            value = getattr(self, field_name)
            if value < 0.0 or value > 1.0:
                raise ValueError(f"{field_name} must stay between 0.0 and 1.0.")

        for field_name in (
            "critical_cvss_threshold",
            "high_cvss_threshold",
            "medium_cvss_threshold",
        ):
            value = getattr(self, field_name)
            if value < 0.0 or value > 10.0:
                raise ValueError(f"{field_name} must stay between 0.0 and 10.0.")

        if not (
            self.critical_epss_threshold >= self.high_epss_threshold >= self.medium_epss_threshold
        ):
            raise ValueError("EPSS thresholds must descend from critical to high to medium.")

        if self.high_cvss_threshold < self.medium_cvss_threshold:
            raise ValueError(
                "high_cvss_threshold must be greater than or equal to medium_cvss_threshold."
            )

        return self

    def methodology_lines(self) -> list[str]:
        return [
            (
                "Critical: KEV or "
                f"(EPSS >= {self.critical_epss_threshold:.2f} and "
                f"CVSS >= {self.critical_cvss_threshold:.1f})"
            ),
            (
                f"High: EPSS >= {self.high_epss_threshold:.2f} or "
                f"CVSS >= {self.high_cvss_threshold:.1f}"
            ),
            (
                f"Medium: CVSS >= {self.medium_cvss_threshold:.1f} or "
                f"EPSS >= {self.medium_epss_threshold:.2f}"
            ),
            "Low: all remaining CVEs",
        ]

    def override_descriptions(self) -> list[str]:
        default_policy = PriorityPolicy()
        if self == default_policy:
            return []

        labels = {
            "critical_epss_threshold": "critical-epss",
            "critical_cvss_threshold": "critical-cvss",
            "high_epss_threshold": "high-epss",
            "high_cvss_threshold": "high-cvss",
            "medium_epss_threshold": "medium-epss",
            "medium_cvss_threshold": "medium-cvss",
        }
        descriptions: list[str] = []

        for field_name, label in labels.items():
            current_value = getattr(self, field_name)
            default_value = getattr(default_policy, field_name)
            if current_value == default_value:
                continue

            if "epss" in field_name:
                descriptions.append(f"{label}={current_value:.3f}")
            else:
                descriptions.append(f"{label}={current_value:.1f}")

        return descriptions


class PrioritizedFinding(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    attack_mapped: bool = False
    attack_relevance: str = "Unmapped"
    attack_rationale: str | None = None
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    attack_note: str | None = None
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    attack_technique_details: list[AttackTechnique] = Field(default_factory=list)
    priority_label: str
    priority_rank: int
    rationale: str
    recommended_action: str


class ComparisonFinding(StrictModel):
    cve_id: str
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    cvss_only_label: str
    cvss_only_rank: int
    enriched_label: str
    enriched_rank: int
    attack_mapped: bool = False
    attack_relevance: str = "Unmapped"
    mapped_technique_count: int = 0
    mapped_tactics: list[str] = Field(default_factory=list)
    changed: bool
    delta_rank: int
    change_reason: str


class EnrichmentResult(BaseModel):
    nvd: dict[str, NvdData] = Field(default_factory=dict)
    epss: dict[str, EpssData] = Field(default_factory=dict)
    kev: dict[str, KevData] = Field(default_factory=dict)
    attack: dict[str, AttackData] = Field(default_factory=dict)
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_source_version: str | None = None
    attack_version: str | None = None
    attack_domain: str | None = None
    mapping_framework: str | None = None
    mapping_framework_version: str | None = None
    warnings: list[str] = Field(default_factory=list)


class AnalysisContext(BaseModel):
    input_path: str
    output_path: str | None = None
    output_format: str
    generated_at: str
    attack_enabled: bool = False
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_source_version: str | None = None
    attack_version: str | None = None
    attack_domain: str | None = None
    mapping_framework: str | None = None
    mapping_framework_version: str | None = None
    warnings: list[str] = Field(default_factory=list)
    total_input: int = 0
    valid_input: int = 0
    findings_count: int = 0
    filtered_out_count: int = 0
    nvd_hits: int = 0
    epss_hits: int = 0
    kev_hits: int = 0
    attack_hits: int = 0
    attack_summary: AttackSummary = Field(default_factory=AttackSummary)
    active_filters: list[str] = Field(default_factory=list)
    policy_overrides: list[str] = Field(default_factory=list)
    priority_policy: PriorityPolicy = Field(default_factory=PriorityPolicy)
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    data_sources: list[str] = Field(default_factory=list)
    cache_enabled: bool = False
    cache_dir: str | None = None
