"""Build structured ATT&CK enrichment from CTID mappings and technique metadata."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from vuln_prioritizer.models import AttackData, AttackMapping, AttackSummary, AttackTechnique

HIGH_IMPACT_TACTICS = {
    "initial-access",
    "execution",
    "privilege-escalation",
    "credential-access",
    "lateral-movement",
    "exfiltration",
    "impact",
}


class AttackEnrichmentService:
    """Combine mapping artifacts into per-CVE ATT&CK enrichment objects."""

    def enrich_ctid(
        self,
        cve_ids: list[str],
        *,
        mappings_by_cve: dict[str, list[AttackMapping]],
        techniques_by_id: dict[str, AttackTechnique],
        source: str,
        source_version: str | None,
        attack_version: str | None,
        domain: str | None,
    ) -> dict[str, AttackData]:
        results: dict[str, AttackData] = {}

        for cve_id in cve_ids:
            mappings = mappings_by_cve.get(cve_id, [])
            techniques = _build_techniques(mappings, techniques_by_id)
            attack_techniques = [technique.attack_object_id for technique in techniques]
            attack_tactics = _collect_attack_tactics(techniques)
            mapping_types = _unique(
                mapping.mapping_type for mapping in mappings if mapping.mapping_type is not None
            )
            capability_groups = _unique(
                mapping.capability_group
                for mapping in mappings
                if mapping.capability_group is not None
            )
            attack_note = _build_attack_note(mappings)
            attack_relevance, attack_rationale = _determine_attack_relevance(
                mapping_types,
                attack_tactics,
                bool(mappings),
            )

            results[cve_id] = AttackData(
                cve_id=cve_id,
                mapped=bool(mappings),
                source=source,
                source_version=source_version,
                attack_version=attack_version,
                domain=domain,
                mappings=mappings,
                techniques=techniques,
                mapping_types=mapping_types,
                capability_groups=capability_groups,
                attack_relevance=attack_relevance,
                attack_rationale=attack_rationale,
                attack_techniques=attack_techniques,
                attack_tactics=attack_tactics,
                attack_note=attack_note,
            )

        return results

    def enrich_legacy_csv(
        self,
        cve_ids: list[str],
        *,
        attack_data: dict[str, AttackData],
    ) -> dict[str, AttackData]:
        results: dict[str, AttackData] = {}
        for cve_id in cve_ids:
            current = attack_data.get(cve_id, AttackData(cve_id=cve_id))
            mapped = bool(
                current.attack_techniques or current.attack_tactics or current.attack_note
            )
            attack_relevance = "Medium" if mapped else "Unmapped"
            attack_rationale = (
                "Legacy local ATT&CK CSV context is available for this CVE."
                if mapped
                else "No ATT&CK context was provided for this CVE."
            )
            results[cve_id] = AttackData(
                cve_id=cve_id,
                mapped=mapped,
                source="local-csv",
                source_version=None,
                attack_version=None,
                domain=None,
                mappings=current.mappings,
                techniques=current.techniques,
                mapping_types=current.mapping_types,
                capability_groups=current.capability_groups,
                attack_relevance=attack_relevance,
                attack_rationale=attack_rationale,
                attack_techniques=current.attack_techniques,
                attack_tactics=current.attack_tactics,
                attack_note=current.attack_note,
            )

        return results

    def summarize(self, attack_items: list[AttackData]) -> AttackSummary:
        mapping_type_distribution: Counter[str] = Counter()
        technique_distribution: Counter[str] = Counter()
        tactic_distribution: Counter[str] = Counter()
        mapped_cves = 0

        for item in attack_items:
            if item.mapped:
                mapped_cves += 1
            mapping_type_distribution.update(item.mapping_types)
            technique_distribution.update(item.attack_techniques)
            tactic_distribution.update(item.attack_tactics)

        return AttackSummary(
            mapped_cves=mapped_cves,
            unmapped_cves=max(len(attack_items) - mapped_cves, 0),
            mapping_type_distribution=dict(mapping_type_distribution),
            technique_distribution=dict(technique_distribution),
            tactic_distribution=dict(tactic_distribution),
        )

    def build_navigator_layer(
        self,
        attack_items: list[AttackData],
        *,
        layer_name: str = "vuln-prioritizer ATT&CK coverage",
    ) -> dict:
        technique_distribution = self.summarize(attack_items).technique_distribution
        techniques = [
            {
                "techniqueID": technique_id,
                "score": score,
                "comment": f"Observed in {score} mapped CVE(s).",
            }
            for technique_id, score in sorted(
                technique_distribution.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
        max_score = max(technique_distribution.values(), default=1)
        return {
            "name": layer_name,
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": (
                "Navigator layer generated from local CTID ATT&CK mappings used by "
                "vuln-prioritizer."
            ),
            "gradient": {
                "colors": ["#dfe7fd", "#4c6ef5"],
                "minValue": 0,
                "maxValue": max_score,
            },
            "techniques": techniques,
            "legendItems": [
                {"label": "Mapped technique", "color": "#4c6ef5"},
            ],
            "showTacticRowBackground": True,
            "selectTechniquesAcrossTactics": True,
        }


def _build_techniques(
    mappings: list[AttackMapping],
    techniques_by_id: dict[str, AttackTechnique],
) -> list[AttackTechnique]:
    technique_ids = _unique(mapping.attack_object_id for mapping in mappings)
    techniques: list[AttackTechnique] = []

    for technique_id in technique_ids:
        metadata = techniques_by_id.get(technique_id)
        if metadata is not None:
            techniques.append(metadata)
            continue

        display_name = next(
            (
                mapping.attack_object_name
                for mapping in mappings
                if mapping.attack_object_id == technique_id and mapping.attack_object_name
            ),
            technique_id,
        )
        techniques.append(
            AttackTechnique(
                attack_object_id=technique_id,
                name=display_name,
                tactics=[],
                url=None,
                revoked=False,
                deprecated=False,
            )
        )

    return techniques


def _determine_attack_relevance(
    mapping_types: list[str],
    attack_tactics: list[str],
    mapped: bool,
) -> tuple[str, str]:
    if not mapped:
        return "Unmapped", "No CTID ATT&CK mapping is available for this CVE."

    normalized_tactics = {_normalize_tactic_name(tactic) for tactic in attack_tactics}
    if "exploitation_technique" in mapping_types or "primary_impact" in mapping_types:
        return (
            "High",
            "CTID ATT&CK mappings include exploitation or primary impact behavior.",
        )
    if normalized_tactics.intersection(HIGH_IMPACT_TACTICS):
        return (
            "High",
            "Resolved ATT&CK tactics include high-impact adversary behaviors.",
        )
    if "secondary_impact" in mapping_types:
        return (
            "Medium",
            "Only secondary impact ATT&CK mappings are available for this CVE.",
        )
    if "uncategorized" in mapping_types:
        return (
            "Low",
            "Only uncategorized ATT&CK mappings are available for this CVE.",
        )
    return (
        "Medium",
        "ATT&CK mappings exist for this CVE, but the available metadata is incomplete.",
    )


def _build_attack_note(mappings: list[AttackMapping]) -> str | None:
    comments = _unique(mapping.comments for mapping in mappings if mapping.comments is not None)
    if comments:
        return " ".join(comment.rstrip(".") + "." for comment in comments)

    descriptions = _unique(
        mapping.capability_description
        for mapping in mappings
        if mapping.capability_description is not None
    )
    if descriptions:
        return " ".join(description.rstrip(".") + "." for description in descriptions[:2])

    return None


def _collect_attack_tactics(techniques: list[AttackTechnique]) -> list[str]:
    tactics: list[str] = []
    for technique in techniques:
        for tactic in technique.tactics:
            if tactic not in tactics:
                tactics.append(tactic)
    return tactics


def _normalize_tactic_name(value: str) -> str:
    return value.strip().lower().replace(" ", "-")


def _unique(values: Iterable[str | None]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if value is None or value in normalized:
            continue
        normalized.append(value)
    return normalized
