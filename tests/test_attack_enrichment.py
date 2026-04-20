from __future__ import annotations

from vuln_prioritizer.models import AttackData, AttackMapping, AttackTechnique
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService


def test_attack_enrichment_service_marks_high_relevance_for_exploitation_mappings() -> None:
    service = AttackEnrichmentService()

    results = service.enrich_ctid(
        ["CVE-2024-0001", "CVE-2024-0002"],
        mappings_by_cve={
            "CVE-2024-0001": [
                AttackMapping(
                    capability_id="CVE-2024-0001",
                    attack_object_id="T1190",
                    attack_object_name="Exploit Public-Facing Application",
                    mapping_type="exploitation_technique",
                    capability_group="sql_injection",
                )
            ]
        },
        techniques_by_id={
            "T1190": AttackTechnique(
                attack_object_id="T1190",
                name="Exploit Public-Facing Application",
                tactics=["initial-access"],
                url="https://attack.mitre.org/techniques/T1190/",
            )
        },
        source="ctid-mappings-explorer",
        source_version="07/28/2025",
        attack_version="16.1",
        domain="enterprise",
    )

    assert results["CVE-2024-0001"].mapped is True
    assert results["CVE-2024-0001"].attack_relevance == "High"
    assert results["CVE-2024-0001"].attack_techniques == ["T1190"]
    assert results["CVE-2024-0001"].attack_tactics == ["initial-access"]
    assert results["CVE-2024-0002"].mapped is False
    assert results["CVE-2024-0002"].attack_relevance == "Unmapped"


def test_attack_enrichment_summary_counts_mapped_and_unmapped_items() -> None:
    service = AttackEnrichmentService()

    summary = service.summarize(
        [
            AttackData(
                cve_id="CVE-2024-0001",
                mapped=True,
                mapping_types=["exploitation_technique"],
                attack_techniques=["T1190"],
                attack_tactics=["initial-access"],
            ),
            AttackData(
                cve_id="CVE-2024-0002",
                mapped=False,
                attack_relevance="Unmapped",
            ),
        ]
    )

    assert summary.mapped_cves == 1
    assert summary.unmapped_cves == 1
    assert summary.mapping_type_distribution == {"exploitation_technique": 1}
    assert summary.technique_distribution == {"T1190": 1}
    assert summary.tactic_distribution == {"initial-access": 1}
