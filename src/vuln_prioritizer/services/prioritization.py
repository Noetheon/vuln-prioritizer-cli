"""Combine enrichment data into prioritized findings."""

from __future__ import annotations

from collections import Counter

from vuln_prioritizer.models import AttackData, EpssData, KevData, NvdData, PrioritizedFinding
from vuln_prioritizer.scoring import build_rationale, determine_priority, recommended_action


class PrioritizationService:
    """Create final prioritized findings from enrichment data."""

    def prioritize(
        self,
        cve_ids: list[str],
        *,
        nvd_data: dict[str, NvdData],
        epss_data: dict[str, EpssData],
        kev_data: dict[str, KevData],
        attack_data: dict[str, AttackData],
    ) -> tuple[list[PrioritizedFinding], dict[str, int]]:
        findings: list[PrioritizedFinding] = []

        for cve_id in cve_ids:
            nvd = nvd_data.get(cve_id, NvdData(cve_id=cve_id))
            epss = epss_data.get(cve_id, EpssData(cve_id=cve_id))
            kev = kev_data.get(cve_id, KevData(cve_id=cve_id, in_kev=False))
            attack = attack_data.get(cve_id, AttackData(cve_id=cve_id))

            priority_label, priority_rank = determine_priority(nvd, epss, kev)
            findings.append(
                PrioritizedFinding(
                    cve_id=cve_id,
                    description=nvd.description,
                    cvss_base_score=nvd.cvss_base_score,
                    cvss_severity=nvd.cvss_severity,
                    epss=epss.epss,
                    epss_percentile=epss.percentile,
                    in_kev=kev.in_kev,
                    attack_techniques=attack.attack_techniques,
                    priority_label=priority_label,
                    priority_rank=priority_rank,
                    rationale=build_rationale(nvd, epss, kev, attack),
                    recommended_action=recommended_action(priority_label),
                )
            )

        findings.sort(
            key=lambda finding: (
                finding.priority_rank,
                0 if finding.in_kev else 1,
                -(finding.epss or -1.0),
                -(finding.cvss_base_score or -1.0),
                finding.cve_id,
            )
        )
        counts = Counter(finding.priority_label for finding in findings)
        return findings, dict(counts)
