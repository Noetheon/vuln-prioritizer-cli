from __future__ import annotations

import pytest

from vuln_prioritizer.models import AttackData, EpssData, KevData, NvdData
from vuln_prioritizer.scoring import determine_priority
from vuln_prioritizer.services.prioritization import PrioritizationService


@pytest.mark.parametrize(
    ("cvss", "epss", "in_kev", "expected"),
    [
        (5.0, 0.05, True, "Critical"),
        (7.2, 0.80, False, "Critical"),
        (9.1, 0.02, False, "High"),
        (6.4, 0.40, False, "High"),
        (7.5, 0.05, False, "Medium"),
        (4.2, 0.10, False, "Medium"),
        (4.2, 0.05, False, "Low"),
    ],
)
def test_determine_priority_matches_mvp_rules(
    cvss: float,
    epss: float,
    in_kev: bool,
    expected: str,
) -> None:
    nvd = NvdData(cve_id="CVE-2024-0001", cvss_base_score=cvss, cvss_severity="HIGH")
    epss_data = EpssData(cve_id="CVE-2024-0001", epss=epss, percentile=0.5)
    kev = KevData(cve_id="CVE-2024-0001", in_kev=in_kev)

    label, _ = determine_priority(nvd, epss_data, kev)

    assert label == expected


def test_kev_overrides_weaker_signals() -> None:
    nvd = NvdData(cve_id="CVE-2024-0001", cvss_base_score=3.1, cvss_severity="LOW")
    epss_data = EpssData(cve_id="CVE-2024-0001", epss=0.01, percentile=0.01)
    kev = KevData(cve_id="CVE-2024-0001", in_kev=True)

    label, rank = determine_priority(nvd, epss_data, kev)

    assert label == "Critical"
    assert rank == 1


def test_missing_scores_do_not_break_prioritization() -> None:
    nvd = NvdData(cve_id="CVE-2024-0001")
    epss_data = EpssData(cve_id="CVE-2024-0001")
    kev = KevData(cve_id="CVE-2024-0001", in_kev=False)

    label, rank = determine_priority(nvd, epss_data, kev)

    assert label == "Low"
    assert rank == 4


def test_attack_context_does_not_change_priority() -> None:
    service = PrioritizationService()
    cve_id = "CVE-2024-0001"

    findings_without_attack, _ = service.prioritize(
        [cve_id],
        nvd_data={cve_id: NvdData(cve_id=cve_id, cvss_base_score=9.0, cvss_severity="CRITICAL")},
        epss_data={cve_id: EpssData(cve_id=cve_id, epss=0.2, percentile=0.6)},
        kev_data={cve_id: KevData(cve_id=cve_id, in_kev=False)},
        attack_data={},
    )

    findings_with_attack, _ = service.prioritize(
        [cve_id],
        nvd_data={cve_id: NvdData(cve_id=cve_id, cvss_base_score=9.0, cvss_severity="CRITICAL")},
        epss_data={cve_id: EpssData(cve_id=cve_id, epss=0.2, percentile=0.6)},
        kev_data={cve_id: KevData(cve_id=cve_id, in_kev=False)},
        attack_data={
            cve_id: AttackData(
                cve_id=cve_id,
                attack_techniques=["T1190"],
                attack_tactics=["Initial Access"],
            )
        },
    )

    assert findings_without_attack[0].priority_label == "High"
    assert findings_with_attack[0].priority_label == "High"
    assert findings_with_attack[0].attack_techniques == ["T1190"]
