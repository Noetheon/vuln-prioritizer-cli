"""Priority logic and deterministic rationale generation."""

from __future__ import annotations

from vuln_prioritizer.config import PRIORITY_RANKS, PRIORITY_RECOMMENDATIONS
from vuln_prioritizer.models import AttackData, EpssData, KevData, NvdData


def determine_priority(nvd: NvdData, epss: EpssData, kev: KevData) -> tuple[str, int]:
    """Apply the fixed MVP priority rules."""
    cvss = nvd.cvss_base_score
    epss_score = epss.epss

    if kev.in_kev or (
        epss_score is not None
        and epss_score >= 0.70
        and cvss is not None
        and cvss >= 7.0
    ):
        label = "Critical"
    elif (epss_score is not None and epss_score >= 0.40) or (
        cvss is not None and cvss >= 9.0
    ):
        label = "High"
    elif (cvss is not None and cvss >= 7.0) or (
        epss_score is not None and epss_score >= 0.10
    ):
        label = "Medium"
    else:
        label = "Low"

    return label, PRIORITY_RANKS[label]


def build_rationale(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData | None = None,
) -> str:
    """Build a deterministic rationale string from the available signals."""
    parts: list[str] = []

    if kev.in_kev:
        parts.append("CISA KEV lists this CVE as known exploited in the wild.")

    if nvd.cvss_base_score is not None:
        severity = f" ({nvd.cvss_severity})" if nvd.cvss_severity else ""
        parts.append(f"NVD reports CVSS {nvd.cvss_base_score:.1f}{severity}.")
    else:
        parts.append("NVD CVSS data is unavailable or not yet analyzed.")

    if epss.epss is not None:
        percentile_note = ""
        if epss.percentile is not None:
            percentile_note = f" (percentile {epss.percentile:.3f})"
        parts.append(f"FIRST EPSS is {epss.epss:.3f}{percentile_note}.")
    else:
        parts.append("FIRST EPSS data is unavailable.")

    if attack and attack.attack_techniques:
        parts.append(
            "Optional ATT&CK context is available for: "
            + ", ".join(attack.attack_techniques)
            + "."
        )

    return " ".join(parts)


def recommended_action(priority_label: str) -> str:
    """Return the action text for a priority label."""
    return PRIORITY_RECOMMENDATIONS[priority_label]
