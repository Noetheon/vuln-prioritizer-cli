"""Priority logic and deterministic rationale generation."""

from __future__ import annotations

from vuln_prioritizer.config import PRIORITY_RANKS, PRIORITY_RECOMMENDATIONS
from vuln_prioritizer.models import (
    AttackData,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityPolicy,
)


def determine_priority(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    policy: PriorityPolicy | None = None,
) -> tuple[str, int]:
    """Apply the fixed MVP priority rules."""
    active_policy = policy or PriorityPolicy()
    cvss = nvd.cvss_base_score
    epss_score = epss.epss

    if kev.in_kev or (
        epss_score is not None
        and epss_score >= active_policy.critical_epss_threshold
        and cvss is not None
        and cvss >= active_policy.critical_cvss_threshold
    ):
        label = "Critical"
    elif (epss_score is not None and epss_score >= active_policy.high_epss_threshold) or (
        cvss is not None and cvss >= active_policy.high_cvss_threshold
    ):
        label = "High"
    elif (cvss is not None and cvss >= active_policy.medium_cvss_threshold) or (
        epss_score is not None and epss_score >= active_policy.medium_epss_threshold
    ):
        label = "Medium"
    else:
        label = "Low"

    return label, PRIORITY_RANKS[label]


def determine_cvss_only_priority(cvss_base_score: float | None) -> tuple[str, int]:
    """Apply the comparison baseline that only uses CVSS severity bands."""
    if cvss_base_score is not None and cvss_base_score >= 9.0:
        label = "Critical"
    elif cvss_base_score is not None and cvss_base_score >= 7.0:
        label = "High"
    elif cvss_base_score is not None and cvss_base_score >= 4.0:
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
            "Optional ATT&CK context is available for: " + ", ".join(attack.attack_techniques) + "."
        )
    if attack and attack.attack_note:
        parts.append(f"ATT&CK mapping note: {attack.attack_note.rstrip('.')}.")

    return " ".join(parts)


def build_comparison_reason(
    finding: PrioritizedFinding,
    *,
    cvss_only_label: str,
    cvss_only_rank: int,
) -> str:
    """Explain why the enriched result differs from or matches the CVSS-only baseline."""
    if finding.priority_rank < cvss_only_rank:
        if finding.in_kev:
            return (
                f"KEV membership raises this CVE from the CVSS-only {cvss_only_label} baseline "
                f"to {finding.priority_label}."
            )
        if finding.epss is not None:
            return (
                f"EPSS {finding.epss:.3f} raises this CVE from the CVSS-only "
                f"{cvss_only_label} baseline to {finding.priority_label}."
            )
        return (
            f"Additional enrichment raises this CVE from the CVSS-only {cvss_only_label} "
            f"baseline to {finding.priority_label}."
        )

    if finding.priority_rank > cvss_only_rank:
        return (
            f"CVSS alone would rate this CVE as {cvss_only_label}, but the enriched model "
            f"lowers it to {finding.priority_label} because KEV is absent and EPSS stays below "
            "the escalation thresholds."
        )

    if finding.cvss_base_score is None and finding.epss is None and not finding.in_kev:
        return "Missing CVSS and EPSS data leave both baseline and enriched views at Low."

    if finding.cvss_base_score is None:
        return (
            f"Missing CVSS keeps the baseline at {cvss_only_label}, and the available "
            "enrichment signals do not change the result."
        )

    if not finding.in_kev and (finding.epss is None or finding.epss < 0.10):
        return (
            f"CVSS alone already yields {cvss_only_label}, and EPSS/KEV do not change the result."
        )

    return f"CVSS and enrichment both support the same {finding.priority_label} outcome."


def recommended_action(priority_label: str) -> str:
    """Return the action text for a priority label."""
    return PRIORITY_RECOMMENDATIONS[priority_label]
