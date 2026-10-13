"""MTTR and enterprise DevSecOps ROI calculation utility."""

from typing import Dict, List


def calculate_remediation_roi(
    remediated_findings_count: int,
    average_manual_fix_hours: float = 4.5,
    engineer_hourly_rate: float = 85.0
) -> Dict[str, any]:
    """Calculate engineering time saved and financial ROI of autonomous patching.

    Args:
        remediated_findings_count: Number of successfully patched findings.
        average_manual_fix_hours: Industry standard triage + patch + test time per vulnerability.
        engineer_hourly_rate: Average engineer loaded hourly cost in USD.

    Returns:
        Dictionary of ROI metrics.
    """
    total_hours_saved = round(remediated_findings_count * average_manual_fix_hours, 1)
    total_cost_saved = round(total_hours_saved * engineer_hourly_rate, 2)
    # Average MTTR drops from 28 days (manual sprint backlog) to ~120 seconds (autonomous bot)
    mttr_reduction_percent = 99.8 if remediated_findings_count > 0 else 0.0

    return {
        "remediated_count": remediated_findings_count,
        "hours_saved": total_hours_saved,
        "cost_savings_usd": total_cost_saved,
        "mttr_reduction_percent": mttr_reduction_percent,
        "autonomous_mttr_seconds": 120
    }
