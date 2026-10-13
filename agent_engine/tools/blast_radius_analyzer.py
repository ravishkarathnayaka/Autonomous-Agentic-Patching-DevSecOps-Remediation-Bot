"""Blast radius and impact analyzer for evaluating patch risk tier prior to PR generation."""

import logging
from typing import Dict, List, Set
from agent_engine.tools.patch_minimizer import count_hunk_changes

logger = logging.getLogger(__name__)


def evaluate_blast_radius(diff_text: str, finding_file: str) -> Dict[str, any]:
    """Calculate the blast radius and regression risk of a proposed security patch.

    Args:
        diff_text: Generated unified diff.
        finding_file: Original file flagged by scanner.

    Returns:
        Risk evaluation dictionary containing risk_tier, score, and impacted files.
    """
    if not diff_text:
        return {
            "risk_tier": "LOW",
            "risk_score": 1,
            "impacted_files": [],
            "reason": "Empty diff"
        }

    stats = count_hunk_changes(diff_text)
    total_delta = stats["total_delta"]
    files_count = stats["files_changed"]

    # Calculate blast radius score (1 - 10)
    score = min(10, max(1, (files_count * 2) + (total_delta // 5)))

    if score >= 7 or files_count > 3:
        risk_tier = "HIGH"
        reason = f"Patch modifies {files_count} files with {total_delta} lines changed; broad regression testing recommended."
    elif score >= 4 or total_delta > 15:
        risk_tier = "MEDIUM"
        reason = f"Moderate change surface ({total_delta} lines across {files_count} files)."
    else:
        risk_tier = "LOW"
        reason = f"Surgical, tightly scoped patch ({total_delta} lines in {files_count} file)."

    return {
        "risk_tier": risk_tier,
        "risk_score": score,
        "files_count": files_count,
        "lines_delta": total_delta,
        "reason": reason
    }
