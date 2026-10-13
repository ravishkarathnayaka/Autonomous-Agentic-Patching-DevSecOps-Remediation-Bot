"""Patch minimizer: strips spurious whitespace and normalizes unified diff hunks."""

import logging
import re
from typing import List

logger = logging.getLogger(__name__)


def minimize_patch(diff_text: str) -> str:
    """Normalize and minimize unified diff to eliminate noisy whitespace modifications.

    Args:
        diff_text: Raw unified diff string.

    Returns:
        Cleaned, minimal unified diff.
    """
    if not diff_text or not diff_text.strip():
        return ""

    lines = diff_text.strip().splitlines()
    clean_lines: List[str] = []

    for line in lines:
        # Strip trailing carriage returns and extra spaces on added/removed lines
        if line.startswith("+") and not line.startswith("+++"):
            clean_lines.append(line.rstrip())
        elif line.startswith("-") and not line.startswith("---"):
            clean_lines.append(line.rstrip())
        elif line.startswith(" "):
            clean_lines.append(line.rstrip())
        else:
            clean_lines.append(line.strip())

    result = "\n".join(clean_lines)
    # Ensure terminating newline
    if not result.endswith("\n"):
        result += "\n"

    return result


def count_hunk_changes(diff_text: str) -> dict:
    """Count additions, deletions, and touched files in unified diff."""
    additions = 0
    deletions = 0
    files = set()

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            files.add(line[6:].strip())
        elif line.startswith("+") and not line.startswith("+++"):
            additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1

    return {
        "files_changed": len(files),
        "additions": additions,
        "deletions": deletions,
        "total_delta": additions + deletions
    }
