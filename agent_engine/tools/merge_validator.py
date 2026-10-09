"""Merge conflict detector and git patch sanity validator."""

from dataclasses import dataclass
import logging
import re
from typing import List, Optional

logger = logging.getLogger(__name__)

CONFLICT_START_REGEX = re.compile(r"^<{7}\s+.*$", re.MULTILINE)
CONFLICT_MID_REGEX = re.compile(r"^={7}$", re.MULTILINE)
CONFLICT_END_REGEX = re.compile(r"^>{7}\s+.*$", re.MULTILINE)


@dataclass
class ConflictCheckResult:
    """Result of merge conflict scan."""
    has_conflicts: bool
    conflict_markers_count: int
    error_summary: Optional[str] = None


class MergeValidator:
    """Validates that candidate patches and patched source files contain no unmerged git markers."""

    @classmethod
    def check_for_conflict_markers(cls, content: str) -> ConflictCheckResult:
        """Scan string content for standard git merge conflict markers.

        Args:
            content: File or diff string content.

        Returns:
            ConflictCheckResult indicating whether conflict markers were detected.
        """
        start_matches = CONFLICT_START_REGEX.findall(content)
        mid_matches = CONFLICT_MID_REGEX.findall(content)
        end_matches = CONFLICT_END_REGEX.findall(content)

        total_markers = len(start_matches) + len(mid_matches) + len(end_matches)

        if total_markers > 0:
            summary = (
                f"Detected {len(start_matches)} conflict start ('<<<<<<<'), "
                f"{len(mid_matches)} separator ('======='), and "
                f"{len(end_matches)} end ('>>>>>>>') markers."
            )
            logger.warning("Merge conflict check failed: %s", summary)
            return ConflictCheckResult(
                has_conflicts=True,
                conflict_markers_count=total_markers,
                error_summary=summary
            )

        return ConflictCheckResult(
            has_conflicts=False,
            conflict_markers_count=0,
            error_summary=None
        )
