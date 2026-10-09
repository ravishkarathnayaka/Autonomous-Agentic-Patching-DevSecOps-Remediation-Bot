"""Multi-file patch applicator and hunk parser utility."""

from dataclasses import dataclass
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FilePatchHunk:
    """Individual file diff hunk."""
    target_file: str
    diff_text: str


@dataclass
class MultiPatchResult:
    """Outcome of multi-file patch execution."""
    success: bool
    modified_files: List[str]
    error_message: Optional[str] = None


class PatchApplicator:
    """Parses and applies compound git diffs across multiple files atomically."""

    DIFF_FILE_HEADER_REGEX = re.compile(r"^--- (?:a/)?([^\s\n]+)\n\+\+\+ (?:b/)?([^\s\n]+)", re.MULTILINE)

    @classmethod
    def split_multi_file_diff(cls, full_diff: str) -> List[FilePatchHunk]:
        """Split a unified diff string containing multiple files into individual hunks.

        Args:
            full_diff: Compound unified diff text.

        Returns:
            List of FilePatchHunk objects for each file.
        """
        hunks: List[FilePatchHunk] = []
        # Find all --- a/... +++ b/... occurrences
        matches = list(cls.DIFF_FILE_HEADER_REGEX.finditer(full_diff))

        if not matches:
            # Single file patch or no header
            return [FilePatchHunk(target_file="", diff_text=full_diff)]

        for i, match in enumerate(matches):
            target_file = match.group(2)
            start_pos = match.start()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(full_diff)
            hunk_diff = full_diff[start_pos:end_pos].strip()

            hunks.append(FilePatchHunk(
                target_file=target_file,
                diff_text=hunk_diff
            ))

        return hunks

    @classmethod
    def apply_simple_substitution(cls, original_text: str, remove_lines: List[str], add_lines: List[str]) -> str:
        """Applies line replacement substitution to source text."""
        old_block = "\n".join(remove_lines)
        new_block = "\n".join(add_lines)
        if old_block in original_text:
            return original_text.replace(old_block, new_block, 1)
        return original_text
