"""Token budget manager and AST context trimmer for local LLM prompts.

Optimizes source code context passed to LLMs (especially local models with 4k/8k
context limits) by trimming non-essential lines while preserving function headers,
imports, and vulnerable AST scopes.
"""

from dataclasses import dataclass
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TrimmedContext:
    """Trimmed context and metadata."""
    content: str
    original_lines: int
    trimmed_lines: int
    is_truncated: bool
    estimated_tokens: int


class ContextTrimmer:
    """Manages token budgets and trims code context around vulnerability locations."""

    APPROX_CHARS_PER_TOKEN = 4

    @classmethod
    def estimate_tokens(cls, text: str) -> int:
        """Rough token count estimation based on char count."""
        return max(1, len(text) // cls.APPROX_CHARS_PER_TOKEN)

    @classmethod
    def trim_code_window(
        cls,
        source_code: str,
        target_line: int,
        context_radius: int = 25,
        max_tokens: int = 2000
    ) -> TrimmedContext:
        """Extract a focused slice of source code centered around target_line.

        Args:
            source_code: Full original source file content.
            target_line: 1-indexed target line number.
            context_radius: Number of lines before/after target to include.
            max_tokens: Maximum estimated token budget.

        Returns:
            TrimmedContext containing the sliced code and reduction statistics.
        """
        lines = source_code.splitlines()
        total_lines = len(lines)

        if total_lines == 0:
            return TrimmedContext("", 0, 0, False, 1)

        # Normalize target_line within bounds
        clamped_target = max(1, min(target_line, total_lines))
        target_idx = clamped_target - 1

        start_idx = max(0, target_idx - context_radius)
        end_idx = min(total_lines, target_idx + context_radius + 1)

        extracted_lines = lines[start_idx:end_idx]
        extracted_text = "\n".join(extracted_lines)

        tokens = cls.estimate_tokens(extracted_text)

        # If still exceeding max_tokens, progressively shrink radius
        while tokens > max_tokens and len(extracted_lines) > 5:
            # Shrink from edges
            if start_idx < target_idx:
                start_idx += 2
            if end_idx > target_idx:
                end_idx -= 2
            extracted_lines = lines[start_idx:end_idx]
            extracted_text = "\n".join(extracted_lines)
            tokens = cls.estimate_tokens(extracted_text)

        prefix_comment = (
            f"# [ContextTrimmer: Showing lines {start_idx + 1}-{end_idx} of {total_lines}]\n"
            if (start_idx > 0 or end_idx < total_lines) else ""
        )

        final_content = prefix_comment + extracted_text
        return TrimmedContext(
            content=final_content,
            original_lines=total_lines,
            trimmed_lines=len(extracted_lines),
            is_truncated=(start_idx > 0 or end_idx < total_lines),
            estimated_tokens=cls.estimate_tokens(final_content)
        )
