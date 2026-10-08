"""AST-based syntax and structure validator for candidate security patches.

Pre-screens candidate patched code before launching ephemeral Docker sandbox
to save execution overhead and provide immediate feedback on syntax errors.
"""

import ast
from dataclasses import dataclass
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of pre-sandbox patch validation."""
    is_valid: bool
    error_message: Optional[str] = None
    syntax_error_line: Optional[int] = None
    warnings: Optional[List[str]] = None


class PatchValidator:
    """Validates Python syntax and structure of candidate patched code."""

    @staticmethod
    def validate_python_code(code_str: str) -> ValidationResult:
        """Parse code into Python AST to ensure it compiles without SyntaxError.

        Args:
            code_str: The full patched file content to validate.

        Returns:
            ValidationResult with success status and detailed error if invalid.
        """
        warnings: List[str] = []
        try:
            tree = ast.parse(code_str)
            # Check for empty module if original wasn't empty
            if not tree.body and len(code_str.strip()) > 0:
                warnings.append("Parsed AST has empty body despite non-empty source.")

            return ValidationResult(
                is_valid=True,
                error_message=None,
                warnings=warnings if warnings else None
            )
        except SyntaxError as e:
            msg = f"SyntaxError: {e.msg} at line {e.lineno}, column {e.offset}"
            logger.warning(f"Patch validation failed: {msg}")
            return ValidationResult(
                is_valid=False,
                error_message=msg,
                syntax_error_line=e.lineno,
                warnings=warnings if warnings else None
            )
        except Exception as e:
            msg = f"AST parse exception: {str(e)}"
            logger.warning(f"Unexpected patch validation error: {msg}")
            return ValidationResult(
                is_valid=False,
                error_message=msg,
                warnings=warnings if warnings else None
            )
