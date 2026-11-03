"""Security validator for neutralizing Log Injection (CWE-117) and ANSI escape sequences."""

import re
from typing import Tuple


class LogSanitizerValidator:
    """Validates and sanitizes text before writing to log streams to eliminate CWE-117."""

    ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    @classmethod
    def is_safe_log_message(cls, message: str) -> Tuple[bool, str]:
        """Verify whether a message string is free from CRLF injection and terminal escapes.

        Args:
            message: Raw log content string.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not isinstance(message, str):
            return False, "Log message must be a string."

        if "\r" in message or "\n" in message:
            return False, "Message contains CRLF characters that permit log splitting/injection."

        if cls.ANSI_ESCAPE_PATTERN.search(message):
            return False, "Message contains ANSI terminal escape sequences."

        return True, "Safe log message."

    @classmethod
    def sanitize(cls, message: str, max_length: int = 500) -> str:
        """Strip CRLF and ANSI escapes from a log message, truncating if necessary.

        Args:
            message: Unsanitized input string.
            max_length: Maximum allowed string length.

        Returns:
            Sanitized, single-line log-safe string.
        """
        if not message:
            return ""

        # Remove ANSI escape codes
        cleaned = cls.ANSI_ESCAPE_PATTERN.sub("", message)

        # Replace CR and LF with space or underscore
        cleaned = cleaned.replace("\r", " ").replace("\n", " ").strip()

        if len(cleaned) > max_length:
            return cleaned[:max_length - 3] + "..."

        return cleaned
