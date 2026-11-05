"""Security validator for inspecting query strings against HTTP Parameter Pollution (HPP)."""

from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlparse


class HppValidator:
    """Validates HTTP request parameters and URLs against Parameter Pollution (CWE-235)."""

    @classmethod
    def validate_query_string(
        cls,
        query_string_or_url: str,
        allowed_multi_keys: List[str] = None,
    ) -> Tuple[bool, str, Dict[str, List[str]]]:
        """Inspect query string or URL for duplicate parameter keys.

        Args:
            query_string_or_url: Raw query string (e.g. 'id=1&id=2') or full URL.
            allowed_multi_keys: List of parameter names allowed to repeat (e.g. 'filter', 'tags').

        Returns:
            Tuple of (is_safe: bool, reason: str, parsed_params: dict).
        """
        if not query_string_or_url:
            return True, "Empty query string is safe.", {}

        allowed = set(allowed_multi_keys or [])

        # If it looks like a URL, extract query part
        if "?" in query_string_or_url:
            query_part = urlparse(query_string_or_url).query
        else:
            query_part = query_string_or_url

        parsed = parse_qs(query_part, keep_blank_values=True)
        duplicated_keys = []

        for key, values in parsed.items():
            if len(values) > 1 and key not in allowed:
                duplicated_keys.append(f"'{key}' ({len(values)} occurrences)")

        if duplicated_keys:
            joined = ", ".join(duplicated_keys)
            return False, f"HTTP Parameter Pollution detected with duplicate keys: {joined}", parsed

        return True, "No unexpected duplicate query parameters detected.", parsed
