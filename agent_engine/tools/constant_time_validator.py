"""Static analysis validator for identifying timing discrepancies in secret comparisons."""

import ast
from typing import List, NamedTuple


class TimingVulnerability(NamedTuple):
    line_number: int
    variable_name: str
    message: str


class ConstantTimeValidator:
    """Detects unsafe variable comparisons that leak secret values via timing side channels (CWE-208)."""

    SENSITIVE_NAMES = {
        "secret", "token", "apikey", "api_key", "signature", "digest",
        "mac", "hmac", "hash", "password", "auth", "credential", "session_token"
    }

    @classmethod
    def audit_code(cls, source_code: str) -> List[TimingVulnerability]:
        """Audit Python source code for naive equality checks involving sensitive variables.

        Args:
            source_code: Python source code string.

        Returns:
            List of detected TimingVulnerability instances.
        """
        findings: List[TimingVulnerability] = []
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op in node.ops:
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        names = cls._extract_names(node.left)
                        for comparator in node.comparators:
                            names.extend(cls._extract_names(comparator))

                        for name in names:
                            if any(sens in name.lower() for sens in cls.SENSITIVE_NAMES):
                                findings.append(
                                    TimingVulnerability(
                                        line_number=node.lineno,
                                        variable_name=name,
                                        message=(
                                            f"Potential timing attack (CWE-208): Sensitive variable '{name}' "
                                            "compared using non-constant-time equality. Use 'hmac.compare_digest'."
                                        )
                                    )
                                )
                                break
        return findings

    @classmethod
    def _extract_names(cls, node: ast.AST) -> List[str]:
        names = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        return names
