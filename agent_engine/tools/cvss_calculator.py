"""CVSS v3.1 and v4.0 calculation and baseline mapping engine for security findings."""

from typing import Dict, Optional, Tuple
from agent_engine.state import SeverityLevel


# Standard baseline CVSS v3.1 scores and vectors for common CWEs
CWE_CVSS_BASELINES: Dict[str, Tuple[float, str]] = {
    "CWE-78": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # OS Command Injection
    "CWE-89": (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),   # SQL Injection
    "CWE-798": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # Hardcoded Credentials
    "CWE-502": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # Deserialization of Untrusted Data
    "CWE-918": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),  # SSRF
    "CWE-22": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),   # Path Traversal
    "CWE-327": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),  # Broken Cryptography
    "CWE-79": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),   # XSS
    "CWE-200": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),  # Info Exposure
    "CWE-639": (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),  # IDOR
    "CWE-1333": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), # ReDoS
}


class CVSSCalculator:
    """Calculates CVSS base metrics and assigns standard severity classifications."""

    @staticmethod
    def score_to_severity(score: float) -> SeverityLevel:
        """Convert standard numeric CVSS score (0.0 - 10.0) to normalized SeverityLevel."""
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score > 0.0:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    @classmethod
    def estimate_from_cwe(cls, cwe_id: str) -> Tuple[float, str, SeverityLevel]:
        """
        Estimate CVSS v3.1 score, vector string, and severity from a CWE identifier.
        Returns: (cvss_score, vector_string, severity_level)
        """
        clean_cwe = cwe_id.upper().strip()
        if not clean_cwe.startswith("CWE-"):
            clean_cwe = f"CWE-{clean_cwe}"

        if clean_cwe in CWE_CVSS_BASELINES:
            score, vector = CWE_CVSS_BASELINES[clean_cwe]
            return score, vector, cls.score_to_severity(score)

        # Default fallback for unknown CWE
        score = 5.0
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        return score, vector, SeverityLevel.MEDIUM
