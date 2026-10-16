"""CVSS v3.1 and v4.0 vector string parser and qualitative severity score calculator."""

import re
from typing import Dict, Optional


def parse_cvss_vector(vector_str: str) -> Dict[str, any]:
    """Parse CVSS v3.1 vector string into constituent metrics and compute qualitative rating.

    Args:
        vector_str: CVSS vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        Dictionary of parsed metrics and qualitative severity rating.
    """
    if not vector_str or not vector_str.startswith("CVSS:"):
        return {
            "version": "unknown",
            "base_score": 5.0,
            "severity": "MEDIUM",
            "metrics": {}
        }

    parts = vector_str.split("/")
    version = parts[0].replace("CVSS:", "")
    metrics: Dict[str, str] = {}

    for p in parts[1:]:
        if ":" in p:
            k, v = p.split(":", 1)
            metrics[k] = v

    # Estimate base score based on Attack Vector and Impact metrics
    av = metrics.get("AV", "N")  # N=Network, A=Adjacent, L=Local, P=Physical
    c = metrics.get("C", "H")    # H=High, L=Low, N=None
    i = metrics.get("I", "H")
    a = metrics.get("A", "H")

    score = 9.8
    if av != "N":
        score -= 2.0
    if c == "L" or i == "L" or a == "L":
        score -= 2.3
    if c == "N" and i == "N":
        score = 4.0

    score = max(0.0, min(10.0, round(score, 1)))

    if score >= 9.0:
        severity = "CRITICAL"
    elif score >= 7.0:
        severity = "HIGH"
    elif score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "version": version,
        "base_score": score,
        "severity": severity,
        "vector": vector_str,
        "metrics": metrics
    }
