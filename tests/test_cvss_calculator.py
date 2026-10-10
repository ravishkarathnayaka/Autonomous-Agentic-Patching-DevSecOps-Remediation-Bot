import pytest
from agent_engine.state import SeverityLevel
from agent_engine.tools.cvss_calculator import CVSSCalculator


def test_score_to_severity():
    assert CVSSCalculator.score_to_severity(9.8) == SeverityLevel.CRITICAL
    assert CVSSCalculator.score_to_severity(9.0) == SeverityLevel.CRITICAL
    assert CVSSCalculator.score_to_severity(8.8) == SeverityLevel.HIGH
    assert CVSSCalculator.score_to_severity(7.0) == SeverityLevel.HIGH
    assert CVSSCalculator.score_to_severity(6.5) == SeverityLevel.MEDIUM
    assert CVSSCalculator.score_to_severity(4.0) == SeverityLevel.MEDIUM
    assert CVSSCalculator.score_to_severity(3.1) == SeverityLevel.LOW
    assert CVSSCalculator.score_to_severity(0.0) == SeverityLevel.INFO


def test_estimate_from_cwe():
    score, vector, sev = CVSSCalculator.estimate_from_cwe("CWE-78")
    assert score == 9.8
    assert "AV:N" in vector
    assert sev == SeverityLevel.CRITICAL

    score, vector, sev = CVSSCalculator.estimate_from_cwe("89")
    assert score == 8.8
    assert sev == SeverityLevel.HIGH

    score, vector, sev = CVSSCalculator.estimate_from_cwe("CWE-999999")
    assert score == 5.0
    assert sev == SeverityLevel.MEDIUM
