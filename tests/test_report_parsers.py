"""Unit tests for Semgrep and Trivy security report parsers."""

from pathlib import Path
import pytest

from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.report_parsers import (
    _extract_cwe_ids,
    _map_semgrep_severity,
    _map_trivy_severity,
    load_findings_from_file,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_semgrep_findings():
    """Verify parsing Semgrep SAST JSON into normalized Finding objects."""
    semgrep_file = FIXTURES_DIR / "semgrep_findings.json"
    findings = load_findings_from_file(semgrep_file)

    assert len(findings) == 3

    # Finding 1: SQL Injection
    sqli = findings[0]
    assert sqli.scanner == "semgrep"
    assert sqli.finding_type == FindingType.SAST
    assert "sqlite_sql_injection" in sqli.rule_id
    assert sqli.severity == SeverityLevel.HIGH
    assert "CWE-89" in sqli.cwe_ids
    assert sqli.cvss_score == 9.8
    assert sqli.file_path == "target_repo/app.py"
    assert sqli.start_line == 28
    assert "SELECT * FROM items" in sqli.vulnerable_code

    # Finding 2: Path Traversal
    traversal = findings[1]
    assert traversal.severity == SeverityLevel.MEDIUM
    assert "CWE-22" in traversal.cwe_ids
    assert traversal.start_line == 42

    # Finding 3: Command Injection
    cmdi = findings[2]
    assert cmdi.severity == SeverityLevel.HIGH
    assert "CWE-78" in cmdi.cwe_ids


def test_parse_trivy_findings():
    """Verify parsing Trivy SCA JSON into normalized Finding objects."""
    trivy_file = FIXTURES_DIR / "trivy_findings.json"
    findings = load_findings_from_file(trivy_file)

    assert len(findings) == 2

    flask_vuln = findings[0]
    assert flask_vuln.scanner == "trivy"
    assert flask_vuln.finding_type == FindingType.SCA
    assert flask_vuln.rule_id == "CVE-2023-30861"
    assert flask_vuln.package_name == "Flask"
    assert flask_vuln.installed_version == "2.2.0"
    assert flask_vuln.fixed_version == "2.2.5"
    assert flask_vuln.severity == SeverityLevel.HIGH
    assert "CWE-384" in flask_vuln.cwe_ids
    assert flask_vuln.cvss_score == 7.5


def test_extract_cwe_ids():
    """Verify flexible extraction of CWE identifiers from messy scanner inputs."""
    assert _extract_cwe_ids(["CWE-89: SQL Injection", "CWE-79"]) == ["CWE-89", "CWE-79"]
    assert _extract_cwe_ids("CWE-22") == ["CWE-22"]
    assert _extract_cwe_ids([]) == []
    assert _extract_cwe_ids(None) == []


def test_severity_mappings():
    """Verify severity string mapping."""
    assert _map_semgrep_severity("ERROR") == SeverityLevel.HIGH
    assert _map_semgrep_severity("WARNING") == SeverityLevel.MEDIUM
    assert _map_semgrep_severity("INFO") == SeverityLevel.LOW

    assert _map_trivy_severity("CRITICAL") == SeverityLevel.CRITICAL
    assert _map_trivy_severity("HIGH") == SeverityLevel.HIGH
    assert _map_trivy_severity("MEDIUM") == SeverityLevel.MEDIUM
    assert _map_trivy_severity("LOW") == SeverityLevel.LOW


def test_load_findings_invalid_file(tmp_path):
    """Verify error raised on non-existent or unsupported file."""
    with pytest.raises(FileNotFoundError):
        load_findings_from_file(tmp_path / "non_existent.json")

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text('{"unknown_key": "data"}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_findings_from_file(invalid_json)
