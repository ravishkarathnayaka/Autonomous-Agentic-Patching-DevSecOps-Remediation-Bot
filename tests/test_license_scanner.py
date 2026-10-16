"""
Unit tests for LicenseRiskScanner.
"""

from agent_engine.tools.license_scanner import LicenseRiskScanner


def test_license_scanner_compliant_permissive():
    scanner = LicenseRiskScanner()
    deps = [
        {"name": "fastapi", "version": "0.110.0", "license": "MIT"},
        {"name": "urllib3", "version": "2.1.0", "license": "Apache-2.0"},
        {"name": "pydantic", "version": "2.6.0", "license": "MIT"}
    ]

    result = scanner.audit_dependencies(deps)
    assert result["passed"] is True
    assert result["violation_count"] == 0
    assert result["compliant_count"] == 3


def test_license_scanner_strong_copyleft_violation():
    scanner = LicenseRiskScanner(policy={"allow_strong_copyleft": False})
    deps = [
        {"name": "gpl-library", "version": "1.0.0", "license": "GPL-3.0"},
        {"name": "mit-library", "version": "2.0.0", "license": "MIT"}
    ]

    result = scanner.audit_dependencies(deps)
    assert result["passed"] is False
    assert result["violation_count"] == 1
    assert result["violations"][0]["package"] == "gpl-library"
    assert result["violations"][0]["tier"] == "STRONG_COPYLEFT"


def test_license_scanner_banned_license():
    scanner = LicenseRiskScanner(policy={"banned_licenses": ["MPL-2.0"]})
    deps = [
        {"name": "certifi", "version": "2024.2.2", "license": "MPL-2.0"}
    ]

    result = scanner.audit_dependencies(deps)
    assert result["passed"] is False
    assert result["violation_count"] == 1
    assert "banned by policy" in result["violations"][0]["reason"]
