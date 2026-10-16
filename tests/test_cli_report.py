"""
Unit tests for CLI executive security posture report generator.
"""

import json
from cli.report import generate_executive_report


def test_generate_executive_report_markdown():
    findings = [
        {"severity": "CRITICAL", "cwe": "CWE-89", "file": "app.py", "line": 10, "description": "SQLi"},
        {"severity": "HIGH", "cwe": "CWE-79", "file": "view.js", "line": 20, "description": "XSS"},
        {"severity": "LOW", "cwe": "CWE-200", "file": "info.py", "line": 5, "description": "Info leak"}
    ]

    report = generate_executive_report(findings, repository="my-app", output_format="markdown")
    assert "# Executive DevSecOps Security Posture Report" in report
    assert "my-app" in report
    assert "CWE-89" in report
    assert "CWE-79" in report
    assert "Critical" in report


def test_generate_executive_report_json():
    findings = [
        {"severity": "MEDIUM", "cwe": "CWE-338", "file": "token.py", "line": 12, "description": "PRNG"}
    ]

    report_str = generate_executive_report(findings, repository="token-service", output_format="json")
    data = json.loads(report_str)

    assert data["repository"] == "token-service"
    assert data["total_findings"] == 1
    assert data["severity_distribution"]["MEDIUM"] == 1
    assert data["risk_posture"] == "HEALTHY"
    assert "CWE-338" in data["top_cwes"]
