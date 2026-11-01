from agent_engine.tools.opsgenie_formatter import OpsgenieAlertFormatter
from agent_engine.state import Finding, FindingType, SeverityLevel


def test_opsgenie_alert_formatter_critical():
    finding = Finding(
        id="cwe-89-sqli-finding",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-89",
        title="SQL Injection in user route",
        description="Dynamic string formatting into database cursor execute",
        severity=SeverityLevel.CRITICAL,
        cvss_score=9.8,
        cwe_ids=["CWE-89"],
        file_path="target_repo/app.py",
        start_line=38
    )

    alert = OpsgenieAlertFormatter.format_alert(finding, status="SANDBOX_FAILED")

    assert alert["priority"] == "P1"
    assert "SANDBOX_FAILED" in alert["message"]
    assert alert["alias"] == "remediation-cwe-89-sqli-finding"
    assert alert["details"]["CVSS"] == "9.8"
    assert alert["details"]["CWE"] == "CWE-89"
    assert "devsecops-bot" in alert["tags"]
    assert "semgrep" in alert["tags"]
