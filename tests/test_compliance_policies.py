import pytest
from agent_engine.policy_engine import RemediationPolicy, RemediationPolicyEngine
from agent_engine.state import Finding, SeverityLevel


def test_pci_dss_compliance_signoff():
    policy = RemediationPolicy({
        "compliance_profile": "PCI-DSS"
    })
    engine = RemediationPolicyEngine(policy)

    # Finding with CWE-327 (Broken Crypto) requires manual sign-off under PCI-DSS
    finding_crypto = Finding(
        id="f-pci-1",
        scanner="semgrep",
        rule_id="crypto-rule",
        title="MD5 used",
        description="Weak hash",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-327"],
        file_path="auth.py"
    )
    report = engine.evaluate_compliance(finding_crypto)
    assert report["compliance_profile"] == "PCI-DSS"
    assert report["requires_manual_signoff"] is True
    assert "PCI-DSS Req 6.4" in report["notes"][0]

    # Non-sensitive finding (e.g. CWE-79 XSS) does not require manual sign-off
    finding_xss = Finding(
        id="f-pci-2",
        scanner="semgrep",
        rule_id="xss-rule",
        title="XSS",
        description="XSS finding",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-79"],
        file_path="views.py"
    )
    report2 = engine.evaluate_compliance(finding_xss)
    assert report2["requires_manual_signoff"] is False


def test_soc2_compliance_sandbox_check():
    policy = RemediationPolicy({
        "compliance_profile": "SOC2",
        "require_sandbox": False
    })
    engine = RemediationPolicyEngine(policy)

    finding = Finding(
        id="f-soc-1",
        scanner="semgrep",
        rule_id="sqli-rule",
        title="SQLi",
        description="SQLi finding",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        file_path="app.py"
    )
    report = engine.evaluate_compliance(finding)
    assert report["compliance_profile"] == "SOC2"
    assert "SOC2 Trust Services Criteria CC7.1" in report["notes"][0]
