import pytest
from agent_engine.tools.constant_time_validator import ConstantTimeValidator


def test_constant_time_validator_detects_token_compare():
    code = """
def verify_request(req):
    user_token = req.headers.get("X-Auth")
    expected_secret = "secret_123"
    if user_token == expected_secret:
        return True
    return False
"""
    vulnerabilities = ConstantTimeValidator.audit_code(code)
    assert len(vulnerabilities) >= 1
    assert any("user_token" in v.variable_name or "expected_secret" in v.variable_name for v in vulnerabilities)
    assert "CWE-208" in vulnerabilities[0].message


def test_constant_time_validator_ignores_harmless_compare():
    code = """
def check_item(item):
    if item.status == "ACTIVE":
        return True
    return False
"""
    vulnerabilities = ConstantTimeValidator.audit_code(code)
    assert len(vulnerabilities) == 0
