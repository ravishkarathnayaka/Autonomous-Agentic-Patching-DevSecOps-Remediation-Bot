import pytest
from agent_engine.tools.pbkdf2_auditor import Pbkdf2ParameterAuditor


def test_pbkdf2_auditor_compliant_parameters():
    salt = b"0123456789abcdef"  # 16 bytes
    findings = Pbkdf2ParameterAuditor.audit_parameters("sha256", 600000, salt)
    assert len(findings) == 0


def test_pbkdf2_auditor_weak_hash():
    salt = b"0123456789abcdef"
    findings = Pbkdf2ParameterAuditor.audit_parameters("md5", 600000, salt)
    assert any(f.parameter == "hash_name" and f.severity == "CRITICAL" for f in findings)


def test_pbkdf2_auditor_low_iterations_short_salt():
    findings = Pbkdf2ParameterAuditor.audit_parameters("sha256", 100, b"short")
    assert len(findings) == 2
    params = [f.parameter for f in findings]
    assert "iterations" in params
    assert "salt" in params
