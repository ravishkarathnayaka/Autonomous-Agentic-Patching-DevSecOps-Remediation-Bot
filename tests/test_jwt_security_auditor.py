import base64
import json
import time
import pytest
from agent_engine.tools.jwt_security_auditor import JwtSecurityAuditor


def _create_jwt(header: dict, payload: dict, signature: str = "fake_sig") -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.{signature}"


def test_jwt_auditor_safe_token():
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "user123", "exp": int(time.time()) + 3600}
    token = _create_jwt(header, payload)
    issues = JwtSecurityAuditor.audit_token(token)
    assert len(issues) == 0


def test_jwt_auditor_alg_none():
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "exp": int(time.time()) + 3600}
    token = _create_jwt(header, payload, signature="")
    issues = JwtSecurityAuditor.audit_token(token)
    assert any(i.severity == "CRITICAL" and "none" in i.issue for i in issues)


def test_jwt_auditor_missing_exp():
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "user123"}
    token = _create_jwt(header, payload)
    issues = JwtSecurityAuditor.audit_token(token)
    assert any(i.severity == "HIGH" and "exp" in i.issue for i in issues)
