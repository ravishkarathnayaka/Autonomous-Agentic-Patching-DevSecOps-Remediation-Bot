from agent_engine.tools.cookie_security_auditor import CookieSecurityAuditor


def test_cookie_security_auditor_secure():
    is_safe, issues = CookieSecurityAuditor.audit_cookie(
        name="__Host-session",
        value="tok_12345",
        httponly=True,
        secure=True,
        samesite="Strict"
    )
    assert is_safe is True
    assert len(issues) == 0


def test_cookie_security_auditor_insecure():
    is_safe, issues = CookieSecurityAuditor.audit_cookie(
        name="session_token",
        value="tok_12345",
        httponly=False,
        secure=False,
        samesite=None
    )
    assert is_safe is False
    assert any("HttpOnly" in msg for msg in issues)
    assert any("Secure" in msg for msg in issues)
    assert any("SameSite" in msg for msg in issues)
