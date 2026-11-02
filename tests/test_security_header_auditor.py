import pytest
from agent_engine.tools.security_header_auditor import SecurityHeaderAuditor


def test_security_header_auditor_all_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    findings = SecurityHeaderAuditor.audit_headers(headers)
    assert len(findings) == 0


def test_security_header_auditor_detects_missing():
    headers = {
        "Content-Type": "application/json",
    }
    findings = SecurityHeaderAuditor.audit_headers(headers)
    assert len(findings) == 6
    missing_headers = [f.header for f in findings]
    assert "Strict-Transport-Security" in missing_headers
    assert "Content-Security-Policy" in missing_headers


def test_security_header_auditor_detects_weak_values():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src *",
        "X-Content-Type-Options": "sniff",
        "X-Frame-Options": "ALLOW-FROM https://foo.com",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    findings = SecurityHeaderAuditor.audit_headers(headers)
    assert any(f.header == "X-Content-Type-Options" for f in findings)
    assert any(f.header == "X-Frame-Options" for f in findings)
