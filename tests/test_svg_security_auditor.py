from agent_engine.tools.svg_security_auditor import SvgSecurityAuditor


def test_svg_security_auditor_detects_xxe():
    malicious_svg = """<?xml version="1.0"?>
    <!DOCTYPE svg [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <svg>&xxe;</svg>
    """
    is_safe, violations = SvgSecurityAuditor.audit_svg(malicious_svg)
    assert not is_safe
    assert any("DOCTYPE" in v for v in violations)
    assert any("ENTITY" in v for v in violations)


def test_svg_security_auditor_detects_xss():
    xss_svg = """<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
      <circle cx="50" cy="50" r="40" />
    </svg>"""
    is_safe, violations = SvgSecurityAuditor.audit_svg(xss_svg)
    assert not is_safe
    assert any("Inline event handler" in v for v in violations)


def test_svg_security_auditor_allows_clean_svg():
    clean_svg = """<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
      <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />
    </svg>"""
    is_safe, violations = SvgSecurityAuditor.audit_svg(clean_svg)
    assert is_safe
    assert len(violations) == 0
