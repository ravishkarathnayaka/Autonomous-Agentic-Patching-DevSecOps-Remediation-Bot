from agent_engine.tools.regex_complexity_auditor import RegexComplexityAuditor


def test_regex_auditor_detects_nested_quantifiers():
    evil_pattern = r"(a+)+"
    is_safe, warnings = RegexComplexityAuditor.audit_pattern(evil_pattern)
    assert not is_safe
    assert any("Nested quantifiers" in w for w in warnings)


def test_regex_auditor_detects_nested_char_class():
    evil_pattern = r"([a-zA-Z0-9]+)*"
    is_safe, warnings = RegexComplexityAuditor.audit_pattern(evil_pattern)
    assert not is_safe
    assert len(warnings) > 0


def test_regex_auditor_rejects_invalid_syntax():
    invalid_pattern = r"[a-z"
    is_safe, warnings = RegexComplexityAuditor.audit_pattern(invalid_pattern)
    assert not is_safe
    assert any("syntax" in w for w in warnings)


def test_regex_auditor_accepts_clean_pattern():
    clean_pattern = r"^[a-zA-Z0-9_-]{3,16}$"
    is_safe, warnings = RegexComplexityAuditor.audit_pattern(clean_pattern)
    assert is_safe
    assert RegexComplexityAuditor.is_safe_pattern(clean_pattern)
