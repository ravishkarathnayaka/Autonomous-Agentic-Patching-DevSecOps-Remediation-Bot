from agent_engine.tools.xpath_structure_validator import XpathStructureValidator


def test_xpath_validator_detects_single_quote_breakout():
    is_safe, defects = XpathStructureValidator.validate_literal("electronics' or '1'='1")
    assert not is_safe
    assert any("Prohibited delimiter" in d for d in defects)
    assert any("or" in d for d in defects)


def test_xpath_validator_detects_bracket_injection():
    is_safe, defects = XpathStructureValidator.validate_literal("admin][password")
    assert not is_safe
    assert any("]" in d for d in defects)


def test_xpath_validator_allows_alphanumeric_clean():
    clean_val = "smartphones_2026"
    assert XpathStructureValidator.is_safe_literal(clean_val)
    is_safe, defects = XpathStructureValidator.validate_literal(clean_val)
    assert is_safe
    assert len(defects) == 0


def test_xpath_validator_rejects_empty():
    assert not XpathStructureValidator.is_safe_literal("")
