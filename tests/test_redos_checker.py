from agent_engine.tools.redos_checker import ReDoSChecker


def test_redos_checker_nested_plus():
    res = ReDoSChecker.check_regex(r"^([a-zA-Z0-9]+)+$")
    assert res["vulnerable"] is True
    assert res["severity"] == "HIGH"
    assert "nested repetition" in res["remediation"]


def test_redos_checker_nested_star():
    res = ReDoSChecker.check_regex(r"^(a*)*$")
    assert res["vulnerable"] is True
    assert res["severity"] == "HIGH"


def test_redos_checker_safe_regex():
    res = ReDoSChecker.check_regex(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    assert res["vulnerable"] is False
    assert res["severity"] == "NONE"
