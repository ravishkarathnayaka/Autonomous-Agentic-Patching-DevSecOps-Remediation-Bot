from agent_engine.tools.branch_automator import generate_remediation_branch_name, validate_branch_name


def test_generate_remediation_branch_name():
    branch = generate_remediation_branch_name("CWE-89", "SQL Injection in Search Endpoint")
    assert branch.startswith("remediate/cwe-89-sql-injection")
    assert validate_branch_name(branch) is True


def test_validate_branch_name_invalid():
    assert validate_branch_name("invalid branch with spaces") is False
    assert validate_branch_name("/starts-with-slash") is False
    assert validate_branch_name("ends-with-slash/") is False
    assert validate_branch_name("has..two..dots") is False
