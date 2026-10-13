from cli.audit import run_compliance_audit


def test_run_compliance_audit_current_repo():
    result = run_compliance_audit(".")

    assert result["total_checks"] == 3
    assert result["passed_checks"] >= 2
    assert result["score_percent"] > 50.0
    names = [c["name"] for c in result["details"]]
    assert "Secret Exclusion (.env in .gitignore)" in names
