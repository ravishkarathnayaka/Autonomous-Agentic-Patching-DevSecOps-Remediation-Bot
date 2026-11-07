from agent_engine.tools.mass_assignment_auditor import MassAssignmentAuditor


def test_mass_assignment_auditor_detects_privileged_keys():
    payload = {"email": "user@corp.com", "is_admin": True, "role": "superadmin"}
    is_safe, violations = MassAssignmentAuditor.audit_payload(payload)

    assert not is_safe
    assert any("is_admin" in v for v in violations)
    assert any("role" in v for v in violations)


def test_mass_assignment_auditor_enforces_allowed_fields():
    payload = {"email": "user@corp.com", "bio": "Security engineer", "untracked_field": "val"}
    is_safe, violations = MassAssignmentAuditor.audit_payload(payload, allowed_fields=["email", "bio"])

    assert not is_safe
    assert any("untracked_field" in v for v in violations)


def test_mass_assignment_filter_allowed_fields():
    payload = {"email": "user@corp.com", "is_admin": True, "bio": "Hello"}
    filtered = MassAssignmentAuditor.filter_allowed_fields(payload, allowed_fields=["email", "bio"])

    assert "email" in filtered
    assert "bio" in filtered
    assert "is_admin" not in filtered
