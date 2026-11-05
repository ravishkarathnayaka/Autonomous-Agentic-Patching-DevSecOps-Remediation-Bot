from agent_engine.tools.idor_access_validator import IdorAccessValidator


def test_idor_owner_allowed():
    user = {"user_id": "usr_100", "roles": ["member"]}
    record = {"id": "rec_01", "owner_id": "usr_100"}
    authorized, reason = IdorAccessValidator.can_access_record(user, record)
    assert authorized
    assert "direct resource ownership" in reason


def test_idor_stranger_denied():
    user = {"user_id": "usr_200", "roles": ["member"]}
    record = {"id": "rec_01", "owner_id": "usr_100"}
    authorized, reason = IdorAccessValidator.can_access_record(user, record)
    assert not authorized
    assert "Access denied" in reason


def test_idor_admin_allowed():
    user = {"user_id": "usr_999", "roles": ["admin"]}
    record = {"id": "rec_01", "owner_id": "usr_100"}
    authorized, reason = IdorAccessValidator.can_access_record(user, record)
    assert authorized
    assert "administrative privileges" in reason


def test_idor_cross_tenant_denied():
    user = {"user_id": "usr_100", "tenant_id": "org_alpha"}
    record = {"id": "rec_01", "owner_id": "usr_100", "tenant_id": "org_beta"}
    authorized, reason = IdorAccessValidator.can_access_record(user, record)
    assert not authorized
    assert "Cross-tenant access prohibited" in reason
