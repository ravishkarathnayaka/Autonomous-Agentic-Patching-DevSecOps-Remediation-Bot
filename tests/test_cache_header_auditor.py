from agent_engine.tools.cache_header_auditor import CacheHeaderAuditor


def test_cache_header_auditor_flags_missing_headers():
    headers = {"Content-Type": "application/json"}
    is_safe, defects = CacheHeaderAuditor.audit_response_headers(headers, is_authenticated_or_dynamic=True)

    assert not is_safe
    assert any("Missing 'Cache-Control'" in d for d in defects)
    assert any("Missing 'Vary: Cookie'" in d for d in defects)


def test_cache_header_auditor_flags_public_cache():
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
        "Vary": "Cookie",
    }
    is_safe, defects = CacheHeaderAuditor.audit_response_headers(headers, is_authenticated_or_dynamic=True)

    assert not is_safe
    assert any("Dangerous 'Cache-Control: public'" in d for d in defects)


def test_cache_header_auditor_accepts_hardened_headers():
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Vary": "Cookie, Accept-Encoding",
    }
    is_safe, defects = CacheHeaderAuditor.audit_response_headers(headers, is_authenticated_or_dynamic=True)

    assert is_safe
    assert len(defects) == 0
