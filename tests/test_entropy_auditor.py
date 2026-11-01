from agent_engine.tools.entropy_auditor import EntropyAuditor


def test_shannon_entropy_calculation():
    # Low entropy repeating string
    low_ent = EntropyAuditor.calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # High entropy random base64 string
    high_ent = EntropyAuditor.calculate_shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert high_ent > 4.5


def test_find_high_entropy_tokens():
    diff_text = """
    + AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    + USER_NOTICE = "Please contact support for billing questions."
    """
    findings = EntropyAuditor.find_high_entropy_tokens(diff_text, threshold=4.2)
    assert len(findings) >= 1
    tokens = [t[0] for t in findings]
    assert any("wJalrXUtnFEMI" in t for t in tokens)
