from agent_engine.tools.epss_client import get_epss_score


def test_get_epss_score_known_rapid_reset():
    score = get_epss_score("CVE-2023-44487")
    assert score["cve_id"] == "CVE-2023-44487"
    assert score["epss_probability"] > 0.90
    assert score["threat_level"] == "CRITICAL_EXPLOIT_ACTIVITY"


def test_get_epss_score_unknown_cve():
    score = get_epss_score("CVE-2099-99999")
    assert score["cve_id"] == "CVE-2099-99999"
    assert score["threat_level"] == "LOW_PROBABILITY"
