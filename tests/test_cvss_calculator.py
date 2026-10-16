from agent_engine.tools.cvss_calculator import parse_cvss_vector


def test_parse_cvss_vector_critical():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    result = parse_cvss_vector(vector)

    assert result["version"] == "3.1"
    assert result["base_score"] >= 9.0
    assert result["severity"] == "CRITICAL"
    assert result["metrics"]["AV"] == "N"


def test_parse_cvss_vector_low():
    vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"
    result = parse_cvss_vector(vector)
    assert result["base_score"] <= 5.0
    assert result["metrics"]["AV"] == "L"


def test_parse_cvss_vector_empty():
    res = parse_cvss_vector("")
    assert res["version"] == "unknown"
