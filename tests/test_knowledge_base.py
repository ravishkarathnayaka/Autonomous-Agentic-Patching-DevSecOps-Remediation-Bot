import pytest
from agent_engine.knowledge_base import get_cwe_pattern, list_supported_cwes


def test_get_cwe_pattern():
    sqli = get_cwe_pattern("CWE-89")
    assert sqli is not None
    assert sqli.name == "SQL Injection"
    assert "A03:2021-Injection" in sqli.owasp_category
    assert "execute" in sqli.secure_pattern

    # Without 'CWE-' prefix
    cmd = get_cwe_pattern("78")
    assert cmd is not None
    assert cmd.name == "OS Command Injection"
    assert "subprocess.run" in cmd.secure_pattern

    # Non-existent CWE
    assert get_cwe_pattern("CWE-99999") is None


def test_list_supported_cwes():
    cwes = list_supported_cwes()
    assert "CWE-89" in cwes
    assert "CWE-78" in cwes
    assert "CWE-22" in cwes
    assert "CWE-798" in cwes
    assert "CWE-502" in cwes
    assert "CWE-327" in cwes
    assert "CWE-79" in cwes
    assert "CWE-918" in cwes
    assert len(cwes) >= 8
