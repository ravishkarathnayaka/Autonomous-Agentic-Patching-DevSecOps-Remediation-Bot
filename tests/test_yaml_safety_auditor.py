import pytest
from agent_engine.tools.yaml_safety_auditor import YamlSafetyAuditor


def test_yaml_safety_auditor_safe_content():
    content = """
    app:
      name: my-service
      port: 8080
      debug: false
      features:
        - metrics
        - healthcheck
    """
    is_safe, violations = YamlSafetyAuditor.audit_yaml_content(content)
    assert is_safe is True
    assert len(violations) == 0


def test_yaml_safety_auditor_detects_dangerous_tag():
    content = """
    payload: !!python/object/apply:os.system ["calc.exe"]
    """
    is_safe, violations = YamlSafetyAuditor.audit_yaml_content(content)
    assert is_safe is False
    assert len(violations) >= 1
    assert any("!!python/object" in v or "os.system" in v for v in violations)
