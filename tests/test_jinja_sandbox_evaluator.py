from agent_engine.tools.jinja_sandbox_evaluator import JinjaSandboxEvaluator


def test_jinja_sandbox_evaluator_benign():
    template = "Hello {{ name }}! Your order total is ${{ amount }}."
    is_safe, violations = JinjaSandboxEvaluator.evaluate_template_safety(template)
    assert is_safe is True
    assert len(violations) == 0


def test_jinja_sandbox_evaluator_malicious():
    template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    is_safe, violations = JinjaSandboxEvaluator.evaluate_template_safety(template)
    assert is_safe is False
    assert any("__class__" in v for v in violations)
    assert any("__subclasses__" in v for v in violations)
