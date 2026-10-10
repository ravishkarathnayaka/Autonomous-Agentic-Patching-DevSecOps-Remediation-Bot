import pytest
from agent_engine.tools.dependency_bumper import DependencyBumper


def test_bump_requirements_txt():
    sample_reqs = """flask==2.0.1\nrequests==2.25.1\nwerkzeug>=2.0.0\npytest\n"""
    
    # Bump requests to 2.31.0
    updated, mod = DependencyBumper.bump_requirements_txt(sample_reqs, "requests", "2.31.0")
    assert mod is True
    assert "requests==2.31.0" in updated
    assert "flask==2.0.1" in updated

    # Bump werkzeug
    updated2, mod2 = DependencyBumper.bump_requirements_txt(updated, "werkzeug", "3.0.1")
    assert mod2 is True
    assert "werkzeug==3.0.1" in updated2

    # Bump unpinned package
    updated3, mod3 = DependencyBumper.bump_requirements_txt(updated2, "pytest", "8.0.0")
    assert mod3 is True
    assert "pytest==8.0.0" in updated3

    # Non-existent package
    _, mod4 = DependencyBumper.bump_requirements_txt(sample_reqs, "django", "4.2.0")
    assert mod4 is False


def test_bump_package_json():
    sample_pkg = """{
  "name": "my-app",
  "dependencies": {
    "axios": "^0.21.1",
    "react": "^18.2.0"
  }
}"""
    updated, mod = DependencyBumper.bump_package_json(sample_pkg, "axios", "1.6.0")
    assert mod is True
    assert '"axios": "^1.6.0"' in updated
    assert '"react": "^18.2.0"' in updated
