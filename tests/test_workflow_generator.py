from agent_engine.tools.workflow_generator import generate_github_workflow


def test_generate_github_workflow():
    yaml_str = generate_github_workflow(["semgrep", "trivy", "gitleaks"], branch="main")

    assert "Run Semgrep SAST" in yaml_str
    assert "Run Trivy SCA" in yaml_str
    assert "Run Gitleaks Secret Scan" in yaml_str
    assert "sandbox-mode docker" in yaml_str
    assert "schedule:" in yaml_str


def test_generate_github_workflow_local():
    yaml_str = generate_github_workflow(["semgrep"], enable_sandbox=False)
    assert "sandbox-mode local" in yaml_str
    assert "Run Trivy SCA" not in yaml_str
