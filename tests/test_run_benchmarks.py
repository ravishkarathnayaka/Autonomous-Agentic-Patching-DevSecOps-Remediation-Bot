from pathlib import Path
import shutil
from scripts.run_benchmarks import run_benchmarks_and_generate_markdown


def test_run_benchmarks_script(tmp_path: Path):
    # Copy one fixture for lightning test execution
    fixtures_dir = Path(__file__).parent / "fixtures"
    single_fixture_dir = tmp_path / "fixtures"
    single_fixture_dir.mkdir()
    shutil.copy(fixtures_dir / "bandit_findings.json", single_fixture_dir / "bandit_findings.json")

    target_dir = tmp_path / "target_repo"
    shutil.copytree(Path(__file__).parent.parent / "target_repo", target_dir)

    markdown = run_benchmarks_and_generate_markdown(single_fixture_dir, target_dir)
    assert "# DevSecOps Remediation Bot Benchmark Results" in markdown
    assert "bandit" in markdown
    assert "PASSED" in markdown
    assert "Summary" in markdown
