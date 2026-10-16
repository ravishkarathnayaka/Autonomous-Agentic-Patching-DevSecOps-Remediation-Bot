import shutil
from pathlib import Path
from click.testing import CliRunner
from cli.benchmark_cli import benchmark_command


def test_cli_benchmark_command(tmp_path: Path):
    fixtures_dir = Path(__file__).parent / "fixtures"
    target_dir = tmp_path / "target_repo"
    shutil.copytree(Path(__file__).parent.parent / "target_repo", target_dir)

    runner = CliRunner()
    result = runner.invoke(benchmark_command, ["--fixtures-dir", str(fixtures_dir), "--target-dir", str(target_dir)])

    assert result.exit_code == 0
    assert "RUNNING DEVSECOPS BOT BENCHMARK SUITE" in result.output
    assert "Benchmark Completed" in result.output
    assert "Successfully Remediated" in result.output
