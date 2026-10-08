"""Unit tests for TelemetryTracker."""

from pathlib import Path
from agent_engine.telemetry import TelemetryTracker


def test_telemetry_tracker_summary(tmp_path: Path):
    tracker = TelemetryTracker()

    # Record 2 successful attempts and 1 failed attempt
    tracker.record_attempt(
        finding_id="f-01",
        rule_id="rule.sqli",
        severity="HIGH",
        cwe=["CWE-89"],
        duration_seconds=2.5,
        status="PR_READY",
        retry_count=0,
        sandbox_passed=True
    )

    tracker.record_attempt(
        finding_id="f-02",
        rule_id="rule.cmdi",
        severity="CRITICAL",
        cwe=["CWE-78"],
        duration_seconds=3.5,
        status="PR_READY",
        retry_count=1,
        sandbox_passed=True
    )

    tracker.record_attempt(
        finding_id="f-03",
        rule_id="rule.traversal",
        severity="MEDIUM",
        cwe=["CWE-22"],
        duration_seconds=4.0,
        status="FAILED",
        retry_count=3,
        sandbox_passed=False
    )

    report = tracker.generate_report()
    assert report.total_findings == 3
    assert report.successful_patches == 2
    assert report.failed_patches == 1
    assert report.total_retries == 4
    assert round(report.average_duration_seconds, 2) == 3.33

    data = report.to_dict()
    assert data["summary"]["success_rate_percent"] == 66.7

    # Test export
    out_file = tmp_path / "metrics.json"
    report.export_json(out_file)
    assert out_file.exists()
