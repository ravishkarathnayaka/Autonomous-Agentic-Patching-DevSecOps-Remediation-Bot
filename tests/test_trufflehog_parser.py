import json
from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.trufflehog_parser import parse_trufflehog_report


def test_trufflehog_parser_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "trufflehog_findings.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = parse_trufflehog_report(data)
    assert len(findings) == 2

    aws = next(f for f in findings if "AWS" in f.rule_id)
    assert aws.scanner == "trufflehog"
    assert aws.finding_type == FindingType.SECRET
    assert aws.severity == SeverityLevel.CRITICAL
    assert "CWE-798" in aws.cwe_ids
    assert aws.file_path == "config/aws_settings.py"
    assert aws.start_line == 15
    assert "Verified Live" in aws.title

    slack = next(f for f in findings if "Slack" in f.rule_id)
    assert slack.severity == SeverityLevel.HIGH
    assert slack.file_path == ".env.test"
    assert slack.start_line == 4
