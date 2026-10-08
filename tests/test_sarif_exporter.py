"""Unit tests for SARIF exporter."""

import json
from pathlib import Path
from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.sarif_exporter import export_findings_to_sarif


def test_export_findings_to_sarif(tmp_path: Path):
    finding = Finding(
        id="finding-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rules.sqli.query",
        title="SQL Injection",
        description="Dynamic string formatting in query",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        cvss_score=9.8,
        file_path="target_repo/app.py",
        start_line=28,
        end_line=29,
        vulnerable_code="cursor.execute(query)"
    )

    out_file = tmp_path / "output.sarif"
    sarif_doc = export_findings_to_sarif([finding], output_path=out_file)

    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) == 1
    run = sarif_doc["runs"][0]

    # Verify tool rules
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "rules.sqli.query"
    assert "external/cwe/cwe-89" in rules[0]["properties"]["tags"]

    # Verify results occurrence
    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "rules.sqli.query"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "target_repo/app.py"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 28

    # Verify file was written
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["version"] == "2.1.0"
