"""Parser for SpotBugs / FindSecBugs Java security static analysis reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_spotbugs_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse SpotBugs JSON export report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to SpotBugs report.

    Returns:
        List of normalized Finding models representing Java application vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    bugs = data.get("bugs", data.get("BugInstance", [])) if isinstance(data, dict) else []

    for bug in bugs:
        bug_type = bug.get("type", "SECURITY_BUG")
        category = bug.get("category", "SECURITY")
        priority = int(bug.get("priority", 2))
        message = bug.get("message", f"SpotBugs potential issue {bug_type}")
        source_line = bug.get("SourceLine", bug.get("source_line", {}))

        file_path = source_line.get("sourcepath", "src/main/java/App.java")
        line_no = int(source_line.get("start", 1) or 1)

        if priority == 1:
            severity = SeverityLevel.HIGH
        elif priority == 2:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        cwe_id = "CWE-89" if "SQL" in bug_type else ("CWE-78" if "COMMAND" in bug_type else "CWE-20")

        finding = Finding(
            id=f"spotbugs-{bug_type.lower()}-{line_no}",
            scanner="spotbugs",
            finding_type=FindingType.SAST,
            rule_id=bug_type,
            title=f"Java Flaw: {bug_type}",
            description=message,
            severity=severity,
            cwe_ids=[cwe_id],
            cvss_score=7.5 if severity == SeverityLevel.HIGH else 5.0,
            file_path=file_path,
            start_line=line_no,
            end_line=line_no,
            vulnerable_code=f"// SpotBugs rule {bug_type} at line {line_no}"
        )
        findings.append(finding)

    return findings
