"""Parser for normalizing TruffleHog v3 verified secret scanner reports into Finding models."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agent_engine.state import Finding, FindingType, SeverityLevel


def parse_trufflehog_report(data: Union[List[Dict[str, Any]], Dict[str, Any]]) -> List[Finding]:
    """Parse TruffleHog v3 JSON report (list or single dict) into normalized Finding objects."""
    findings: List[Finding] = []
    items: List[Dict[str, Any]] = []

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            items = data["findings"]
        else:
            items = [data]

    for item in items:
        detector_name = item.get("DetectorName", item.get("detector_name", "GenericSecret"))
        verified = item.get("Verified", item.get("verified", False))
        redacted = item.get("Redacted", item.get("redacted", "[REDACTED]"))
        raw = item.get("Raw", item.get("raw", ""))

        # Location details
        source_meta = item.get("SourceMetadata", {}).get("Data", {})
        git_info = source_meta.get("Git", {})
        file_path = git_info.get("file", item.get("file", "unknown_file"))
        line = git_info.get("line", item.get("line", 1))

        # Severity: Verified active secrets are CRITICAL, unverified are HIGH
        severity = SeverityLevel.CRITICAL if verified else SeverityLevel.HIGH

        title = f"Exposed {detector_name} Secret ({'Verified Live' if verified else 'Unverified'})"
        desc = (
            f"TruffleHog detected exposed credential of type '{detector_name}' in {file_path}. "
            f"Status: {'Cryptographically verified valid' if verified else 'Detected pattern'}."
        )

        finding_id = f"trufflehog-{detector_name.lower()}-{uuid.uuid4().hex[:8]}"

        finding = Finding(
            id=finding_id,
            scanner="trufflehog",
            finding_type=FindingType.SECRET,
            rule_id=f"trufflehog-{detector_name}",
            title=title,
            description=desc,
            severity=severity,
            cwe_ids=["CWE-798"],
            file_path=file_path,
            start_line=line,
            end_line=line,
            vulnerable_code=f"# Secret match: {redacted or (raw[:6] + '***' if raw else 'SECRET')}",
            references=["https://trufflesecurity.com/trufflehog"]
        )
        findings.append(finding)

    return findings
