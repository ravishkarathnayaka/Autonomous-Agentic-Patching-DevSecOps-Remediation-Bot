"""Parser for Gitleaks secrets detection scanner reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_gitleaks_report(report_data: Union[str, Dict[str, Any], List[Dict[str, Any]], Path]) -> List[Finding]:
    """Parse Gitleaks JSON findings report and normalize into Finding models.

    Args:
        report_data: Raw JSON string, parsed list/dict, or Path to JSON report file.

    Returns:
        List of normalized Finding models with CWE-798 classification.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    # Gitleaks outputs a top-level list of findings
    results_list: List[Dict[str, Any]] = data if isinstance(data, list) else data.get("findings", [])

    findings: List[Finding] = []

    for idx, item in enumerate(results_list):
        try:
            rule_id = item.get("RuleID", f"gitleaks-secret-{idx}")
            description = item.get("Description", "Hardcoded credential or sensitive secret detected.")
            file_path = item.get("File", "").replace("\\", "/").lstrip("./")
            start_line = item.get("StartLine", 1)
            end_line = item.get("EndLine", start_line)
            match_text = item.get("Match", item.get("Secret", ""))

            finding = Finding(
                id=f"gitleaks-{rule_id}-{file_path}-{start_line}",
                scanner="gitleaks",
                finding_type=FindingType.SAST,
                rule_id=f"gitleaks.{rule_id}",
                title=f"Hardcoded Secret: {description}",
                description=(
                    f"Sensitive secret identified by Gitleaks: {description}. "
                    f"Exposing plaintext credentials violates CWE-798 standards."
                ),
                severity=SeverityLevel.CRITICAL,
                cwe_ids=["CWE-798"],
                cvss_score=8.5,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                vulnerable_code=match_text.strip()
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse Gitleaks finding item %d: %s", idx, e)
            continue

    logger.info("Parsed %d findings from Gitleaks report.", len(findings))
    return findings
