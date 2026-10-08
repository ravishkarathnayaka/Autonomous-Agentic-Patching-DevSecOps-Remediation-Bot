"""SARIF (Static Analysis Results Interchange Format) exporter for normalized findings.

Generates standard SARIF 2.1.0 JSON files compatible with GitHub Code Scanning,
GitLab Security Dashboards, and Azure DevOps.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from agent_engine.state import Finding


def export_findings_to_sarif(
    findings: List[Finding],
    output_path: Optional[Union[str, Path]] = None,
    tool_name: str = "Autonomous-DevSecOps-Bot",
    tool_version: str = "1.0.0"
) -> Dict[str, Any]:
    """Convert normalized Finding models to standard SARIF 2.1.0 schema.

    Args:
        findings: List of Finding models.
        output_path: Optional file destination to write JSON.
        tool_name: Driver tool name in SARIF manifest.
        tool_version: Driver tool semantic version.

    Returns:
        SARIF document as Python dict.
    """
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rules = set()

    for f in findings:
        # Register rule definition if not yet seen
        if f.rule_id not in seen_rules:
            seen_rules.add(f.rule_id)
            cwe_tags = [f"external/cwe/{c.lower()}" for c in f.cwe_ids]
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": "error" if f.severity in ["CRITICAL", "HIGH"] else "warning"
                },
                "properties": {
                    "tags": ["security"] + cwe_tags,
                    "precision": "high"
                }
            })

        # Register scan result occurrence
        results.append({
            "ruleId": f.rule_id,
            "level": "error" if f.severity in ["CRITICAL", "HIGH"] else "warning",
            "message": {
                "text": f"{f.title}: {f.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": max(1, f.start_line),
                            "endLine": max(1, f.end_line),
                            "snippet": {
                                "text": f.vulnerable_code
                            }
                        }
                    }
                }
            ]
        })

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }

    if output_path:
        path_obj = Path(output_path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        with open(path_obj, "w", encoding="utf-8") as out_f:
            json.dump(sarif_doc, out_f, indent=2)

    return sarif_doc
