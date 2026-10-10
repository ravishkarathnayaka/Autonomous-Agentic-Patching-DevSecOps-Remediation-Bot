"""Multi-scanner report aggregator with deduplication, severity merging, and prioritized sorting."""

from typing import Dict, List, Optional, Set, Tuple
from agent_engine.state import Finding, FindingType, SeverityLevel


_SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 3,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFO: 0,
}


def _higher_severity(a: SeverityLevel, b: SeverityLevel) -> SeverityLevel:
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b


class FindingAggregator:
    """Aggregates findings across multiple scanners, deduplicates overlaps, and sorts by risk."""

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def add_findings(self, findings: List[Finding]) -> None:
        """Add findings to aggregator buffer."""
        self.findings.extend(findings)

    def deduplicate(self) -> List[Finding]:
        """
        Deduplicate findings from different scanners targeting the same issue.
        SCA deduplication key: (package_name, rule_id)
        SAST/IaC/Secret deduplication key: (file_path, start_line, primary_cwe or rule_id)
        """
        dedup_map: Dict[Tuple[str, ...], Finding] = {}

        for finding in self.findings:
            key: Tuple[str, ...]
            if finding.finding_type in (FindingType.SCA, FindingType.CONTAINER) and finding.package_name:
                key = ("SCA", finding.package_name.lower(), finding.rule_id.lower())
            else:
                primary_cwe = finding.cwe_ids[0] if finding.cwe_ids else finding.rule_id
                key = ("CODE", finding.file_path.lower().replace("\\", "/"), str(finding.start_line), primary_cwe)

            if key not in dedup_map:
                dedup_map[key] = finding
            else:
                existing = dedup_map[key]
                # Merge scanners attribution if not already present
                if finding.scanner not in existing.scanner:
                    existing.scanner = f"{existing.scanner}+{finding.scanner}"

                # Retain higher severity
                existing.severity = _higher_severity(existing.severity, finding.severity)

                # Merge unique CWEs
                for cwe in finding.cwe_ids:
                    if cwe not in existing.cwe_ids:
                        existing.cwe_ids.append(cwe)

                # Merge unique references
                for ref in finding.references:
                    if ref not in existing.references:
                        existing.references.append(ref)

                # Retain highest CVSS score
                if finding.cvss_score is not None:
                    if existing.cvss_score is None or finding.cvss_score > existing.cvss_score:
                        existing.cvss_score = finding.cvss_score

        # Sort deduplicated list by severity descending
        sorted_findings = sorted(
            dedup_map.values(),
            key=lambda f: _SEVERITY_ORDER.get(f.severity, 0),
            reverse=True
        )
        return sorted_findings
