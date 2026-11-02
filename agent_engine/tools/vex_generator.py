"""Generator for OpenVEX / CSAF Vulnerability Exploitability eXchange documents."""

import datetime
from typing import Any, Dict, List, Optional
from agent_engine.state import Finding, RemediationStatus


class VexDocumentGenerator:
    """Generates standard OpenVEX (v0.2.0) and CSAF-compatible vulnerability status documents.

    Provides machine-readable transparency regarding whether vulnerabilities affect products,
    justifications, and remediation statuses.
    """

    @classmethod
    def generate_openvex(
        cls,
        document_id: str,
        author: str,
        findings: List[Finding],
        remediation_statuses: Optional[Dict[str, RemediationStatus]] = None,
        product_id: str = "pkg:generic/autonomous-remediation-bot@1.0.0",
    ) -> Dict[str, Any]:
        """Generate an OpenVEX document.

        Args:
            document_id: Unique URI or URN for this VEX document.
            author: Identity or tool creating the document.
            findings: List of Finding objects.
            remediation_statuses: Map of finding.id -> RemediationStatus.
            product_id: Software identification (e.g. Package URL / PURL).

        Returns:
            Dictionary formatted according to the OpenVEX specification.
        """
        statuses = remediation_statuses or {}
        statements: List[Dict[str, Any]] = []

        for finding in findings:
            status = statuses.get(finding.id, RemediationStatus.INITIALIZED)
            if status in [RemediationStatus.VERIFIED, RemediationStatus.PR_READY]:
                vex_status = "fixed"
                justification = None
                impact = None
                action = f"Remediated via autonomous patch and verified against {finding.rule_id}."
            elif status == RemediationStatus.FAILED:
                vex_status = "under_investigation"
                justification = None
                impact = "Remediation attempt failed; manual investigation in progress."
                action = "Inspect scanner report and triage root cause."
            else:
                vex_status = "affected"
                justification = None
                impact = finding.description
                action = f"Apply patch recommendation for {finding.rule_id}."

            statement: Dict[str, Any] = {
                "vulnerability": {
                    "name": finding.rule_id,
                    "description": finding.title,
                },
                "products": [product_id],
                "status": vex_status,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            if finding.cwe_ids:
                statement["vulnerability"]["aliases"] = finding.cwe_ids
            if action:
                statement["action_statement"] = action
            if impact:
                statement["impact_statement"] = impact

            statements.append(statement)

        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": document_id,
            "author": author,
            "role": "Autonomous Security Remediation Engine",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "version": 1,
            "statements": statements,
        }
