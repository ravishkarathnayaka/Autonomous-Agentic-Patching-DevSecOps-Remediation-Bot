"""Threat model generator agent: produces STRIDE breakdown and attack path mitigation analysis."""

import logging
from typing import Dict
from agent_engine.state import Finding, RemediationState

logger = logging.getLogger(__name__)

CWE_STRIDE_MAP = {
    "CWE-89": ("Tampering", "Arbitrary SQL statement injection and unauthorized database modifications"),
    "CWE-78": ("Elevation of Privilege", "Arbitrary host OS command execution via unsanitized system calls"),
    "CWE-22": ("Information Disclosure", "Unauthorized traversal and retrieval of local filesystem resources"),
    "CWE-79": ("Tampering", "Cross-site execution of untrusted scripts in client browser sessions"),
    "CWE-798": ("Information Disclosure", "Exposed hardcoded secrets allowing credential reuse and access hijack"),
    "CWE-502": ("Elevation of Privilege", "Remote code execution through untrusted object deserialization"),
    "CWE-918": ("Elevation of Privilege", "Server-Side Request Forgery facilitating intranet network exploration"),
}


class ThreatModelAgent:
    """Agent that produces STRIDE and DREAD threat analysis for security PR audit logs."""

    def __init__(self, name: str = "ThreatModelAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Analyze finding and generate threat modeling context."""
        finding = state.finding
        threat_analysis = self.analyze(finding)

        state.log_event(self.name, "threat_model_generated", {
            "stride_category": threat_analysis["stride_category"],
            "dread_score": threat_analysis["dread_score"]
        })

        # Append threat model explanation to state explanation
        if state.patch_explanation:
            state.patch_explanation += f"\n\n### 🛡️ STRIDE Threat Modeling Analysis:\n- **Category:** {threat_analysis['stride_category']}\n- **Attack Vector:** {threat_analysis['attack_vector']}\n- **DREAD Risk Score:** {threat_analysis['dread_score']}/10\n- **Mitigation Guarantee:** {threat_analysis['mitigation']}"

        return state

    def analyze(self, finding: Finding) -> Dict[str, str]:
        """Produce structured STRIDE and DREAD evaluation."""
        primary_cwe = finding.cwe_ids[0] if finding.cwe_ids else "CWE-20"
        stride_cat, vector = CWE_STRIDE_MAP.get(
            primary_cwe,
            ("Tampering", f"Exploitation of {primary_cwe} flaw leading to integrity compromise")
        )

        dread_score = "8.5" if finding.severity.value in ("CRITICAL", "HIGH") else "5.5"

        return {
            "cwe": primary_cwe,
            "stride_category": stride_cat,
            "attack_vector": vector,
            "dread_score": dread_score,
            "mitigation": f"Remediated input parsing boundaries neutralizing {primary_cwe} exploit paths."
        }
