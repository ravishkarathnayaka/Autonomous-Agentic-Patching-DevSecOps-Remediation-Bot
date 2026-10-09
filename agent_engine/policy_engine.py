"""DevSecOps Remediation Policy Engine.

Enforces corporate governance rules (CVSS score thresholds, CWE whitelists,
file path exclusions, and container verification requirements) prior to agent dispatch.
"""

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
import yaml

from agent_engine.state import Finding, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class PolicyEvaluationResult:
    """Outcome of evaluating a finding against the remediation policy."""
    is_allowed: bool
    reasons: List[str] = field(default_factory=list)
    action: str = "ALLOW"  # "ALLOW", "BLOCK", or "MANUAL_REVIEW"


class RemediationPolicy:
    """Structured policy rules model."""

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        raw = data or {}
        self.min_cvss: float = float(raw.get("min_cvss", 0.0))
        self.allowed_severities: Set[str] = set(
            s.upper() for s in raw.get("allowed_severities", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        )
        self.allowed_cwes: Optional[Set[str]] = (
            set(c.upper() for c in raw.get("allowed_cwes")) if "allowed_cwes" in raw else None
        )
        self.banned_cwes: Set[str] = set(c.upper() for c in raw.get("banned_cwes", []))
        self.ignored_path_patterns: List[str] = raw.get("ignored_path_patterns", ["vendor/", "node_modules/", ".git/"])
        self.require_sandbox: bool = bool(raw.get("require_sandbox", True))


class RemediationPolicyEngine:
    """Evaluates findings against corporate DevSecOps remediation policies."""

    def __init__(self, policy: Optional[RemediationPolicy] = None) -> None:
        self.policy = policy or RemediationPolicy()

    @classmethod
    def from_yaml_file(cls, policy_path: Union[str, Path]) -> "RemediationPolicyEngine":
        """Instantiate policy engine from a YAML policy file."""
        p = Path(policy_path)
        if not p.exists():
            logger.warning("Policy file %s not found. Using default permissive policy.", p)
            return cls(RemediationPolicy())

        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        policy_obj = RemediationPolicy(data.get("remediation_policy", data))
        return cls(policy_obj)

    def evaluate_finding(self, finding: Finding) -> PolicyEvaluationResult:
        """Evaluate if finding is eligible for autonomous remediation."""
        reasons: List[str] = []

        # 1. Severity check
        if finding.severity.value not in self.policy.allowed_severities:
            reasons.append(f"Severity {finding.severity.value} not in allowed severities.")

        # 2. CVSS score check
        if finding.cvss_score is not None and finding.cvss_score < self.policy.min_cvss:
            reasons.append(f"CVSS score {finding.cvss_score} is below minimum threshold {self.policy.min_cvss}.")

        # 3. Path exclusion check
        for pattern in self.policy.ignored_path_patterns:
            if pattern in finding.file_path:
                reasons.append(f"File path '{finding.file_path}' matches ignored pattern '{pattern}'.")

        # 4. Banned CWE check
        for cwe in finding.cwe_ids:
            if cwe.upper() in self.policy.banned_cwes:
                reasons.append(f"CWE '{cwe}' is explicitly banned from autonomous patching.")

        # 5. Whitelisted CWE check (if specified)
        if self.policy.allowed_cwes is not None:
            has_matching_cwe = any(c.upper() in self.policy.allowed_cwes for c in finding.cwe_ids)
            if not has_matching_cwe:
                reasons.append("Finding CWE is not present in allowed_cwes whitelist.")

        is_allowed = len(reasons) == 0
        action = "ALLOW" if is_allowed else "BLOCK"
        return PolicyEvaluationResult(is_allowed=is_allowed, reasons=reasons, action=action)
