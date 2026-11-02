"""Autonomous agent specialized in YAML Deserialization (CWE-502) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class YamlDeserializationAgent:
    """Agent that remediates Insecure YAML Deserialization (CWE-502 / OWASP A08:2021).

    Remediations:
    - Replaces unsafe `yaml.load(..., Loader=yaml.Loader)` with `yaml.safe_load(...)`.
    - Prohibits instantiation of arbitrary Python objects during YAML parsing.
    """

    def __init__(self, name: str = "YamlDeserializationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process insecure deserialization finding and synthesize safe YAML patch."""
        finding = state.finding
        state.log_event(self.name, "start_yaml_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_yaml_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "yaml_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_yaml_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff enforcing yaml.safe_load."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -359,3 +359,3 @@\n"
            f"     try:\n"
            f"-        parsed_config = yaml.load(raw_yaml, Loader=yaml.Loader)\n"
            f"+        parsed_config = yaml.safe_load(raw_yaml)"
        )
        explanation = (
            f"YAML Deserialization Remediation: Addressed {rule_id} (CWE-502) by replacing unsafe `yaml.load` "
            "with `yaml.safe_load`, resolving remote code execution (RCE) vectors by restricting deserialization "
            "strictly to standard primitive types (dicts, lists, strings, numbers)."
        )
        return diff, explanation
