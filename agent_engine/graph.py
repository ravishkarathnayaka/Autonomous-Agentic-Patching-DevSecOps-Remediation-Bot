"""Multi-agent State Machine Orchestrator for Autonomous Vulnerability Remediation."""

import logging
from typing import Optional

from agent_engine.agents.patch_agent import PatchAgent
from agent_engine.agents.pr_agent import PRAgent
from agent_engine.agents.triage_agent import TriageAgent
from agent_engine.agents.verifier_agent import VerifierAgent
from agent_engine.llm.client import BaseLLMClient, get_llm_client
from agent_engine.state import Finding, RemediationState, RemediationStatus
from agent_engine.tools.sandbox_executor import SandboxExecutor

logger = logging.getLogger(__name__)


class RemediationGraph:
    """State machine governing the Triage -> Patch -> Verify (Loop) -> PR lifecycle."""

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        sandbox_executor: Optional[SandboxExecutor] = None,
        max_retries: int = 3,
        test_file: Optional[str] = "test_app.py"
    ):
        self.llm_client = llm_client or get_llm_client(provider="mock")
        self.sandbox_executor = sandbox_executor or SandboxExecutor()
        self.max_retries = max_retries

        # Initialize sub-agents
        self.triage_agent = TriageAgent()
        self.patch_agent = PatchAgent(llm_client=self.llm_client)
        self.verifier_agent = VerifierAgent(sandbox_executor=self.sandbox_executor, test_file=test_file)
        self.pr_agent = PRAgent(llm_client=self.llm_client)

    def run(self, state: RemediationState) -> RemediationState:
        """Execute state machine transitions until a terminal state is reached."""
        state.max_retries = self.max_retries

        # Step 1: Triage
        if state.status == RemediationStatus.INITIALIZED:
            logger.info("Executing TriageAgent for finding %s...", state.finding.id)
            state = self.triage_agent.execute(state)
            if state.status == RemediationStatus.FAILED:
                logger.error("Triage failed: %s", state.last_error_trace)
                return state

        # Step 2: Patch -> Verify -> Feedback Loop
        while state.status in (RemediationStatus.TRIAGED, RemediationStatus.RETRY_NEEDED):
            # Patch Generation
            logger.info("Executing PatchAgent (attempt %d/%d)...", state.retry_count + 1, state.max_retries)
            state = self.patch_agent.execute(state)
            if state.status == RemediationStatus.FAILED:
                logger.error("Patch generation failed: %s", state.last_error_trace)
                return state

            # Verification in Sandbox
            logger.info("Executing VerifierAgent in ephemeral sandbox...")
            state = self.verifier_agent.execute(state)

            if state.status == RemediationStatus.VERIFIED:
                logger.info("Verification PASSED!")
                break
            elif state.status == RemediationStatus.RETRY_NEEDED:
                logger.warning(
                    "Verification FAILED. Triggering self-healing retry loop (%d/%d)...",
                    state.retry_count,
                    state.max_retries
                )
                continue
            elif state.status == RemediationStatus.FAILED:
                logger.error("Remediation exhausted maximum retry attempts (%d). Marking as FAILED.", state.max_retries)
                return state

        # Step 3: PR Generation (only if successfully verified)
        if state.status == RemediationStatus.VERIFIED:
            logger.info("Executing PRAgent to establish branch, commit, and PR documentation...")
            state = self.pr_agent.execute(state)

        return state

    @classmethod
    def create_and_run(
        cls,
        finding: Finding,
        target_repo_path: str,
        llm_client: Optional[BaseLLMClient] = None,
        sandbox_executor: Optional[SandboxExecutor] = None,
        max_retries: int = 3,
        test_file: Optional[str] = "test_app.py"
    ) -> RemediationState:
        """Convenience factory to initialize state and run remediation end-to-end."""
        state = RemediationState(
            finding=finding,
            target_repo_path=target_repo_path,
            max_retries=max_retries
        )
        graph = cls(
            llm_client=llm_client,
            sandbox_executor=sandbox_executor,
            max_retries=max_retries,
            test_file=test_file
        )
        return graph.run(state)
