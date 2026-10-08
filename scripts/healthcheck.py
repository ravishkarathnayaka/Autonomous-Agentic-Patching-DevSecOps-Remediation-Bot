#!/usr/bin/env python3
"""Quick runtime healthcheck for agent engine components."""

import sys
from agent_engine.llm.client import get_llm_client
from agent_engine.graph import RemediationGraph
from agent_engine.tools.sandbox_executor import SandboxExecutor


def main() -> None:
    print("Running Agent Engine component health checks...")

    # 1. LLM Client
    try:
        client = get_llm_client(provider="mock")
        print("  [OK] Mock LLM Provider initialized successfully.")
    except Exception as e:
        print(f"  [FAIL] LLM initialization failed: {e}")
        sys.exit(1)

    # 2. Sandbox Executor
    try:
        executor = SandboxExecutor(force_local=True)
        print(f"  [OK] Sandbox Executor initialized (Docker ready={executor.is_docker_ready()}).")
    except Exception as e:
        print(f"  [FAIL] Sandbox executor initialization failed: {e}")
        sys.exit(1)

    # 3. Remediation State Graph
    try:
        graph = RemediationGraph(llm_client=client, executor=executor)
        print("  [OK] Remediation Multi-Agent State Graph constructed.")
    except Exception as e:
        print(f"  [FAIL] State graph construction failed: {e}")
        sys.exit(1)

    print("All core engine components are healthy.")


if __name__ == "__main__":
    main()
