from agent_engine.tools.batch_orchestrator import BatchOrchestrator


def test_batch_orchestrator_existing_and_missing():
    orchestrator = BatchOrchestrator(["target_repo", "non_existent_microservice"])
    summary = orchestrator.run_campaign()

    assert summary["total_repositories"] == 2
    assert summary["successful"] == 1
    assert summary["failed_or_skipped"] == 1
    assert summary["details"]["target_repo"]["status"] == "SUCCESS"
    assert summary["details"]["non_existent_microservice"]["status"] == "SKIPPED"
