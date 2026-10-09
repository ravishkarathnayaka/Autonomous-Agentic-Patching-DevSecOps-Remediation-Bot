from agent_engine.agents.patch_agent import PatchAgent


def test_temperature_annealing_schedule():
    # Attempt 0 (initial attempt)
    assert PatchAgent.compute_temperature(0) == 0.0

    # Attempt 1 (first retry)
    assert PatchAgent.compute_temperature(1) == 0.2

    # Attempt 2 (second retry)
    assert PatchAgent.compute_temperature(2) == 0.4

    # Attempt 3 (third retry)
    assert PatchAgent.compute_temperature(3) == 0.6

    # Attempt 4+ (capped at max_temp = 0.7)
    assert PatchAgent.compute_temperature(4) == 0.7
    assert PatchAgent.compute_temperature(10) == 0.7


def test_temperature_annealing_custom_params():
    temp = PatchAgent.compute_temperature(retry_count=2, base_temp=0.1, step=0.15, max_temp=0.5)
    assert temp == 0.4
