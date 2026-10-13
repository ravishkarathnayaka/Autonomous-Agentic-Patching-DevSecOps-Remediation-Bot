from agent_engine.tools.mttr_calculator import calculate_remediation_roi


def test_calculate_remediation_roi():
    roi = calculate_remediation_roi(10, average_manual_fix_hours=4.0, engineer_hourly_rate=100.0)

    assert roi["remediated_count"] == 10
    assert roi["hours_saved"] == 40.0
    assert roi["cost_savings_usd"] == 4000.0
    assert roi["mttr_reduction_percent"] == 99.8


def test_calculate_remediation_roi_zero():
    roi = calculate_remediation_roi(0)
    assert roi["hours_saved"] == 0.0
    assert roi["cost_savings_usd"] == 0.0
