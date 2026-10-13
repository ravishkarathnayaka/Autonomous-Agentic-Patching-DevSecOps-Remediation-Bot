from agent_engine.tools.blast_radius_analyzer import evaluate_blast_radius


def test_evaluate_blast_radius_low():
    small_diff = (
        "--- a/target_repo/app.py\n"
        "+++ b/target_repo/app.py\n"
        "@@ -10,1 +10,1 @@\n"
        "-bad()\n"
        "+good()\n"
    )

    res = evaluate_blast_radius(small_diff, "target_repo/app.py")
    assert res["risk_tier"] == "LOW"
    assert res["files_count"] == 1
    assert res["risk_score"] <= 3


def test_evaluate_blast_radius_empty():
    res = evaluate_blast_radius("", "app.py")
    assert res["risk_tier"] == "LOW"
    assert res["risk_score"] == 1
