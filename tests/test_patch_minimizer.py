from agent_engine.tools.patch_minimizer import minimize_patch, count_hunk_changes


def test_minimize_patch():
    raw_diff = (
        "--- a/app.py   \n"
        "+++ b/app.py   \n"
        "@@ -1,2 +1,2 @@\n"
        "-old line with trailing space   \n"
        "+new line clean   \n"
    )

    cleaned = minimize_patch(raw_diff)
    assert "-old line with trailing space" in cleaned
    assert not cleaned.endswith("   \n")


def test_count_hunk_changes():
    diff = (
        "--- a/target_repo/app.py\n"
        "+++ b/target_repo/app.py\n"
        "@@ -10,2 +10,3 @@\n"
        "-bad_code()\n"
        "+good_code_1()\n"
        "+good_code_2()\n"
    )

    counts = count_hunk_changes(diff)
    assert counts["files_changed"] == 1
    assert counts["additions"] == 2
    assert counts["deletions"] == 1
    assert counts["total_delta"] == 3
