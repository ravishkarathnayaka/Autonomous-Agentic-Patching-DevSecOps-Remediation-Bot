"""Unit tests for MergeValidator."""

from agent_engine.tools.merge_validator import MergeValidator


def test_clean_content_no_conflicts():
    clean_code = """
def clean_func():
    return "No conflicts here"
"""
    result = MergeValidator.check_for_conflict_markers(clean_code)
    assert result.has_conflicts is False
    assert result.conflict_markers_count == 0
    assert result.error_summary is None


def test_conflict_markers_detected():
    conflicted_code = """
<<<<<<< HEAD
    query = "SELECT * FROM users WHERE name = ?"
=======
    query = f"SELECT * FROM users WHERE name = '{name}'"
>>>>>>> branch-fix
"""
    result = MergeValidator.check_for_conflict_markers(conflicted_code)
    assert result.has_conflicts is True
    assert result.conflict_markers_count == 3
    assert "conflict start" in (result.error_summary or "")
