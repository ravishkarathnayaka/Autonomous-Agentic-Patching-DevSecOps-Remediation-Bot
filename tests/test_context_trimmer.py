"""Unit tests for ContextTrimmer."""

from agent_engine.tools.context_trimmer import ContextTrimmer


def test_trim_small_file_not_truncated():
    source = "\n".join([f"line_{i}" for i in range(1, 10)])
    result = ContextTrimmer.trim_code_window(source, target_line=5, context_radius=10)
    assert result.is_truncated is False
    assert result.original_lines == 9
    assert result.trimmed_lines == 9
    assert "line_5" in result.content


def test_trim_large_file_truncated_around_target():
    source = "\n".join([f"line_{i} = {i}" for i in range(1, 201)])
    result = ContextTrimmer.trim_code_window(source, target_line=100, context_radius=10)
    assert result.is_truncated is True
    assert result.original_lines == 200
    assert result.trimmed_lines <= 25
    assert "line_100 = 100" in result.content
    assert "line_1 = 1" not in result.content  # Out of range


def test_trim_empty_source():
    result = ContextTrimmer.trim_code_window("", target_line=1)
    assert result.original_lines == 0
    assert result.content == ""
