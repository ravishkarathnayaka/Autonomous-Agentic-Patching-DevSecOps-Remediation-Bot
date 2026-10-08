"""Unit tests for AST PatchValidator."""

from agent_engine.tools.patch_validator import PatchValidator


def test_validate_valid_python_code():
    code = """
def secure_query(name: str):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM items WHERE name = ?", (name,))
    return cursor.fetchall()
"""
    result = PatchValidator.validate_python_code(code)
    assert result.is_valid is True
    assert result.error_message is None
    assert result.syntax_error_line is None


def test_validate_invalid_syntax():
    code = """
def broken_query(name: str):
    cursor.execute("SELECT * FROM items WHERE name = ?", (name, # Missing closing parenthesis
"""
    result = PatchValidator.validate_python_code(code)
    assert result.is_valid is False
    assert result.error_message is not None
    assert "SyntaxError" in result.error_message
    assert result.syntax_error_line is not None


def test_validate_empty_string():
    result = PatchValidator.validate_python_code("")
    assert result.is_valid is True
    assert result.error_message is None
