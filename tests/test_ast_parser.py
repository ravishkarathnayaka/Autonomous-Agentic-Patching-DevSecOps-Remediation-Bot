"""Unit tests for AST source code context extraction."""

from agent_engine.tools.ast_parser import extract_ast_context

SAMPLE_CODE = """import os
import sqlite3
from flask import Flask, request

class ItemService:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def find_item_by_name(self, name: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = f"SELECT * FROM items WHERE name = '{name}'"
        cursor.execute(query)
        return cursor.fetchall()

def standalone_helper(x, y):
    return x + y
"""


def test_extract_ast_inside_class_method():
    """Verify AST accurately identifies enclosing method and class for line 13."""
    target_line = 13  # query = f"SELECT..." line
    ctx = extract_ast_context(SAMPLE_CODE, target_line)

    assert ctx.enclosing_function == "find_item_by_name"
    assert ctx.enclosing_class == "ItemService"
    assert "def find_item_by_name(self, name)" in (ctx.function_signature or "")
    assert ctx.scope_start_line == 9
    assert any("sqlite3" in imp for imp in ctx.imports)
    assert any("from flask import Flask" in imp for imp in ctx.imports)
    assert "find_item_by_name" in ctx.surrounding_snippet
    assert "Class: ItemService" in ctx.context_summary


def test_extract_ast_standalone_function():
    """Verify AST extraction for a top-level standalone function."""
    target_line = 17  # inside standalone_helper
    ctx = extract_ast_context(SAMPLE_CODE, target_line)

    assert ctx.enclosing_function == "standalone_helper"
    assert ctx.enclosing_class is None
    assert "def standalone_helper(x, y)" in (ctx.function_signature or "")


def test_extract_ast_syntax_error_fallback():
    """Verify graceful line window fallback when syntax is broken."""
    broken_code = "def broken(\nthis is not valid python!\nreturn 42"
    ctx = extract_ast_context(broken_code, target_line=2)

    assert ctx.enclosing_function is None
    assert ctx.surrounding_snippet != ""
    assert "Non-AST context" in ctx.context_summary
