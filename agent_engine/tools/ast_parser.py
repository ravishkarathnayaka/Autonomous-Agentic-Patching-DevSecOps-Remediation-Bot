"""AST context extractor for Python source files to enrich vulnerability triage."""

import ast
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CodeContext:
    """Enriched structural context extracted via AST for a target line range."""
    enclosing_function: Optional[str] = None
    enclosing_class: Optional[str] = None
    scope_start_line: int = 1
    scope_end_line: int = 1
    function_signature: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    surrounding_snippet: str = ""
    context_summary: str = ""


class _ContextVisitor(ast.NodeVisitor):
    """AST NodeVisitor that tracks scopes and imports overlapping a line range."""

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.enclosing_function: Optional[str] = None
        self.enclosing_class: Optional[str] = None
        self.func_start: Optional[int] = None
        self.func_end: Optional[int] = None
        self.class_start: Optional[int] = None
        self.class_end: Optional[int] = None
        self.func_sig: Optional[str] = None
        self.imports: List[str] = []
        self._class_stack: List[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.imports.append(f"import {alias.name} as {alias.asname}")
            else:
                self.imports.append(f"import {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.asname:
                self.imports.append(f"from {module} import {alias.name} as {alias.asname}")
            else:
                self.imports.append(f"from {module} import {alias.name}")
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        if node.lineno <= self.target_line <= (getattr(node, "end_lineno", node.lineno)):
            self.enclosing_class = node.name
            self.class_start = node.lineno
            self.class_end = getattr(node, "end_lineno", node.lineno)

        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_func(node)

    def _handle_func(self, node: ast.AST) -> None:
        lineno = getattr(node, "lineno", 1)
        end_lineno = getattr(node, "end_lineno", lineno)
        name = getattr(node, "name", "")

        if lineno <= self.target_line <= end_lineno:
            self.enclosing_function = name
            self.func_start = lineno
            self.func_end = end_lineno
            # Format argument signature
            args = getattr(node, "args", None)
            if args:
                arg_names = [a.arg for a in args.args]
                self.func_sig = f"def {name}({', '.join(arg_names)})"
            else:
                self.func_sig = f"def {name}()"

            if self._class_stack:
                self.enclosing_class = self._class_stack[-1]

        self.generic_visit(node)


def extract_ast_context(source_code: str, target_line: int, window: int = 15) -> CodeContext:
    """Analyze Python code with AST to determine the enclosing scope for the target line.

    Args:
        source_code: Full contents of the Python source file.
        target_line: Line number where the vulnerability was flagged (1-based).
        window: Fallback lines before and after if AST scope cannot be determined.

    Returns:
        CodeContext object with enclosing symbols, imports, and surrounding code.
    """
    lines = source_code.splitlines()
    total_lines = len(lines)
    clamped_target = max(1, min(target_line, total_lines if total_lines > 0 else 1))

    try:
        tree = ast.parse(source_code)
        visitor = _ContextVisitor(clamped_target)
        visitor.visit(tree)

        enclosing_function = visitor.enclosing_function
        enclosing_class = visitor.enclosing_class
        imports = visitor.imports

        if visitor.func_start and visitor.func_end:
            start_idx = max(0, visitor.func_start - 1)
            end_idx = min(total_lines, visitor.func_end)
            scope_start = visitor.func_start
            scope_end = visitor.func_end
            surrounding = "\n".join(lines[start_idx:end_idx])
        elif visitor.class_start and visitor.class_end:
            start_idx = max(0, visitor.class_start - 1)
            end_idx = min(total_lines, visitor.class_end)
            scope_start = visitor.class_start
            scope_end = visitor.class_end
            surrounding = "\n".join(lines[start_idx:end_idx])
        else:
            # Fallback to line window around target
            start_idx = max(0, clamped_target - window)
            end_idx = min(total_lines, clamped_target + window)
            scope_start = start_idx + 1
            scope_end = end_idx
            surrounding = "\n".join(lines[start_idx:end_idx])

        summary_parts = []
        if enclosing_class:
            summary_parts.append(f"Class: {enclosing_class}")
        if enclosing_function:
            summary_parts.append(f"Function: {enclosing_function}")
        if visitor.func_sig:
            summary_parts.append(f"Signature: {visitor.func_sig}")
        summary_parts.append(f"Lines: {scope_start}-{scope_end}")

        return CodeContext(
            enclosing_function=enclosing_function,
            enclosing_class=enclosing_class,
            scope_start_line=scope_start,
            scope_end_line=scope_end,
            function_signature=visitor.func_sig,
            imports=imports,
            surrounding_snippet=surrounding,
            context_summary=" | ".join(summary_parts)
        )

    except Exception:
        # Non-Python or unparseable syntax: provide line window fallback
        start_idx = max(0, clamped_target - window)
        end_idx = min(total_lines, clamped_target + window)
        surrounding = "\n".join(lines[start_idx:end_idx]) if lines else source_code
        return CodeContext(
            scope_start_line=start_idx + 1,
            scope_end_line=end_idx,
            surrounding_snippet=surrounding,
            context_summary=f"Non-AST context (lines {start_idx + 1}-{end_idx})"
        )
