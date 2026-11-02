# Dynamic AST Rewriting Architecture Specification

## 1. Executive Summary

Traditional automated remediation solutions rely on regex pattern replacements, which are brittle and susceptible to syntax corruption. The **Autonomous DevSecOps Remediation Bot** utilizes Concrete Syntax Tree (CST) and Abstract Syntax Tree (AST) parsing (`libcst`, `tree-sitter`, Python `ast`) to generate syntax-guaranteed patches while preserving formatting, comments, and stylistic idioms.

---

## 2. Transformation Pipeline

```
┌────────────────────────────────────────────────────────┐
│ Raw Source File (`app.py`, `service.go`, etc.)         │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ CST Parsing & Node Identification                      │
│ - Exact token positions and indentation retention      │
│ - Finding coordinate matching (line, column, AST node) │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ AST Transformer Agent                                  │
│ - Node replacement (e.g. Call(yaml.load) -> safe_load) │
│ - Import injection & deduplication                     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ AST Equivalence & Proof Verification                   │
│ - Verifies target fix is applied                       │
│ - Checks for zero unintended side-effects              │
└────────────────────────────────────────────────────────┘
```

---

## 3. Supported AST Rewrite Capabilities

- **Import Injection**: Automatically analyzes existing module imports and adds necessary standard library modules (`hmac`, `secrets`, `tempfile`, `defusedxml`) without duplicate import statements.
- **Function Call Parameterization**: Replaces dynamic string formatting inside database queries (`cursor.execute(f"...")`) with parameterized tuple arguments (`cursor.execute("...", (param,))`).
- **Context Manager Wrapping**: Transforms unmanaged file creation or temporary paths into safe Python context managers (`with tempfile.NamedTemporaryFile() as f:`).
- **Constant-Time Replacement**: Detects binary comparison operations on secrets and rewrites them into function calls (`hmac.compare_digest(a, b)`).
