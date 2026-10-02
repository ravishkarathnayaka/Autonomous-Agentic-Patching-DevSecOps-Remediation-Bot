"""Deterministic Mock LLM Provider for offline unit tests and CI runners."""

import re
from typing import Optional


class MockLLMProvider:
    """Mock LLM engine that returns realistic, deterministic security patches and PR summaries."""

    def __init__(self, simulate_retry_failure: bool = False):
        self.simulate_retry_failure = simulate_retry_failure
        self.call_count = 0

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> str:
        """Route prompt to appropriate mock generator based on prompt content and call state."""
        self.call_count += 1
        prompt_lower = prompt.lower()

        # If simulate_retry_failure is true and this is call 1 for a patch prompt, return broken patch
        if self.simulate_retry_failure and self.call_count == 1 and ("diff" in prompt_lower or "patch" in prompt_lower):
            return self._generate_syntax_error_patch()

        # PR Agent prompt detection
        if "pull request" in prompt_lower or "pr description" in prompt_lower or "threat analysis" in prompt_lower:
            return self._generate_mock_pr_description(prompt)

        # Patch Agent prompts based on vulnerability class / CWE
        if "cwe-89" in prompt_lower or "sql injection" in prompt_lower:
            return self._generate_sqli_patch()
        elif "cwe-22" in prompt_lower or "path traversal" in prompt_lower:
            return self._generate_path_traversal_patch()
        elif "cwe-78" in prompt_lower or "command injection" in prompt_lower:
            return self._generate_command_injection_patch()
        elif "sca" in prompt_lower or "requirements.txt" in prompt_lower or "cve-" in prompt_lower:
            return self._generate_sca_patch(prompt)

        # Default fallback patch
        return self._generate_generic_patch()

    def _generate_syntax_error_patch(self) -> str:
        """Simulate an erroneous patch on the first attempt to test verifier feedback loop."""
        return """```diff
--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -28,2 +28,2 @@
-    query = f"SELECT * FROM items WHERE name = '{name}'"
-    cursor.execute(query)
+    query = "SELECT * FROM items WHERE name = ?"
+    cursor.execute(query, (name,  # INTENTIONAL SYNTAX ERROR
```"""

    def _generate_sqli_patch(self) -> str:
        """Generate parameterized query patch for SQL Injection (CWE-89)."""
        return """```diff
--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -28,3 +28,3 @@
-    query = f"SELECT * FROM items WHERE name = '{name}'"
-    cursor.execute(query)
+    query = "SELECT * FROM items WHERE name = ?"
+    cursor.execute(query, (name,))
```
### Remediation Rationale
Replaced untrusted string interpolation with parameterized SQL query using standard SQLite placeholder `?`.
This prevents SQL injection attacks (CWE-89) by separating SQL query code from user-supplied data arguments."""

    def _generate_path_traversal_patch(self) -> str:
        """Generate safe path resolution patch for Path Traversal (CWE-22)."""
        return """```diff
--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -42,3 +42,6 @@
-    file_path = os.path.join(SAFE_DIR, filename)
-    with open(file_path, "r") as f:
-        return f.read()
+    base_dir = os.path.abspath(SAFE_DIR)
+    file_path = os.path.abspath(os.path.join(base_dir, filename))
+    if not file_path.startswith(base_dir + os.sep) and file_path != base_dir:
+        return "Access denied: Invalid file path", 403
+    with open(file_path, "r", encoding="utf-8") as f:
+        return f.read()
```
### Remediation Rationale
Enforced canonical path resolution via `os.path.abspath` and validated that the target path remains within `SAFE_DIR`.
Blocks directory traversal sequences (e.g. `../`) per CWE-22 guidance."""

    def _generate_command_injection_patch(self) -> str:
        """Generate shell=False list-based execution patch for Command Injection (CWE-78)."""
        return """```diff
--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -58,3 +58,4 @@
-    cmd = f"ping {count_flag} 1 {host}"
-    output = subprocess.check_output(cmd, shell=True, text=True)
-    return output
+    import re
+    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
+        return "Invalid hostname format", 400
+    output = subprocess.check_output(["ping", count_flag, "1", host], shell=False, text=True)
+    return output
```
### Remediation Rationale
Avoided `shell=True` and passed command arguments as a list.
Additionally enforced strict hostname regex filtering to eliminate command injection vectors (CWE-78)."""

    def _generate_sca_patch(self, prompt: str) -> str:
        """Generate dependency version bump patch for SCA reports."""
        pkg_match = re.search(r"Package:\s*([\w\.\-]+)", prompt, re.IGNORECASE)
        pkg_name = pkg_match.group(1).strip() if pkg_match else "Flask"

        installed_match = re.search(r"Installed Version:\s*([\w\.\-]+)", prompt, re.IGNORECASE)
        installed_version = installed_match.group(1).strip() if installed_match else "2.2.0"

        fixed_match = re.search(r"Fixed Version:\s*([\w\.\-]+)", prompt, re.IGNORECASE)
        target_version = fixed_match.group(1).strip() if fixed_match else "2.2.5"

        return f"""```diff
--- a/target_repo/requirements.txt
+++ b/target_repo/requirements.txt
@@ -1,3 +1,3 @@
-{pkg_name}=={installed_version}
+{pkg_name}=={target_version}
```
### Remediation Rationale
Bumped vulnerable dependency {pkg_name} to patched release {target_version} to remediate known CVE advisory."""

    def _generate_generic_patch(self) -> str:
        """Generic fallback unified diff."""
        return """```diff
--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -10,1 +10,1 @@
-# placeholder
+# remediated code
```
### Remediation Rationale
Applied secure hardening patch to prevent vulnerability."""

    def _generate_mock_pr_description(self, prompt: str) -> str:
        """Generate production-ready markdown PR description."""
        return """## 🛡️ Autonomous DevSecOps Security Remediation

### 1. Executive Summary
- **Vulnerability ID**: Identified finding remediated automatically by the DevSecOps Bot.
- **Remediation Strategy**: Replaced vulnerable pattern with secure parameterized handling and input validation.
- **Verification Verdict**: ✅ PASS (Ephemeral Container Sandbox)

### 2. Threat Analysis & CWE Mitigation
- **Attack Vector**: An adversary could supply crafted input to manipulate backend execution.
- **Impact**: Arbitrary execution or data exfiltration.
- **Mitigation Applied**: Strict input sanitization, canonical validation, and unprivileged execution.

### 3. Verification Test Evidence
```text
============================= test session starts =============================
platform linux -- Python 3.11.8, pytest-8.1.1
collected 3 items

test_app.py::test_search_valid PASSED                                    [ 33%]
test_app.py::test_file_view_valid PASSED                                 [ 66%]
test_app.py::test_ping_valid PASSED                                      [100%]

============================== 3 passed in 0.42s ==============================
```

### 4. Regression & Rollback Plan
- Zero breaking changes to public endpoints.
- In case of unexpected edge cases, revert branch via standard Git revert workflow.

---
*Generated autonomously by Autonomous Agentic Patching & DevSecOps Remediation Bot.*"""
