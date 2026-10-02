import { Finding } from '../types';

export interface PresetScenario {
  id: string;
  name: string;
  icon: string;
  category: 'SAST' | 'SCA';
  finding: Finding;
  initialSourceCode: string;
  passingPatchDiff: string;
  failingPatchDiff: string;
  remediationExplanation: string;
}

export const PRESET_SCENARIOS: PresetScenario[] = [
  {
    id: 'sqli',
    name: 'SQL Injection (CWE-89)',
    icon: 'Database',
    category: 'SAST',
    finding: {
      id: 'semgrep-sqlite-sqli-01',
      scanner: 'semgrep',
      type: 'SAST',
      ruleId: 'rules.python.security.sqlite_sql_injection',
      title: 'SQL Injection in /items endpoint',
      description: 'User-controllable input formatted directly into raw SQL query allows arbitrary query execution.',
      severity: 'HIGH',
      cwe: ['CWE-89'],
      cvss: 9.8,
      filePath: 'target_repo/app.py',
      startLine: 28,
      endLine: 29,
      vulnerableCode: '    query = f"SELECT * FROM items WHERE name = \'{name}\'"\n    cursor.execute(query)',
      astContext: 'Function: get_items(name) | Lines: 25-32\nImports: import sqlite3, from flask import Flask, request'
    },
    initialSourceCode: `@app.route("/items", methods=["GET"])
def get_items():
    name = request.args.get("name", "")
    cursor = get_db().cursor()
    query = f"SELECT * FROM items WHERE name = '{name}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify([{"id": r[0], "name": r[1]} for r in rows])`,
    passingPatchDiff: `--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -28,3 +28,3 @@
-    query = f"SELECT * FROM items WHERE name = '{name}'"
-    cursor.execute(query)
+    query = "SELECT * FROM items WHERE name = ?"
+    cursor.execute(query, (name,))`,
    failingPatchDiff: `--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -28,2 +28,2 @@
-    query = f"SELECT * FROM items WHERE name = '{name}'"
-    cursor.execute(query)
+    query = "SELECT * FROM items WHERE name = ?"
+    cursor.execute(query, (name,  # SYNTAX ERROR`,
    remediationExplanation: 'Replaced dynamic string formatting with parameterized SQLite query using placeholder `?`. This separates untrusted user inputs from SQL compilation per CWE-89 mitigation standards.'
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal (CWE-22)',
    icon: 'FolderTree',
    category: 'SAST',
    finding: {
      id: 'semgrep-path-traversal-02',
      scanner: 'semgrep',
      type: 'SAST',
      ruleId: 'rules.python.security.path_traversal_open',
      title: 'Arbitrary File Read via Path Traversal',
      description: 'Unvalidated user filename combined directly with base path enables directory traversal via ../ sequences.',
      severity: 'HIGH',
      cwe: ['CWE-22'],
      cvss: 7.5,
      filePath: 'target_repo/app.py',
      startLine: 42,
      endLine: 44,
      vulnerableCode: '    file_path = os.path.join(SAFE_DIR, filename)\n    with open(file_path, "r") as f:\n        return f.read()',
      astContext: 'Function: view_file() | Lines: 40-45\nImports: import os'
    },
    initialSourceCode: `@app.route("/files", methods=["GET"])
def view_file():
    filename = request.args.get("filename", "")
    file_path = os.path.join(SAFE_DIR, filename)
    with open(file_path, "r") as f:
        return f.read()`,
    passingPatchDiff: `--- a/target_repo/app.py
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
+        return f.read()`,
    failingPatchDiff: `--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -42,2 +42,2 @@
-    file_path = os.path.join(SAFE_DIR, filename)
+    file_path = os.path.join(SAFE_DIR, filename.replace("../", "")`,
    remediationExplanation: 'Canonicalized file path via `os.path.abspath` and ensured destination resides strictly inside `SAFE_DIR`. Eliminates directory traversal without relying on naive blacklist substring stripping.'
  },
  {
    id: 'cmd-injection',
    name: 'Command Injection (CWE-78)',
    icon: 'Terminal',
    category: 'SAST',
    finding: {
      id: 'semgrep-cmd-injection-03',
      scanner: 'semgrep',
      type: 'SAST',
      ruleId: 'rules.python.security.subprocess_command_injection',
      title: 'OS Command Injection in /ping',
      description: 'Host parameter concatenated into shell string and executed via subprocess with shell=True.',
      severity: 'CRITICAL',
      cwe: ['CWE-78'],
      cvss: 9.8,
      filePath: 'target_repo/app.py',
      startLine: 58,
      endLine: 60,
      vulnerableCode: '    cmd = f"ping {count_flag} 1 {host}"\n    output = subprocess.check_output(cmd, shell=True, text=True)\n    return output',
      astContext: 'Function: ping() | Lines: 56-62\nImports: import subprocess'
    },
    initialSourceCode: `@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "127.0.0.1")
    count_flag = "-n" if sys.platform == "win32" else "-c"
    cmd = f"ping {count_flag} 1 {host}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output`,
    passingPatchDiff: `--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -58,3 +58,4 @@
-    cmd = f"ping {count_flag} 1 {host}"
-    output = subprocess.check_output(cmd, shell=True, text=True)
-    return output
+    import re
+    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
+        return "Invalid hostname format", 400
+    output = subprocess.check_output(["ping", count_flag, "1", host], shell=False, text=True)
+    return output`,
    failingPatchDiff: `--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -58,2 +58,2 @@
-    cmd = f"ping {count_flag} 1 {host}"
+    cmd = f"ping {count_flag} 1 {host}; echo done"`,
    remediationExplanation: 'Avoided `shell=True` by passing arguments as an array directly to the executable. Added strict alphanumeric regex hostname validation to eliminate command injection.'
  },
  {
    id: 'flask-sca',
    name: 'Flask Cookie Leak (CVE-2023-30861)',
    icon: 'Package',
    category: 'SCA',
    finding: {
      id: 'trivy-cve-2023-30861',
      scanner: 'trivy',
      type: 'SCA',
      ruleId: 'CVE-2023-30861',
      title: 'Flask session cookie disclosure vulnerability',
      description: 'Improper handling of secret keys in specific configurations allows session hijacking.',
      severity: 'HIGH',
      cwe: ['CWE-384'],
      cvss: 7.5,
      filePath: 'target_repo/requirements.txt',
      startLine: 1,
      endLine: 1,
      vulnerableCode: 'Flask==2.2.0',
      packageInfo: {
        name: 'Flask',
        installedVersion: '2.2.0',
        fixedVersion: '2.2.5'
      }
    },
    initialSourceCode: `Flask==2.2.0
Werkzeug==2.2.2
pytest>=8.0.0`,
    passingPatchDiff: `--- a/target_repo/requirements.txt
+++ b/target_repo/requirements.txt
@@ -1,2 +1,2 @@
-Flask==2.2.0
+Flask==2.2.5`,
    failingPatchDiff: `--- a/target_repo/requirements.txt
+++ b/target_repo/requirements.txt
@@ -1,2 +1,2 @@
-Flask==2.2.0
+Flask==99.99.99-nonexistent`,
    remediationExplanation: 'Upgraded pinned Flask dependency from 2.2.0 to official security patch 2.2.5 resolving CVE-2023-30861.'
  }
];
