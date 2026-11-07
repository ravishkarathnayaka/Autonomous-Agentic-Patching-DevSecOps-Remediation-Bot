"""Sample vulnerable target application for DevSecOps automated remediation bot testing.

Contains intentional security vulnerabilities:
1. CWE-89: SQL Injection (/items)
2. CWE-22: Path Traversal (/files)
3. CWE-78: Command Injection (/ping)
4. CWE-502: Insecure Deserialization (/session/load)
5. CWE-327: Use of a Broken or Risky Cryptographic Algorithm (/user/hash_password)
6. CWE-79: Cross-Site Scripting (/search)
"""

import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
import sys
import tempfile
from flask import Flask, jsonify, redirect, render_template_string, request

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAFE_DIR = os.path.join(BASE_DIR, "safe_files")
DB_PATH = os.path.join(BASE_DIR, "sample.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/items", methods=["GET"])
def get_items():
    name = request.args.get("name", "")
    cursor = get_db().cursor()
    query = f"SELECT * FROM items WHERE name = '{name}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify([{"id": r[0], "name": r[1], "category": r[2]} for r in rows])


@app.route("/files", methods=["GET"])
def view_file():
    filename = request.args.get("filename", "")
    file_path = os.path.join(SAFE_DIR, filename)
    with open(file_path, "r") as f:
        return f.read()


@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "127.0.0.1")
    count_flag = "-n" if sys.platform == "win32" else "-c"
    cmd = f"ping {count_flag} 1 {host}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output


@app.route("/session/load", methods=["POST"])
def load_session():
    payload = request.form.get("payload", "")
    if not payload:
        return jsonify({"error": "Missing payload"}), 400
    try:
        raw_bytes = base64.b64decode(payload.encode("utf-8"))
        obj = pickle.loads(raw_bytes)
        user = obj.get("user", "guest") if isinstance(obj, dict) else "guest"
        return jsonify({"status": "loaded", "session_user": str(user)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/user/hash_password", methods=["POST"])
def hash_password():
    password = request.form.get("password", "")
    # Vulnerable: Insecure MD5 hash without salt violates CWE-327
    md5_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    return jsonify({"algo": "md5", "hash": md5_hash})


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    # Vulnerable: Unescaped reflected user input in HTML template (CWE-79)
    html = f"<html><body><h1>Search Results for: {q}</h1><p>No matches found.</p></body></html>"
    return html, 200, {"Content-Type": "text/html"}


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    # Vulnerable: Server-Side Request Forgery (CWE-918) fetches arbitrary internal/external URLs
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "DevSecOpsBot/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            content = resp.read()[:500].decode("utf-8", errors="ignore")
            return jsonify({"status": "success", "content": content}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/redirect", methods=["GET"])
def handle_redirect():
    target = request.args.get("next", "/")
    # Vulnerable: Open Redirect (CWE-601) redirects to arbitrary untrusted external domains
    from flask import redirect
    return redirect(target)


@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    xml_data = request.data.decode("utf-8", errors="ignore")
    # Vulnerable: Insecure XML parsing allowing external entity resolution (CWE-611)
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_data)
        return jsonify({"root_tag": root.tag}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/verify-token", methods=["POST"])
def verify_token():
    auth_header = request.headers.get("Authorization", "")
    # Vulnerable: Hardcoded API secret in source code (CWE-798)
    HARDCODED_INTERNAL_SECRET = "sk_live_99a88b77cc66dd55ee44"
    if auth_header == f"Bearer {HARDCODED_INTERNAL_SECRET}":
        return jsonify({"authenticated": True, "scope": "admin"}), 200
    return jsonify({"authenticated": False}), 401


@app.route("/api/user-data", methods=["GET"])
def get_user_data():
    # Vulnerable: Overly permissive wildcard CORS header on authenticated endpoint (CWE-942)
    resp = jsonify({"account_id": "ACC-1029", "balance": 5000})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp, 200


@app.route("/api/headers", methods=["GET"])
def check_headers():
    # Vulnerable: Endpoint returning sensitive data without CSP or X-Frame-Options (CWE-693)
    return jsonify({"message": "Secure portal dashboard", "sensitive": True}), 200


@app.route("/generate-token", methods=["GET"])
def generate_token():
    # Vulnerable: Insecure PRNG used for security-sensitive token generation (CWE-338)
    import random
    token = "".join(random.choice("0123456789abcdef") for _ in range(32))
    return jsonify({"token": token, "algorithm": "pseudo-random"}), 200


@app.route("/extract-archive", methods=["POST"])
def extract_archive():
    # Vulnerable: Zip Slip path traversal during archive decompression (CWE-29)
    data = request.get_json() or {}
    filenames = data.get("files", [])
    extracted = []
    base_dir = "/tmp/app_extracted"
    for fname in filenames:
        # Insecurely joining path without checking if it escapes base_dir
        target_path = os.path.join(base_dir, fname)
        extracted.append(target_path)
    return jsonify({"extracted_count": len(extracted), "targets": extracted}), 200


@app.route("/validate-hmac", methods=["POST"])
def validate_hmac():
    # Vulnerable: Non-constant time comparison of HMAC signatures susceptible to timing attacks (CWE-208)
    data = request.get_json() or {}
    signature = data.get("signature", "")
    expected = "8f4e2a1b9c3d7e5f6a0b"
    # Vulnerable comparison: == terminates early on first mismatch
    is_valid = signature == expected
    return jsonify({"valid": is_valid}), 200 if is_valid else 403


@app.route("/login-session", methods=["POST"])
def login_session():
    # Vulnerable: Insecure session cookie missing HttpOnly, Secure, and SameSite flags (CWE-614)
    data = request.get_json() or {}
    username = data.get("username", "guest")
    resp = jsonify({"status": "logged_in", "user": username})
    resp.set_cookie("session_token", "sess_xyz_12345", httponly=False, secure=False, samesite=None)
    return resp, 200


@app.route("/validate-regex", methods=["POST"])
def validate_regex_pattern():
    # Vulnerable: Regular Expression Denial of Service (CWE-1333) with catastrophic backtracking
    import re
    data = request.get_json(silent=True) or {}
    user_str = data.get("text", "")
    pattern = re.compile(r"^([a-zA-Z0-9]+)+$")
    matched = bool(pattern.match(user_str))
    return jsonify({"matched": matched}), 200


@app.route("/batch-process", methods=["POST"])
def batch_process():
    # Vulnerable: Allocation of Resources Without Limits (CWE-770) allows unbounded loop allocation
    data = request.get_json(silent=True) or {}
    items = data.get("items", [])
    processed = [f"item_{i}" for i in range(len(items))]
    return jsonify({"count": len(processed), "processed": processed}), 200


@app.route("/telemetry-stream", methods=["GET"])
def telemetry_stream():
    # Vulnerable: Cleartext Transmission of Sensitive Information (CWE-319) missing secure transport flag
    api_key = request.headers.get("X-API-Key", "demo_telemetry_key_xyz")
    return jsonify({"telemetry": "active", "key": api_key, "transport": "cleartext"}), 200


@app.route("/debug-query", methods=["POST"])
def debug_query():
    # Vulnerable: Information Exposure Through an Error Message (CWE-209) leaking database path and stack traces
    data = request.get_json(silent=True) or {}
    table_name = data.get("table", "unknown_table")
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        return jsonify({"rows": rows}), 200
    except Exception as e:
        # Sensitive stack/db info leaked to caller
        return jsonify({"error": str(e), "db_path": DB_PATH, "trace": sys.exc_info()[0].__name__}), 500


@app.route("/eval-expression", methods=["POST"])
def eval_expression():
    # Vulnerable: Code Injection through eval() (CWE-95)
    data = request.get_json(silent=True) or {}
    expr = data.get("expr", "1 + 1")
    # Insecure dynamic evaluation of untrusted expression string
    try:
        result = eval(expr, {"__builtins__": {}})
        return jsonify({"result": result}), 200
    except Exception as e:
        return jsonify({"error": "Evaluation error"}), 400


@app.route("/upload-profile-image", methods=["POST"])
def upload_profile_image():
    # Vulnerable: Unrestricted Upload of File with Dangerous Type (CWE-434)
    # Accepts file without MIME type validation or extension whitelist
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    filename = file.filename
    upload_dir = os.path.join(tempfile.gettempdir(), "user_uploads")
    os.makedirs(upload_dir, exist_ok=True)
    destination = os.path.join(upload_dir, filename)
    file.save(destination)
    return jsonify({"status": "uploaded", "filename": filename, "path": destination}), 201


@app.route("/render-template", methods=["POST"])
def render_template_endpoint():
    # Vulnerable: Server-Side Template Injection (CWE-1336)
    data = request.get_json(silent=True) or {}
    name = data.get("name", "Guest")
    # Untrusted user input concatenated directly into template string
    template = f"Hello {name}! Welcome to the platform."
    rendered = render_template_string(template)
    return jsonify({"rendered": rendered}), 200


@app.route("/api/documents/<int:doc_id>", methods=["GET"])
def get_document(doc_id):
    # Vulnerable: Insecure Direct Object References (IDOR / CWE-639)
    # Directly retrieves document without verifying caller identity or ownership
    sample_docs = {
        101: {"id": 101, "title": "Public Quarterly Report", "owner": "admin"},
        102: {"id": 102, "title": "Confidential Memo", "owner": "cfo"},
        103: {"id": 103, "title": "Engineering Roadmap", "owner": "lead"}
    }
    if doc_id in sample_docs:
        return jsonify(sample_docs[doc_id]), 200
    return jsonify({"error": "Document not found"}), 404


@app.route("/api/account-summary", methods=["GET"])
def get_account_summary():
    # Vulnerable: Insecure CORS with Null Origin (CWE-942)
    # Reflects origin directly with credentials enabled
    origin = request.headers.get("Origin", "null")
    resp = jsonify({"account_number": "ACC-99812", "balance_usd": 12500.50, "currency": "USD"})
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp, 200


@app.route("/user/ldap-lookup", methods=["POST"])
def ldap_lookup():
    # Vulnerable: Improper Neutralization of Special Elements used in an LDAP Query (CWE-90)
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    # Insecure string formatting into LDAP filter query without sanitization
    ldap_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
    directory = {
        "alice": {"cn": "Alice Smith", "mail": "alice@corp.internal", "department": "Security"},
        "bob": {"cn": "Bob Jones", "mail": "bob@corp.internal", "department": "DevOps"}
    }
    user_info = directory.get(username)
    if user_info:
        return jsonify({"filter": ldap_filter, "user": user_info}), 200
    return jsonify({"filter": ldap_filter, "error": "User not found"}), 404


@app.route("/user/update-profile", methods=["POST"])
def update_profile():
    # Vulnerable: Modification of Assumed-Immutable Attribute (Mass Assignment / CWE-915)
    # Directly binds all request JSON fields into user record without property whitelisting
    data = request.get_json(silent=True) or {}
    user_record = {
        "user_id": 42,
        "username": "developer1",
        "email": "dev1@corp.internal",
        "is_admin": False,
        "role": "engineer"
    }
    user_record.update(data)
    return jsonify({"status": "profile_updated", "user": user_record}), 200


@app.route("/query-xml", methods=["POST"])
def query_xml():
    # Vulnerable: Improper Neutralization of Data within XPath Expressions (CWE-643)
    data = request.get_json(silent=True) or {}
    username = data.get("username", "guest")
    # Insecure concatenation of user input into XPath query
    xpath_query = f"/users/user[username/text()='{username}']"
    mock_users = {
        "admin": {"username": "admin", "role": "superuser", "email": "admin@internal.net"},
        "guest": {"username": "guest", "role": "viewer", "email": "guest@internal.net"}
    }
    if username in mock_users:
        return jsonify({"xpath": xpath_query, "user": mock_users[username]}), 200
    return jsonify({"xpath": xpath_query, "error": "User not found"}), 404


@app.route("/load-yaml-config", methods=["POST"])
def load_yaml_config():
    # Vulnerable: Deserialization of Untrusted Data (CWE-502) using unsafe yaml.load
    import yaml
    raw_yaml = request.data.decode("utf-8", errors="ignore")
    if not raw_yaml:
        return jsonify({"error": "Empty YAML payload"}), 400
    try:
        # Insecure: Loader=yaml.Loader allows instantiation of arbitrary Python objects
        parsed_config = yaml.load(raw_yaml, Loader=yaml.Loader)
        return jsonify({"status": "config_loaded", "config": parsed_config}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/check-dns", methods=["POST"])
def check_dns():
    # Vulnerable: Server-Side Request Forgery via DNS Resolution (CWE-918)
    import socket
    data = request.get_json(silent=True) or {}
    hostname = data.get("host", "")
    if not hostname:
        return jsonify({"error": "Host required"}), 400
    try:
        ip = socket.gethostbyname(hostname)
        return jsonify({"host": hostname, "ip": ip, "resolved": True}), 200
    except Exception as e:
        return jsonify({"error": str(e), "resolved": False}), 400


@app.route("/admin/toggle-maintenance", methods=["POST"])
def toggle_maintenance():
    # Vulnerable: Client-Side Security Check without Server Authorization (CWE-602)
    # Relies on client-controlled header 'X-Client-Is-Admin' without server verification
    is_client_admin = request.headers.get("X-Client-Is-Admin", "false").lower() == "true"
    if not is_client_admin:
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json(silent=True) or {}
    mode = bool(data.get("maintenance_mode", False))
    return jsonify({"status": "updated", "maintenance_mode": mode}), 200


@app.route("/generate-report-temp", methods=["POST"])
def generate_report_temp():
    # Vulnerable: Insecure Temporary File Creation (CWE-377)
    # Uses predictable file path without atomic creation or secure tempfile module
    data = request.get_json(silent=True) or {}
    report_title = data.get("title", "Daily Security Report")
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"report_{report_title.replace(' ', '_').lower()}.txt")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(f"Report: {report_title}\nGenerated on automated trigger.\n")
        return jsonify({"status": "generated", "path": temp_path}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/preview/mako-template", methods=["POST"])
def preview_mako_template():
    # Vulnerable: Server-Side Template Injection with Sandbox Bypass (CWE-1336 / CWE-94)
    # Evaluates user-supplied template strings without an AST-restricted rendering environment
    data = request.get_json(silent=True) or {}
    template_str = data.get("template", "Hello {{name}}")
    user_context = data.get("context", {"name": "Guest"})
    try:
        # Intentionally renders unescaped string directly into Jinja2 engine
        rendered = render_template_string(template_str, **user_context)
        return jsonify({"rendered": rendered}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/v1/config/deep-merge", methods=["POST"])
def config_deep_merge():
    # Vulnerable: Prototype Pollution / Object Attribute Injection (CWE-1321)
    # Recursively merges untrusted dictionary without key allowlist or protection against special attributes
    payload = request.get_json(silent=True) or {}
    base_config = {"version": "1.0.0", "env": "production", "features": {"telemetry": True}}

    def unsafe_merge(target, src):
        for k, v in src.items():
            if isinstance(v, dict) and k in target and isinstance(target[k], dict):
                unsafe_merge(target[k], v)
            else:
                target[k] = v
        return target

    merged = unsafe_merge(base_config, payload)
    return jsonify({"status": "merged", "config": merged}), 200


@app.route("/api/v1/auth/audit-log", methods=["POST"])
def write_audit_log():
    # Vulnerable: Improper Output Handling for Logs / Log Injection (CWE-117)
    # Writes unsanitized user input containing potential CRLF characters to log
    data = request.get_json(silent=True) or {}
    username = data.get("username", "anonymous")
    action = data.get("action", "login_attempt")
    log_entry = f"AUDIT: user='{username}' performed action='{action}'"
    # Unsanitized append to audit log file
    audit_file = os.path.join(tempfile.gettempdir(), "app_audit.log")
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")
    return jsonify({"status": "logged", "entry": log_entry}), 201


@app.route("/api/v1/directory/ldap-search", methods=["POST"])
def directory_ldap_search():
    # Vulnerable: Improper Neutralization of Special Elements used in an LDAP Query (CWE-90)
    # Direct concatenation of user input into LDAP query filter without RFC 4515 escaping
    data = request.get_json(silent=True) or {}
    query = data.get("query", "")
    if not query:
        return jsonify({"error": "Query required"}), 400
    ldap_filter = f"(&(objectCategory=person)(sAMAccountName={query}))"
    # Mock directory search response matching filter
    return jsonify({
        "status": "success",
        "filter_executed": ldap_filter,
        "results": [{"dn": f"uid={query},ou=engineering,dc=corp,dc=internal"}]
    }), 200


@app.route("/api/v1/crypto/derive-key", methods=["POST"])
def crypto_derive_key():
    # Vulnerable: Use of Password Hash With Insufficient Computational Effort (CWE-916 / CWE-326)
    # Uses hardcoded static salt and low iteration count (100) instead of CSPRNG salt & 600,000+ iterations
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400
    static_salt = b"hardcoded_salt_123"
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), static_salt, 100)
    return jsonify({
        "status": "derived",
        "key_hex": derived.hex(),
        "algorithm": "PBKDF2-HMAC-SHA256"
    }), 200


@app.route("/api/v1/storage/read-symlink", methods=["POST"])
def read_storage_symlink():
    # Vulnerable: Improper Link Resolution Before File Access (CWE-59 / CWE-22)
    # Reads file contents directly without resolving symlinks or ensuring target is inside SAFE_DIR
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    target_path = os.path.join(SAFE_DIR, filename)
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"status": "read", "content": content}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/v1/transfer/funds", methods=["POST"])
def transfer_funds():
    # Vulnerable: HTTP Parameter Pollution (HPP / CWE-235)
    # Allows multiple recipient parameters; security validation checks first item while execution uses last
    recipients = request.form.getlist("recipient")
    amount = request.form.get("amount", "0")
    if not recipients:
        return jsonify({"error": "Recipient required"}), 400
    # Flawed logic: validation checks first, transaction executes last
    first_recipient = recipients[0]
    final_recipient = recipients[-1]
    return jsonify({
        "status": "transferred",
        "validated_recipient": first_recipient,
        "transferred_to": final_recipient,
        "amount": amount
    }), 200


@app.route("/api/v1/documents/render-pdf", methods=["POST"])
def render_pdf_document():
    # Vulnerable: Server-Side Request Forgery (SSRF / CWE-918) via PDF HTML rendering
    # Renders user HTML with external resource fetching without internal IP filtering
    data = request.get_json(silent=True) or {}
    html_content = data.get("html", "")
    if not html_content:
        return jsonify({"error": "HTML content required"}), 400
    # Simulate PDF engine fetching linked images or stylesheets
    import re
    external_links = re.findall(r'(?:src|href)=["\'](http[s]?://[^"\']+)["\']', html_content)
    return jsonify({
        "status": "rendered",
        "fetched_resources": external_links,
        "byte_size": len(html_content)
    }), 200


@app.route("/api/v1/profile/avatar-svg", methods=["POST"])
def upload_avatar_svg():
    # Vulnerable: XML External Entity Reference (XXE / CWE-611) via SVG vector graphic
    # Parses raw XML without disabling external DTD or parameter entities
    data = request.get_json(silent=True) or {}
    svg_raw = data.get("svg_data", "")
    if not svg_raw:
        return jsonify({"error": "SVG data required"}), 400
    try:
        import xml.etree.ElementTree as ET
        # Insecure default parser without defusedxml
        root = ET.fromstring(svg_raw)
        tag = root.tag
        width = root.attrib.get("width", "100")
        height = root.attrib.get("height", "100")
        return jsonify({"status": "parsed", "root_tag": tag, "dimensions": f"{width}x{height}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/v1/search/regex-filter", methods=["POST"])
def search_regex_filter():
    # Vulnerable: Inefficient Regular Expression Complexity (CWE-1333 / ReDoS)
    # Compiles and matches arbitrary user-provided regex without execution timeout or complexity check
    data = request.get_json(silent=True) or {}
    pattern = data.get("pattern", "")
    target_string = data.get("text", "")
    if not pattern:
        return jsonify({"error": "Pattern required"}), 400
    try:
        import re
        match = re.search(pattern, target_string)
        return jsonify({
            "status": "matched" if match else "no_match",
            "matched_text": match.group(0) if match else None
        }), 200
    except re.error as e:
        return jsonify({"error": f"Invalid regex: {str(e)}"}), 400


@app.route("/api/v1/invoices/download", methods=["GET"])
def download_invoice():
    # Vulnerable: Insecure Direct Object Reference (IDOR / CWE-639 / OWASP API1:2023)
    # Retrieves invoice based solely on query param 'id' without checking current user's ownership
    invoice_id = request.args.get("id", "")
    if not invoice_id:
        return jsonify({"error": "Invoice ID required"}), 400
    mock_invoices = {
        "1001": {"owner": "alice", "amount_due": "$450.00", "billing_address": "123 Maple St"},
        "1002": {"owner": "bob", "amount_due": "$1,200.00", "billing_address": "456 Oak Ave"},
        "1003": {"owner": "charlie", "amount_due": "$89.50", "billing_address": "789 Pine Rd"},
    }
    invoice = mock_invoices.get(str(invoice_id))
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404
    return jsonify({"status": "retrieved", "invoice_id": invoice_id, "data": invoice}), 200


@app.route("/api/v1/templates/render-greeting", methods=["POST"])
def render_greeting_template():
    # Vulnerable: Server-Side Template Injection (SSTI / CWE-1336)
    # Renders user-supplied string template directly using jinja2.Template without sandbox
    data = request.get_json(silent=True) or {}
    template_str = data.get("template", "")
    username = data.get("username", "Guest")
    if not template_str:
        return jsonify({"error": "Template string required"}), 400
    try:
        from jinja2 import Template
        tmpl = Template(template_str)
        rendered = tmpl.render(username=username)
        return jsonify({"status": "rendered", "output": rendered}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS items")
    cursor.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, category TEXT)")
    cursor.execute("INSERT INTO items (name, category) VALUES ('laptop', 'electronics')")
    cursor.execute("INSERT INTO items (name, category) VALUES ('phone', 'electronics')")
    cursor.execute("INSERT INTO items (name, category) VALUES ('desk', 'furniture')")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
