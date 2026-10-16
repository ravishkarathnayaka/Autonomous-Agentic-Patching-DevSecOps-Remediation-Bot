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
from flask import Flask, jsonify, request

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
