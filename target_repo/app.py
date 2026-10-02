"""Sample vulnerable target application for DevSecOps automated remediation bot testing.

Contains intentional security vulnerabilities:
1. CWE-89: SQL Injection (/items)
2. CWE-22: Path Traversal (/files)
3. CWE-78: Command Injection (/ping)
"""

import os
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
