"""Functional regression test suite for target_repo application.

These tests verify valid application business logic and must continue passing
both before and after security remediation patches are applied.
"""

import base64
import io
import os
import pickle
import pytest
try:
    from target_repo.app import app, init_db
except ImportError:
    from app import app, init_db


@pytest.fixture(autouse=True)
def setup_database():
    """Ensure database has fixture records prior to test execution."""
    init_db()


@pytest.fixture
def client():
    """Create test client for the Flask app."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_search_valid(client):
    """Verify that querying existing items returns correct 200 JSON response."""
    resp = client.get("/items?name=laptop")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["name"] == "laptop"
    assert data[0]["category"] == "electronics"


def test_file_view_valid(client):
    """Verify reading legitimate files within safe_files returns 200 with content."""
    resp = client.get("/files?filename=welcome.txt")
    assert resp.status_code == 200
    assert b"Welcome to the sample target repository" in resp.data


def test_ping_valid(client):
    """Verify that pinging localhost succeeds."""
    resp = client.get("/ping?host=127.0.0.1")
    assert resp.status_code == 200
    assert any(term in resp.data.lower() for term in [b"ttl", b"bytes", b"packets", b"received", b"reply", b"loss"])


def test_load_session_valid(client):
    """Verify loading legitimate base64 session payload returns 200."""
    payload = base64.b64encode(pickle.dumps({"user": "alice"})).decode("utf-8")
    resp = client.post("/session/load", data={"payload": payload})
    assert resp.status_code == 200
    assert resp.get_json()["session_user"] == "alice"


def test_hash_password_valid(client):
    """Verify password hashing endpoint returns hash digest."""
    resp = client.post("/user/hash_password", data={"password": "SecretPassword123"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "hash" in data
    assert len(data["hash"]) > 0


def test_search_html_valid(client):
    """Verify that searching renders html with query term."""
    resp = client.get("/search?q=laptop")
    assert resp.status_code == 200
    assert b"Search Results for: laptop" in resp.data


def test_fetch_url_missing_param(client):
    """Verify that requesting fetch-url without url returns 400."""
    resp = client.post("/fetch-url", json={})
    assert resp.status_code == 400


def test_redirect_default(client):
    """Verify default redirect targets root."""
    resp = client.get("/redirect")
    assert resp.status_code == 302
    assert "/" in resp.headers.get("Location", "")


def test_parse_xml_valid(client):
    """Verify standard XML snippet parses successfully."""
    xml_payload = b"<inventory><item id='1'>laptop</item></inventory>"
    resp = client.post("/parse-xml", data=xml_payload, content_type="application/xml")
    assert resp.status_code == 200
    assert resp.get_json()["root_tag"] == "inventory"


def test_verify_token_valid(client):
    """Verify bearer authentication with internal secret."""
    headers = {"Authorization": "Bearer sk_live_99a88b77cc66dd55ee44"}
    resp = client.post("/verify-token", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["authenticated"] is True


def test_user_data_cors(client):
    """Verify user data endpoint returns account information."""
    resp = client.get("/api/user-data")
    assert resp.status_code == 200
    assert resp.get_json()["account_id"] == "ACC-1029"
    assert "Access-Control-Allow-Origin" in resp.headers


def test_check_headers(client):
    """Verify headers endpoint returns sensitive payload."""
    resp = client.get("/api/headers")
    assert resp.status_code == 200
    assert resp.get_json()["sensitive"] is True


def test_generate_token(client):
    """Verify pseudo-random token generation endpoint returns 32-char hex string."""
    resp = client.get("/generate-token")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["token"]) == 32
    assert data["algorithm"] == "pseudo-random"


def test_extract_archive(client):
    """Verify archive extraction endpoint extracts relative path targets."""
    payload = {"files": ["document.pdf", "image.png", "../../etc/passwd"]}
    resp = client.post("/extract-archive", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["extracted_count"] == 3
    assert len(data["targets"]) == 3


def test_validate_hmac_valid(client):
    """Verify HMAC endpoint accepts matching signature."""
    resp = client.post("/validate-hmac", json={"signature": "8f4e2a1b9c3d7e5f6a0b"})
    assert resp.status_code == 200
    assert resp.get_json()["valid"] is True


def test_validate_hmac_invalid(client):
    """Verify HMAC endpoint rejects invalid signature."""
    resp = client.post("/validate-hmac", json={"signature": "invalid_sig"})
    assert resp.status_code == 403
    assert resp.get_json()["valid"] is False


def test_login_session_cookie(client):
    """Verify login session endpoint sets session cookie."""
    resp = client.post("/login-session", json={"username": "alice"})
    assert resp.status_code == 200
    assert resp.get_json()["user"] == "alice"
    assert "Set-Cookie" in resp.headers
    assert "session_token" in resp.headers["Set-Cookie"]


def test_validate_regex_valid(client):
    """Verify regex validation endpoint matches alphanumeric string."""
    resp = client.post("/validate-regex", json={"text": "validUser123"})
    assert resp.status_code == 200
    assert resp.get_json()["matched"] is True


def test_batch_process(client):
    """Verify batch process endpoint executes item transformation."""
    resp = client.post("/batch-process", json={"items": ["a", "b", "c"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 3
    assert "item_0" in data["processed"]


def test_telemetry_stream(client):
    """Verify telemetry stream endpoint returns telemetry metadata."""
    resp = client.get("/telemetry-stream", headers={"X-API-Key": "my-secret-key"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["telemetry"] == "active"
    assert data["key"] == "my-secret-key"


def test_debug_query_error_leak(client):
    """Verify debug query error response returns detailed database error structure."""
    resp = client.post("/debug-query", json={"table": "nonexistent_table_xyz"})
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert "db_path" in data


def test_eval_expression_valid(client):
    """Verify eval-expression calculates mathematical expression."""
    resp = client.post("/eval-expression", json={"expr": "10 * 5"})
    assert resp.status_code == 200
    assert resp.get_json()["result"] == 50


def test_upload_profile_image_valid(client):
    """Verify upload profile image endpoint stores file and returns 201."""
    data = {
        "file": (io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."), "avatar.png")
    }
    resp = client.post("/upload-profile-image", data=data, content_type="multipart/form-data")
    assert resp.status_code == 201
    res_data = resp.get_json()
    assert res_data["status"] == "uploaded"
    assert res_data["filename"] == "avatar.png"


def test_upload_profile_image_missing_file(client):
    """Verify upload profile image endpoint returns 400 when no file is provided."""
    resp = client.post("/upload-profile-image", data={})
    assert resp.status_code == 400


def test_render_template_valid(client):
    """Verify render template endpoint processes valid template string."""
    resp = client.post("/render-template", json={"name": "Alice"})
    assert resp.status_code == 200
    assert "Hello Alice!" in resp.get_json()["rendered"]







def test_get_document_valid(client):
    """Verify document retrieval returns document data for existing ID."""
    resp = client.get("/api/documents/101")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == 101
    assert "title" in resp.get_json()


def test_get_document_not_found(client):
    """Verify document retrieval returns 404 for unknown ID."""
    resp = client.get("/api/documents/999")
    assert resp.status_code == 404


def test_account_summary_cors(client):
    """Verify account summary endpoint returns account data with CORS origin reflection."""
    resp = client.get("/api/account-summary", headers={"Origin": "https://trusted-portal.internal"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "account_number" in data
    assert "balance_usd" in data
    assert resp.headers.get("Access-Control-Allow-Origin") == "https://trusted-portal.internal"


def test_ldap_lookup_valid_user(client):
    """Verify ldap lookup returns user details for existing user."""
    resp = client.post("/user/ldap-lookup", json={"username": "alice"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user"]["cn"] == "Alice Smith"
    assert "(&(objectClass=user)" in data["filter"]


def test_ldap_lookup_not_found(client):
    """Verify ldap lookup returns 404 for nonexistent user."""
    resp = client.post("/user/ldap-lookup", json={"username": "nonexistent"})
    assert resp.status_code == 404


def test_update_profile_valid(client):
    """Verify update profile endpoint updates benign profile fields."""
    resp = client.post("/user/update-profile", json={"email": "alice_updated@corp.internal"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "profile_updated"
    assert data["user"]["email"] == "alice_updated@corp.internal"
    assert data["user"]["username"] == "developer1"


def test_query_xml_valid(client):
    """Verify query-xml endpoint retrieves user details for existing username."""
    resp = client.post("/query-xml", json={"username": "admin"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user"]["role"] == "superuser"
    assert "admin" in data["xpath"]


def test_query_xml_not_found(client):
    """Verify query-xml returns 404 for unknown username."""
    resp = client.post("/query-xml", json={"username": "unknown_user"})
    assert resp.status_code == 404


def test_load_yaml_config_valid(client):
    """Verify load-yaml-config correctly parses valid YAML structure."""
    yaml_payload = "app_name: devsecops-demo\nmax_connections: 50\n"
    resp = client.post("/load-yaml-config", data=yaml_payload, content_type="application/x-yaml")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "config_loaded"
    assert data["config"]["app_name"] == "devsecops-demo"
    assert data["config"]["max_connections"] == 50


def test_load_yaml_config_empty(client):
    """Verify load-yaml-config returns 400 for empty payload."""
    resp = client.post("/load-yaml-config", data="", content_type="application/x-yaml")
    assert resp.status_code == 400


def test_check_dns_localhost(client):
    """Verify check-dns endpoint resolves localhost."""
    resp = client.post("/check-dns", json={"host": "localhost"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["resolved"] is True
    assert data["host"] == "localhost"
    assert data["ip"] in ["127.0.0.1", "::1"]


def test_check_dns_missing_host(client):
    """Verify check-dns returns 400 when host is empty."""
    resp = client.post("/check-dns", json={})
    assert resp.status_code == 400


def test_toggle_maintenance_authorized(client):
    """Verify toggle maintenance endpoint allows admin update."""
    resp = client.post(
        "/admin/toggle-maintenance",
        headers={"X-Client-Is-Admin": "true"},
        json={"maintenance_mode": True}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "updated"
    assert data["maintenance_mode"] is True


def test_toggle_maintenance_forbidden(client):
    """Verify toggle maintenance endpoint blocks unauthorized callers."""
    resp = client.post("/admin/toggle-maintenance", json={"maintenance_mode": True})
    assert resp.status_code == 403


def test_generate_report_temp_valid(client):
    """Verify generate-report-temp writes temporary report and returns 201."""
    resp = client.post("/generate-report-temp", json={"title": "Q3 Incident Log"})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "generated"
    assert "report_q3_incident_log.txt" in data["path"]
    assert os.path.exists(data["path"])


def test_preview_mako_template_valid(client):
    """Verify preview template endpoint renders template with context."""
    resp = client.post(
        "/api/v1/preview/mako-template",
        json={"template": "Welcome {{user}}!", "context": {"user": "Alice"}}
    )
    assert resp.status_code == 200
    assert resp.get_json()["rendered"] == "Welcome Alice!"


def test_config_deep_merge_valid(client):
    """Verify deep merge endpoint combines dictionary configuration."""
    resp = client.post(
        "/api/v1/config/deep-merge",
        json={"features": {"metrics": True, "tracing": False}, "cluster": "us-east-1"}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "merged"
    assert data["config"]["features"]["metrics"] is True
    assert data["config"]["features"]["telemetry"] is True
    assert data["config"]["cluster"] == "us-east-1"


def test_write_audit_log_valid(client):
    """Verify write audit log endpoint appends entry and returns 201."""
    resp = client.post(
        "/api/v1/auth/audit-log",
        json={"username": "bob_smith", "action": "view_dashboard"}
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "logged"
    assert "user='bob_smith'" in data["entry"]


def test_directory_ldap_search_valid(client):
    """Verify ldap search endpoint returns matching user and filter string."""
    resp = client.post("/api/v1/directory/ldap-search", json={"query": "charlie"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert "sAMAccountName=charlie" in data["filter_executed"]
    assert len(data["results"]) == 1


def test_directory_ldap_search_empty(client):
    """Verify ldap search endpoint returns 400 when query is omitted."""
    resp = client.post("/api/v1/directory/ldap-search", json={})
    assert resp.status_code == 400


def test_crypto_derive_key_valid(client):
    """Verify key derivation endpoint generates hex-encoded derived key."""
    resp = client.post("/api/v1/crypto/derive-key", json={"password": "MySuperSecretPassword!"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "derived"
    assert len(data["key_hex"]) == 64
    assert data["algorithm"] == "PBKDF2-HMAC-SHA256"


def test_crypto_derive_key_missing_password(client):
    """Verify key derivation returns 400 when password is omitted."""
    resp = client.post("/api/v1/crypto/derive-key", json={})
    assert resp.status_code == 400


def test_read_storage_symlink_valid(client):
    """Verify read-symlink endpoint reads safe file in storage."""
    resp = client.post("/api/v1/storage/read-symlink", json={"filename": "welcome.txt"})
    assert resp.status_code == 200
    assert "Welcome to the sample target repository" in resp.get_json()["content"]


def test_read_storage_symlink_missing_filename(client):
    """Verify read-symlink returns 400 when filename is omitted."""
    resp = client.post("/api/v1/storage/read-symlink", json={})
    assert resp.status_code == 400
