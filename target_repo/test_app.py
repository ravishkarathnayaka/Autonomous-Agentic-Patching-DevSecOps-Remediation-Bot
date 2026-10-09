"""Functional regression test suite for target_repo application.

These tests verify valid application business logic and must continue passing
both before and after security remediation patches are applied.
"""

import base64
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
