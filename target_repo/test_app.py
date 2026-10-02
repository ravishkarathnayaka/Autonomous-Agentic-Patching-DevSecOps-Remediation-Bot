"""Functional regression test suite for target_repo application.

These tests verify valid application business logic and must continue passing
both before and after security remediation patches are applied.
"""

import os
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
