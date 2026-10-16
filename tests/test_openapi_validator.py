"""
Unit tests for OpenAPISecurityValidator.
"""

import pytest
from agent_engine.tools.openapi_validator import OpenAPISecurityValidator


def test_openapi_validator_secure_v3():
    spec = """
    openapi: "3.0.3"
    info:
      title: Secure API
      version: "1.0.0"
    servers:
      - url: https://api.enterprise.com/v1
    components:
      securitySchemes:
        bearerAuth:
          type: http
          scheme: bearer
    security:
      - bearerAuth: []
    paths:
      /users:
        get:
          summary: List users
        post:
          summary: Create user
    """
    validator = OpenAPISecurityValidator.from_string(spec)
    result = validator.validate()

    assert result["version"] == "3.0.3"
    assert result["passed"] is True
    assert result["security_schemes_count"] == 1
    assert result["unsecured_routes_count"] == 0
    assert len(result["critical_findings"]) == 0


def test_openapi_validator_unprotected_mutating_route():
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Flawed API", "version": "1.0.0"},
        "components": {
            "securitySchemes": {
                "ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}
            }
        },
        "paths": {
            "/public/health": {
                "get": {"summary": "Health check"}
            },
            "/admin/reset": {
                "post": {
                    "summary": "Reset database",
                    "security": []  # Explicitly unauthenticated override
                }
            }
        }
    }
    validator = OpenAPISecurityValidator(spec)
    result = validator.validate()

    assert result["passed"] is False
    assert result["unsecured_routes_count"] >= 1
    mutation_findings = [f for f in result["critical_findings"] if f["rule"] == "SEC003-UNPROTECTED-MUTATION"]
    assert len(mutation_findings) == 1
    assert "POST /admin/reset" in mutation_findings[0]["message"]


def test_openapi_validator_no_schemes():
    spec = {
        "swagger": "2.0",
        "info": {"title": "Legacy Swagger", "version": "1.0"},
        "schemes": ["http"],
        "paths": {
            "/data": {
                "post": {"summary": "Upload"}
            }
        }
    }
    validator = OpenAPISecurityValidator(spec)
    result = validator.validate()

    assert result["passed"] is False
    rules = [f["rule"] for f in result["critical_findings"]]
    assert "SEC001-NO-SCHEMES" in rules
    assert "SEC002-PLAINTEXT-TRANSPORT" in rules
