"""
OpenAPI / Swagger Security Specification Validator
Validates OpenAPI 3.x and Swagger 2.0 schemas against REST API security best practices,
detecting unsecured endpoints, missing authentication schemes, plaintext HTTP schemes,
and missing authorization constraints on mutating routes.
"""

from typing import Dict, List, Any, Optional
import json
import yaml


class OpenAPISecurityValidator:
    """
    Evaluates OpenAPI 2.0 (Swagger) and OpenAPI 3.0/3.1 specs for critical security controls.
    """

    def __init__(self, spec_data: Dict[str, Any]):
        self.spec = spec_data
        self.version = self._detect_version()

    @classmethod
    def from_string(cls, content: str) -> "OpenAPISecurityValidator":
        """Instantiate validator from raw JSON or YAML text."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("OpenAPI specification must be a dictionary or mapping.")
        return cls(data)

    def _detect_version(self) -> str:
        if "openapi" in self.spec:
            return str(self.spec["openapi"])
        if "swagger" in self.spec:
            return str(self.spec["swagger"])
        return "unknown"

    def get_security_schemes(self) -> Dict[str, Any]:
        """Extract declared authentication / security schemes."""
        if self.version.startswith("3."):
            components = self.spec.get("components", {})
            return components.get("securitySchemes", {})
        elif self.version.startswith("2."):
            return self.spec.get("securityDefinitions", {})
        return {}

    def get_global_security(self) -> List[Dict[str, List[str]]]:
        """Extract global security requirement definitions."""
        return self.spec.get("security", [])

    def validate(self) -> Dict[str, Any]:
        """
        Run comprehensive security analysis on the OpenAPI specification.
        Returns a dictionary summarizing findings, unsecured routes, and overall compliance.
        """
        findings = []
        warnings = []
        unsecured_routes = []

        schemes = self.get_security_schemes()
        global_security = self.get_global_security()

        # Check 1: Security Schemes Defined
        if not schemes:
            findings.append({
                "rule": "SEC001-NO-SCHEMES",
                "severity": "CRITICAL",
                "message": "No security schemes or definitions declared in the specification."
            })

        # Check 2: Transport Layer Security (HTTPS)
        if self.version.startswith("2."):
            declared_schemes = self.spec.get("schemes", [])
            if declared_schemes and "https" not in declared_schemes:
                findings.append({
                    "rule": "SEC002-PLAINTEXT-TRANSPORT",
                    "severity": "HIGH",
                    "message": "Swagger spec explicitly allows plaintext HTTP transport."
                })
        elif self.version.startswith("3."):
            servers = self.spec.get("servers", [])
            for server in servers:
                url = server.get("url", "")
                if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                    warnings.append({
                        "rule": "SEC002-PLAINTEXT-TRANSPORT",
                        "severity": "MEDIUM",
                        "message": f"Server URL uses unencrypted HTTP: {url}"
                    })

        # Check 3: Route Authorization Audit
        paths = self.spec.get("paths", {})
        mutating_methods = {"post", "put", "patch", "delete"}

        for path_name, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                # An operation has security if defined at operation level or inherited globally
                # If operation defines security: [], it explicitly overrides global security to none
                has_op_security = "security" in operation
                op_sec = operation.get("security", None)

                effective_sec = op_sec if has_op_security else global_security

                if not effective_sec:
                    route_id = f"{method.upper()} {path_name}"
                    unsecured_routes.append(route_id)
                    if method.lower() in mutating_methods:
                        findings.append({
                            "rule": "SEC003-UNPROTECTED-MUTATION",
                            "severity": "HIGH",
                            "message": f"Mutating endpoint {route_id} does not require authentication."
                        })
                    else:
                        warnings.append({
                            "rule": "SEC004-UNPROTECTED-QUERY",
                            "severity": "LOW",
                            "message": f"Endpoint {route_id} allows unauthenticated access."
                        })

        passed = len([f for f in findings if f["severity"] in {"CRITICAL", "HIGH"}]) == 0

        return {
            "version": self.version,
            "passed": passed,
            "security_schemes_count": len(schemes),
            "unsecured_routes_count": len(unsecured_routes),
            "unsecured_routes": unsecured_routes,
            "critical_findings": findings,
            "warnings": warnings,
            "total_issues": len(findings) + len(warnings)
        }
