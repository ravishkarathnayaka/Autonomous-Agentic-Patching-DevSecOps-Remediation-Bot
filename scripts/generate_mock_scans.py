"""Synthetic multi-scanner report generator for offline testing and CI simulations."""

import json
from pathlib import Path
from typing import Dict, Any


def generate_all_mock_reports(output_dir: Path) -> Dict[str, Path]:
    """Generate mock scan reports for various security scanners in output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    created: Dict[str, Path] = {}

    # 1. Semgrep SAST
    semgrep_data = {
        "results": [
            {
                "check_id": "rules.python.sqli",
                "path": "target_repo/app.py",
                "start": {"line": 25, "col": 5},
                "end": {"line": 25, "col": 55},
                "extra": {
                    "message": "Potential SQL Injection via f-string.",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"], "cvss": 8.8},
                    "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
                }
            }
        ]
    }
    p = output_dir / "mock_semgrep.json"
    p.write_text(json.dumps(semgrep_data, indent=2), encoding="utf-8")
    created["semgrep"] = p

    # 2. Trivy SCA
    trivy_data = {
        "Results": [
            {
                "Target": "target_repo/requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.1",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Title": "Proxy-Authorization header leak",
                        "Description": "Requests leaked Proxy-Authorization header upon HTTP redirect.",
                        "CweIDs": ["CWE-200"],
                        "CVSS": {"nvd": {"V3Score": 6.1}}
                    }
                ]
            }
        ]
    }
    p = output_dir / "mock_trivy.json"
    p.write_text(json.dumps(trivy_data, indent=2), encoding="utf-8")
    created["trivy"] = p

    # 3. Gitleaks Secrets
    gitleaks_data = [
        {
            "Description": "Generic API Key",
            "RuleID": "generic-api-key",
            "File": "target_repo/app.py",
            "StartLine": 12,
            "EndLine": 12,
            "Secret": "sk_live_1234567890abcdef",
            "Match": "API_KEY = 'sk_live_1234567890abcdef'"
        }
    ]
    p = output_dir / "mock_gitleaks.json"
    p.write_text(json.dumps(gitleaks_data, indent=2), encoding="utf-8")
    created["gitleaks"] = p

    return created


if __name__ == "__main__":
    out = Path("./tests/fixtures/generated")
    res = generate_all_mock_reports(out)
    print(f"Generated {len(res)} synthetic reports in {out}")
