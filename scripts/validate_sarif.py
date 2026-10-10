"""Validator utility for checking SARIF 2.1.0 schema conformance."""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def validate_sarif_file(file_path: Path) -> Tuple[bool, List[str]]:
    """Validate SARIF JSON file for key OASIS 2.1.0 schema requirements."""
    errors: List[str] = []

    if not file_path.is_file():
        return False, [f"File not found: {file_path}"]

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]

    if not isinstance(data, dict):
        return False, ["Root SARIF element must be a JSON object."]

    # 1. Version check
    if data.get("version") != "2.1.0":
        errors.append(f"Expected SARIF version '2.1.0', got '{data.get('version')}'.")

    # 2. Runs array check
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) == 0:
        errors.append("SARIF document must contain a non-empty 'runs' array.")
    else:
        for idx, run in enumerate(runs):
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            if not driver.get("name"):
                errors.append(f"Run [{idx}] tool driver is missing required 'name' field.")

            results = run.get("results", [])
            if not isinstance(results, list):
                errors.append(f"Run [{idx}] results must be a list.")
            else:
                for r_idx, result in enumerate(results):
                    if not result.get("ruleId"):
                        errors.append(f"Run [{idx}] Result [{r_idx}] is missing required 'ruleId'.")
                    if not result.get("message", {}).get("text"):
                        errors.append(f"Run [{idx}] Result [{r_idx}] is missing required 'message.text'.")

    return len(errors) == 0, errors


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python validate_sarif.py <path_to_sarif_file>")
        sys.exit(1)
    valid, errs = validate_sarif_file(Path(sys.argv[1]))
    if valid:
        print("[✓] SARIF file is valid 2.1.0 schema.")
    else:
        print("[!] Validation errors:\n" + "\n".join(errs))
        sys.exit(1)
