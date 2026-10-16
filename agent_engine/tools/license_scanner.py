"""
Open Source License Compliance and Risk Scanner
Audits package dependencies against software license policies to prevent legal
and commercial compliance risks associated with strong copyleft and unlicensed components.
"""

from typing import Dict, List, Any, Optional
import re


class LicenseRiskScanner:
    """
    Evaluates open source licenses for commercial compatibility and legal risk.
    """

    LICENSE_TIERS = {
        "MIT": "PERMISSIVE",
        "APACHE-2.0": "PERMISSIVE",
        "BSD-2-CLAUSE": "PERMISSIVE",
        "BSD-3-CLAUSE": "PERMISSIVE",
        "ISC": "PERMISSIVE",
        "CC0-1.0": "PERMISSIVE",
        "UNLICENSE": "PERMISSIVE",

        "LGPL-2.1": "WEAK_COPYLEFT",
        "LGPL-3.0": "WEAK_COPYLEFT",
        "MPL-2.0": "WEAK_COPYLEFT",
        "EPL-2.0": "WEAK_COPYLEFT",

        "GPL-2.0": "STRONG_COPYLEFT",
        "GPL-3.0": "STRONG_COPYLEFT",
        "AGPL-3.0": "NETWORK_COPYLEFT",
        "SSPL-1.0": "COMMERCIAL_RESTRICTIVE"
    }

    def __init__(self, policy: Optional[Dict[str, Any]] = None):
        """
        Policy options:
          - allow_permissive: bool (default True)
          - allow_weak_copyleft: bool (default True)
          - allow_strong_copyleft: bool (default False)
          - allow_network_copyleft: bool (default False)
          - banned_licenses: List[str]
        """
        self.policy = policy or {
            "allow_permissive": True,
            "allow_weak_copyleft": True,
            "allow_strong_copyleft": False,
            "allow_network_copyleft": False,
            "banned_licenses": []
        }

    def normalize_license(self, raw_license: str) -> str:
        """Standardize license identifier string."""
        if not raw_license:
            return "UNKNOWN"
        cleaned = raw_license.strip().upper()
        cleaned = re.sub(r"[()\"\']", "", cleaned)
        if "APACHE" in cleaned:
            return "APACHE-2.0"
        if "BSD-3" in cleaned:
            return "BSD-3-CLAUSE"
        if "BSD-2" in cleaned:
            return "BSD-2-CLAUSE"
        if "BSD" in cleaned:
            return "BSD-3-CLAUSE"
        if "MIT" in cleaned:
            return "MIT"
        if "AGPL" in cleaned:
            return "AGPL-3.0"
        if "LGPL-3" in cleaned:
            return "LGPL-3.0"
        if "LGPL-2" in cleaned:
            return "LGPL-2.1"
        if "GPL-3" in cleaned:
            return "GPL-3.0"
        if "GPL-2" in cleaned:
            return "GPL-2.0"
        if "MPL-2" in cleaned:
            return "MPL-2.0"
        return cleaned

    def classify_license(self, license_id: str) -> str:
        """Return license tier category."""
        norm = self.normalize_license(license_id)
        return self.LICENSE_TIERS.get(norm, "UNKNOWN")

    def audit_dependencies(self, dependencies: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Audit a list of packages: [{"name": "requests", "version": "2.31.0", "license": "Apache-2.0"}]
        """
        violations = []
        compliant = []

        banned_set = {b.upper() for b in self.policy.get("banned_licenses", [])}

        for dep in dependencies:
            pkg_name = dep.get("name", "unknown")
            pkg_ver = dep.get("version", "unknown")
            raw_lic = dep.get("license", "UNKNOWN")
            norm_lic = self.normalize_license(raw_lic)
            tier = self.classify_license(norm_lic)

            is_violation = False
            reason = ""

            if norm_lic in banned_set:
                is_violation = True
                reason = f"License {norm_lic} is explicitly banned by policy."
            elif tier == "STRONG_COPYLEFT" and not self.policy.get("allow_strong_copyleft", False):
                is_violation = True
                reason = f"Strong copyleft license {norm_lic} requires source distribution."
            elif tier == "NETWORK_COPYLEFT" and not self.policy.get("allow_network_copyleft", False):
                is_violation = True
                reason = f"Network copyleft license {norm_lic} triggered by SaaS deployment."
            elif tier == "WEAK_COPYLEFT" and not self.policy.get("allow_weak_copyleft", True):
                is_violation = True
                reason = f"Weak copyleft license {norm_lic} disallowed by enterprise configuration."
            elif tier == "UNKNOWN":
                is_violation = True
                reason = f"Unrecognized or missing license {raw_lic}; requires legal review."

            record = {
                "package": pkg_name,
                "version": pkg_ver,
                "license": norm_lic,
                "tier": tier,
                "reason": reason
            }

            if is_violation:
                violations.append(record)
            else:
                compliant.append(record)

        return {
            "passed": len(violations) == 0,
            "total_packages": len(dependencies),
            "compliant_count": len(compliant),
            "violation_count": len(violations),
            "violations": violations,
            "compliant": compliant
        }
