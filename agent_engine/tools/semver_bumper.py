"""Semantic Versioning (SemVer 2.0.0) analyzer and safe upgrade path calculator."""

import re
from typing import Any, Dict, Optional, Tuple


class SemVerBumper:
    """Parses and computes semantic version increments, evaluating breaking-change risks for automated patching."""

    SEMVER_REGEX = re.compile(
        r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
        r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+(?P<buildmetadata>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
    )

    @classmethod
    def parse_version(cls, version_str: str) -> Optional[Tuple[int, int, int]]:
        """Parse version string into (major, minor, patch) integer tuple."""
        clean = version_str.strip().lstrip("vV")
        match = cls.SEMVER_REGEX.match(clean)
        if not match:
            # Fallback for 2-part versions like '2.3'
            parts = clean.split(".")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                return int(parts[0]), int(parts[1]), 0
            return None
        return int(match.group("major")), int(match.group("minor")), int(match.group("patch"))

    @classmethod
    def compare(cls, v1: str, v2: str) -> int:
        """Compare two SemVer strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        t1 = cls.parse_version(v1) or (0, 0, 0)
        t2 = cls.parse_version(v2) or (0, 0, 0)
        if t1 < t2:
            return -1
        elif t1 > t2:
            return 1
        return 0

    @classmethod
    def evaluate_upgrade_risk(cls, current_version: str, target_version: str) -> Dict[str, Any]:
        """Assess the risk profile of bumping a dependency from current to target version.

        Args:
            current_version: Currently installed version.
            target_version: Patched target version.

        Returns:
            Dict containing `is_breaking: bool`, `upgrade_tier: str`, `safe_to_autopatch: bool`, `reason: str`.
        """
        c = cls.parse_version(current_version)
        t = cls.parse_version(target_version)

        if not c or not t:
            return {
                "is_breaking": True,
                "upgrade_tier": "UNKNOWN",
                "safe_to_autopatch": False,
                "reason": "Non-standard version format. Manual review required."
            }

        c_major, c_minor, c_patch = c
        t_major, t_minor, t_patch = t

        if t_major > c_major:
            return {
                "is_breaking": True,
                "upgrade_tier": "MAJOR",
                "safe_to_autopatch": False,
                "reason": f"Major version bump ({c_major} -> {t_major}) carries breaking API risk."
            }
        elif t_minor > c_minor:
            return {
                "is_breaking": False,
                "upgrade_tier": "MINOR",
                "safe_to_autopatch": True,
                "reason": f"Minor version bump ({c_major}.{c_minor} -> {t_major}.{t_minor}) adds backwards-compatible features."
            }
        elif t_patch > c_patch:
            return {
                "is_breaking": False,
                "upgrade_tier": "PATCH",
                "safe_to_autopatch": True,
                "reason": f"Patch bump ({current_version} -> {target_version}) contains backwards-compatible bug and security fixes."
            }
        else:
            return {
                "is_breaking": False,
                "upgrade_tier": "NONE",
                "safe_to_autopatch": False,
                "reason": f"Target version {target_version} is not newer than current {current_version}."
            }
