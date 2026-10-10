"""Automated vulnerable dependency version bumper for requirements.txt and package.json."""

import json
from pathlib import Path
import re
from typing import Optional, Tuple


class DependencyBumper:
    """Safely updates vulnerable package versions in dependency manifest files."""

    @staticmethod
    def bump_requirements_txt(content: str, package_name: str, target_version: str) -> Tuple[str, bool]:
        """
        Updates package_name version specification in requirements.txt.
        Returns (updated_content, modified_boolean).
        """
        escaped_pkg = re.escape(package_name)
        pattern = re.compile(
            rf"^(\s*{escaped_pkg}\s*)(==|>=|<=|~=)(\s*[\w\.\-]+)(.*)$",
            re.IGNORECASE | re.MULTILINE
        )

        match = pattern.search(content)
        if match:
            # Replace with target_version
            replacement = rf"\g<1>=={target_version}\g<4>"
            updated = pattern.sub(replacement, content, count=1)
            return updated, True

        # Check if package is unversioned on a line by itself
        unpinned_pattern = re.compile(
            rf"^(\s*{escaped_pkg}\s*)$",
            re.IGNORECASE | re.MULTILINE
        )
        if unpinned_pattern.search(content):
            updated = unpinned_pattern.sub(rf"{package_name}=={target_version}", content, count=1)
            return updated, True

        return content, False

    @staticmethod
    def bump_package_json(content: str, package_name: str, target_version: str) -> Tuple[str, bool]:
        """
        Updates package_name version in package.json under dependencies or devDependencies.
        Returns (updated_content, modified_boolean).
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return content, False

        modified = False
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            if section in data and isinstance(data[section], dict):
                if package_name in data[section]:
                    data[section][package_name] = f"^{target_version}" if not target_version.startswith("^") else target_version
                    modified = True

        if modified:
            return json.dumps(data, indent=2) + "\n", True
        return content, False
