"""Security validator for archive member path traversal and Zip Slip vulnerabilities."""

import os
from typing import List, Tuple


class ZipSlipValidator:
    """Validates archive member filenames against path traversal (CWE-22 / CWE-29)."""

    @classmethod
    def is_safe_member_path(cls, member_name: str, target_dir: str) -> Tuple[bool, str]:
        """Verify whether an archive member path safely resolves inside the target directory.

        Args:
            member_name: Filename or entry path stored in archive (zip, tar).
            target_dir: Base directory where archive is to be extracted.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not member_name or not member_name.strip():
            return False, "Empty archive member name."

        name = member_name.strip()

        # Reject absolute paths, leading slashes, or Windows drive letters
        if os.path.isabs(name) or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
            return False, f"Archive member has absolute or drive-relative path: {name}"

        # Normalize and resolve realpaths
        base_dir = os.path.realpath(os.path.abspath(target_dir))
        resolved_path = os.path.realpath(os.path.abspath(os.path.join(base_dir, name)))

        try:
            common = os.path.commonpath([base_dir, resolved_path])
        except ValueError:
            # Different drives on Windows
            return False, f"Archive member path resides on different filesystem drive."

        if common != base_dir:
            return False, f"Zip Slip traversal detected: '{name}' escapes destination root '{target_dir}'."

        return True, "Safe archive member path."

    @classmethod
    def find_unsafe_members(cls, member_names: List[str], target_dir: str) -> List[str]:
        """Filter a list of member paths to identify any unsafe entries.

        Args:
            member_names: Collection of archive filenames.
            target_dir: Base destination directory.

        Returns:
            List of member names that violate path traversal rules.
        """
        unsafe = []
        for name in member_names:
            is_safe, _ = cls.is_safe_member_path(name, target_dir)
            if not is_safe:
                unsafe.append(name)
        return unsafe
