"""Security validator for verifying symbolic link resolution and canonical boundaries."""

import os
from typing import Tuple


class SymlinkSecurityValidator:
    """Validates filesystem paths against unauthorized symbolic link traversal (CWE-59)."""

    @classmethod
    def is_safe_path(cls, base_dir: str, target_subpath: str, allow_symlinks: bool = False) -> Tuple[bool, str]:
        """Verify whether a target subpath resolves strictly within base_dir.

        Args:
            base_dir: Designated root directory.
            target_subpath: Relative user-supplied filename or path.
            allow_symlinks: Whether internal symlinks pointing within base_dir are permitted.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not target_subpath or not target_subpath.strip():
            return False, "Target subpath is empty."

        clean_sub = target_subpath.strip()

        # Reject absolute paths or Windows drive prefixes
        if os.path.isabs(clean_sub) or clean_sub.startswith(("/", "\\")) or (len(clean_sub) > 1 and clean_sub[1] == ":"):
            return False, "Absolute path not permitted."

        canonical_base = os.path.realpath(os.path.abspath(base_dir))
        full_unresolved = os.path.abspath(os.path.join(canonical_base, clean_sub))

        # Check if the path or any existing parent is a symbolic link when symlinks are prohibited
        if not allow_symlinks and os.path.islink(full_unresolved):
            return False, f"Path '{clean_sub}' is a symbolic link, which is disallowed."

        canonical_target = os.path.realpath(full_unresolved)

        try:
            common = os.path.commonpath([canonical_base, canonical_target])
        except ValueError:
            return False, "Target path resides on a different filesystem drive."

        if common != canonical_base:
            return False, f"Symlink traversal detected: '{clean_sub}' escapes base directory '{base_dir}'."

        return True, "Safe path within designated boundary."
