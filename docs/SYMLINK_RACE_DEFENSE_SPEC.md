# Symbolic Link Traversal & TOCTOU Race Condition Defense Specification

## 1. Executive Summary

Improper Link Resolution (CWE-59) occurs when software attempts to access a file in a restricted directory without verifying whether the target is a symbolic link pointing to a sensitive file outside the trust boundary (e.g., `/etc/shadow` or `.ssh/id_rsa`). Combined with Time-of-Check to Time-of-Use (TOCTOU) race conditions, attackers can swap files with symlinks between permission validation and reading/writing.

---

## 2. Secure Filesystem Resolution Pipeline

```
┌────────────────────────────────────────────────────────┐
│ User Path Input (e.g. filename: "reports/q3.csv")      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ SymlinkSecurityValidator (symlink_validator.py)        │
│ 1. Canonicalize base directory: realpath(base_dir)     │
│ 2. Canonicalize full path: realpath(base_dir + sub)    │
│ 3. Check os.path.commonpath([base, target]) == base    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Atomic Open Flags                                      │
│ - POSIX O_NOFOLLOW: fails if the final path component  │
│   is a symbolic link.                                  │
│ - tempfile.NamedTemporaryFile: guarantees atomic O_EXCL│
└────────────────────────────────────────────────────────┘
```

---

## 3. Defense Patterns

1. **Strict Canonical Realpath Checking**:
   Ensure `os.path.commonpath([base_dir, resolved_path]) == base_dir`.
2. **Rejection of Unintended Symlinks**:
   When opening files in user-controlled storage directories, verify `not os.path.islink(path)`.
3. **Atomic File Descriptors**:
   Where supported, pass `os.O_NOFOLLOW` to `os.open` to eliminate TOCTOU symlink swap windows.
