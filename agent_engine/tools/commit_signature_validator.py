"""Cryptographic git commit and tag signature verification tool for supply chain integrity."""

import subprocess
from typing import Dict, Any, Optional


class CommitSignatureValidator:
    """Verifies GPG, SSH, and X.509 cryptographic signatures on git commits to satisfy SLSA Level 3."""

    @classmethod
    def verify_commit(cls, commit_ref: str = "HEAD", cwd: str = ".") -> Dict[str, Any]:
        """Verify the cryptographic signature of a git commit.

        Args:
            commit_ref: Git commit hash or reference.
            cwd: Working directory of git repository.

        Returns:
            Dict containing `signed: bool`, `status: str`, `signer: Optional[str]`, `key_id: Optional[str]`.
        """
        try:
            # Query git log format %G? (G=Good, B=Bad, U=Good untrusted, X=Expired, Y=Expired key, R=Revoked, E=Missing key, N=None)
            cmd = ["git", "log", "-1", "--format=%G?|%GS|%GK", commit_ref]
            proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

            if proc.returncode != 0:
                return {
                    "signed": False,
                    "status": "ERROR",
                    "signer": None,
                    "key_id": None,
                    "details": proc.stderr.strip() or "Git execution failed"
                }

            out = proc.stdout.strip()
            parts = out.split("|")
            sig_flag = parts[0] if parts else "N"
            signer = parts[1] if len(parts) > 1 and parts[1] else None
            key_id = parts[2] if len(parts) > 2 and parts[2] else None

            flag_map = {
                "G": ("GOOD", True),
                "U": ("UNTRUSTED_KEY", True),
                "B": ("BAD_SIGNATURE", False),
                "X": ("EXPIRED_SIGNATURE", False),
                "Y": ("EXPIRED_KEY", False),
                "R": ("REVOKED_KEY", False),
                "E": ("CANNOT_CHECK", False),
                "N": ("UNSIGNED", False),
            }

            status, is_signed = flag_map.get(sig_flag, ("UNKNOWN", False))

            return {
                "signed": is_signed,
                "status": status,
                "signer": signer,
                "key_id": key_id,
                "commit": commit_ref
            }
        except Exception as e:
            return {
                "signed": False,
                "status": "EXCEPTION",
                "signer": None,
                "key_id": None,
                "details": str(e)
            }
