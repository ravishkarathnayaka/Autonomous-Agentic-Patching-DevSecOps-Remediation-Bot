#!/usr/bin/env python3
"""Development environment bootstrap and preflight check script."""

import os
import shutil
import subprocess
import sys


def print_status(msg: str, ok: bool) -> None:
    symbol = "[\033[92mOK\033[0m]" if ok else "[\033[91mFAIL\033[0m]"
    print(f"{symbol} {msg}")


def check_python_version() -> bool:
    v = sys.version_info
    ok = v.major == 3 and v.minor >= 11
    print_status(f"Python version >= 3.11 (Detected: {v.major}.{v.minor}.{v.micro})", ok)
    return ok


def check_docker() -> bool:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        print_status("Docker CLI executable found in PATH", False)
        return False

    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        ok = res.returncode == 0
        print_status("Docker daemon responsive and accessible", ok)
        return ok
    except Exception:
        print_status("Docker daemon responsive and accessible", False)
        return False


def check_git() -> bool:
    git_bin = shutil.which("git")
    ok = git_bin is not None
    print_status("Git CLI executable found in PATH", ok)
    return ok


def check_ollama() -> bool:
    try:
        import urllib.request
        req = urllib.request.urlopen("http://localhost:11434/api/version", timeout=2)
        ok = req.status == 200
        print_status("Local Ollama service active at http://localhost:11434 (Optional)", ok)
        return True
    except Exception:
        print("[\033[93mINFO\033[0m] Ollama not running locally (Mock provider will be used for $0 testing).")
        return False


def main() -> None:
    print("=" * 65)
    print("  DEVSECOPS REMEDIATION BOT - ENVIRONMENT PREFLIGHT CHECK")
    print("=" * 65)

    py_ok = check_python_version()
    git_ok = check_git()
    docker_ok = check_docker()
    check_ollama()

    print("-" * 65)
    if py_ok and git_ok:
        print("\033[92mEnvironment meets core requirements!\033[0m")
        if not docker_ok:
            print("Note: Docker is optional; sandbox will fall back to process isolation mode.")
    else:
        print("\033[91mPlease install missing prerequisites before proceeding.\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
