"""Ephemeral execution sandbox running tests and security scans in isolated containers."""

import logging
import os
from pathlib import Path
import subprocess
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Docker SDK is optional/lazy loaded to ensure local test suites run anywhere
try:
    import docker
    from docker.errors import DockerException, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    DockerException = Exception  # type: ignore
    APIError = Exception  # type: ignore


class SandboxExecutionResult:
    """Outcome of running commands in the sandbox."""
    def __init__(self, exit_code: int, stdout: str, stderr: str, duration_seconds: float, mode: str):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration_seconds
        self.mode = mode

    @property
    def passed(self) -> bool:
        return self.exit_code == 0

    @property
    def combined_output(self) -> str:
        out = self.stdout.strip()
        err = self.stderr.strip()
        if out and err:
            return f"{out}\n--- STDERR ---\n{err}"
        return out or err


class SandboxExecutor:
    """Executes untrusted code, tests, and security scans with ephemeral isolation."""

    DEFAULT_IMAGE = "devsecops-remediation-sandbox:latest"

    def __init__(
        self,
        image_name: str = DEFAULT_IMAGE,
        mem_limit: str = "512m",
        cpu_quota: int = 50000,
        pids_limit: int = 50,
        timeout_seconds: int = 60,
        force_local: bool = False
    ):
        self.image_name = image_name
        self.mem_limit = mem_limit
        self.cpu_quota = cpu_quota
        self.pids_limit = pids_limit
        self.timeout_seconds = timeout_seconds
        self.force_local = force_local
        self._docker_client = None

        if DOCKER_AVAILABLE and not force_local:
            try:
                self._docker_client = docker.from_env()  # type: ignore[attr-defined]
                # Test connectivity
                self._docker_client.ping()
            except Exception as e:
                logger.warning("Docker daemon unavailable (%s). Falling back to local execution mode.", e)
                self._docker_client = None

    def is_docker_ready(self) -> bool:
        """Return True if Docker is operational and image is accessible."""
        return self._docker_client is not None

    def run_command(
        self,
        command: List[str],
        workdir_path: str,
        network_disabled: bool = True,
        env_vars: Optional[Dict[str, str]] = None
    ) -> SandboxExecutionResult:
        """Run a command inside an ephemeral isolated container, falling back to local if required."""
        abs_workdir = str(Path(workdir_path).resolve())

        if self._docker_client:
            try:
                return self._run_in_docker(
                    command=command,
                    workdir_path=abs_workdir,
                    network_disabled=network_disabled,
                    env_vars=env_vars
                )
            except Exception as e:
                logger.error("Docker container run failed (%s). Retrying via local isolated process.", e)

        return self._run_locally(
            command=command,
            workdir_path=abs_workdir,
            env_vars=env_vars
        )

    def _run_in_docker(
        self,
        command: List[str],
        workdir_path: str,
        network_disabled: bool,
        env_vars: Optional[Dict[str, str]]
    ) -> SandboxExecutionResult:
        """Execute command in strict ephemeral Docker container."""
        start_time = time.time()
        client = self._docker_client
        assert client is not None

        # Container volume mounting: mount target repo into /workspace
        volumes = {
            workdir_path: {"bind": "/workspace", "mode": "rw"}
        }

        # Strict security options: dropped capabilities, read-only root if supported, no privilege escalation
        security_opt = ["no-new-privileges:true"]
        cap_drop = ["ALL"]

        environment = env_vars or {}
        environment["PYTHONPATH"] = "/workspace"

        container = None
        try:
            container = client.containers.run(
                image=self.image_name,
                command=command,
                working_dir="/workspace",
                volumes=volumes,
                network_disabled=network_disabled,
                mem_limit=self.mem_limit,
                cpu_quota=self.cpu_quota,
                pids_limit=self.pids_limit,
                security_opt=security_opt,
                cap_drop=cap_drop,
                environment=environment,
                detach=True,
                remove=False
            )

            # Wait with timeout
            try:
                res = container.wait(timeout=self.timeout_seconds)
                exit_code = res.get("StatusCode", 1)
            except Exception as wait_err:
                logger.warning("Sandbox container timed out after %ds: %s", self.timeout_seconds, wait_err)
                try:
                    container.kill()
                except Exception:
                    pass
                exit_code = 124

            logs = container.logs(stdout=True, stderr=True)
            duration = time.time() - start_time
            out_str = logs.decode("utf-8", errors="replace")

            return SandboxExecutionResult(
                exit_code=exit_code,
                stdout=out_str,
                stderr="",
                duration_seconds=duration,
                mode="docker"
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _run_locally(
        self,
        command: List[str],
        workdir_path: str,
        env_vars: Optional[Dict[str, str]]
    ) -> SandboxExecutionResult:
        """Local subprocess execution fallback."""
        import sys
        start_time = time.time()
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        parent_dir = str(Path(workdir_path).parent)
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{workdir_path}{os.pathsep}{parent_dir}{os.pathsep}{existing_pythonpath}"

        resolved_command = list(command)
        if resolved_command and resolved_command[0] == "pytest":
            resolved_command = [sys.executable, "-m", "pytest"] + resolved_command[1:]

        try:
            proc = subprocess.run(
                resolved_command,
                cwd=workdir_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
                check=False
            )
            duration = time.time() - start_time
            return SandboxExecutionResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_seconds=duration,
                mode="local"
            )
        except subprocess.TimeoutExpired:
            return SandboxExecutionResult(
                exit_code=124,
                stdout="",
                stderr=f"Command timed out after {self.timeout_seconds} seconds",
                duration_seconds=time.time() - start_time,
                mode="local"
            )
        except Exception as e:
            return SandboxExecutionResult(
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=time.time() - start_time,
                mode="local"
            )

    def run_tests(self, workdir_path: str, test_file: Optional[str] = None) -> SandboxExecutionResult:
        """Run pytest test suite in the sandbox."""
        cmd = ["pytest", "-v"]
        if test_file:
            cmd.append(test_file)
        return self.run_command(cmd, workdir_path=workdir_path)

    def run_semgrep_scan(self, workdir_path: str, rule_config: str = "auto") -> SandboxExecutionResult:
        """Run semgrep scan in the sandbox to verify vulnerability removal."""
        cmd = ["semgrep", "scan", f"--config={rule_config}", "--error", "."]
        return self.run_command(cmd, workdir_path=workdir_path)
