"""Security inspector for analyzing Python serialized pickle payloads against CWE-502."""

import pickletools
from io import BytesIO
from typing import List, Set, Tuple


class PickleSafetyInspector:
    """Inspects pickle byte streams for dangerous opcodes and code execution primitives (CWE-502)."""

    DANGEROUS_OPCODES = {"GLOBAL", "STACK_GLOBAL", "INST", "OBJ", "REDUCE", "BUILD"}
    DANGEROUS_MODULES = {
        "os", "posix", "nt", "subprocess", "sys", "builtins", "__builtin__",
        "commands", "socket", "pty", "shlex", "importlib",
    }
    DANGEROUS_CALLABLES = {
        "system", "popen", "spawn", "exec", "eval", "call", "check_call",
        "run", "Popen", "__import__", "getattr", "open",
    }

    @classmethod
    def inspect_bytes(cls, payload_bytes: bytes) -> Tuple[bool, List[str]]:
        """Inspect pickle byte stream using pickletools opcode disassembler.

        Args:
            payload_bytes: Raw binary payload.

        Returns:
            Tuple of (is_safe: bool, list_of_violations: List[str]).
        """
        violations: List[str] = []

        if not payload_bytes:
            return False, ["Payload byte stream is empty."]

        try:
            # Disassemble pickle opcode instructions safely without executing them
            for opcode, arg, pos in pickletools.genops(BytesIO(payload_bytes)):
                op_name = opcode.name

                if op_name in cls.DANGEROUS_OPCODES:
                    if arg and isinstance(arg, str):
                        parts = arg.split(" ")
                        module = parts[0] if parts else ""
                        func = parts[1] if len(parts) > 1 else ""

                        if module in cls.DANGEROUS_MODULES or func in cls.DANGEROUS_CALLABLES:
                            violations.append(
                                f"Disallowed executable import '{arg}' at position {pos} (CWE-502 / RCE hazard)."
                            )
                        elif op_name in {"GLOBAL", "STACK_GLOBAL", "REDUCE"}:
                            violations.append(
                                f"Dangerous opcode '{op_name}' referencing '{arg}' at position {pos}."
                            )
                    else:
                        violations.append(f"Dangerous opcode '{op_name}' detected at position {pos}.")
        except Exception as e:
            violations.append(f"Malformed or truncated pickle stream: {str(e)}")

        is_safe = len(violations) == 0
        return is_safe, violations
