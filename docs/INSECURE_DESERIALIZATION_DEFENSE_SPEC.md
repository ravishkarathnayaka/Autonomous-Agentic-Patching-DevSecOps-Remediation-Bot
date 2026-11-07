# Insecure Deserialization (CWE-502) Defense Specification

## 1. Executive Summary

Insecure Deserialization (CWE-502) occurs when untrusted or user-supplied byte streams are passed directly to object serialization frameworks (such as Python's `pickle`, `marshal`, or `shelve`, Java's `ObjectInputStream`, or PHP's `unserialize()`). Attackers craft gadget chains using magic methods (e.g. `__reduce__` in Python or `readObject` in Java) to execute arbitrary shell commands or gain remote shell access during object instantiation.

---

## 2. Threat Mechanisms

### Python Pickle Opcode Execution
Python's `pickle` format is not a pure data serialization protocol; it is a stack-based virtual machine:
- Opcodes like `GLOBAL` or `STACK_GLOBAL` import arbitrary modules (`os`, `subprocess`).
- The `REDUCE` opcode calls imported callables with arguments on the stack.
- Consequently, executing `pickle.loads(untrusted_bytes)` without cryptographic verification leads directly to Remote Code Execution (RCE).

---

## 3. Defense-in-Depth Architecture

1. **Format Migration (Preferred)**:
   Migrate from native binary serialization to structured, type-safe data formats such as JSON, Protocol Buffers (protobuf), or MessagePack without custom object deserialization hooks.

2. **Pre-flight Opcode Analysis via `PickleSafetyInspector`**:
   Before attempting to process pickle streams, inspect byte streams with `pickletools.genops()` to ensure no `GLOBAL`, `REDUCE`, or `BUILD` opcodes exist.

3. **HMAC Signing for State Integrity**:
   When serialized session objects must be transported across client-server boundaries, sign payloads using HMAC-SHA256 with an ephemeral server secret:
   ```python
   expected_sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
   if not hmac.compare_digest(received_sig, expected_sig):
       abort(403, "Tampered session payload")
   ```
