# Structured Logging Hygiene & Log Injection Prevention Guide

## 1. Threat Definition

Log Injection / Log Forgery (CWE-117) occurs when an application writes untrusted user input directly into audit log streams or SIEM collectors without removing line feed (`\n`) and carriage return (`\r`) delimiters. An adversary can inject fabricated log lines to:
- Conceal unauthorized malicious activities.
- Forge admin authorization entries to mislead forensic investigators.
- Exploit log parsers (e.g. Log4Shell / terminal ANSI escape command execution).

---

## 2. Defensive Engineering Standards

### Rule 1: Eliminate Carriage Return & Line Feed Delimiters
All string arguments bound to logging calls must be sanitized by replacing `\r` and `\n` with spaces or underscores.

### Rule 2: Structured JSON Logging
Applications must avoid unformatted string formatting (`logger.info(f"User {user} logged in")`). Instead, use structured key-value parameters:
```python
logger.info("user_authenticated", extra={"user": clean_username, "ip": remote_ip})
```

### Rule 3: Strip ANSI Terminal Escapes
Adversaries frequently inject ANSI escape sequences (e.g. `\x1b[2J\x1b[H`) to clear terminal displays or alter log viewer output. The `LogSanitizerValidator` automatically strips these sequences.
