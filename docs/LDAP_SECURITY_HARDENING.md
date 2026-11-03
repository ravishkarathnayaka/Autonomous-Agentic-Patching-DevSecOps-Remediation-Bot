# LDAP Injection Defense & Directory Service Hardening Specification

## 1. Vulnerability Analysis

LDAP Injection (CWE-90) occurs when untrusted user input is concatenated into an LDAP query filter without proper neutralization of special syntax characters defined in RFC 4515. Attackers can manipulate query semantics to bypass authentication checks or enumerate sensitive directory attributes (e.g. Active Directory passwords, group memberships).

---

## 2. RFC 4515 Character Encoding Reference

To prevent filter breakout, user inputs placed inside LDAP assertion values must be escaped into their corresponding 2-digit hexadecimal representations:

| Reserved Character | Hex Escape | Attack Vector Mitigated |
| :---: | :---: | :--- |
| `\` | `\5c` | Escape prefix breakout |
| `*` | `\2a` | Wildcard search expansion |
| `(` | `\28` | Assertion group open breakout |
| `)` | `\29` | Assertion group close breakout |
| `\0` (NULL) | `\00` | C-string termination truncation |

---

## 3. Autonomous Patching Strategy

The `LdapSanitizerAgent` and `LdapFilterValidator` identify dynamic string concatenations inside LDAP search invocations and wrap user parameters with RFC 4515 compliant sanitization functions before query execution.
