# Cross-Site Request Forgery (CSRF) Defense-in-Depth Architecture

## 1. Threat Overview

Cross-Site Request Forgery (CWE-352) allows malicious websites to trick an authenticated user's browser into executing unauthorized state-changing operations against a target application. When sessions rely purely on ambient credentials (HTTP cookies), the browser implicitly includes session cookies in cross-origin requests.

---

## 2. Multi-Layered Remediation Framework

```
┌────────────────────────────────────────────────────────┐
│ State-Changing Request (POST, PUT, DELETE, PATCH)      │
└───────────────────────────┬────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
┌───────────────────────────┐┌───────────────────────────┐
│ Synchronizer Token Pattern││ SameSite Cookie Policy    │
│ - Cryptographic CSRF token││ - SameSite='Lax' / Strict │
│ - Verified in header/body ││ - Blocks cross-site cookie│
└─────────────┬─────────────┘└─────────────┬─────────────┘
              │                            │
              └─────────────┬──────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│ Origin & Referer Verification                          │
│ - Enforces request origin matches host domain          │
└────────────────────────────────────────────────────────┘
```

---

## 3. Implementation Patterns

1. **Header Verification**:
   Modern Single-Page Applications (SPAs) should pass the Anti-CSRF token in the `X-CSRF-Token` header, matching an encrypted double-submit cookie.

2. **Bearer Token Architecture**:
   Decoupling session authorization from ambient cookies into `Authorization: Bearer <token>` headers renders applications fundamentally immune to browser-driven CSRF attacks.
