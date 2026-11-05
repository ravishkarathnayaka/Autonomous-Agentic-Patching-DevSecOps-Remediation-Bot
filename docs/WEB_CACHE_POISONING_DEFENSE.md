# Web Cache Poisoning & Unkeyed Header Defense Guide

## 1. Attack Vectors

Web Cache Poisoning (CWE-444 / CWE-524) occurs when an attacker manipulates unkeyed HTTP request inputs (such as `X-Forwarded-Host`, `X-Forwarded-Scheme`, or `X-Original-URL`) that are reflected in server responses without being included in the cache key.

If an intermediate proxy (e.g. Cloudflare, AWS CloudFront, Fastly, or Varnish) caches this poisoned response, innocent users requesting the normal URL receive the attacker's payload (e.g. injected malicious JavaScript or phishing links).

---

## 2. Hardening Directives

### A. HTTP Cache-Control Standardization
Dynamic, personalized, or authenticated API endpoints must explicitly mandate anti-caching behavior:

```http
Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0
Pragma: no-cache
Expires: 0
```

### B. Vary Header Partitioning
When responses vary based on authentication credentials, language, or compression, downstream caches must partition entries:

```http
Vary: Cookie, Authorization, Accept-Encoding
```

### C. Stripping Dangerous Unkeyed Headers
Reverse proxies and ingress controllers must strip or overwrite unrecognized forwarding headers (`X-Forwarded-Host`, `X-Host`, `X-Rewrite-URL`) before forwarding requests to application microservices.
