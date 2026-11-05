# SVG XML External Entity (XXE) & Stored XSS Hardening Guide

## 1. Threat Profile

Scalable Vector Graphics (SVG) files are XML documents by specification. Because they permit XML Document Type Definitions (DTDs) and embedded scripts, parsing untrusted SVG uploads exposes applications to high-impact vulnerabilities:

- **XML External Entity (CWE-611)**: Local file reading (`file:///etc/passwd`, `/proc/self/environ`), internal port scanning (SSRF), and Billion Laughs denial of service.
- **Stored Cross-Site Scripting (CWE-79)**: Inline `<script>` tags, event handlers (`onload`, `onerror`), and `<foreignObject>` payloads executed when viewing images directly in the browser.

---

## 2. Hardening Strategy

### A. Safe XML Parsing with defusedxml
Standard libraries like `xml.etree.ElementTree` or `lxml` must never parse untrusted user input without entity restrictions:

```python
import defusedxml.ElementTree as DefusedET

try:
    # forbid_dtd and forbid_entities prevent external resolution & expansion
    tree = DefusedET.fromstring(svg_bytes, forbid_dtd=True, forbid_entities=True)
except Exception as err:
    raise SecurityException(f"Malicious or malformed SVG structure: {err}")
```

### B. Pre-Ingestion Heuristic Auditing
Applications invoke `SvgSecurityAuditor.audit_svg(raw_content)` before saving files to object storage (S3/GCS) or rendering pipelines.

### C. Content-Disposition & Content Security Policy (CSP)
- Serve user-uploaded SVG avatars with `Content-Disposition: attachment; filename="avatar.svg"`.
- If inline SVG rendering is necessary, enforce `script-src 'none'; object-src 'none'`.
