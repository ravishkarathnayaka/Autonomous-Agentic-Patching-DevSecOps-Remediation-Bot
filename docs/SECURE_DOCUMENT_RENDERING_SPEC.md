# Secure Document & Headless Browser Rendering Specification

## 1. Threat Landscape

Headless rendering utilities (e.g. Puppeteer, Playwright, wkhtmltopdf, pdfkit, Chromium headless) convert HTML templates, CSS, and SVG graphics into downloadable PDF documents or images. These conversion engines run full browser rendering contexts, exposing applications to critical risks:

- **SSRF via Network Fetching (CWE-918)**: `<img src="http://169.254.169.254/latest/meta-data/">` extracts AWS/GCP cloud credentials.
- **Local File Reading (CWE-59 / CWE-22)**: `<iframe src="file:///etc/passwd">` embeds sensitive server secrets directly into client-rendered PDFs.
- **JavaScript Execution Abuse**: Malicious scripts executing inside headless instances consume CPU or steal session cookies.

---

## 2. Hardening Standards

### A. Network Isolation & URL Pre-Validation
Before any document renderer receives an external URL or resource link, `PdfUriAllowlistValidator` verifies:
- Protocol scheme is strictly `https:` or `http:`.
- Target host is not `localhost`, loopback `127.0.0.1`, link-local `169.254.169.254`, or RFC 1918 private subnets.

### B. Headless Flag Hardening
When spawning headless Chromium / rendering processes, pass mandatory security flags:
```bash
--disable-gpu
--disable-dev-shm-usage
--no-sandbox (only inside unprivileged container namespaces)
--disable-web-security=false
--disable-local-file-access
--disable-extensions
--allow-file-access-from-files=false
```

### C. Resource Timing Budgets
All rendering jobs must execute with strict execution timeouts (e.g. 5 seconds) to prevent infinite loops or rendering-based denial of service.
