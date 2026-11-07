# Server-Side Template Injection (SSTI - CWE-1336) Defense-in-Depth Specification

## 1. Problem Definition

Server-Side Template Injection (CWE-1336 / CWE-94) happens when applications concatenate user-provided strings directly into template engine compilation contexts (such as Jinja2, Mako, Thymeleaf, or Twig) rather than passing data into fixed template variables.

Attackers exploit template expression syntax (e.g. `{{ ''.__class__.__mro__[1].__subclasses__() }}`) to traverse the runtime Python object tree and invoke `os.system` or `subprocess.Popen`.

---

## 2. Hardening Architecture

### A. Separation of Template Code and User Data
Templates must never be dynamically constructed from untrusted string concatenation:
```python
# Vulnerable:
tmpl = Template(f"<h1>Welcome {user_input}</h1>")

# Secure:
tmpl = env.get_template("welcome.html")
rendered = tmpl.render(username=user_input)
```

### B. Sandboxed Environment Enforcement
When user-defined templates are an explicit functional feature (e.g., custom notification formatting), wrap execution inside `jinja2.sandbox.SandboxedEnvironment`:
- Intercepts attribute lookups and raises `SecurityError` on dunder attributes (`__`).
- Enforces `autoescape=True` to prevent Cross-Site Scripting (XSS).
- Overrides `is_safe_attribute` to enforce strict property allowlisting.
