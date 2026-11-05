# HTTP Parameter Pollution (HPP) Defense Specification

## 1. Executive Summary

HTTP Parameter Pollution (CWE-235) occurs when web applications or intermediary reverse proxies process multiple parameters sharing identical names in an inconsistent manner. Attackers exploit parameter precedence differences between web application firewalls (WAFs), reverse proxies, and backend microservices to bypass access controls or alter transaction logic (e.g. injecting `recipient=alice&recipient=attacker` where the WAF inspects the first value while the application executes the second).

---

## 2. Parameter Precedence Matrix

Different HTTP servers and web frameworks exhibit divergent parameter precedence behaviors:

| Web Framework / Engine | Multi-Parameter Parsing Behavior | Risk Scenario |
| :--- | :--- | :--- |
| **Flask / Werkzeug** | `request.args.get('param')` returns first value | WAF checks last, backend takes first |
| **PHP / Apache** | Last value overrides preceding instances | WAF checks first, backend takes last |
| **ASP.NET / IIS** | Concatenates values with comma separator | Type conversion bypasses or logic errors |
| **Express / Node.js** | Converts parameter into an Array `['val1', 'val2']` | Type confusion, crashes or SQL bypass |

---

## 3. Remediation Architecture

The autonomous remediation bot implements three defense-in-depth layers:

1. **Explicit Multiplicity Inspection**:
   Replaces naive `request.args.get(key)` with `request.args.getlist(key)` on financial, authorization, and administrative endpoints.

2. **Automated HppValidator Enforcement**:
   ```python
   is_safe, reason, params = HppValidator.validate_query_string(
       request.query_string.decode('utf-8'),
       allowed_multi_keys=['tags', 'filter']
   )
   if not is_safe:
       abort(400, description=reason)
   ```

3. **Strict Parameter White-Listing**:
   Endpoints specify exact type constraints and disallow unexpected repeated keys in API schemas.
