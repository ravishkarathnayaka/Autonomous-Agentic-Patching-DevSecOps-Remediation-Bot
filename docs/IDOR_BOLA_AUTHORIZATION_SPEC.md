# Insecure Direct Object References (IDOR/BOLA) Authorization Specification

## 1. Context and Problem Statement

Broken Object Level Authorization (OWASP API Top 10 API1:2023 / CWE-639) occurs when an endpoint accepts user-supplied identifiers (e.g. `GET /api/invoices/1042` or `POST /documents/delete?id=55`) and executes business logic without verifying that the requesting session owns or has authorized access to that specific entity.

Attackers manipulate IDs sequentially or enumerate UUIDs to view, modify, or delete sensitive data belonging to arbitrary tenants.

---

## 2. Server-Side Enforcement Architecture

### A. Context-Driven Ownership Assertion
Every object query must join or filter on the authenticated user ID / tenant ID directly at the persistence layer, rather than querying solely by primary key:

```python
# Unsafe:
invoice = Invoice.query.filter_by(id=invoice_id).first()

# Safe:
current_user_id = session.get("user_id")
invoice = Invoice.query.filter_by(id=invoice_id, owner_id=current_user_id).first()
if not invoice:
    abort(404)  # Prevent enumeration by returning 404 rather than revealing existence via 403
```

### B. Decoupled Validator Integration
For complex multi-tenant workflows or role escalations, the `IdorAccessValidator` tool evaluates permissions:

```python
authorized, reason = IdorAccessValidator.can_access_record(
    user_context=g.current_user,
    record=target_record,
    owner_field="created_by",
    tenant_field="organization_id",
)
if not authorized:
    logger.warning("IDOR attempt intercepted: %s", reason)
    abort(403)
```
