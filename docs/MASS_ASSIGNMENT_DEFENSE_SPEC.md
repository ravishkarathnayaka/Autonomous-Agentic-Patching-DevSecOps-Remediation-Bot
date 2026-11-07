# Mass Assignment & Parameter Tampering (CWE-915) Defense Specification

## 1. Threat Profile

Mass Assignment (CWE-915 / OWASP API6:2023) happens when software frameworks automatically bind HTTP request body properties directly into internal database models or domain objects without enforcing strict parameter whitelisting.

Attackers discover or guess internal object properties (such as `is_admin`, `verified`, `role`, `account_balance`, or `tenant_id`) and append them into legitimate requests (e.g. `POST /api/user/profile`), causing the framework to overwrite protected database columns.

---

## 2. Hardening Strategy

### A. Dedicated Data Transfer Objects (DTOs)
Never bind request payloads directly onto ORM models. Maintain explicit DTO schemas (using Pydantic, Marshmallow, or dataclasses) declaring only customer-editable fields:

```python
class UserProfileUpdateDTO(BaseModel):
    display_name: Optional[str] = Field(None, max_length=50)
    bio: Optional[str] = Field(None, max_length=500)
    email: Optional[EmailStr] = None
```

### B. Pre-Update Filtering via `MassAssignmentAuditor`
When working with dynamic dictionaries, invoke `MassAssignmentAuditor.filter_allowed_fields()` to strip unauthorized keys before executing model updates.
