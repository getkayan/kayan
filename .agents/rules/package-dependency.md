---
trigger: always_on
---

## 2. Package Dependency Rules

### 2.1 Dependency Direction (Strictly Enforced)

```
core/domain     ← Depends on: core/identity, core/audit ONLY
core/identity   ← Depends on: stdlib ONLY (zero internal deps)
core/flow       ← Depends on: core/domain, core/identity, core/audit
core/session    ← Depends on: core/domain, core/identity
core/rbac       ← Depends on: stdlib ONLY (zero internal deps)
core/rebac      ← Depends on: stdlib ONLY (zero internal deps)
core/policy     ← Depends on: stdlib ONLY (zero internal deps)
core/tenant     ← Depends on: stdlib ONLY (zero internal deps)
core/audit      ← Depends on: stdlib ONLY (zero internal deps)
core/oauth2     ← Depends on: core/identity
core/oidc       ← Depends on: core/identity
core/saml       ← Depends on: core/identity
kgorm/          ← Depends on: core/domain, core/identity, core/audit (GORM adapter)
```

### 2.2 Forbidden Dependencies
- `core/` packages must **never** import `kgorm/` or any storage adapter.
- `core/identity` must **never** import other `core/` packages — it is the leaf dependency.
- `core/rbac`, `core/rebac`, `core/policy`, `core/tenant` must **never** import `core/flow` or `core/session`.
- No package may import `core/flow` except through its exported interfaces.

### 2.3 External Dependency Policy
- `core/identity`: **Zero external deps** — stdlib only.
- `core/flow`, `core/session`: Minimal deps (`golang-jwt`, `x/crypto`, `google/uuid`).
- New external dependencies in `core/` require justification. Prefer stdlib solutions.
- Database drivers and ORM dependencies belong in adapter packages (`kgorm/`), never in `core/`.

