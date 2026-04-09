---
trigger: always_on
---

# Kayan Project Context for AI Agents

> **Purpose**: This file provides comprehensive context for AI agents working with the Kayan codebase. Read this first to understand the project's architecture, patterns, and conventions.

---

## Project Identity

**Kayan** is a headless, non-generic, extensible Identity & Access Management (IAM) library for Go.

**Mission**: Provide open-source, developer-experience friendly, enterprise-grade authentication and authorization without forcing schema migrations or UI opinions.

**Philosophy**:
1. **Headless** - No UI, pure APIs
2. **Non-Generic** - Uses interfaces, not Go generics
3. **BYOS** - Bring Your Own Schema (your models, your way)
4. **Strategy Pattern** - Pluggable auth methods
5. **Enterprise Ready** - Multi-tenancy, RBAC, ABAC, compliance

---
## Repository Structure

```
kayan/                    # Core library (main package)
│   ├── core/             # Core packages
│   │   ├── flow/         # Registration, Login managers & strategies
│   │   ├── session/      # Session management (JWT, Database)
│   │   ├── identity/     # Identity types and interfaces
│   │   ├── policy/       # Authorization engines (ABAC)
│   │   ├── rbac/         # Role-based access control
│   │   ├── tenant/       # Multi-tenancy support
│   │   ├── oauth2/       # OAuth2 provider implementation
│   │   ├── oidc/         # OpenID Connect client
│   │   ├── saml/         # SAML 2.0 SP
│   │   ├── audit/        # Audit logging
│   │   ├── compliance/   # Data retention, encryption
│   │   └── telemetry/    # OpenTelemetry, Prometheus
│   ├── kgorm/            # GORM storage adapter
│   ├── cmd/              # CLI tools
│   └── docs/             # Documentation
│       ├── architecture/ # Deep technical docs
│       ├── concepts/     # Concept guides
│       ├── reference/    # API & config reference
│       └── openapi/      # OpenAPI sp
```

## Quick Reference

| Task | Package/Function |
|------|------------------|
| Hash password | `flow.NewBcryptHasher(cost)` |
| Create user | `regManager.Submit(ctx, "password", traits, secret)` |
| Authenticate | `loginManager.Authenticate(ctx, "password", id, secret)` |
| Create session | `sessManager.Create(sessionID, identityID)` |
| Validate session | `sessManager.Validate(token)` |
| Check role | `rbacManager.Authorize(userID, role)` |
| Check attribute | `abacEngine.Can(ctx, user, action, resource)` |
| Check relationship | `rebacManager.Check(ctx, subType, subID, rel, objType, objID)` |
| Grant relation | `rebacManager.Grant(ctx, subType, subID, rel, objType, objID)` |
| Resolve tenant | `tenantManager.Resolve(ctx, request)` |

---
