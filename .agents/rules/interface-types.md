---
trigger: always_on
---


## 3. Interface & Type Contracts

### 3.1 Strategy Pattern
All pluggable behaviors must follow the strategy pattern:

| Domain | Interface | Methods |
|--------|-----------|---------|
| Registration | `RegistrationStrategy` | `ID() string`, `Register(ctx, traits, secret) (any, error)` |
| Login | `LoginStrategy` | `ID() string`, `Authenticate(ctx, identifier, secret) (any, error)` |
| Session | `session.Strategy` | `Create()`, `Validate()`, `Refresh()`, `Delete()` |
| Authorization | `policy.Engine` | `Can(ctx, subject, action, resource) (bool, error)` |
| Tenant Resolution | `tenant.Resolver` | `Resolve(ctx, *http.Request) (string, error)` |

- Every new auth method **must** implement `RegistrationStrategy` and/or `LoginStrategy`.
- Every new authorization model **must** implement `policy.Engine`.
- Strategy ID strings must be lowercase, alphanumeric with underscores (e.g., `"password"`, `"magic_link"`, `"webauthn"`).

### 3.2 Manager Pattern
Managers orchestrate strategies and provide hooks:

- Managers own the strategy map and lifecycle hooks (`PreHook`, `PostHook`).
- Managers must be **thread-safe**: use `sync.RWMutex` for strategy registration and lookup.
- Managers delegate to strategies — they never implement auth logic directly.

### 3.3 Storage Interfaces
- `domain.Storage` is the composite interface. Adapters implement sub-interfaces:
  - `IdentityStorage` — identity CRUD + credential access
  - `SessionStorage` — session lifecycle
  - `CredentialStorage` — credential lookup
  - `TokenStore` — token persistence
  - `audit.AuditStore` — audit event persistence
- Storage methods use `any` for models and `func() any` factories for instantiation.
- Never return concrete types from storage interfaces — always `any` or interface types.

---
