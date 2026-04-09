# Kayan — AI Agent Rules

> **Purpose**: Architectural guardrails for AI agents working on the Kayan codebase. These rules enforce the project's design philosophy and prevent architectural drift.

---

## 1. Core Philosophy (NEVER Violate)

### 1.1 Headless Only
- Kayan is a **library**, not a service. Never add UI code, HTML templates, or frontend assets to this repo.
- Never add HTTP framework dependencies to `core/`. Framework bindings belong in separate repos (`kayan-echo`, `kayan-gin`, etc.).

### 1.2 Non-Generic Architecture
- **Do NOT use Go generics** (type parameters `[T any]`). Kayan uses interfaces + `any` + factory functions.
- Use `any` with type assertions at boundaries, not generic type constraints.
- Factory pattern: `func() any { return &Type{} }` for instantiation.

### 1.3 BYOS (Bring Your Own Schema)
- Never force specific struct fields or table names on user models.
- The **only required interface** for identity models is `FlowIdentity`:
  ```go
  type FlowIdentity interface {
      GetID() any
      SetID(any)
  }
  ```
- Use reflection-based field mapping (`MapFields`) for accessing user-defined fields.
- Optional interfaces (`TraitSource`, `CredentialSource`) are opt-in, never mandatory.

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

## 4. File & Package Conventions

### 4.1 File Naming

| Pattern | Example | Purpose |
|---------|---------|---------|
| `strategy_*.go` | `strategy_password.go` | Auth strategy implementations |
| `*_manager.go` or `manager.go` | `registration.go`, `manager.go` | Manager/orchestrator |
| `*_store.go` or `store.go` | `memory_store.go` | Storage implementations |
| `*_test.go` | `lockout_test.go` | Tests (must match source file) |
| `middleware.go` | `middleware.go` | HTTP middleware |
| `types.go` | `types.go` | Type definitions and constants |
| `checker.go` | `checker.go` | Validation/verification logic |

### 4.2 Package Doc Comments
Every package must have a doc comment in its primary `.go` file with:
- One-line description of purpose
- Subpackage listing (if applicable)
- Usage example in godoc format

### 4.3 New Package Checklist
When adding a new package under `core/`:
1. Create the package directory under `core/`
2. Add a primary file with package doc comment
3. Define interfaces **in the consuming package** (consumer-defined interfaces)
4. Ensure it does not violate dependency rules (Section 2)
5. Add tests (`*_test.go`) — **do not merge untested packages**
6. Update `core/kayan.go` doc comment with the new subpackage
7. Update `docs/architecture/README.md` with the new component

---

## 5. Code Style Rules

### 5.1 Error Handling
- Return `error` as the last return value.
- Use `fmt.Errorf("package: description: %w", err)` wrapping with package prefix.
- Define sentinel errors for cases consumers need to handle:
  ```go
  var ErrMFARequired = errors.New("login: mfa required")
  ```
- Never expose internal error messages to HTTP responses — use generic messages at the handler layer.

### 5.2 Context Usage
- `context.Context` must be the **first parameter** for any function that:
  - Calls external services or databases
  - May need cancellation or timeout
  - Passes through audit/tenant context
- Strategies, managers, and storage methods must accept `context.Context`.

### 5.3 Constructor Pattern
```go
// Required dependencies as positional args
// Optional config via functional options or setters
func NewManager(store Store, resolver Resolver, opts ...ManagerOption) *Manager

// Option type
type ManagerOption func(*Manager)
func WithHooks(hooks Hooks) ManagerOption { ... }
```

### 5.4 Audit Integration
- All `RegistrationManager` and `LoginManager` flows must emit audit events for both success and failure.
- Audit events must include: `Type`, `ActorID`, `Status`, `Message`.
- Audit is **opt-in**: check `if auditStore != nil` before logging (never panic on missing audit).

---

## 6. Testing Rules

### 6.1 Requirements
- Every new strategy, manager, or storage adapter **must** have corresponding `*_test.go` files.
- Use **table-driven tests** for strategies with multiple input scenarios.
- Use **test interfaces** or mocks, never concrete storage in unit tests.
- Tests must run with `go test -race` (no data races).

### 6.2 Test File Location
- Unit tests: same package, `*_test.go` suffix.
- Integration tests: use `//go:build integration` build tag.

---

## 7. Security Rules

### 7.1 Secrets
- Never log passwords, tokens, or hashed secrets.
- Password hashes must use `bcrypt` (default) or `argon2`. Never use MD5, SHA-1, or SHA-256 for password hashing.
- JWT secrets must not be hardcoded. Always accept them via configuration.

### 7.2 OIDC/OAuth
- OIDC state parameters must be **cryptographically random** and validated on callback.
- Always use PKCE (`code_challenge`/`code_verifier`) for OAuth2 authorization code flows.
- Never return raw tokens in API responses meant for production use.

### 7.3 Timing Safety
- Use constant-time comparison (`subtle.ConstantTimeCompare`) for token validation.
- Use the `Hasher.Compare()` interface (which uses bcrypt's constant-time comparison) for passwords.

---

## 8. Architecture Decision Records

| Decision | Rationale |
|----------|-----------|
| Non-generic design | Supports any ID type without compile-time constraints. Trades compile-time safety for universal compatibility. |
| `any`-based interfaces | Enables BYOS — users keep their models, Kayan adapts with reflection. |
| Strategy pattern | Allows mixing auth methods without modifying core logic. New methods = new files, not modified files. |
| Separate adapter repos | `kgorm/` is co-located but self-contained. Future adapters (MongoDB, Redis) follow the same pattern. |
| Consumer-defined interfaces | Interfaces are declared where they're consumed, not where they're implemented. Follows Go best practices. |
| Hook system over inheritance | Pre/post hooks on managers instead of subclassing. Keeps the API surface flat and composable. |

---

## Quick Reference

```
kayan/
├── core/                     # Core library — NO framework deps
│   ├── identity/             # Leaf dep: types only (Identity, Session, Credential, JSON)
│   ├── domain/               # Storage interfaces (IdentityStorage, SessionStorage, etc.)
│   ├── flow/                 # Auth flows: strategies, managers, hooks, rate limiting
│   ├── session/              # Session management: JWT + Database strategies
│   ├── rbac/                 # RBAC engine (standalone, no core deps)
│   ├── rebac/                # ReBAC engine (standalone, no core deps)
│   ├── policy/               # ABAC + Hybrid policy engine (standalone)
│   ├── tenant/               # Multi-tenancy: resolver, manager, scoped store
│   ├── oauth2/               # OAuth2 provider (auth codes, tokens, PKCE)
│   ├── oidc/                 # OIDC provider (discovery, userinfo, ID tokens)
│   ├── saml/                 # SAML 2.0 SP/IdP
│   ├── audit/                # Audit logging (events, store interface)
│   ├── compliance/           # Data retention, encryption
│   ├── telemetry/            # OpenTelemetry, Prometheus
│   ├── config/               # Dynamic configuration
│   ├── consent/              # GDPR/CCPA consent management
│   ├── health/               # Health check utilities
│   └── logger/               # Structured logging
├── kgorm/                    # GORM storage adapter
├── cmd/                      # CLI tools
└── docs/                     # Documentation
```
