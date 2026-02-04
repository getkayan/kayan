# Kayan Project Context for AI Agents

> **Purpose**: This file provides comprehensive context for AI agents working with the Kayan codebase. Read this first to understand the project's architecture, patterns, and conventions.

---

## Project Identity

**Kayan** is a headless, non-generic, extensible Identity & Access Management (IAM) library for Go.

**Mission**: Provide enterprise-grade authentication and authorization without forcing schema migrations or UI opinions.

**Philosophy**:
1. **Headless** - No UI, pure APIs
2. **Non-Generic** - Uses interfaces, not Go generics
3. **BYOS** - Bring Your Own Schema (your models, your way)
4. **Strategy Pattern** - Pluggable auth methods
5. **Enterprise Ready** - Multi-tenancy, RBAC, ABAC, compliance

---

## Repository Structure

```
kayan-workspace/
├── kayan/                    # Core library (main package)
│   ├── core/                 # Core packages
│   │   ├── flow/             # Registration, Login managers & strategies
│   │   ├── session/          # Session management (JWT, Database)
│   │   ├── identity/         # Identity types and interfaces
│   │   ├── policy/           # Authorization engines (ABAC)
│   │   ├── rbac/             # Role-based access control
│   │   ├── tenant/           # Multi-tenancy support
│   │   ├── oauth2/           # OAuth2 provider implementation
│   │   ├── oidc/             # OpenID Connect client
│   │   ├── saml/             # SAML 2.0 SP
│   │   ├── audit/            # Audit logging
│   │   ├── compliance/       # Data retention, encryption
│   │   └── telemetry/        # OpenTelemetry, Prometheus
│   ├── kgorm/                # GORM storage adapter
│   ├── cmd/                  # CLI tools
│   └── docs/                 # Documentation
│       ├── architecture/     # Deep technical docs
│       ├── concepts/         # Concept guides
│       ├── reference/        # API & config reference
│       └── openapi/          # OpenAPI spec
│
├── kayan-echo/               # Echo framework integration
│   └── handler.go            # HTTP handlers for Echo
│
├── kayan-js/                 # TypeScript SDK
│   ├── src/
│   │   ├── client.ts         # Simple client wrapper
│   │   ├── generated/        # Auto-generated from OpenAPI
│   │   └── types.ts          # TypeScript types
│   └── package.json
│
├── kayan-console/            # Admin UI (Next.js)
│   ├── app/                  # Next.js app router
│   └── components/           # React components
│
└── kayan-examples/           # 23+ runnable examples
    ├── byos_schema/          # Field mapping example
    ├── webauthn_passkeys/    # Passkey auth
    ├── multi_tenancy/        # Tenant isolation
    ├── rbac_basic/           # Role-based access
    ├── abac_policy/          # Attribute-based access
    └── ...
```

---

## Core Concepts

### 1. BYOS (Bring Your Own Schema)

Users keep their existing database models. Kayan adapts via:
- **Field mapping**: `pwStrategy.MapFields([]string{"Email"}, "PasswordHash")`
- **Factory functions**: `func() any { return &MyUser{} }`
- **Minimal interface**: Only `GetID()` and `SetID(any)` required

```go
// User's existing model - NO changes required
type User struct {
    ID           uuid.UUID `gorm:"primaryKey"`
    Email        string    `gorm:"uniqueIndex"`
    PasswordHash string
}

// Only interface needed
func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(uuid.UUID) }
```

### 2. Strategy Pattern

All auth methods are pluggable strategies:

```go
// Registration strategies
regManager.RegisterStrategy(passwordStrategy)
regManager.RegisterStrategy(magicLinkStrategy)

// Login strategies  
loginManager.RegisterStrategy(passwordStrategy)
loginManager.RegisterStrategy(oidcStrategy)
loginManager.RegisterStrategy(webauthnStrategy)

// Use by name
regManager.Submit(ctx, "password", traits, secret)
loginManager.Authenticate(ctx, "webauthn", identifier, "")
```

### 3. Session Strategies

Two primary modes:
- **JWT (stateless)**: Token contains claims, no DB lookup
- **Database (stateful)**: Token is ID, requires DB lookup, revocable

### 4. Hook System

Pre/post hooks for extensibility:

```go
regManager.AddPostHook(func(ctx context.Context, ident any) error {
    user := ident.(*User)
    return sendWelcomeEmail(user.Email)
})
```

### 5. Multi-Tenancy

Tenant resolution from requests → Per-tenant settings → Scoped queries

---

## Key Interfaces

```go
// Required for all identity models
type FlowIdentity interface {
    GetID() any
    SetID(any)
}

// Storage abstraction
type IdentityRepository interface {
    CreateIdentity(identity any) error
    GetIdentity(factory func() any, id any) (any, error)
    FindIdentity(factory func() any, query map[string]any) (any, error)
    UpdateIdentity(identity any) error
    DeleteIdentity(id any) error
}

// Auth strategies
type RegistrationStrategy interface {
    ID() string
    Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}

type LoginStrategy interface {
    ID() string
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}

// Session strategies
type SessionStrategy interface {
    Create(sessionID, identityID string) (*Session, error)
    Validate(token string) (*Session, error)
    Delete(token string) error
}

// Policy engines
type Engine interface {
    Can(ctx context.Context, subject any, action string, resource any) (bool, error)
}
```

---

## Common Patterns

### Initialization Pattern

```go
// 1. Database
db, _ := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
repo := kgorm.NewRepository(db)

// 2. Factory (creates empty instances for DB scanning)
factory := func() any { return &User{} }

// 3. Managers
regManager := flow.NewRegistrationManager(repo, factory)
loginManager := flow.NewLoginManager(repo)

// 4. Strategies
hasher := flow.NewBcryptHasher(10)
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "", factory)
pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
pwStrategy.SetIDGenerator(func() any { return uuid.New().String() })

// 5. Register strategies
regManager.RegisterStrategy(pwStrategy)
loginManager.RegisterStrategy(pwStrategy)

// 6. Sessions
sessManager := session.NewManager(session.NewHS256Strategy(secret, 24*time.Hour))
```

### HTTP Handler Pattern (Echo)

```go
e.POST("/register", func(c echo.Context) error {
    var req RegisterRequest
    c.Bind(&req)
    
    traits := identity.JSON(fmt.Sprintf(`{"Email":"%s"}`, req.Email))
    ident, err := regManager.Submit(c.Request().Context(), "password", traits, req.Password)
    if err != nil {
        return c.JSON(400, map[string]string{"error": err.Error()})
    }
    
    return c.JSON(201, ident)
})
```

### Auth Middleware Pattern

```go
func AuthMiddleware(sessManager *session.Manager) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            token := c.Request().Header.Get("Authorization")
            token = strings.TrimPrefix(token, "Bearer ")
            
            sess, err := sessManager.Validate(token)
            if err != nil {
                return c.JSON(401, map[string]string{"error": "Unauthorized"})
            }
            
            c.Set("session", sess)
            c.Set("user_id", sess.IdentityID)
            return next(c)
        }
    }
}
```

---

## File Naming Conventions

| Pattern | Example | Purpose |
|---------|---------|---------|
| `*_strategy.go` | `password_strategy.go` | Auth strategy impl |
| `*_manager.go` | `registration_manager.go` | Manager orchestration |
| `*_store.go` | `session_store.go` | Storage implementation |
| `*_test.go` | `password_test.go` | Unit tests |
| `handler.go` | `handler.go` | HTTP handlers |
| `middleware.go` | `middleware.go` | HTTP middleware |

---

## Code Style

- **Errors**: Return `error` as last return value, check with `if err != nil`
- **Context**: First parameter for functions that may need cancellation
- **Interfaces**: Define in the package that uses them (consumer-defined)
- **Factories**: Use `func() any` for generic instantiation
- **Field access**: Use reflection for BYOS field mapping
- **Logging**: Structured logging with key-value pairs

---

## Testing

Examples are the primary test suite. Each example in `kayan-examples/` is:
- Self-contained (`main.go` + `go.mod`)
- Uses local SQLite (auto-deleted)
- Demonstrates one feature pattern

Run examples:
```bash
cd kayan-examples/byos_schema
go run main.go
```

---

## Dependencies

**Core**: Standard library + minimal deps
- `golang.org/x/crypto` - bcrypt
- `github.com/golang-jwt/jwt/v5` - JWT handling

**Storage** (kgorm):
- `gorm.io/gorm` - ORM

**OIDC/OAuth2**:
- `github.com/coreos/go-oidc/v3` - OIDC client
- `golang.org/x/oauth2` - OAuth2

**WebAuthn**:
- `github.com/go-webauthn/webauthn` - FIDO2/WebAuthn

---

## Important Notes for AI Agents

1. **BYOS is key**: Users don't change their models, Kayan adapts
2. **Non-generic**: Don't suggest generic type parameters
3. **Strategy ID**: String identifies strategy (`"password"`, `"oidc"`, `"webauthn"`)
4. **Factory pattern**: `func() any { return &Type{} }` for creating instances
5. **Field mapping**: Reflection-based, not compile-time
6. **Examples first**: Check `kayan-examples/` for patterns
7. **No UI**: Kayan is headless, `kayan-console` is separate

---

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

## ReBAC (Relationship-Based Access Control)

ReBAC provides fine-grained authorization based on relationships:

```go
// Create ReBAC manager with in-memory store
store := rebac.NewMemoryStore()
manager := rebac.NewManager(store)

// Grant a relationship
manager.Grant(ctx, "user", "alice", "viewer", "document", "readme")

// Check permission
allowed, _ := manager.Check(ctx, "user", "alice", "viewer", "document", "readme")

// Group membership
manager.AddToGroup(ctx, "alice", "engineering")
manager.GrantUserset(ctx, "group", "engineering", "member", "viewer", "document", "specs")

// Hierarchical resources (folder → document inheritance)
manager.SetParent(ctx, "folder", "home", "document", "readme")
```

For computed relations (owner→editor→viewer), define schemas:

```go
schema := rebac.Schema{
    Type: "document",
    Relations: map[string]rebac.RelationConfig{
        "viewer": {
            DirectAllowed: true,
            ComputedFrom: []rebac.ComputedRule{
                {Relation: "editor"}, // editors are also viewers
            },
        },
    },
}
manager := rebac.NewManager(store, rebac.WithSchema(schema))
```

See `rebac_basic` and `rebac_google_drive` examples for complete usage.

---

## Links

- [Architecture Overview](./docs/architecture/README.md)
- [Security Model](./docs/architecture/security-model.md)
- [OpenAPI Spec](./docs/openapi/openapi.yaml)
- [Examples](../kayan-examples/README.md)

