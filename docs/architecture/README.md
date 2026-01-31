# Kayan Architecture Overview

Kayan is a headless, non-generic, extensible Identity & Access Management (IAM) library for Go. This document describes the core architecture and design decisions.

---

## Design Philosophy

### 1. Headless First
Kayan provides no UI. It exposes pure Go APIs and optional HTTP handlers that you wire into your framework of choice (Echo, Gin, Chi, stdlib).

### 2. Non-Generic Architecture
Unlike many Go libraries, Kayan does **not** use Go generics. Instead, it uses:
- **Interfaces** for contracts (`FlowIdentity`, `Repository`)
- **Factory functions** for instantiation (`func() any { return &MyUser{} }`)
- **Type assertions** at boundaries

This enables any ID type (UUID, int64, string, snowflake) without compile-time constraints.

### 3. Bring Your Own Schema (BYOS)
Your database schema is yours. Kayan adapts to your models through:
- **Field mapping** (reflection-based trait/secret extraction)
- **Optional interfaces** (implement only what you need)

### 4. Strategy Pattern
All authentication methods (password, OIDC, WebAuthn, SAML) are pluggable strategies implementing common interfaces.

---

## Core Packages

```
github.com/getkayan/kayan/
├── core/
│   ├── flow/          # Registration, Login, Strategies
│   ├── session/       # Session management (JWT, Database)
│   ├── identity/      # Identity types and interfaces
│   ├── policy/        # Authorization engines (RBAC, ABAC)
│   ├── rbac/          # Role-based access control
│   ├── tenant/        # Multi-tenancy support
│   ├── oauth2/        # OAuth2 provider implementation
│   ├── oidc/          # OpenID Connect client
│   ├── saml/          # SAML 2.0 SP
│   ├── audit/         # Audit logging
│   ├── compliance/    # Data retention, encryption
│   └── telemetry/     # OpenTelemetry, Prometheus
├── kgorm/             # GORM storage adapter
└── cmd/               # CLI tools
```

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                           APPLICATION                                │
├─────────────────────────────────────────────────────────────────────┤
│  HTTP Framework (Echo/Gin/Chi)  ←→  kayan-echo (optional adapter)   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐             │
│  │  Registration │   │    Login     │   │   Session    │             │
│  │    Manager    │   │   Manager    │   │   Manager    │             │
│  └───────┬──────┘   └───────┬──────┘   └───────┬──────┘             │
│          │                  │                   │                    │
│          └─────────┬────────┴───────────┬──────┘                    │
│                    ▼                    ▼                            │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │                    STRATEGY LAYER                           │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │     │
│  │  │ Password │ │   OIDC   │ │ WebAuthn │ │   SAML   │  ...  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                │                                     │
│                    ┌───────────┴───────────┐                        │
│                    ▼                       ▼                        │
│  ┌──────────────────────────┐  ┌──────────────────────────┐        │
│  │      HOOK SYSTEM         │  │     POLICY ENGINE        │        │
│  │  Pre/Post Registration   │  │  RBAC / ABAC / Hybrid    │        │
│  │  Pre/Post Login          │  │                          │        │
│  └──────────────────────────┘  └──────────────────────────┘        │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                      STORAGE LAYER                                   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                 IdentityRepository Interface                  │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐              │   │
│  │  │   kgorm    │  │  MongoDB   │  │   Custom   │              │   │
│  │  │  (GORM)    │  │  Adapter   │  │  Storage   │              │   │
│  │  └────────────┘  └────────────┘  └────────────┘              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  PostgreSQL  │  MySQL  │  SQLite  │  MongoDB  │  Redis       │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Request Flow

### Registration Flow

```
1. HTTP Request → POST /api/v1/registration
        │
        ▼
2. RegistrationManager.Submit(ctx, method, traits, secret)
        │
        ├── Run PreHooks(ctx, nil)
        │
        ├── Validate traits against Schema (if set)
        │
        ├── Delegate to Strategy.Register(ctx, traits, secret)
        │   │
        │   ├── Generate ID (via IDGenerator)
        │   ├── Hash secret (for password strategy)
        │   ├── Map traits to model fields
        │   └── repo.CreateIdentity(identity)
        │
        ├── Run PostHooks(ctx, identity)
        │
        └── Return created identity
```

### Authentication Flow

```
1. HTTP Request → POST /api/v1/login
        │
        ▼
2. LoginManager.Authenticate(ctx, method, identifier, secret)
        │
        ├── Run PreHooks(ctx, nil)
        │
        ├── Delegate to Strategy.Authenticate(ctx, identifier, secret)
        │   │
        │   ├── repo.FindIdentity(query)
        │   ├── Verify secret (bcrypt compare, TOTP check, etc)
        │   └── Return identity or error
        │
        ├── Run PostHooks(ctx, identity)
        │
        └── Return authenticated identity
        │
        ▼
3. SessionManager.Create(sessionID, identityID)
        │
        ├── JWT Strategy: Sign claims, return token
        └── Database Strategy: Insert session row, return ID
```

---

## Core Interfaces

### FlowIdentity (Required)

Every identity model must implement this minimal interface:

```go
type FlowIdentity interface {
    GetID() any
    SetID(any)
}
```

### IdentityRepository

Storage operations Kayan needs:

```go
type IdentityRepository interface {
    CreateIdentity(identity any) error
    GetIdentity(factory func() any, id any) (any, error)
    FindIdentity(factory func() any, query map[string]any) (any, error)
    UpdateIdentity(identity any) error
    DeleteIdentity(id any) error
}
```

### RegistrationStrategy

```go
type RegistrationStrategy interface {
    ID() string  // "password", "magic_link", etc.
    Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}
```

### LoginStrategy

```go
type LoginStrategy interface {
    ID() string
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}
```

### SessionStrategy

```go
type SessionStrategy interface {
    Create(sessionID, identityID string) (*Session, error)
    Validate(token string) (*Session, error)
    Delete(token string) error
}
```

### PolicyEngine

```go
type Engine interface {
    Can(ctx context.Context, subject any, action string, resource any) (bool, error)
}
```

---

## Extension Points

| What | How |
|------|-----|
| Custom ID types | Implement `FlowIdentity`, set `IDGenerator` |
| Custom storage | Implement `IdentityRepository` |
| Custom auth method | Implement `RegistrationStrategy` / `LoginStrategy` |
| Custom session storage | Implement `SessionStrategy` |
| Custom authorization | Implement `policy.Engine` |
| Pre/post processing | Add hooks to managers |
| Custom tenant resolution | Implement `tenant.Resolver` |

---

## Security Model

### Password Hashing
- **Default**: bcrypt with configurable cost (4-31)
- **Alternative**: Implement `Hasher` interface for argon2, scrypt

### Token Security
- **JWT**: HS256/RS256 signing, configurable expiry
- **Database sessions**: Cryptographically random IDs, server-side storage

### Rate Limiting
- In-memory or Redis-backed
- Per-IP and per-identity limits
- Progressive lockout after failures

### CSRF Protection
- State parameter in OIDC/OAuth flows
- PKCE support for OAuth2

---

## Multi-Tenancy Model

```
┌─────────────────────────────────────────────────┐
│                  KAYAN INSTANCE                  │
├─────────────────────────────────────────────────┤
│  Tenant Resolver                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Header  │ │ Domain  │ │  Path   │           │
│  └────┬────┘ └────┬────┘ └────┬────┘           │
│       └──────────┬┴───────────┘                 │
│                  ▼                               │
│  ┌───────────────────────────────────────────┐  │
│  │           Tenant Context                   │  │
│  │  - ID, Settings, Password Policy           │  │
│  │  - Allowed Strategies, MFA Requirements    │  │
│  └───────────────────────────────────────────┘  │
│                  │                               │
│       ┌──────────┴──────────┐                   │
│       ▼                     ▼                   │
│  ┌──────────┐         ┌──────────┐             │
│  │ Tenant A │         │ Tenant B │             │
│  │ Identities│         │ Identities│            │
│  └──────────┘         └──────────┘             │
└─────────────────────────────────────────────────┘
```

**Isolation**: Identities have `TenantID` field, queries are scoped.

---

## Performance Considerations

| Operation | Typical Latency | Notes |
|-----------|----------------|-------|
| Password hash | 100ms-1s | Depends on bcrypt cost |
| JWT validate | <1ms | No I/O |
| DB session validate | 1-5ms | Single query |
| RBAC check | 1-10ms | May need identity fetch |

### Scaling

- **Stateless**: JWT sessions scale horizontally
- **Shared state**: Redis for rate limits, sessions
- **Database**: Use read replicas for identity lookups

---

## Observability

### Metrics (Prometheus)
- `kayan_registrations_total{status="success|failure"}`
- `kayan_logins_total{method="password|oidc|..."}`
- `kayan_sessions_active`
- `kayan_policy_evaluations_total{decision="allow|deny"}`

### Tracing (OpenTelemetry)
- Spans for registration, login, session operations
- Trace context propagation

### Audit Logging
- All authentication events logged with timestamp, IP, identity
- SOC 2 / ISO 27001 aligned event format
