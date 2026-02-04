# Kayan

[![Go Reference](https://pkg.go.dev/badge/github.com/getkayan/kayan.svg)](https://pkg.go.dev/github.com/getkayan/kayan)
[![Go Version](https://img.shields.io/github/go-mod/go-version/getkayan/kayan)](https://go.dev/)
[![Build Status](https://github.com/getkayan/kayan/actions/workflows/ci.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/ci.yml)
[![Test Status](https://github.com/getkayan/kayan/actions/workflows/test.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/test.yml)
[![Coverage](https://codecov.io/gh/getkayan/kayan/branch/main/graph/badge.svg)](https://codecov.io/gh/getkayan/kayan)
[![Go Report Card](https://goreportcard.com/badge/github.com/getkayan/kayan)](https://goreportcard.com/report/github.com/getkayan/kayan)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/v/release/getkayan/kayan)](https://github.com/getkayan/kayan/releases)

**Kayan** is a headless, non-generic, extensible Identity & Access Management (IAM) library for Go.

---

## Why Kayan?

| Challenge | Kayan's Solution |
|-----------|------------------|
| IAM solutions force their schema | **BYOS** - Bring Your Own Schema |
| Go generics are complex | Non-generic design with interfaces |
| Need UI flexibility | **Headless** - no opinions on frontend |
| Single auth method lock-in | **Strategy pattern** - mix methods |
| Scaling concerns | Stateless sessions, pluggable storage |

---

## Quick Start

```go
import (
    "github.com/getkayan/kayan/core/flow"
    "github.com/getkayan/kayan/core/session"
    "github.com/getkayan/kayan/kgorm"
)

// 1. Your model
type User struct {
    ID           string `gorm:"primaryKey"`
    Email        string `gorm:"uniqueIndex"`
    PasswordHash string
}
func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }

// 2. Setup
db, _ := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
repo := kgorm.NewRepository(db)
factory := func() any { return &User{} }

// 3. Registration
regManager := flow.NewRegistrationManager(repo, factory)
hasher := flow.NewBcryptHasher(10)
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "", factory)
pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
regManager.RegisterStrategy(pwStrategy)

// 4. Login
loginManager := flow.NewLoginManager(repo)
loginManager.RegisterStrategy(pwStrategy)

// 5. Sessions
sessManager := session.NewManager(session.NewHS256Strategy(secret, 24*time.Hour))
```

---

## Key Features

### Authentication Strategies
- **Password** - Bcrypt, argon2
- **OIDC** - Google, GitHub, Microsoft
- **WebAuthn** - Passkeys, FIDO2
- **SAML 2.0** - Enterprise SSO
- **Magic Link** - Passwordless email
- **TOTP** - Two-factor authentication

### Session Management
- **JWT** - Stateless tokens
- **Database** - Revocable sessions
- **Rotation** - Access/refresh patterns

### Authorization
- **RBAC** - Role-based access
- **ABAC** - Attribute-based policies
- **Hybrid** - Combined RBAC+ABAC

### Enterprise
- **Multi-tenancy** - Tenant isolation
- **Audit logging** - Compliance ready
- **Rate limiting** - Brute-force protection

---

## Documentation

### Getting Started
- [Quick Start Guide](./docs/getting-started.md)

### Concepts
- [BYOS (Bring Your Own Schema)](./docs/concepts/byos.md)
- [Authentication Strategies](./docs/concepts/strategies.md)
- [Session Management](./docs/concepts/sessions.md)
- [Authorization (RBAC/ABAC)](./docs/concepts/authorization.md)
- [Multi-Tenancy](./docs/concepts/multi-tenancy.md)

### Architecture
- [Architecture Overview](./docs/architecture/README.md)
- [Security Model](./docs/architecture/security-model.md)
- [Strategy Internals](./docs/architecture/strategy-internals.md)
- [Storage Layer](./docs/architecture/storage-layer.md)
- [Extending Kayan](./docs/architecture/extending-kayan.md)

### Reference
- [Configuration](./docs/reference/configuration.md)
- [API Reference](./docs/reference/api.md)
- [OpenAPI Spec](./docs/openapi/openapi.yaml)

### SDKs
- [JavaScript/TypeScript](./docs/sdk/javascript.md)

### Examples
- [20+ Examples](../kayan-examples/)

---

## Ecosystem

| Package | Description |
|---------|-------------|
| `kayan` | Core library |
| `kayan-echo` | Echo framework integration |
| `kayan-js` | TypeScript SDK |
| `kayan-console` | Admin UI (Next.js) |
| `kayan-examples` | Working examples |

---

## License

Apache 2.0
