# Kayan

[![Go Reference](https://pkg.go.dev/badge/github.com/getkayan/kayan.svg)](https://pkg.go.dev/github.com/getkayan/kayan)
[![Go Version](https://img.shields.io/github/go-mod/go-version/getkayan/kayan)](https://go.dev/)
[![Build Status](https://github.com/getkayan/kayan/actions/workflows/ci.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/ci.yml)
[![Test Status](https://github.com/getkayan/kayan/actions/workflows/test.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/test.yml)
[![Coverage](https://codecov.io/gh/getkayan/kayan/branch/main/graph/badge.svg)](https://codecov.io/gh/getkayan/kayan)
[![Go Report Card](https://goreportcard.com/badge/github.com/getkayan/kayan)](https://goreportcard.com/report/github.com/getkayan/kayan)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/v/release/getkayan/kayan)](https://github.com/getkayan/kayan/releases)

Kayan is a headless, non-generic, extensible IAM library for Go. It gives you authentication, session management, authorization, federation, provisioning, audit, compliance, and observability primitives without forcing an HTTP framework, a UI, or a fixed user schema.

## Core Principles

- Headless only. Kayan is a library, not a hosted service or UI framework.
- Non-generic public APIs. Extension points use interfaces, `any`, and factory functions instead of type parameters.
- BYOS. Your identity model, field names, ID type, and storage topology remain yours.
- Strategy-driven composition. Authentication, sessions, authorization, tenancy, and protocol integrations are designed to be mixed and extended.

## What You Get

- Authentication flows in `core/flow` for password, magic link, OTP, WebAuthn, recovery, verification, step-up, rate limiting, and lockout.
- Session strategies in `core/session` for stateless JWT and revocable database-backed sessions.
- Authorization packages for RBAC, ABAC, hybrid policy, and ReBAC.
- Federation and provisioning support across OAuth 2.0, OIDC, SAML 2.0, and SCIM 2.0.
- Operational packages for audit, consent, compliance, telemetry, health checks, config, and logging.
- Adapters such as `kgorm` and `kredis` for concrete persistence and distributed runtime support.

## Quick Links

- 🚀 **[5-Minute Quick Start](./docs/QUICKSTART.md)** — Get up and running fast
- 🤖 **[AI Assistant Instructions](./.ai-instructions.md)** — Context for AI coding assistants
- 🌐 **[HTTP Framework Integration](./docs/adapters/http-frameworks.md)** — Fiber, Echo, Gin, stdlib
- 📚 **[Complete Examples](./examples/)** — Password, magic link, TOTP, WebAuthn, and more
- 🏗️ **[Architecture Guide](./docs/architecture/README.md)** — Design principles and patterns

## Quick Start

```go
package main

import (
    "context"
    "log"
    "os"
    "time"

    "github.com/getkayan/kayan/core/flow"
    "github.com/getkayan/kayan/core/identity"
    "github.com/getkayan/kayan/core/session"
    "github.com/getkayan/kayan/kgorm"
    "github.com/google/uuid"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

type User struct {
    ID           string `gorm:"primaryKey"`
    Email        string `gorm:"uniqueIndex"`
    PasswordHash string
    Traits       identity.JSON
}

func (u *User) GetID() any { return u.ID }

func (u *User) SetID(id any) { u.ID = id.(string) }

func main() {
    db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
    if err != nil {
        log.Fatal(err)
    }

    repo := kgorm.NewRepository(db)
    factory := func() any { return &User{} }

    reg, login := flow.PasswordAuth(
        repo,
        factory,
        "email",
        flow.WithHasherCost(12),
        flow.WithIDGenerator(func() any { return uuid.NewString() }),
        flow.WithPasswordPolicy(&flow.PasswordPolicy{
            MinLength:        12,
            RequireUppercase: true,
            RequireLowercase: true,
            RequireDigit:     true,
        }),
    )

    ctx := context.Background()
    traits := identity.JSON(`{"email":"dev@example.com"}`)

    _, err = reg.Submit(ctx, "password", traits, "StrongPass1234")
    if err != nil {
        log.Fatal(err)
    }

    authenticated, err := login.Authenticate(ctx, "password", "dev@example.com", "StrongPass1234")
    if err != nil {
        log.Fatal(err)
    }

    jwtStrategy := session.NewHS256Strategy(os.Getenv("SESSION_SECRET"), 15*time.Minute)
    sessionManager := session.NewManager(jwtStrategy)

    _, err = sessionManager.Create(uuid.NewString(), authenticated.(*User).GetID())
    if err != nil {
        log.Fatal(err)
    }
}
```

For a deeper integration path with BYOS models, hooks, multiple auth strategies, tenancy, and authorization, start with [docs/getting-started.md](./docs/getting-started.md).

## Documentation

Start with the docs index in [docs/README.md](./docs/README.md).

### Integration Path

- [Getting Started](./docs/getting-started.md)
- [BYOS](./docs/concepts/byos.md)
- [Authentication Strategies](./docs/concepts/strategies.md)
- [Session Management](./docs/concepts/sessions.md)
- [Authorization](./docs/concepts/authorization.md)
- [Multi-Tenancy](./docs/concepts/multi-tenancy.md)

### Architecture

- [Architecture Overview](./docs/architecture/README.md)
- [Authentication Flows](./docs/architecture/authentication-flows.md)
- [Authorization Models](./docs/architecture/authorization-models.md)
- [Security Model](./docs/architecture/security-model.md)
- [Storage Layer](./docs/architecture/storage-layer.md)
- [Strategy Internals](./docs/architecture/strategy-internals.md)
- [Extending Kayan](./docs/architecture/extending-kayan.md)

### Package and Runtime Reference

- [Infrastructure Packages](./docs/core/infrastructure.md)
- [OIDC and OAuth 2.0](./docs/core/oidc.md)
- [SAML 2.0](./docs/core/saml.md)
- [SCIM 2.0](./docs/core/scim.md)
- [Storage Adapters](./docs/adapters/storage.md)
- [Operations](./docs/operations/README.md)
- [Configuration](./docs/reference/configuration.md)
- [API Reference](./docs/reference/api.md)
- [JavaScript and TypeScript Integration](./docs/sdk/javascript.md)
- [OpenAPI Specification](./docs/openapi/openapi.yaml)

## Docs Site

This repository now includes a MkDocs navigation file over the existing `docs/` tree.

Install the docs dependencies:

```bash
python -m pip install -r requirements-docs.txt
```

Run the docs locally:

```bash
mkdocs serve
```

Build a static site for GitHub Pages or any static host:

```bash
mkdocs build
```

The site configuration lives in `mkdocs.yml` and uses `docs/README.md` as the documentation home page.

## Package Map

### Identity and authentication

- `core/identity`: default identity, credential, session, and JSON helpers
- `core/domain`: persistence contracts and shared interfaces
- `core/flow`: registration, login, password auth, passwordless methods, WebAuthn, recovery, verification, step-up, rate limiting, lockout
- `core/session`: JWT and database-backed sessions
- `core/device`: device trust and fingerprinting
- `core/mfa`: MFA enrollment, challenge, recovery codes, and verification
- `core/risk`: adaptive risk scoring

### Authorization and tenancy

- `core/rbac`: role and permission checks
- `core/rebac`: relationship-based authorization
- `core/policy`: ABAC and hybrid policy engines
- `core/tenant`: tenant resolution, hooks, and scoped storage
- `core/admin`: admin-oriented headless APIs

### Federation and provisioning

- `core/oauth2`: OAuth 2.0 authorization server components
- `core/oidc`: OIDC discovery, ID tokens, and logout helpers
- `core/saml`: SAML 2.0 service provider support
- `core/scim`: SCIM 2.0 provisioning and mapping

### Operations and compliance

- `core/audit`: audit events and store contracts
- `core/events`: event dispatch and topics
- `core/consent`: consent tracking and export
- `core/compliance`: retention and encryption helpers
- `core/config`: environment-backed configuration
- `core/logger`: logging setup
- `core/telemetry`: OpenTelemetry traces and metrics
- `core/health`: liveness, readiness, and detailed health reports

### Adapters

- `kgorm`: GORM-backed storage adapter for identities, credentials, sessions, OAuth 2.0, RBAC, ReBAC, SCIM, and audit
- `kredis`: Redis-backed runtime support for sessions, revocation-adjacent state, rate limiting, lockout, and WebAuthn sessions

## Examples

- [core/flow/example_passwordauth_test.go](./core/flow/example_passwordauth_test.go)
- [core/tenant/example_manager_test.go](./core/tenant/example_manager_test.go)
- [examples/nextjs-kayan-demo](./examples/nextjs-kayan-demo)

## License

Apache 2.0
