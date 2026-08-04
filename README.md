# Kayan

[![Go Reference](https://pkg.go.dev/badge/github.com/getkayan/kayan.svg)](https://pkg.go.dev/github.com/getkayan/kayan)
[![Go Version](https://img.shields.io/github/go-mod/go-version/getkayan/kayan)](https://go.dev/)
[![Build Status](https://github.com/getkayan/kayan/actions/workflows/ci.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/ci.yml)
[![Test Status](https://github.com/getkayan/kayan/actions/workflows/test.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/test.yml)
[![Security](https://github.com/getkayan/kayan/actions/workflows/security.yml/badge.svg)](https://github.com/getkayan/kayan/actions/workflows/security.yml)
[![Coverage](https://codecov.io/gh/getkayan/kayan/branch/main/graph/badge.svg)](https://codecov.io/gh/getkayan/kayan)
[![Go Report Card](https://goreportcard.com/badge/github.com/getkayan/kayan)](https://goreportcard.com/report/github.com/getkayan/kayan)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Headless, non-generic, extensible IAM for Go.** Authentication, sessions,
authorization, federation, provisioning, audit, and multi-tenancy — without a
router, a UI, or a fixed user schema.

```go
reg, login := flow.PasswordAuth(repo, factory, "email")
```

> [!WARNING]
> **Pre-1.0. Not ready for production use.**
>
> The public API will change without a deprecation cycle — see
> [VERSIONING.md](./VERSIONING.md).
>
> Known gaps:
>
> - **ReBAC** (`core/rebac`) — `ListDirectObjects` returns direct grants only and
>   does not walk the relation graph, so it can omit access that `Check` allows.
>   `Check` is the authoritative answer.
> - **OAuth 2.0** (`kayan-oidc-provider`) — `authorization_code`,
>   `refresh_token`, and `client_credentials`. No device code, token exchange,
>   DPoP, `private_key_jwt`, or dynamic client registration.
> - **SCIM** (`kayan-scim`) — no `/Schemas`, `/ResourceTypes`,
>   `/ServiceProviderConfig`, or bulk operations. Value filters
>   (`emails[type eq "work"]`) work in PATCH but not in list queries.
> - **SSO sessions** (`core/session`) — the cross-application session store is
>   in-memory only, so single sign-on is single-process.

---

## Mission

Give Go services the security-critical half of identity — authentication
flows, sessions, authorization, federation, provisioning — without dictating
the half that belongs to the application: its HTTP framework, its user schema,
its database, or its cryptographic choices.

## Vision

An IAM library that is correct by default and swappable at every layer, so a
team never has to choose between "secure" and "fits our architecture."

Identity libraries usually force one of two trades. Frameworks make you adopt
their router, their user table, and their session model. Toolkits hand you
primitives and leave you to assemble the security properties — which is where
authentication bypasses come from, because the assembly is the hard part.

Kayan takes a third position: **the security decisions live inside the
library; the architectural decisions live in your application.**

---

## The three principles

### Headless — you own transport

Kayan has no router and no server. It never writes to an
`http.ResponseWriter`. What it does own is the parsing and validation:

```go
// Kayan validates. You transport.
req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
jwks, err := provider.JWKS(ctx)
form, err := idp.PostBindingForm(acsURL, response, relayState)
```

This is not a limitation dressed up as a feature. Security checks belong
*inside* the parser: `ParseAuthorizeRequest` enforces the `redirect_uri`
allowlist, the PKCE policy, and the supported response types. A caller who
hand-parses a query string has to reimplement all three — and that is exactly
where open redirectors come from.

### Nothing is forced — safe default, real seam

Every algorithm, hash, store, and clock sits behind an interface with a secure
default you can replace:

```go
// Default: RSA + RS256.
provider := keys.NewStaticProvider(&keys.Key{
    KID: "2026-01", Method: jwt.SigningMethodRS256,
    Private: rsaKey, Public: &rsaKey.PublicKey,
})

// Ed25519 instead. Nothing else changes.
provider := keys.NewStaticProvider(&keys.Key{
    KID: "2026-01", Method: jwt.SigningMethodEdDSA,
    Private: edPriv, Public: edPub,
})

// Key never leaves the HSM — implement Signer and Kayan never holds it.
oauth2.NewProvider(..., oauth2.WithSigner(&kmsSigner{}))
```

The same shape covers password hashing (`domain.Hasher`, bcrypt by default,
argon2id is one line), XML signatures (`saml.SignatureVerifier`), tenant
isolation (`tenant.Scoper` — row-level by default, schema- or
database-per-tenant if you implement it), and migrations
(`gormstore.Migrations()` returns an `fs.FS`, so you keep your own runner).

**Secure by default, never secure by mandate.** PKCE is required unless you
turn it off. Unsigned SAML assertions are refused unless you allow them. Each
escape hatch documents what it gives up.

### BYOS — your identity model stays yours

No generics, no base struct to embed, no reserved column names:

```go
type User struct {          // Your struct. Your fields. Your ID type.
    ID    string
    Email string
}

repo.GetIdentity(ctx, func() any { return &User{} }, id)
```

---

## Quick start

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
    gormstore "github.com/getkayan/kayan/kayan-gorm"
    "github.com/glebarez/sqlite"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

// Your model. Kayan stores it as-is.
type User struct {
    ID     string `gorm:"primaryKey"`
    Email  string `gorm:"uniqueIndex"`
    Traits identity.JSON
}

func (u *User) GetID() any     { return u.ID }
func (u *User) SetID(id any)   { u.ID = id.(string) }

func main() {
    ctx := context.Background()

    db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
    if err != nil {
        log.Fatal(err)
    }

    repo := gormstore.NewRepository(db)
    if err := repo.AutoMigrateDev(&User{}); err != nil { // development only
        log.Fatal(err)
    }

    factory := func() any { return &User{} }

    reg, login := flow.PasswordAuth(repo, factory, "email",
        flow.WithPasswordPolicy(&flow.PasswordPolicy{
            MinLength:        12,
            RequireUppercase: true,
            RequireDigit:     true,
        }),
    )

    traits := identity.JSON(`{"email":"dev@example.com"}`)
    if _, err := reg.Submit(ctx, "password", traits, "StrongPass1234"); err != nil {
        log.Fatal(err)
    }

    user, err := login.Authenticate(ctx, "password", "dev@example.com", "StrongPass1234")
    if err != nil {
        log.Fatal(err)
    }

    sessions := session.NewManager(
        session.NewHS256Strategy(os.Getenv("SESSION_SECRET"), 15*time.Minute),
    )
    if _, err := sessions.Create(ctx, uuid.NewString(), user.(*User).GetID()); err != nil {
        log.Fatal(err)
    }
}
```

`AutoMigrateDev` is for development. Production applies the versioned SQL from
`gormstore.Migrations(dialect)` with your own migration tool.

---

## Modules

Protocols and their storage live outside `core`, so a deployment compiles only
what it uses — password authentication pulls in no OAuth 2.0, SCIM, or SAML.

| Module | Purpose |
|---|---|
| `core` | Contracts, identity, sessions, flows, RBAC, ABAC, ReBAC, tenancy, audit |
| `kayan-gorm` | GORM storage, tenant isolation callbacks, versioned migrations |
| `kayan-redis` | Sessions, rate limiting, lockout, WebAuthn ceremonies |
| `kayan-oidc-provider` | OAuth 2.0 and OpenID Connect (`gormstore/` adapter optional) |
| `kayan-saml` | SAML 2.0 service provider and identity provider |
| `kayan-scim` | SCIM 2.0 provisioning (`gormstore/` adapter optional) |
| `kayan-ldap` | LDAP directory authentication |
| `kayan-testing` | In-memory stores and a storage contract suite — tests only |

The dependency arrow points one way: **`core` never imports a sibling
module**, and CI enforces it.

Writing your own backend? `kayantesting.StorageSuite` is the contract, so a
Mongo or filesystem store can prove it behaves like the bundled ones:

```go
func TestMongoStore(t *testing.T) {
    kayantesting.StorageSuite(t, func() domain.Storage {
        return mongostore.New(testDatabase(t))
    })
}
```

---

## What you get

**Authentication** (`core/flow`) — password, magic link, OTP, TOTP, WebAuthn,
API keys, recovery codes, LDAP, social/OIDC, step-up, rate limiting, lockout.

**Sessions** (`core/session`) — stateless JWT and revocable database-backed
strategies, with algorithm pinning on every parse path.

**Authorization** — RBAC with role inheritance and wildcard permissions
(`users:*` matches `users:delete`), ABAC, hybrid policy, and ReBAC.

**Federation and provisioning** — OAuth 2.0, OIDC, SAML 2.0 with XML-DSig
signature verification and structural signature-wrapping defense, SCIM 2.0
with PATCH and a filter grammar.

**Multi-tenancy** (`core/tenant`) — eight resolution strategies, with
isolation enforced at the storage layer. A scoped query with no tenant in
context is an error, never an unscoped read.

**Operations** — audit, consent, compliance, telemetry, health checks.

---

## Documentation

- [Getting Started](./docs/getting-started.md) · [Quick Start](./docs/QUICKSTART.md)
- [BYOS](./docs/concepts/byos.md) · [Strategies](./docs/concepts/strategies.md) · [Sessions](./docs/concepts/sessions.md)
- [Authorization](./docs/concepts/authorization.md) · [Multi-Tenancy](./docs/concepts/multi-tenancy.md)
- [Architecture](./docs/architecture/README.md) · [Security Model](./docs/architecture/security-model.md)
- [Examples](./examples/README.md) — runnable backends per strategy
- [AGENTS.md](./AGENTS.md) / [CLAUDE.md](./CLAUDE.md) — architectural rules for contributors and AI agents

## Project

- [Versioning and Support](./VERSIONING.md) · [Deprecation Policy](./DEPRECATION.md)
- [Security Policy](./SECURITY.md) · [Contributing](./CONTRIBUTING.md) · [Changelog](./CHANGELOG.md)

## License

Apache 2.0 — see [LICENSE](./LICENSE).
