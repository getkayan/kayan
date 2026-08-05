# Kayan Documentation

Headless, non-generic, extensible IAM for Go.

If you are new here, read [Getting Started](./getting-started.md). It builds a
working password-authentication service and then shows what each piece is
actually doing, which is the fastest route to understanding the rest.

---

## By task

**"I want to authenticate users."**
[Getting Started](./getting-started.md) → [Strategies](./concepts/strategies.md) → [Sessions](./concepts/sessions.md)

**"I have my own user table and I am not changing it."**
[BYOS](./concepts/byos.md) — Kayan stores your struct as-is. No embedded base
type, no reserved column names, no generics.

**"I need to decide who can do what."**
[Authorization](./concepts/authorization.md) — RBAC with inheritance and
wildcards, ABAC, and relationship-based access control, plus which to reach
for.

**"I am serving several customers from one deployment."**
[Multi-Tenancy](./concepts/multi-tenancy.md) — resolution strategies, and how
isolation is enforced in storage rather than left to application discipline.

**"I need SSO with an enterprise identity provider."**
[SAML reference](./reference/saml.md) for SAML 2.0, or
[OIDC provider reference](./reference/oidc-provider.md) if you are the one
issuing tokens.

**"Okta or Entra needs to provision users into my service."**
[SCIM reference](./reference/scim.md) — including the PATCH shapes both
products actually send.

**"I want to store this somewhere Kayan does not ship an adapter for."**
[Storage Layer](./architecture/storage-layer.md) then
[Adapters reference](./reference/adapters.md). `kayantesting.StorageSuite` is
the contract your implementation must satisfy, and it will tell you where you
diverge.

**"I am reviewing this for production use."**
[Security Model](./architecture/security-model.md) — what is enforced, what
fails closed, and what is still missing. The gaps are listed in the root
[README](../README.md) and kept current.

---

## Reference

Generated from the source, not from memory. Every signature here was read from
the code.

| Document | Covers |
|---|---|
| [core](./reference/core.md) | `domain`, `identity`, `keys`, `flow`, `session`, `rbac`, `rebac`, `policy`, `tenant`, `mfa`, `device`, `audit`, and the rest of `core` |
| [oidc-provider](./reference/oidc-provider.md) | OAuth 2.0 and OpenID Connect: provider, request parsers, discovery, JWKS, ID tokens |
| [saml](./reference/saml.md) | SAML 2.0 service provider and identity provider, signature verification, replay protection |
| [scim](./reference/scim.md) | SCIM 2.0 resources, PATCH, and the filter grammar |
| [adapters](./reference/adapters.md) | `kayan-gorm`, `kayan-redis`, `kayan-ldap`, `kayan-testing` |
| [configuration](./reference/configuration.md) | Environment variables and configuration types |

## Concepts

Narrative explanations of the ideas the API assumes you already hold.

- [BYOS](./concepts/byos.md) — why there are no generics, and what that buys you
- [Strategies](./concepts/strategies.md) — how authentication methods compose
- [Sessions](./concepts/sessions.md) — stateless versus revocable, and the trade
- [Authorization](./concepts/authorization.md) — RBAC, ABAC, ReBAC, and when each fits
- [Multi-Tenancy](./concepts/multi-tenancy.md) — resolution and enforcement

## Architecture

For contributors, and for anyone deciding whether to depend on this.

- [Overview](./architecture/README.md) — module topology and the one-way dependency rule
- [Security Model](./architecture/security-model.md) — the threat model and what defends against it
- [Authentication Flows](./architecture/authentication-flows.md) — request paths end to end
- [Authorization Models](./architecture/authorization-models.md) — how the engines evaluate
- [Storage Layer](./architecture/storage-layer.md) — the contract, and writing your own backend
- [Strategy Internals](./architecture/strategy-internals.md) — what a strategy is and how one is built
- [Extending Kayan](./architecture/extending-kayan.md) — adding a strategy, store, or protocol

## Operations

- [Operations](./operations/README.md) — migrations, health checks, telemetry, audit
- [HTTP Framework Integration](./adapters/http-frameworks.md) — wiring Kayan behind chi, gin, echo, fiber, or `net/http`

## Examples

[examples/](../examples/README.md) has a runnable backend per authentication
strategy. Each is a single `main.go` you can read start to finish.

They read `SESSION_SECRET` from the environment and refuse to start without
it. That is deliberate: a secret hardcoded in a sample is the one that ends up
signing real sessions.

---

## The three rules

Everything in this documentation follows from these. If something here
contradicts one of them, the documentation is wrong.

**Headless.** Kayan has no router and never writes to an
`http.ResponseWriter`. It parses and validates; you transport. The reason is
not minimalism — it is that security checks belong inside the parser.
`ParseAuthorizeRequest` enforces the `redirect_uri` allowlist, the PKCE
policy, and the supported response types, so a caller cannot skip them by
hand-parsing a query string.

**Nothing is forced.** Every algorithm, hash, store, and clock sits behind an
interface with a secure default you can replace. PKCE is required unless you
turn it off. Unsigned SAML assertions are refused unless you allow them. Each
escape hatch documents what it costs.

**BYOS.** Your identity model, field names, ID type, and storage topology stay
yours.

## Project

- [Versioning and Support](../VERSIONING.md) · [Deprecation Policy](../DEPRECATION.md)
- [Security Policy](../SECURITY.md) · [Contributing](../CONTRIBUTING.md)
- [AGENTS.md](../AGENTS.md) / [CLAUDE.md](../CLAUDE.md) — architectural rules
