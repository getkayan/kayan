# Kayan Documentation

Kayan is a headless IAM library for Go. It is not an HTTP framework, not a hosted service, and not an opinionated user schema. The core packages give you authentication, sessions, authorization, federation, provisioning, compliance, and observability primitives that you compose inside your own application.

The codebase is organized around three hard constraints:

- Headless only. `core/` contains no UI and no framework-specific transport logic.
- Non-generic public APIs. Extension points use interfaces, `any`, and factory functions instead of Go type parameters.
- BYOS. Your identity model, ID type, field names, and storage adapter remain yours.

## Reading Path

Start here if you are integrating Kayan into an application for the first time:

1. [Getting Started](./getting-started.md)
2. [BYOS](./concepts/byos.md)
3. [Authentication Strategies](./concepts/strategies.md)
4. [Session Management](./concepts/sessions.md)
5. [Authorization](./concepts/authorization.md)
6. [Multi-Tenancy](./concepts/multi-tenancy.md)

Use these sections when you are designing or extending the library:

- [Architecture Overview](./architecture/README.md)
- [Authentication Flows](./architecture/authentication-flows.md)
- [Authorization Models](./architecture/authorization-models.md)
- [Security Model](./architecture/security-model.md)
- [Storage Layer](./architecture/storage-layer.md)
- [Strategy Internals](./architecture/strategy-internals.md)
- [Extending Kayan](./architecture/extending-kayan.md)

Use these package-level references when you need feature-specific guidance:

- [Infrastructure Packages](./core/infrastructure.md)
- [OIDC and OAuth 2.0](./core/oidc.md)
- [SAML 2.0](./core/saml.md)
- [SCIM 2.0](./core/scim.md)
- [Storage Adapters](./adapters/storage.md)
- [Operations](./operations/README.md)
- [Configuration](./reference/configuration.md)
- [API Reference](./reference/api.md)
- [JavaScript and TypeScript Integration](./sdk/javascript.md)

## Package Map

### Identity and authentication

- `core/identity`: default identity, credential, session, JSON helpers
- `core/domain`: persistence contracts and helper interfaces
- `core/flow`: registration, login, MFA checks, magic link, OTP, WebAuthn, password policy, rate limiting, lockout, recovery, step-up
- `core/session`: JWT and database-backed sessions
- `core/device`: device trust and fingerprinting
- `core/mfa`: standalone MFA enrollment, challenge, and verification orchestration
- `core/risk`: adaptive risk evaluation

### Authorization and tenancy

- `core/rbac`: role and permission checks
- `core/rebac`: relation graph authorization
- `core/policy`: ABAC and hybrid policies
- `core/tenant`: tenant resolution, hooks, scoped storage
- `core/admin`: framework-agnostic admin management APIs

### Federation and provisioning

- `core/oauth2`: OAuth 2.0 authorization server
- `core/oidc`: OIDC discovery, ID tokens, logout helpers
- `core/saml`: SAML 2.0 service provider
- `core/scim`: SCIM 2.0 provisioning and mapping

### Compliance and operations

- `core/audit`: audit event model and store interface
- `core/events`: event dispatch and topic model
- `core/consent`: consent tracking and export
- `core/compliance`: retention and encryption helpers
- `core/config`: environment-backed configuration loader
- `core/logger`: zap-backed logging
- `core/telemetry`: OpenTelemetry traces and metrics
- `core/health`: liveness, readiness, and detailed health checks

### Adapters

- `kgorm`: GORM-backed persistence for identities, sessions, audit, OAuth 2.0, RBAC, ReBAC, and SCIM
- `kredis`: Redis-backed session, rate-limit, lockout, and WebAuthn-related support

## What Kayan Does Not Do

- It does not choose your HTTP framework.
- It does not require the default identity structs.
- It does not force a single authorization model.
- It does not own your migrations, tenant topology, or UI.

That separation is deliberate. The recommended pattern is to keep Kayan in your domain layer and adapt it outward into handlers, middleware, CLIs, jobs, and background workers.