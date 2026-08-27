# Changelog

All notable changes to Kayan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CONTRIBUTING.md with development guidelines
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- SECURITY.md with vulnerability reporting process
- GitHub issue and PR templates

## Unreleased 1.0 Roadmap (Not Yet Shipped)

### Breaking changes from the historical 0.1 development release

- Replaced the `kgorm` module path with the optional `kayan-gorm` adapter.
- Split protocols and infrastructure dependencies out of `core`.
- Added atomic `TokenStore.ConsumeToken` and atomic SSO storage contracts.
- Replaced the social-login OAuth placeholder with the transport-neutral
  `flow.OIDCClient` PKCE contract.
- Made OIDC-provider audit configuration explicit and observable.
- `JWTStrategy.Delete` now returns an error when no revocation store is
  configured, instead of reporting a successful logout that did not end the
  session. Configure one with `WithRevocationStore`.
- JWT revocation is keyed on the session id rather than on the token string,
  so revoking a session also ends its refresh token.
- `JWTStrategy.Refresh` checks revocation and revokes the token it spends, so
  a refresh token is single use and a revoked session cannot be refreshed.
- Tenant isolation now covers identities, credentials, sessions, auth tokens,
  and audit events in `kayan-gorm`. Multi-tenant deployments whose identity
  model is supplied by the application must implement `tenant.Scoped` on it.
- `OTPStrategy.Authenticate` requires the code to belong to the identifier
  presenting it; a code issued to one account no longer authenticates another.
- OIDC account linking requires a `email_verified` claim that is boolean true.
- `LoginManager.Authenticate` returns a nil identity with `*MFARequiredError`
  when a second factor is outstanding. The pending identity is reachable with
  `flow.MFAIdentityFrom(err)`; `errors.Is(err, ErrMFARequired)` still works.
- Login success is audited and dispatched after post-hooks run, so a login a
  post-hook denies is no longer recorded as successful.
- `flow.PasswordAuth` installs account lockout by default. Tune it with
  `WithLockout`/`WithLockoutStore`, or opt out explicitly with
  `WithoutLockout`.
- Sessions can be revoked in bulk: `JWTStrategy.RevokeAll` and
  `DatabaseStrategy.RevokeAll`, backed by the new
  `session.IdentityRevocationStore` and `domain.BulkSessionStorage`.
- `RecoveryManager` ends the identity's other sessions on a successful
  password reset when a revoker is supplied with
  `WithRecoverySessionRevoker`.
- `session.Manager.Rotate` issues a new session and ends the one the request
  arrived with. Use it on login and after any step-up; `Create` alone leaves
  the previous session live.
- Removed `flow.OIDCManager` and `gormstore.NewDefaultOIDCManager`. Use
  `flow.NewKayanOIDCStrategy`, which validates CSRF state and requests a nonce.
- `LoginManager.ReloadStrategies` returns an error naming any strategy that
  failed to rebuild, rather than logging to stderr and keeping the previous
  definition live.
- `core/telemetry`, `core/logger`, and `core/config` moved to the optional
  `kayan-observability` module. Their APIs are unchanged; update the import
  path. This drops `core` from 265 transitive dependencies to 53 by removing
  the OpenTelemetry SDK, its exporters, zap, and viper from every consumer's
  build.

See [the pre-1.0 migration notes](docs/reference/pre-1.0-migration.md) for the
upgrade path. These changes are not published as a stable 1.0 release yet.

### Added
- **Authentication Strategies**
  - Password strategy with bcrypt hashing
  - OIDC strategy for social login (Google, GitHub, etc.)
  - WebAuthn/Passkeys strategy for passwordless auth
  - SAML 2.0 SP/IdP support for enterprise SSO
  - Magic Link strategy for email-based login
  - TOTP strategy for multi-factor authentication

- **Session Management**
  - Database-backed sessions with revocation
  - JWT stateless sessions
  - Session rotation with refresh tokens
  - Logout notification hooks

- **Authorization**
  - RBAC (Role-Based Access Control) engine
  - ABAC (Attribute-Based Access Control) engine
  - Hybrid policy combining RBAC + ABAC

- **Multi-Tenancy**
  - Full tenant isolation
  - Multiple resolution strategies (header, domain, path)
  - Tenant lifecycle hooks

- **Security**
  - Rate limiting with Redis backend
  - Account lockout protection
  - Audit logging (SOC 2/ISO 27001 aligned)
  - Compliance utilities (data retention, encryption)

- **Consent Management**
  - GDPR/CCPA aligned consent tracking
  - Consent history and versioning
  - Export capabilities

- **Observability**
  - OpenTelemetry tracing
  - Prometheus metrics
  - Structured logging with zap

- **Developer Experience**
  - BYOS (Bring Your Own Schema) architecture
  - Hook system for registration/login flows
  - Comprehensive examples directory
  - OpenAPI specification

The items below are historical aspirations, not claims about a released or
supported version. The authoritative current status is in
[docs/reference/capabilities.md](./docs/reference/capabilities.md).

---

## Release Categories

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Features to be removed in future
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Vulnerability fixes
