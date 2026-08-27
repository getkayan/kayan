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
