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
- `telemetry.Subscribe(dispatcher, provider)` connects OpenTelemetry metrics to
  the domain events `core/flow` already emits, so login, MFA, session, lockout,
  and rate-limit metrics work without `core` importing OpenTelemetry.
- `logger.InitLogger` returns an error instead of panicking, and `logger.Log`
  starts as a no-op logger rather than nil, so logging before configuration
  discards the line instead of crashing.
- `saml.ParseIdPMetadata` keeps every advertised signing certificate rather
  than only the first, so an IdP signing-key rollover no longer breaks logins
  at cutover.
- `scim.ApplyGroupPatch` applies PATCH to groups, including membership add,
  remove, and replace in the shapes Okta and Entra send. Group provisioning
  previously could not be served: `ApplyPatch` accepted only users.
- SAML encrypted assertions are supported through `saml.WithDecrypter` and
  `saml.NewRSADecrypter`. Key transport is RSA-OAEP and content encryption is
  AES-GCM; `rsa-1_5` and CBC modes are refused as unsafe for an endpoint that
  decrypts unauthenticated input.
- `oidc.Server.UserInfo` implements the UserInfo endpoint's logic, authorized
  by token introspection through the new `oidc.WithTokenIntrospector`.
- ID tokens carry `at_hash` and `c_hash` when `IDTokenRequest.AccessToken` or
  `Code` is set, binding the ID token to what was issued alongside it.
- SAML single logout: `ServiceProvider.InitiateLogout` builds a LogoutRequest
  redirect, `ProcessLogoutRequest` verifies an inbound one and reports whose
  session to end, and `BuildLogoutResponse` produces the reply. The signature
  on an inbound request is mandatory.
- `saml.ServiceProvider.ProcessRedirectLogoutRequest` verifies a LogoutRequest
  that arrived over the HTTP-Redirect binding, which the metadata document
  already advertised but no code path could check. `saml.VerifyRedirectSignature`
  is exported for callers verifying other redirect-bound messages.
- Outgoing SAML `AuthnRequest` messages are signed when `Config.SignRequests`
  is set, through the new `saml.RedirectSigner` seam and
  `saml.WithRedirectSigner`. Previously the flag was read only to populate
  metadata, so a service provider advertised signed requests and sent unsigned
  ones; it now fails closed when it cannot sign. `Config.SignatureMethod` is
  honoured, and RSA-SHA1 is refused rather than silently upgraded.
- SAML metadata generation emits `KeyDescriptor` elements, logout endpoints,
  NameID formats, and `WantAssertionsSigned`. The previous documents carried
  no key material, so an identity provider had nothing to verify signatures
  against or encrypt to. `saml.Config` gains `NameIDFormat` and
  `EncryptionCertificate`.

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
