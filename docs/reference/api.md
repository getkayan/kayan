# API Reference

This is a package-oriented reference for the primary constructors, interfaces, and extension points in the repository.

## core/flow

Primary constructors:

- `flow.PasswordAuth(repo, factory, identifierField, opts...)`
- `flow.NewRegistrationManager(repo, factory, opts...)`
- `flow.NewLoginManager(repo, factory, opts...)`
- `flow.NewPasswordStrategy(repo, hasher, identifierField, factory)`

Important interfaces:

- `FlowIdentity`
- `RegistrationStrategy`
- `LoginStrategy`
- `Initiator`
- `Attacher`
- `Hook`

Important options:

- `WithRegDispatcher`
- `WithSchema`
- `WithLinker`
- `WithRegPreHook`
- `WithRegPostHook`
- `WithPreventPasswordCapture`
- `WithLoginDispatcher`
- `WithStrategyStore`
- `WithLoginPreHook`
- `WithLoginPostHook`
- `WithHasherCost`
- `WithIDGenerator`
- `WithQuickDispatcher`
- `WithRegHook`
- `WithLoginHook`
- `WithPasswordPolicy`

## core/session

Primary constructors:

- `session.NewManager(strategy)`
- `session.NewDatabaseStrategy(repo)`
- `session.NewJWTStrategy(config)`
- `session.NewHS256Strategy(secret, expiry)`
- `session.NewMemoryRevocationStore()`

Important interfaces:

- `session.Strategy`
- `session.RevocationStore`

## core/rbac

Primary constructors:

- `rbac.NewManager(strategy)`
- `rbac.NewBasicStrategy(loader)`
- built-in strategies such as the in-memory and storage-backed variants in the package

Important interfaces:

- `rbac.Strategy`
- `rbac.RoleSource`
- `rbac.PermissionSource`

## core/rebac

Primary constructors:

- `rebac.NewManager(store, opts...)`

Important interfaces and types:

- `rebac.Store`
- `rebac.Schema`
- `rebac.SubjectRef`
- `rebac.ObjectRef`

## core/policy

Primary constructors:

- `policy.NewABACStrategy()`
- `policy.NewHybridStrategy(...)`

Important interface:

- `policy.Engine`

## core/tenant

Primary constructors:

- `tenant.NewManager(store, resolver, opts...)`
- `tenant.NewHeaderResolver(name)`
- `tenant.NewPathResolver(prefix, position)`
- `tenant.NewSubdomainResolver(baseDomain)`
- `tenant.NewScopedStore(inner, tenantID)`

Important types:

- `tenant.Resolver`
- `tenant.ResolveInfo`
- `tenant.Hooks`

## core/oauth2

Primary constructors:

- `oauth2.NewProvider(clientStore, authCodeStore, refreshTokenStore, issuer, signingKey, keyID, opts...)`

Important interfaces:

- `oauth2.ClientStore`
- `oauth2.AuthCodeStore`
- `oauth2.RefreshTokenStore`
- `oauth2.RevocationStore`

## core/oidc

Primary constructors:

- `oidc.NewServer(issuer, signingKey, keyID)`

Important types:

- `oidc.Server`
- `oidc.Discovery`

## core/saml

Primary constructors:

- `saml.NewServiceProvider(config, sessionStore, identityRepo, factory)`

Important types:

- `saml.Config`
- `saml.IdPConfig`
- `saml.Hooks`
- `saml.SessionStore`

## core/scim

Primary constructors:

- `scim.NewManager(storage, mapper)`

Important types:

- `scim.ScimStorage`
- `scim.Mapper`
- `scim.User`
- `scim.Group`

## core/mfa

Primary constructors:

- `mfa.NewManager(store, opts...)`

Important interfaces and types:

- `mfa.Method`
- `mfa.MFAStore`
- `mfa.Enrollment`
- `mfa.Challenge`

## core/device

Primary constructors:

- `device.NewManager(store, opts...)`

Important types:

- `device.Store`
- `device.Device`
- `device.TrustLevel`

## core/risk

Primary constructors:

- `risk.NewEngine(...)`

Important types:

- `risk.Rule`
- `risk.Assessment`
- `risk.Input`

## core/consent

Primary constructors:

- `consent.NewManager(store, version, opts...)`

Important types:

- `consent.Purpose`
- `consent.Consent`
- `consent.Hooks`

## core/health

Primary constructors:

- `health.NewManager(version, opts...)`
- `health.NewDatabaseChecker(name, pingFn)`
- `health.NewRedisChecker(name, pingFn)`

Important interfaces:

- `health.Checker`

## core/admin

Primary constructors:

- `admin.NewManager(opts...)`

Important options:

- `admin.WithUserStore`
- `admin.WithSessionStore`
- `admin.WithTenantStore`
- `admin.WithRoleStore`
- `admin.WithAuditStore`
- `admin.WithPasswordHasher`
- `admin.WithIDGenerator`

## Adapters

- `kgorm.NewRepository(db)` for relational persistence
- `kredis` package constructors for Redis-backed security state and session support

For concrete usage patterns, prefer the package tests alongside this reference. The tests are the most precise source of expected behavior.