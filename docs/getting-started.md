# Getting Started

This guide shows the minimum production-grade Kayan integration: your own identity model, a repository implementation, password authentication, revocable or stateless sessions, and optional tenancy and authorization.

## 1. Install Kayan

```bash
go get github.com/getkayan/kayan
```

If you want the built-in GORM adapter and Redis-backed helpers:

```bash
go get github.com/getkayan/kayan/kgorm
go get github.com/getkayan/kayan/kredis
```

## 2. Define Your Identity Model

The only hard requirement for authentication flows is `flow.FlowIdentity`:

```go
package app

import "github.com/getkayan/kayan/core/identity"

type User struct {
	ID           string         `gorm:"primaryKey"`
	Email        string         `gorm:"uniqueIndex"`
	PasswordHash string
	Traits       identity.JSON
	Roles        []string       `gorm:"-"`
	Permissions  []string       `gorm:"-"`
	VerifiedAt   *time.Time
	MFAEnabled   bool
	MFASecret    string
}

func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }

func (u *User) GetTraits() identity.JSON      { return u.Traits }
func (u *User) SetTraits(v identity.JSON)     { u.Traits = v }
func (u *User) MFAConfig() (bool, string)     { return u.MFAEnabled, u.MFASecret }
func (u *User) IsVerified() bool              { return u.VerifiedAt != nil }
func (u *User) MarkVerified(ts time.Time)     { u.VerifiedAt = &ts }
func (u *User) GetRoles() []string            { return u.Roles }
func (u *User) GetPermissions() []string      { return u.Permissions }
```

Optional interfaces unlock additional features without coupling your model to every package:

- `flow.TraitSource` for trait-aware flows and OIDC claims
- `flow.MFAIdentity` for MFA enforcement during login
- `flow.VerificationIdentity` for verification and recovery flows
- `rbac.RoleSource` and `rbac.PermissionSource` for RBAC

## 3. Wire Storage

Kayan core logic depends on `core/domain` interfaces, not a concrete database.

Using GORM:

```go
db, err := gorm.Open(sqlite.Open("kayan.db"), &gorm.Config{})
if err != nil {
	log.Fatal(err)
}

repo := kgorm.NewRepository(db)
```

For BYOS, your adapter must satisfy only the interfaces you need. Password registration and login typically require:

- `domain.IdentityStorage`
- `domain.CredentialStorage`
- `audit.AuditStore` if you want automatic audit logging

## 4. Choose an Authentication Setup

### Fast path: one-call password setup

Use `flow.PasswordAuth` when you want a complete password registration and login pair:

```go
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
```

### Full-control path: explicit managers and strategies

Use explicit managers when you need more than password auth:

```go
factory := func() any { return &User{} }

regMgr := flow.NewRegistrationManager(
	repo,
	factory,
	flow.WithRegPreHook(func(ctx context.Context, ident any) error {
		return nil
	}),
)

loginMgr := flow.NewLoginManager(
	repo,
	factory,
	flow.WithLoginPostHook(func(ctx context.Context, ident any) error {
		return nil
	}),
)

hasher := flow.NewBcryptHasher(12)
password := flow.NewPasswordStrategy(repo, hasher, "email", factory)
magic := flow.NewMagicLinkStrategy(repo, tokenStore)
otp := flow.NewOTPStrategy(repo, tokenStore, otpSender)

regMgr.RegisterStrategy(password)
loginMgr.RegisterStrategy(password)
loginMgr.RegisterStrategy(magic)
loginMgr.RegisterStrategy(otp)
```

Use this mode when you need hooks, event dispatch, account linking, dynamic strategy reloads, or mixed methods such as password plus magic link.

## 5. Register and Authenticate Users

```go
traits := identity.JSON(`{"email":"dev@example.com","name":"Dev User"}`)

user, err := reg.Submit(ctx, "password", traits, "StrongPass123!")
if err != nil {
	return err
}

authenticated, err := login.Authenticate(ctx, "password", "dev@example.com", "StrongPass123!")
if err != nil {
	return err
}

registeredUser := user.(*User)
authenticatedUser := authenticated.(*User)

_ = registeredUser
	_ = authenticatedUser
```

Authentication method strings are strategy IDs. Built-ins include `password`, `magic_link`, `otp`, and additional strategies implemented in `core/flow` such as TOTP and WebAuthn.

## 6. Create Sessions

### Database-backed sessions

```go
sessionManager := session.NewManager(session.NewDatabaseStrategy(repo))
sess, err := sessionManager.Create(uuid.NewString(), authenticatedUser.GetID())
```

Database sessions are revocable and rotate session and refresh tokens on refresh. Use them when you need strict server-side invalidation.

### JWT sessions

```go
jwtStrategy := session.NewHS256Strategy(os.Getenv("SESSION_SECRET"), 15*time.Minute)
jwtStrategy.WithRevocationStore(session.NewMemoryRevocationStore())

sessionManager := session.NewManager(jwtStrategy)
sess, err := sessionManager.Create(uuid.NewString(), authenticatedUser.GetID())
```

JWT sessions are stateless for validation, but can still support revocation when backed by a revocation store such as Redis.

## 7. Add Authorization

### RBAC

```go
rbacManager := rbac.NewManager(rbac.NewBasicStrategy(nil))
allowed, err := rbacManager.AuthorizePermission(authenticatedUser, "billing:read")
```

### ABAC or hybrid policies

```go
engine := policy.NewABACStrategy()
engine.AddRule("invoice:read", func(ctx context.Context, subject, resource any, pctx policy.Context) (bool, error) {
	return true, nil
})
```

### Relationship-based authorization

```go
rebacManager := rebac.NewManager(store, rebac.WithSchema(schema))
ok, err := rebacManager.Check(ctx, subject, "viewer", object)
```

Use RBAC for simple role gates, ABAC for contextual rules, and ReBAC for hierarchical or graph-based access.

## 8. Add Multi-Tenancy

```go
tenantManager := tenant.NewManager(
	tenantStore,
	tenant.NewHeaderResolver("X-Tenant-ID"),
	tenant.WithOptionalTenant(),
)

resolvedTenant, ctx, err := tenantManager.Resolve(ctx, tenant.ResolveInfo{
	Headers: map[string]string{"X-Tenant-ID": "acme"},
})
```

The tenant manager resolves a tenant, validates it, and stores either the full tenant or just the tenant ID in context.

## 9. Production Hardening Checklist

- Use bcrypt cost values appropriate for your deployment profile.
- Enforce `flow.PasswordPolicy` instead of relying on UI-only checks.
- Enable rate limiting and lockout for credential flows.
- Use RSA or ECDSA keys for OAuth 2.0 and OIDC JWT signing.
- Back JWT revocation, session refresh rotation, and rate limiting with Redis in distributed deployments.
- Emit audit events and export telemetry.
- Resolve tenant context before invoking authentication or admin flows in multi-tenant systems.
- Use the package-specific docs before enabling SAML, OIDC, SCIM, MFA, or device trust in production.

## 10. Next Steps

- [BYOS](./concepts/byos.md) explains the schema contract in detail.
- [Authentication Strategies](./concepts/strategies.md) covers strategy registration, hooks, and multi-method flows.
- [Session Management](./concepts/sessions.md) compares JWT and database strategies in depth.
- [Storage Adapters](./adapters/storage.md) shows how `kgorm` and `kredis` fit into a full deployment.