# Getting Started

This builds a working authentication service, then explains what each piece is
doing and why it is shaped that way. By the end you will have registration,
login, sessions, and role-based authorization, and you will know which parts
to replace when your requirements differ from the defaults.

Every code sample here is compiled against the real modules before release. If
one does not build for you, that is a bug — please report it.

---

## Install

Kayan is a multi-module workspace. Take only what you need.

```bash
go get github.com/getkayan/kayan/core
go get github.com/getkayan/kayan/kayan-gorm    # storage
```

A password-authentication service needs those two. OAuth 2.0, SAML, SCIM, and
LDAP live in separate modules, so a deployment that does not use them does not
compile them.

---

## 1. Your identity model

Start with the struct you already have, or would have written anyway.

```go
type User struct {
    ID    string `gorm:"primaryKey"`
    Email string `gorm:"uniqueIndex"`
    Name  string
}

func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }
```

There is no base type to embed and no reserved column name. Kayan stores this
struct as-is, addressing it through the two methods above and a factory
function you supply.

That is what BYOS means in practice: your schema is not a translation of
Kayan's. See [BYOS](./concepts/byos.md) for why this is done with `any` and a
factory rather than generics.

---

## 2. Storage

```go
db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
if err != nil {
    return err
}

repo := gormstore.NewRepository(db)

// Development only.
if err := repo.AutoMigrateDev(&User{}); err != nil {
    return err
}
```

`AutoMigrateDev` builds tables from the Go models. It is named that way
because GORM's automatic migration cannot drop a column, cannot transform
existing rows, and keeps no record of what it ran — on a table holding
accounts, a schema change that turns out to be wrong is not recoverable.

For production, apply the versioned SQL:

```go
files, err := gormstore.Migrations(gormstore.DialectPostgres)
```

That returns an `fs.FS` of numbered `.sql` files rather than applying
anything, so the migration runner stays your choice —
[golang-migrate](https://github.com/golang-migrate/migrate), Atlas, goose, and
dbmate all read this layout.

**Not using GORM?** `repo` is any `domain.Storage`. See
[Storage Layer](./architecture/storage-layer.md); `kayantesting.StorageSuite`
is the contract a new backend must satisfy, and it reports exactly where an
implementation diverges.

---

## 3. Registration and login

```go
reg, login := flow.PasswordAuth(repo, factory, "email",
    flow.WithPasswordPolicy(&flow.PasswordPolicy{
        MinLength:        12,
        RequireUppercase: true,
        RequireDigit:     true,
    }),
)
```

`PasswordAuth` returns a registration manager and a login manager already
wired together. `factory` is `func() any { return &User{} }` — how Kayan
allocates your type without knowing it. `"email"` names the field that
identifies a user.

Register someone:

```go
traits := identity.JSON(`{"email":"ada@example.com","name":"Ada"}`)

user, err := reg.Submit(ctx, "password", traits, "correct horse battery staple")
if err != nil {
    return err
}
```

Authenticate:

```go
user, err := login.Authenticate(ctx, "password", "ada@example.com", password)
if err != nil {
    // Deliberately indistinguishable between "no such user" and "wrong
    // password". Reporting which one would let an attacker enumerate accounts.
    return errUnauthorized
}
```

### Choosing a password hash

The default is bcrypt at cost 12 — roughly 250ms per hash, high enough to make
offline cracking expensive and low enough that a login burst does not exhaust
CPU.

To use something else, implement `domain.Hasher`:

```go
type Hasher interface {
    Hash(password string) (string, error)
    Compare(password, hash string) bool
}
```

Then pass it to `flow.NewPasswordStrategy`. Argon2id, scrypt, and a remote
hashing service all fit that shape. Kayan picks a default; it does not pick
for you.

---

## 4. Sessions

```go
sessions := session.NewManager(
    session.NewHS256Strategy(os.Getenv("SESSION_SECRET"), 15*time.Minute),
)

sess, err := sessions.Create(ctx, uuid.NewString(), user.(*User).ID)
```

`sess.ID` is the token you return to the client. To check it:

```go
sess, err := sessions.Validate(ctx, token)
if err != nil {
    return errUnauthorized
}
// sess.IdentityID is the authenticated user.
```

### Stateless or revocable

`NewHS256Strategy` is stateless: the token carries its own claims and
validating it touches no database. Fast, and it scales without shared state.
The cost is that you cannot revoke one before it expires — which is why the
example uses a short expiry.

When immediate revocation matters, either use `NewDatabaseStrategy(repo)`,
where every validation is a lookup and deleting the row ends the session, or
attach a revocation store to the JWT strategy:

```go
strategy := session.NewJWTStrategy(config).
    WithRevocationStore(session.NewMemoryRevocationStore())
```

Without a revocation store, `Delete` on a stateless strategy returns an error:
there is nothing server-side to remove, so it refuses to report a successful
logout that did not happen.

### Choosing a signing algorithm

`NewHS256Strategy` is a convenience. The general form takes any algorithm:

```go
session.NewJWTStrategy(session.JWTConfig{
    SigningMethod: jwt.SigningMethodES256,
    SigningKey:    ecPrivateKey,
    VerifyingKey:  &ecPrivateKey.PublicKey,
    Expiry:        15 * time.Minute,
})
```

RS256, ES256, EdDSA, and HS256 all work through the same wiring. Every parse
path pins the algorithm to the one configured, so a token re-signed with a
different algorithm — the classic attack against asymmetric keys — is
rejected.

---

## 5. Authorization

```go
strategy := rbac.NewMemoryStrategy()

strategy.DefineRole(&rbac.Role{
    Name:        "viewer",
    Permissions: []string{"docs:read"},
})
strategy.DefineRole(&rbac.Role{
    Name:        "editor",
    Permissions: []string{"docs:write"},
    Inherits:    []string{"viewer"},   // editors can also read
})

strategy.AssignRole(userID, "editor")

authz := rbac.NewManager(strategy)

if err := authz.RequirePermission(ctx, userID, "docs:write"); err != nil {
    return errForbidden
}
```

Two things worth knowing:

**Permissions match by segment.** A role granted `docs:*` satisfies a check for
`docs:write`. Use `**` to match any depth: `docs:**` covers `docs:a:b:c`. A
wildcard is only honored in a grant, never in the permission being checked —
otherwise a caller could ask "may I do anything?" and be answered yes because
some narrow grant exists.

**Matching is not a regular expression.** A regex in a permission string is a
denial-of-service vector, and its semantics are unclear to whoever writes the
grant.

### More than one replica

`MemoryStrategy` keeps roles in process memory, which is correct for a single
instance. Several replicas each keep their own copy, so a role defined on one
is unknown to the others.

For anything running more than one instance, put definitions in storage:

```go
authz := rbac.NewStorageStrategy(assignmentStore, roleStore)
```

An assignment naming a role with no definition returns `rbac.ErrRoleNotFound`
rather than quietly resolving to no permissions. The two cases need different
responses: one is a legitimate refusal, the other is a broken configuration,
and treating them alike hides the second.

For richer models, see [Authorization](./concepts/authorization.md) — ABAC for
attribute-based rules, ReBAC for "who is related to what."

---

## 6. Wiring it to HTTP

Kayan has no router. It parses and validates; you transport.

```go
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }

    ctx := r.Context()

    user, err := s.login.Authenticate(ctx, "password", body.Email, body.Password)
    if err != nil {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }

    sess, err := s.sessions.Create(ctx, uuid.NewString(), user.(*User).ID)
    if err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"token": sess.ID})
}
```

Pass `r.Context()` rather than `context.Background()`. Cancellation propagates,
and the ambient tenant travels there — a query with no context cannot be
tenant-scoped.

This works identically behind chi, gin, echo, fiber, or `net/http`; see
[HTTP Framework Integration](./adapters/http-frameworks.md).

---

## 7. Multi-tenancy

Tenancy resolves from the request and is enforced in storage.

```go
tenants := tenant.NewManager(tenantStore, tenant.NewSubdomainResolver("example.com"))

// Once per request, before touching storage.
_, ctx, err := tenants.ResolveFromRequest(r.Context(), r)
if err != nil {
    return err
}
```

For the GORM adapter, register the isolation callbacks once at startup:

```go
if err := gormstore.RegisterTenantIsolation(db); err != nil {
    return err
}
```

Every query on a model implementing `tenant.Scoped` then carries a tenant
predicate automatically, and inserts are stamped with the ambient tenant. This
is a callback rather than a predicate in each repository method for a specific
reason: per-method application is how leaks happen, because the one query
somebody forgets is the one that returns another customer's rows, and nothing
fails until it does.

**Isolation fails closed.** A scoped query with no tenant in the context
returns `tenant.ErrNoTenant` rather than running unscoped. Silently returning
every tenant's rows to a caller who believes they asked a narrow question is
the worst available outcome.

Deliberate cross-tenant work says so:

```go
// A background job that spans tenants by design.
ctx = tenant.WithSystemContext(ctx)
```

That is explicit and greppable, which an absent value would not be.

See [Multi-Tenancy](./concepts/multi-tenancy.md) for the eight resolution
strategies and for schema- or database-per-tenant isolation.

---

## Next

**Add another authentication method.** Magic links, one-time codes, TOTP,
WebAuthn, API keys, LDAP, and social login all implement the same
`flow.LoginStrategy` interface and register on the same manager. See
[Strategies](./concepts/strategies.md).

**Become an identity provider.** [OIDC provider reference](./reference/oidc-provider.md)
covers the authorization code flow with PKCE, refresh rotation with reuse
detection, JWKS, and discovery.

**Accept enterprise SSO.** [SAML reference](./reference/saml.md).

**Accept provisioning.** [SCIM reference](./reference/scim.md), including the
PATCH shapes Okta and Entra ID actually send.

**Read the whole API.** Start with the exhaustive
[Go API index](./reference/go-api.md), then use the
[core behavioral reference](./reference/core.md) for lifecycle and security
semantics.

---

## Before production

Kayan is pre-1.0. The public API changes without a deprecation cycle, and the
[README](../README.md) lists the gaps that would otherwise surprise you.

The tested [production wiring reference](../examples/12-production/README.md)
shows the users, login, sessions, roles, permissions, audit, and administration
path together. Check these deployment properties before exposing it:

**The session secret is not in your source.** The examples read
`SESSION_SECRET` and refuse to start without it, for the reason that a secret
committed in a sample is the one that ends up signing real sessions.

**Migrations are versioned.** `AutoMigrateDev` has no way back.

**Logout is actually revocable.** Use database sessions or attach a shared
revocation store to JWT sessions. A bare JWT strategy returns an error from
`Delete` because it cannot end the token.

**Role definitions and assignments are persistent.** Use
`rbac.NewStorageStrategy`; the memory strategy gives each replica a different
authorization view.

**Lockout is shared across replicas.** Pass a Redis-backed store to
`flow.WithLockoutStore`, or each replica gives an attacker a separate attempt
budget.

**Audit events are persistent and audit-store failures are observed.** Use
`flow.WithQuickAudit` (or the manager-specific audit options) with a non-nil
error handler.

**Tenant isolation is registered** if you are multi-tenant, and you have tested
that a query with no tenant errors rather than returning everything.

**TLS and browser CSRF policy belong to the host application.** Bearer headers
avoid ambient cookie authentication. If you use cookies, add `Secure`,
`HttpOnly`, `SameSite`, and explicit CSRF protection.

**MFA and device trust have a persistent store.** The in-memory
implementations lose every enrollment on restart, which locks out every user
who enrolled a second factor — they cannot re-enroll without signing in first.
