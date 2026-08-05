# Storage Layer

Kayan does not own your database. `core/domain` declares what persistence must
do; adapters decide how. `kayan-gorm` is the reference relational
implementation, `kayan-redis` covers ephemeral distributed state, and
`kayantesting.MemoryStore` proves the contract is implementable in about four
hundred lines of maps.

The design goal is that a Mongo, DynamoDB, or filesystem backend is a
first-class option rather than a fork. That only works if the contract is
written down precisely and mechanically checkable, which is what
`kayantesting.StorageSuite` is for.

---

## The `domain.Storage` contract

`core/domain/storage.go` defines a composite interface built from five parts:

```go
type Storage interface {
    IdentityStorage
    SessionStorage
    CredentialStorage
    audit.AuditStore
    TokenStore
}
```

`IdentityStorage` itself embeds `CredentialStorage`, so the credential methods
arrive twice. That is legal Go — overlapping method sets in embedded interfaces
have been permitted since Go 1.14 — and it reflects the fact that identity
operations and credential operations are usually served by the same tables.

### `IdentityStorage`

```go
type IdentityStorage interface {
    CredentialStorage

    CreateIdentity(ctx context.Context, ident any) error
    GetIdentity(ctx context.Context, factory func() any, id any) (any, error)
    FindIdentity(ctx context.Context, factory func() any, query map[string]any) (any, error)
    ListIdentities(ctx context.Context, factory func() any, page, limit int) ([]any, error)
    UpdateIdentity(ctx context.Context, ident any) error
    DeleteIdentity(ctx context.Context, factory func() any, id any) error
    CreateCredential(ctx context.Context, cred any) error
}
```

The `any` plus `func() any` shape is BYOS made concrete. The store never names
your type, and it never allocates one either — the factory does, so the store
can fill in a value whose type it does not know. See
[BYOS](../concepts/byos.md) for why this is done with a factory rather than
generics.

`FindIdentity` takes a `map[string]any` of field-value pairs, and the contract
is **conjunctive**: every field must match. The suite asserts this explicitly,
because a store that ORs the conditions would return the wrong user for a
two-field lookup and no compile error would reveal it.

`ListIdentities` pages are **1-based**, and a page past the end must return an
empty slice with a nil error, not an error. That distinction matters to
pagination loops, which would otherwise treat exhaustion as failure.

### `SessionStorage`

```go
type SessionStorage interface {
    CreateSession(ctx context.Context, s *identity.Session) error
    GetSession(ctx context.Context, id any) (*identity.Session, error)
    GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error)
    DeleteSession(ctx context.Context, id any) error
}
```

Sessions are one of the few places Kayan does define a concrete type, because
`identity.Session` is Kayan's own record rather than the caller's model:

```go
type Session struct {
    ID               string    `json:"id"`
    IdentityID       string    `json:"identity_id"`
    RefreshToken     string    `json:"refresh_token,omitempty"`
    ExpiresAt        time.Time `json:"expires_at"`
    RefreshExpiresAt time.Time `json:"refresh_expires_at,omitempty"`
    IssuedAt         time.Time `json:"issued_at"`
    Active           bool      `json:"active"`
}
```

The refresh-token lookup is a second index over the same record, and the suite
asserts that `DeleteSession` invalidates **both** paths. A store that deletes
the primary row but leaves a refresh-token index entry behind leaves a deleted
session refreshable, which is a logout that did not log anyone out.

### `CredentialStorage`

```go
type CredentialStorage interface {
    GetCredentialByIdentifier(ctx context.Context, identifier string, method string) (*identity.Credential, error)
    UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
}
```

A naming wrinkle worth knowing: the contract calls the second dimension
**method**, while the stored field is `identity.Credential.Type`. Both the
memory store and the GORM adapter map one onto the other. The values in use are
plain strings — `"password"`, `"webauthn"`, `"oidc"`, `"totp"`.

The method **scopes the lookup**. A credential stored under `"password"` must
not be returned when `"totp"` is requested for the same identifier. The suite
asserts this because collapsing the two dimensions would let a factor intended
for one method satisfy another.

`MemoryStore` builds its composite key as `method + "\x00" + identifier`, with
the method first, so that an identifier containing the separator cannot forge a
key for a different method.

### `TokenStore`

```go
type AuthToken struct {
    Token      string    `json:"token"`
    IdentityID string    `json:"identity_id"`
    Type       string    `json:"type"` // "recovery", "verification", "magic_link"
    ExpiresAt  time.Time `json:"expires_at"`
}

type TokenStore interface {
    SaveToken(ctx context.Context, token *AuthToken) error
    GetToken(ctx context.Context, token string) (*AuthToken, error)
    DeleteToken(ctx context.Context, token string) error
    DeleteExpiredTokens(ctx context.Context) error
}
```

These are the shortest-lived and most security-sensitive records in the
library: an `AuthToken` authenticates password recovery, email verification,
and magic-link login. Anyone holding one can become the identity it names.

**`GetToken` must not return an expired token.** This is a contract obligation
on the store, not a suggestion to callers, and the reason it is written that
way is given below — it is the requirement the conformance suite caught
`kayan-gorm` violating.

### `audit.AuditStore`

```go
type AuditStore interface {
    SaveEvent(ctx context.Context, event *AuditEvent) error
    Query(ctx context.Context, filter Filter) ([]AuditEvent, error)
    Count(ctx context.Context, filter Filter) (int64, error)
    Export(ctx context.Context, filter Filter, format ExportFormat) (io.Reader, error)
    Purge(ctx context.Context, olderThan time.Time) (int64, error)
}
```

Audit is part of the composite because most deployments back it with the same
database. It is also the part the conformance suite does **not** currently
cover — see the gaps section below.

### Supporting contracts

Three smaller interfaces live alongside, and each is a seam.

```go
type Hasher interface {
    Hash(password string) (string, error)
    Compare(password, hash string) bool
}

type Clock interface {
    Now() time.Time
}

type IDGenerator func() any
type TokenGenerator func() (string, error)
```

`Compare` returns a bare `bool` rather than `(bool, error)`. That is
deliberate: a hash comparison has exactly two useful outcomes, and an error
return invites the caller to write `if err != nil { return true }` or some
equivalent inversion.

The bundled `BcryptHasher` defaults to `DefaultBcryptCost = 12` and **rejects**
secrets over 72 bytes rather than truncating them. bcrypt silently ignores
input past 72 bytes, which would mean two distinct passwords sharing a 72-byte
prefix both verify. Returning an error is the honest behavior.

`IDGenerator` and `TokenGenerator` are two distinct named types on purpose.
Record identifiers can be UUIDv4, UUIDv7, ULID, or a database sequence —
readability and sortability are legitimate goals there. Security tokens have
exactly one requirement, unpredictability, and a timestamp-ordered ID is
catastrophic as a magic-link token. Keeping them as separate types means a
generator chosen for readable IDs **cannot be wired into a credential path by
accident**; it will not compile.

```go
const DefaultTokenBytes = 32
func NewTokenGenerator(n int) TokenGenerator
var DefaultTokenGenerator = NewTokenGenerator(DefaultTokenBytes)
```

`NewTokenGenerator` panics for `n < 16` rather than producing a weak generator
quietly. The 32-byte default is well beyond the 128-bit floor RFC 6749 section
10.10 sets for authorization codes. Output is unpadded base64url.

`StrategyStore`, in `core/domain/config.go`, is **not** part of the `Storage`
composite. It is an opt-in interface for deployments that want to enable and
disable login strategies from the database at runtime:

```go
type StrategyStore interface {
    GetStrategies(ctx context.Context) ([]*StrategyConfig, error)
    GetStrategy(ctx context.Context, id string) (*StrategyConfig, error)
    SaveStrategy(ctx context.Context, config *StrategyConfig) error
    DeleteStrategy(ctx context.Context, id string) error
}
```

### No sentinel errors

`core/domain` defines no error variables. Every error is an inline
`fmt.Errorf` with a `domain:` prefix, and adapters return whatever their driver
produces — `gorm.ErrRecordNotFound`, `redis.Nil`, a custom type.

This is a deliberate constraint on the contract, and the suite honors it: it
asserts only whether an operation **succeeded or failed**, never which error
value came back. The tradeoff is real. A caller cannot portably distinguish "no
such identity" from "the database is down", which means a store that returns an
error for a missing record and a store that returns one for a connection
failure are indistinguishable at the call site. Code that needs that
distinction has to know its adapter.

---

## Why every method takes `ctx`

This is a non-negotiable listed in [AGENTS.md](../../AGENTS.md), and it is not
a style rule.

**The ambient tenant lives in the context.** `tenant.WithTenant` and
`tenant.WithTenantID` place it there; `tenant.RequireID(ctx)` reads it back. A
storage method with no `context.Context` parameter cannot see the tenant, and
therefore cannot scope its query. Tenant isolation is not merely inconvenient
without `ctx` — it is **architecturally impossible**, because there is no path
by which the request's tenant can reach the SQL.

The doc comment on `IdentityStorage` states it directly:

> Every method takes a context so a storage implementation can honor
> cancellation and read request-scoped values — the ambient tenant among them.
> Without it, tenant isolation cannot reach the query.

The commit history shows the ordering. `refactor!: thread context.Context
through the storage and session contracts` is marked breaking, and it landed
*before* `feat(tenant): enforce isolation at the storage layer`. The first was
the precondition for the second.

The secondary benefits — cancellation propagating into a query, deadlines,
tracing spans — are real but subordinate. Pass `r.Context()` rather than
`context.Background()` in a handler and all of it works; pass
`context.Background()` and a multi-tenant deployment fails closed at the first
scoped query, which is the intended outcome.

---

## Tenant isolation at the storage layer

Resolution and enforcement are separate concerns. `core/tenant` resolves a
tenant from the request and puts it in the context. The **storage adapter**
enforces it. Nothing in `core/flow` or `core/session` checks a tenant ID.

### The contract

```go
type Scoper interface {
    Scope(ctx context.Context, query any) (any, error)
}

type Scoped interface {
    TenantID() string
    SetTenantID(id string)
}
```

`query any` is opaque on purpose. Kayan does not dictate *how* tenants are
separated: row-level with a `tenant_id` column, schema-per-tenant, and
database-per-tenant are all valid, and the right answer depends on the
deployment. A GORM `Scoper` receives a `*gorm.DB`; a Mongo one receives a
filter document; each asserts the type it expects.

`Scoped` is implemented by records that belong to a tenant, so an adapter can
stamp the tenant on write and verify it on read.

### Failing closed

```go
func RequireID(ctx context.Context) (string, bool) {
    if IsSystemContext(ctx) {
        return "", true
    }

    id := IDFromContext(ctx)
    if id == "" {
        return "", false
    }
    return id, true
}
```

An adapter that gets `ok == false` **must fail the operation**. It must not
proceed unscoped. Silently widening a scoped query is how one customer's data
reaches another, and it is invisible until it is a breach: the caller believed
they asked a narrow question and got a broad answer with no error.

There is a subtlety here that adapter authors get wrong. A system context
returns `("", true)` — empty ID, `ok` true. An adapter that checks only `ok`
and then appends `tenant_id = ""` will silently break every system-context
operation. `gormstore.scopeQuery` avoids it by testing
`tenant.IsSystemContext(ctx)` and returning *before* it calls `RequireID`.

Deliberate cross-tenant work is marked:

```go
// A background job that spans tenants by design.
ctx = tenant.WithSystemContext(ctx)
```

Explicit and greppable, which an absent value would not be. The canonical use
is exactly `DeleteExpiredTokens` — a sweep that must cross every tenant.

For adapters that cannot push a predicate into the query at all — a key-value
store, a cache — `tenant.Verify(ctx, record)` enforces on the way out,
returning `ErrNoTenant` or `ErrCrossTenant`. The `ErrCrossTenant` message
deliberately does not name the record's actual tenant: doing so would confirm
the record exists and disclose its owner.

### How `kayan-gorm` does it

```go
func RegisterTenantIsolation(db *gorm.DB) error
const TenantColumn = "tenant_id"
```

One call at startup registers five GORM callbacks:

| Callback | Hook | Handler |
|---|---|---|
| `kayan:tenant_query` | `Query().Before("gorm:query")` | `scopeQuery` |
| `kayan:tenant_update` | `Update().Before("gorm:update")` | `scopeQuery` |
| `kayan:tenant_delete` | `Delete().Before("gorm:delete")` | `scopeQuery` |
| `kayan:tenant_row` | `Row().Before("gorm:row")` | `scopeQuery` |
| `kayan:tenant_create` | `Create().Before("gorm:create")` | `stampTenant` |

Only models implementing `tenant.Scoped` are affected, so tables with no tenant
dimension are untouched. When the tenant is missing, both handlers call
`db.AddError(tenant.ErrNoTenant)` and return, so the statement errors rather
than executing.

**Why a callback rather than a predicate in each repository method?** Because
per-method application is how leaks happen. The one query somebody forgets is
the one that returns another customer's rows, and nothing fails until it does.
A callback cannot be forgotten by an individual method — it is registered once
and applies to every statement GORM issues.

Two implementation details are load-bearing. `stampTenant` uses
`db.Statement.SetColumn(TenantColumn, id)` rather than a field assignment, so
it applies to every row of a batch insert including maps and slices. And
`isScopedModel` falls through to reflecting into a destination slice's
*element* type, so `Find(&[]User{})` is still scoped — checking only the
top-level destination type would leave list queries unscoped, which is the
worst possible place to miss.

The scoping clause qualifies the column with the table name when one is
available, so it stays unambiguous once a join is involved. The column name is
a constant and the tenant ID is a bound parameter, so neither reaches the SQL
grammar.

One honest caveat about the current state: the bundled `gormIdentity`,
`gormCredential`, and `gormSession` models have `tenant_id` **columns in the
SQL migrations** but no `TenantID` field on the Go structs, so they do not
implement `tenant.Scoped` and the callbacks skip them. Tenant isolation today
applies to caller-defined models that implement `tenant.Scoped`. If you store
identities in Kayan's built-in tables and need isolation on them, define your
own model implementing `Scoped` rather than assuming the bundled ones are
covered.

---

## The factory pattern

Storage never allocates your type, because it does not know your type.

```go
factory := func() any { return &User{} }

user, err := repo.GetIdentity(ctx, factory, "user-123")
if err != nil {
    return err
}
u := user.(*User)
```

The adapter calls `factory()` to get a pointer to an empty value, scans the row
into it by reflection, and hands it back as `any`. The caller asserts. This is
what "non-generic" buys: any ID type, any field set, no type parameters
propagating through every signature in the library, and no compile-time
coupling between `core/domain` and your model package.

The cost is that the type assertion is a runtime check. A mismatched factory
compiles and fails at the assertion.

The only interface a model must satisfy for the flow layer is:

```go
type FlowIdentity interface {
    GetID() any
    SetID(any)
}
```

`TraitSource` and `CredentialSource` are optional and opt-in.

`kayan-gorm` also offers a registry for constructing a store by name:

```go
func Register(name string, provider any)
func NewStorage(name string, dsn string, extra any, models ...any) (domain.Storage, error)
```

`sqlite`, `postgres`, and `mysql` register themselves in an `init`. The SQLite
driver is `github.com/glebarez/sqlite`, which is pure Go and needs no cgo.

---

## Writing your own backend

Implement `domain.Storage`, or the narrower sub-interfaces if your component
only needs some of it. Nothing in `core` imports your package, and your package
imports only `core/domain`, `core/identity`, and `core/audit`.

A practical order of work:

1. **Assert the contract at compile time.** Put
   `var _ domain.Storage = (*MyStore)(nil)` in the package. This catches a
   missing or misspelled method immediately rather than at the call site.
2. **Take `ctx` on every method and actually use it** — for cancellation, and
   for `tenant.RequireID` if you support multi-tenancy.
3. **Honor the factory.** Never construct a concrete identity type. Never
   return one.
4. **Filter expired tokens in `GetToken`.** See below.
5. **Delete both session indexes** in `DeleteSession`.
6. **Scope the credential lookup by method.**
7. **Run the suite.**

```go
func TestMongoStore(t *testing.T) {
    kayantesting.StorageSuite(t, func() domain.Storage {
        return mongostore.New(testDatabase(t))
    })
}
```

If your model is not the suite's default, use `StorageSuiteWithModel` and
supply your own factory. The suite validates the model first and fails with a
clear message if it lacks the string fields it needs.

For tenant support, implement `tenant.Scoper` for your query type and enforce
`RequireID` failing closed. The suite does not cover tenancy, so that path
needs your own tests — `kayan-gorm/tenant_test.go` is a usable template, with
cases for cross-tenant reads, fail-closed behavior, system context, insert
stamping, unscoped models, and caller override attempts.

---

## `kayantesting.StorageSuite` as the conformance contract

```go
func StorageSuite(t *testing.T, newStore func() domain.Storage)
func StorageSuiteWithModel(t *testing.T, newStore func() domain.Storage, factory func() any)
```

`newStore` must return a **fresh, empty store on each call**. The suite invokes
it once per subtest so a failure in one cannot cascade into the next.

`kayan-testing` is its own module depending only on `core` — no testify, no
GORM, no Redis. It must never be imported outside a `_test.go` file; its stores
lose everything on restart, and CI enforces the restriction.

### What it asserts

**Identity** — create/get round-trip; get-missing errors; find by field;
find-with-no-match errors rather than returning empty success; **find requires
every field to match**; update persists; delete makes get error; list paginates
with 1-based pages and returns an empty page past the end with a nil error.

**Credential** — create then look up; **method scopes the lookup**; missing
credential errors; update secret persists.

**Session** — create/get; get by refresh token; **delete invalidates both the
ID and refresh-token paths**; missing session errors.

**Token** — save/get round-trip; delete; **an expired token is not returned**;
`DeleteExpiredTokens` sweeps only expired tokens and leaves live ones.

Each of those is a behavior some plausible implementation gets wrong, and each
failure mode is an authentication defect rather than a cosmetic one.

### The bug it found

The `Token/expired token is not returned` case caught a real defect in
`kayan-gorm` the first time the suite ran against it. The fix is commit
`83c82e6`, `fix(kgorm): reject expired tokens in GetToken`, and the diff is one
line:

```go
// Before
First(&gt, "token = ?", token)

// After
First(&gt, "token = ? AND expires_at > ?", token, time.Now())
```

The commit message is worth reading in full because it is honest about
severity:

> GetToken returned any auth token matching the value, ignoring ExpiresAt.
> These tokens authenticate password recovery, email verification, and
> magic-link login.
>
> Not currently exploitable: flow/recovery.go:129, flow/strategy_magic.go:45,
> and flow/verification.go all check expiry after loading. The comment at
> strategy_magic.go:44 reads "Store should handle this, but double check",
> which describes a layer that was not in fact there. Any new caller that
> omits the check would inherit an authentication bypass, so the filter
> belongs in the store.
>
> Found by the domain.Storage contract suite in kayan-testing.

This is the argument for a conformance suite in one example. The bug was not
exploitable, because three callers happened to re-check expiry — and one of
them carried a comment asserting that the store handled it, describing a layer
that did not exist. The defense was three independent checks that all had to
keep being written correctly, forever, by everyone who ever adds a fourth
caller. The suite turned an invariant that lived in a comment into one that
lives in a test.

The current implementation:

```go
// GetToken implements domain.TokenStore.
//
// Expired tokens are reported as not found. These tokens authenticate password
// recovery, email verification, and magic-link login, so the store filters on
// expiry rather than relying on every caller to re-check it.
func (r *Repository) GetToken(ctx context.Context, token string) (*domain.AuthToken, error) {
    var gt gormAuthToken
    err := r.db.WithContext(ctx).
        First(&gt, "token = ? AND expires_at > ?", token, time.Now()).Error
    if err != nil {
        return nil, err
    }
    return toCoreAuthToken(&gt), nil
}
```

### Where the suite falls short

Three gaps, stated plainly because a conformance suite that is trusted beyond
its coverage is worse than one nobody trusts.

**It does not exercise `audit.AuditStore` at all**, despite `AuditStore` being
part of the `Storage` composite. A store can pass the whole suite with a
`SaveEvent` that discards events.

**It does not cover tenancy.** Every subtest uses a bare
`context.Background()`. Isolation is tested per-adapter instead.

**`DeleteExpiredTokens` is only half-asserted.** The subtest checks that a live
token survives the sweep; it does not check that the expired one was actually
removed. A no-op `DeleteExpiredTokens` passes that case, though the separate
`expired token is not returned` case catches the resulting behavior indirectly.

One more, about the repository rather than the suite: **`kayan-gorm` does not
currently run `StorageSuite`.** It has its own hand-written `sqlite_test.go`
covering similar ground. The suite found the expired-token bug, but it is not
wired in as a standing regression gate — doing so would mean `kayan-gorm`
taking a module dependency on `kayan-testing`. Anyone writing a new adapter
should run the suite; the bundled GORM adapter is currently checked by
equivalent bespoke tests instead.

### Clock injection

```go
func NewFakeClock(t time.Time) *FakeClock
func (c *FakeClock) Now() time.Time
func (c *FakeClock) Advance(d time.Duration)
func (c *FakeClock) Set(t time.Time)
```

`Advance` accepts a negative duration, which is how clock-skew handling gets
tested. `FakeClock` is safe for concurrent use.

`MemoryStore` accepts a clock through `WithClock`. **`kayan-gorm` does not** —
it calls `time.Now()` directly, so its expiry behavior is not injectable and
time-dependent tests against it must use real durations.

The two also disagree on two boundary conditions. `MemoryStore` treats
`now == ExpiresAt` as expired and a **zero `ExpiresAt` as never expiring**. The
GORM predicate `expires_at > ?` is strict at the instant, and treats a zero
time as **always expired**. Neither is wrong, but a token saved with no expiry
behaves oppositely across the two stores. Always set `ExpiresAt` explicitly.

---

## Versioned migrations

`AutoMigrateDev` builds tables from Go models and is named to be unattractive
in production. GORM's automatic migration cannot drop a column, cannot
transform existing rows, and keeps no record of what it ran. On a table holding
accounts, a schema change that turns out to be wrong is not recoverable.

For production, the adapter ships SQL:

```go
const (
    DialectPostgres = "postgres"
    DialectMySQL    = "mysql"
    DialectSQLite   = "sqlite"
)

func Migrations(dialect string) (fs.FS, error)
func MigrationNames(dialect string) ([]string, error)
```

`Migrations` returns an `fs.FS` of numbered `.sql` files — it **does not apply
anything**. The runner stays your choice: golang-migrate, Atlas, goose, dbmate,
and a shell script all read a directory of numbered files. The naming
convention is `NNNN_description.up.sql` / `NNNN_description.down.sql`, and
numeric prefixes make lexical order the same as application order.

Dialect names are normalized, so `postgresql` and `pgx` resolve to
`DialectPostgres`, `mariadb` to `DialectMySQL`, and `sqlite3` to
`DialectSQLite`. An unrecognized dialect is an error rather than a silent
fallback.

The bundled `0001_initial_schema` creates eleven tables: `identities`,
`credentials`, `sessions`, `auth_tokens`, `audit_events`, `relation_tuples`,
`mfa_enrollments`, `mfa_challenges`, `mfa_recovery_codes`, `devices`, and
`role_assignments`.

The schema header states the indexing invariant that makes isolation
performant:

> Every table carrying identity data has a tenant_id column. It is indexed
> alongside the columns each query filters on, because the tenant predicate is
> added to every statement by the isolation callback — an index that omits it
> is an index the planner will not use.

Two index choices are worth calling out. `idx_credentials_lookup` is
`UNIQUE (tenant_id, type, identifier)` — an identifier is unique within a
tenant and method, not globally, because two tenants may each have a user with
the same email address. And `idx_sessions_refresh_token` is a partial unique
index on `refresh_token` alone, deliberately *not* tenant-leading, because
refresh tokens are globally unique bearer values.

`migrations_test.go` includes `TestMigrationsMatchTheModels`, which guards
against drift between the embedded SQL and what `AutoMigrateDev` would build.
Without it the two definitions diverge silently and development stops
resembling production.

---

## Choosing a backend

**`kayan-gorm`** is the system of record: identities, credentials, sessions,
audit events, tokens, RBAC assignments, ReBAC tuples, MFA enrollments, device
trust.

**`kayan-redis`** is not a replacement for it. It provides shared ephemeral
state where a single process is not enough: sessions, rate limiting, account
lockout, WebAuthn ceremony data. The in-memory implementations of those in
`core/flow` are correct for one instance and wrong for several — a lockout
counter that lives in one replica's memory does not slow an attacker who is
load-balanced across four.

Protocol storage ships with its protocol: `kayan-oidc-provider/gormstore` and
`kayan-scim/gormstore`, not `kayan-gorm`. A deployment that only needs password
authentication therefore compiles no OAuth 2.0 or SCIM persistence at all. See
[the architecture overview](./README.md) for why the modules are cut that way.

---

## Related

- [Architecture Overview](./README.md) — module topology and the dependency rule
- [Security Model](./security-model.md) — what fails closed, and why token
  entropy has its own type
- [BYOS](../concepts/byos.md) — the factory pattern and why not generics
- [Multi-Tenancy](../concepts/multi-tenancy.md) — resolution strategies and
  isolation modes
- [Extending Kayan](./extending-kayan.md) — writing an adapter end to end
- [Getting Started](../getting-started.md) — the GORM setup walkthrough
- [AGENTS.md](../../AGENTS.md) — the `ctx` and fail-closed non-negotiables
