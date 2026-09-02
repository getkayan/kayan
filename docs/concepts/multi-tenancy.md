# Multi-Tenancy

A multi-tenant service holds several customers' data in one deployment, and the
whole job is that no customer ever sees another's. Kayan splits that into two
halves that fail differently: **resolution**, which decides whose request this
is, and **isolation**, which makes sure the query cannot return anyone else's
rows.

Resolution is a request-scoped concern and lives in `core/tenant`. Isolation is
a storage concern and lives in the adapter — `kayan-gorm` for GORM, yours for
anything else.

This page covers data isolation. Protecting shared CPU, database, Redis, and
worker capacity from a noisy tenant is a separate concern; see
[Tenant Resource Governance](./resource-governance.md).

The reason for the split is that a resolution bug is loud and an isolation bug
is silent. Resolve the wrong tenant and the customer sees an empty account and
opens a ticket within the hour. Forget a predicate in one query and everything
looks correct until the day a list endpoint returns somebody else's users, with
nothing in the logs saying when it started.

---

## The Tenant type

```go
type Tenant struct {
    ID        string
    Name      string
    Domain    string          // for domain-based resolution
    Slug      string          // URL-friendly identifier
    Settings  json.RawMessage
    Metadata  json.RawMessage
    Active    bool
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

`Settings` and `Metadata` are `json.RawMessage` rather than a fixed struct
because per-tenant configuration is exactly the thing a library cannot guess.
`TenantSettings` is a starting shape if you want one — allowed strategies,
session TTL, MFA requirement, a `PasswordPolicy`, a `RateLimitConfig`, branding,
and a `Custom` blob — but nothing requires you to use it. Unmarshal `Settings`
into your own struct instead and nothing breaks.

`Active` is checked during resolution: an inactive tenant fails to resolve. That
is how a suspended customer is cut off in one place rather than in every
handler.

Persistence is behind an interface:

```go
type Store interface {
    Create(ctx context.Context, tenant *Tenant) error
    Get(ctx context.Context, id string) (*Tenant, error)
    GetByDomain(ctx context.Context, domain string) (*Tenant, error)
    GetBySlug(ctx context.Context, slug string) (*Tenant, error)
    Update(ctx context.Context, tenant *Tenant) error
    Delete(ctx context.Context, id string) error
    List(ctx context.Context, filter ListFilter) ([]*Tenant, error)
}
```

---

## Resolution

```go
type Resolver interface {
    Resolve(ctx context.Context, info ResolveInfo) (string, error)
}
```

A resolver returns a tenant **ID**, or the empty string when it cannot
determine one. Empty is not an error — it is how a chain knows to try the next
resolver.

`ResolveInfo` is why this is headless:

```go
type ResolveInfo struct {
    Host       string
    Path       string
    Method     string
    RemoteAddr string
    Headers    map[string][]string
    Query      map[string][]string
    Attributes map[string]any
}

func ResolveInfoFromRequest(r *http.Request) ResolveInfo
```

Resolvers take this struct rather than an `*http.Request`, so tenancy resolves
identically for a gRPC call, a message consumer, or a CLI invocation. The HTTP
constructor is a convenience over the same struct. `info.HeaderValue(name)` and
`info.QueryValue(name)` return the first matching value.

`ResolverFunc` adapts a plain function, so a one-off resolver does not need a
type.

### SubdomainResolver

```go
resolver := tenant.NewSubdomainResolver("example.com")
```

`acme.example.com` resolves to `acme`. The port is stripped first, so
`acme.example.com:8443` works.

Two cases return empty rather than a value: the bare base domain and
`www.` prefixed base domain resolve to nothing, and so does any host that is
not a subdomain of `BaseDomain`. That suffix check is the security-relevant
part — without it, `example.com.attacker.net` would resolve to a tenant of the
attacker's choosing.

`Position` selects which label to use when there are several. `0` (the default)
takes the first, and `-1` takes the last before the base domain.

### HeaderResolver

```go
resolver := tenant.NewHeaderResolver("X-Tenant-ID")   // "" defaults to X-Tenant-ID
```

Reads the header and returns it verbatim.

**A header is client-supplied.** Anyone who can reach your service can set
`X-Tenant-ID` to any value. This resolver is safe behind a gateway that
overwrites the header from an authenticated source, and unsafe on an endpoint
a browser can reach directly. If the client can set it, pair it with a check
that the authenticated user belongs to the tenant they named — resolution puts
a tenant in the context, it does not prove the caller is entitled to it.

`JWTClaimResolver` exists precisely because it does not have this problem.

### PathResolver

```go
resolver := tenant.NewPathResolver("/api/v1/tenants/", 0)
```

`/api/v1/tenants/acme/users` resolves to `acme`. A path not carrying the prefix
returns empty. `Position` is the segment index counted from after the prefix,
and an out-of-range position returns empty rather than panicking.

### QueryResolver

```go
resolver := tenant.NewQueryResolver("tenant")   // "" defaults to "tenant"
```

`?tenant=acme` resolves to `acme`. Client-supplied, with everything said about
`HeaderResolver` applying — and more so, because query strings end up in access
logs, browser history, and `Referer` headers.

### JWTClaimResolver

```go
resolver := tenant.NewJWTClaimResolver("tenant_id", claimsContextKey)
```

Reads a claim from a `map[string]any` you have already put in the context under
`claimsContextKey`. It returns empty if the value is not a `map[string]any` or
the claim is not a string.

**It does not verify the token.** It reads a map. Your authentication middleware
parses and verifies the JWT, checks the signature and expiry, and puts the
verified claims in the context; this resolver only picks a field out of them. A
middleware that stores unverified claims turns this into the least trustworthy
resolver rather than the most.

Done correctly it is the strongest option available, because the tenant is
bound to the same signature that authenticated the user — a client cannot
change it without invalidating their session.

### ChainResolver

```go
resolver := tenant.NewChainResolver(
    tenant.NewJWTClaimResolver("tenant_id", claimsKey),
    tenant.NewSubdomainResolver("example.com"),
    tenant.NewHeaderResolver("X-Tenant-ID"),
)
```

Tries each in order and returns the first non-empty result. An error from any
resolver aborts the chain immediately rather than falling through — a resolver
that failed did not decline, and continuing past it would let a downstream
resolver's weaker answer stand in for the one that broke.

**Order is a security decision, not a preference.** The chain above trusts the
signed claim first and the client-supplied header last, so a client that sets
`X-Tenant-ID` on an authenticated request changes nothing. Reverse the order and
the header wins over the token, which hands every authenticated user access to
every tenant.

### StaticResolver

```go
resolver := tenant.NewStaticResolver("acme")
```

Always the same ID. Useful for a single-tenant deployment that wants the
isolation machinery on anyway, and for tests.

### CacheResolver

```go
resolver := tenant.NewCacheResolver(inner, cache, func(info tenant.ResolveInfo) string {
    return info.Host
})
```

Wraps a resolver and caches the result. The key function defaults to
`info.Host` when nil, and `TTL` defaults to 300 seconds — set the field
directly to change it.

```go
type Cache interface {
    Get(ctx context.Context, key string) (string, bool)
    Set(ctx context.Context, key string, value string, ttlSeconds int) error
}
```

Only non-empty results are cached, so a miss is retried rather than remembered.

**The key function must cover everything the wrapped resolver reads.** The
default key is the host, which is correct over a `SubdomainResolver` and wrong
over a `PathResolver` — two paths on the same host would share a cache entry,
and the second request would be resolved to the first request's tenant. That is
a cross-tenant read produced by a caching layer. If the inner resolver reads the
path, header, or a claim, the key must include it.

`Set` errors are ignored: a cache that cannot write still resolves correctly,
just without the benefit.

### ValidatingResolver

```go
resolver := tenant.NewValidatingResolver(inner, store)
```

Resolves, then loads the tenant and checks it exists and is `Active`. An unknown
or inactive tenant becomes an error rather than an ID that fails later.

Note that `Manager.Resolve` already loads and checks `Active`, so wrapping is
redundant when you go through the manager. It earns its place when a resolver is
used directly — inside a `ChainResolver`, for example, where validating one
branch makes the chain fall through to the next instead of accepting a dead
tenant ID.

---

## Manager

```go
manager := tenant.NewManager(store, resolver)
```

`NewManager` defaults to `RequireTenant: true` and `LoadFullTenant: true`. The
first is the important one: **a request with no resolvable tenant is an error by
default.** Options loosen it:

```go
tenant.WithDefaultTenant("public")   // fallback ID; also sets RequireTenant = false
tenant.WithOptionalTenant()          // no tenant is allowed; Resolve returns (nil, ctx, nil)
tenant.WithLightweight()             // store only the ID in context, not the full struct
tenant.WithHooks(hooks)
```

### Resolve and ResolveFromRequest

```go
func (m *Manager) Resolve(ctx context.Context, info ResolveInfo) (*Tenant, context.Context, error)
func (m *Manager) ResolveFromRequest(ctx context.Context, r *http.Request) (*Tenant, context.Context, error)
```

`ResolveFromRequest` is `Resolve` over `ResolveInfoFromRequest(r)`.

Both return a **new context**. That is the return value that matters — the
tenant travels in it, and every storage call downstream reads it from there.

```go
func (s *server) middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, ctx, err := s.tenants.ResolveFromRequest(r.Context(), r)
        if err != nil {
            http.Error(w, "unknown tenant", http.StatusNotFound)
            return
        }
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Discarding the returned context is the mistake to watch for.** Writing
`t, _, err := m.Resolve(...)` compiles, resolves correctly, and leaves the
tenant out of the context entirely. Every scoped query downstream then fails
with `ErrNoTenant` — loudly, which is the design working, but the cause is a
dropped return value rather than anything about tenancy.

`Resolve` runs seven steps in order: the `BeforeResolve` hook (which can
short-circuit resolution), the resolver, the default tenant ID, the
`RequireTenant` check, loading the tenant from the store, validation, and
putting it in the context. Then `AfterResolve` fires.

Validation is `ValidateTenant` from the hooks if you set one, and otherwise the
`Active` check. Setting the hook **replaces** the `Active` check rather than
adding to it — if your hook does not test `Active`, suspended tenants resolve
successfully.

Under `WithOptionalTenant`, a request with no tenant returns `(nil, ctx, nil)`
with the context unchanged. That is not a failure, and it means scoped queries
in that request will fail closed later. Optional tenancy is for endpoints that
genuinely have no tenant dimension — a health check, a public signup — not for
making the errors go away.

`HTTPMiddleware` and `HTTPMiddlewareFunc` wrap this for `net/http`. They are the
one place in Kayan that touches an `http.Handler`, and they are a convenience:
writing the middleware yourself, as above, is the same six lines and gives you
control of the error response.

### Context helpers

```go
ctx = tenant.WithTenant(ctx, t)           // full struct
ctx = tenant.WithTenantID(ctx, "acme")    // just the ID

t := tenant.FromContext(ctx)              // *Tenant, nil if absent or ID-only
id := tenant.IDFromContext(ctx)           // "" if absent
```

`WithLightweight` makes the manager use `WithTenantID`, which means
`FromContext` returns nil and only `IDFromContext` works. Isolation only needs
the ID, so lightweight mode is enough for enforcement — it costs you the tenant
struct in handlers that wanted `Settings`.

---

## Isolation

Resolution put a tenant in the context. Isolation is what makes that binding.

### Scoped

```go
type Scoped interface {
    TenantID() string
    SetTenantID(id string)
}
```

Implement it on every model that belongs to a tenant:

```go
type User struct {
    ID     string `gorm:"primaryKey"`
    Tenant string `gorm:"index"`
    Email  string
}

func (u *User) TenantID() string      { return u.Tenant }
func (u *User) SetTenantID(id string) { u.Tenant = id }
```

The column name is yours. Kayan reads the interface, not a reserved field.

`SetTenantID` is what an adapter calls before an insert, so a record cannot be
created without a tenant. `TenantID` is what it reads to verify a record on the
way out.

Models that have no tenant dimension — a global feature flag table, a shared
reference list — simply do not implement it, and isolation leaves them alone.
That is a decision worth making per model rather than by default: a table you
forgot to mark as scoped is a table with no isolation at all, and nothing will
tell you.

`tenant.AsScoped(v)` adapts a value implementing either `Scoped` or the
deprecated `TenantAware`. Do not implement `TenantAware` in new code — it had no
call sites, meaning the automatic scoping it advertised did not exist.

### Scoper

```go
type Scoper interface {
    Scope(ctx context.Context, query any) (any, error)
}
```

`Scope` takes an in-progress query and returns it narrowed to the ambient
tenant. The query type is deliberately opaque: a GORM adapter receives a
`*gorm.DB`, a Mongo adapter a filter document, a SQL adapter a builder.
Implementations assert the type they expect.

```go
func (s *mongoScoper) Scope(ctx context.Context, q any) (any, error) {
    filter, ok := q.(bson.M)
    if !ok {
        return nil, fmt.Errorf("expected bson.M, got %T", q)
    }
    id, ok := tenant.RequireID(ctx)
    if !ok {
        return nil, tenant.ErrNoTenant
    }
    filter["tenant_id"] = id
    return filter, nil
}
```

`ScoperFunc` adapts a function for a one-off.

This interface is why the isolation *model* is not fixed. `core/tenant` never
decides whether tenants are separated by a column, a schema, or a database — it
only says the query must be narrowed, and the adapter says how. See
[Isolation models](#isolation-models) below.

### RequireID

```go
func RequireID(ctx context.Context) (string, bool)
```

The second result is `false` when there is no ambient tenant **and** the context
was not marked as a system context. An adapter that gets `false` must fail the
operation, not proceed unscoped:

```go
id, ok := tenant.RequireID(ctx)
if !ok {
    return tenant.ErrNoTenant
}
db = db.Where("tenant_id = ?", id)
```

There is one subtlety worth reading carefully. In a system context `RequireID`
returns `("", true)` — an **empty ID with ok true**. That is not a bug: a system
context deliberately spans tenants, so there is no ID to scope by and the caller
should add no predicate. Code that treats a `true` result as "I have an ID" and
writes `WHERE tenant_id = ''` will match nothing, silently. Branch on
`IsSystemContext` if you need to distinguish, or handle the empty string.

### WithSystemContext

```go
ctx = tenant.WithSystemContext(ctx)
```

Marks the context as a deliberate cross-tenant operation — a platform
administrator listing every tenant, a background job sweeping expired tokens
across the estate.

Isolation fails closed, so genuine cross-tenant work needs a way to say so. It
is a function call rather than an absent value because that makes it
**explicit and greppable**: every place in the codebase that crosses a tenant
boundary can be found with one search, and each one can be reviewed. An implicit
mechanism — "no tenant means all tenants" — would make the dangerous case and
the forgotten case indistinguishable, and it is the forgotten case that leaks.

`tenant.IsSystemContext(ctx)` reports whether it was set.

Treat every call site as security-relevant. A system context on a request-handling
path removes isolation from everything downstream of it, including code you did
not write.

### Verify

```go
func Verify(ctx context.Context, record Scoped) error
```

For adapters that cannot push isolation into the query — a key-value store, a
cache, a lookup by primary key that returned a row before anything could be
filtered. `Verify` checks the record on the way out:

```go
user, err := cache.Get(ctx, id)
if err != nil {
    return nil, err
}
if err := tenant.Verify(ctx, user); err != nil {
    return nil, err
}
return user, nil
```

It returns `nil` in a system context, `ErrNoTenant` when there is no ambient
tenant, and `ErrCrossTenant` when the record belongs to somebody else.

**`ErrCrossTenant` deliberately does not name the record's owning tenant.**
Doing so would confirm the record exists and disclose who has it — a lookup by
guessed ID would become an enumeration oracle over the whole customer base.

### The errors

```go
var ErrNoTenant   = errors.New("tenant: no tenant in context")
var ErrCrossTenant = errors.New("tenant: record belongs to a different tenant")
```

`ErrNoTenant` means the operation could not be scoped. It is a failure, never
"return everything" — silently widening a scoped query is how one customer's
data reaches another.

`ErrCrossTenant` means the operation reached a record outside the boundary.
Treat both as internal errors at the HTTP layer: return 404 or 500, not a
message repeating what the error said. `ErrCrossTenant` in particular tells the
caller that a record with that ID exists.

---

## GORM enforcement

```go
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
if err != nil {
    return err
}

if err := gormstore.RegisterTenantIsolation(db); err != nil {
    return err
}
```

One call at startup. After it:

- reads, updates, and deletes on scoped models gain a tenant predicate;
- inserts are stamped with the ambient tenant;
- a query with no tenant in the context fails rather than running unscoped.

Only models implementing `tenant.Scoped` are affected, so tables with no tenant
dimension are untouched.

### Why a callback and not a predicate per method

Because the one query somebody forgets is the one that leaks.

The alternative shape is a `.Where("tenant_id = ?", id)` in every repository
method. It works, right up until somebody adds a method, or writes a raw query
for a report, or copies an existing method and edits it, or adds a preload that
loads a related table nobody remembered was scoped. Each of those is a one-line
omission that produces no error, no failing test, and no log entry. It returns
another customer's rows and looks exactly like a correct query returning a lot
of results.

A GORM callback runs on every statement of the registered kinds, so the default
is scoped and the exception has to be written down. That inverts which mistake
is possible: forgetting produces an error, and crossing a boundary requires
typing `tenant.WithSystemContext`.

It is the same argument the README makes about parsers — a security check belongs
in the one place that cannot be bypassed, not in documentation asking every
caller to remember it.

### Fails closed

A scoped query with no tenant in the context returns an error. It does not run
unscoped and it does not return an empty result.

Both alternatives are worse than the error. Running unscoped hands every
tenant's rows to a caller who believes they asked a narrow question, which is
the breach. Returning empty is a silent wrong answer that looks like "this
customer has no users" — and it will be believed, because that is a thing that
happens.

This is worth testing in your own deployment, and the test is short:

```go
func TestScopedQueryWithoutTenantFails(t *testing.T) {
    ctx := context.Background()   // deliberately no tenant

    var users []User
    err := db.WithContext(ctx).Find(&users).Error

    if err == nil {
        t.Fatal("scoped query with no tenant returned no error")
    }
    if len(users) != 0 {
        t.Fatalf("scoped query with no tenant returned %d rows", len(users))
    }
}
```

Assert both. A test asserting only `err != nil` can pass for an unrelated
reason, and this repository has had several tests that did.

---

## Isolation models

Row-level isolation — a `tenant_id` column on shared tables — is the default and
what `RegisterTenantIsolation` implements. It is the cheapest to operate: one
schema, one connection pool, one migration to run, and adding a tenant is an
insert.

The two stronger models are reachable by implementing `Scoper` rather than by a
configuration flag, because they change how your application connects to its
database and that is not a decision a library should make for you.

**Schema-per-tenant.** Each tenant gets its own schema in one database. A
`Scoper` sets the search path (Postgres) or qualifies table names for the
resolved tenant. Isolation no longer depends on a predicate being present, which
is a real strength — a query that forgets its scope reads an empty schema rather
than everyone's rows. The cost is that every migration runs N times and DDL
becomes an operational project.

**Database-per-tenant.** Each tenant gets its own database, and a `Scoper`
selects the connection. The strongest separation available: a bug in your query
layer cannot cross a boundary that a network connection does not cross, and a
tenant can be backed up, restored, or moved to its own hardware independently.
The cost is a connection pool per tenant, which puts a ceiling on tenant count,
and cross-tenant reporting stops being a query.

`core/tenant` supports all three because `Scoper.Scope` takes and returns `any`
and never inspects it. The decision belongs to the adapter, and the adapter
belongs to you.

---

## Practical guidance

**Resolve once, at the edge.** One middleware, before anything touches storage.
Resolving deeper means some paths reach storage first, and those paths fail
closed — correctly, but confusingly.

**Pass `r.Context()`, never `context.Background()`.** A fresh context has no
tenant, so every scoped query beneath it fails. This is the most common cause of
an unexpected `ErrNoTenant`, and it is usually a goroutine started from a
handler.

**Background work is a system context or a per-tenant loop.** A worker that
processes a queue has no request to resolve from. Either mark it explicitly with
`WithSystemContext`, or iterate tenants and set `WithTenantID` for each — the
second is safer, because a bug then affects one tenant instead of all of them.

**Index the tenant column.** Every scoped query gains a predicate on it, so
without an index every query in the system does more work than it should.

**Order your resolver chain by trust.** Signed claims first, client-supplied
headers last, and know that anything the client controls is a claim rather than
proof. Resolution decides which tenant a request is about; it does not
authenticate that the caller may act for it.

**Test the cross-tenant case adversarially.** Create two tenants, insert a
record under one, and assert a read under the other returns nothing and an
error. Then revert the isolation registration and confirm the test fails — a
test that passes with the protection removed proves nothing.

---

## Related

- [Getting Started](../getting-started.md) — the shortest multi-tenant wiring
- [BYOS](./byos.md) — why `Scoped` is an interface on your model, not a base struct
- [Storage Layer](../architecture/storage-layer.md) — the adapter contract isolation plugs into
- [Authorization](./authorization.md) — scoping roles and policy per tenant
- [Sessions](./sessions.md) — why every session method takes a context
- [Security Model](../architecture/security-model.md) — what fail-closed isolation defends against
