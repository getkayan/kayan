# Authorization

Authentication answers "who is this." Authorization answers "may they do this."
Kayan ships three models for the second question, because the three answer
genuinely different shapes of question and picking the wrong one produces a
policy nobody can read.

All three implement one interface:

```go
type Engine interface {
    Can(ctx context.Context, subject any, action string, resource any) (bool, error)
}
```

`subject` and `resource` are `any` for the same reason identities are — they are
your types. See [BYOS](./byos.md).

---

## Choosing between them

**RBAC** — permissions attach to roles, roles attach to people. Use it when the
answer depends only on who is asking: an admin may delete users, an editor may
publish. It is the model an administrator can hold in their head, and most of
what a service needs.

Where it stops working is per-object questions. "May Ada edit *this* document"
is not a role question, and the usual workaround — a role per document — turns
into thousands of roles nobody can audit.

**ABAC** — a rule evaluates attributes of the subject, the resource, and the
environment. Use it when the answer depends on the object or the circumstances:
the owner may edit, a manager may approve below their limit, nobody may deploy
outside a change window.

Where it stops working is sharing. "Ada shared this folder with Bob's team, so
Bob can read everything inside it" is a graph, and expressing a graph traversal
inside a boolean rule means loading the graph yourself on every check.

**ReBAC** — permission derives from relationships between entities, following
group memberships and parent-child links. Use it when access is granted by
users to other users, and inherits down a hierarchy. This is the Google Docs
model.

Where it stops working is conditions that are not relationships. Time of day,
IP range, and dollar limits are not edges in a graph.

**Hybrid combines them.** `policy.NewHybridStrategy` takes any number of engines
and a combinator, so "has the role *and* satisfies the rule" is one engine:

```go
hybrid := policy.NewHybridStrategy(policy.DenyOverrides, rbacEngine, abacEngine)
allowed, err := hybrid.Can(ctx, user, "documents:publish", doc)
```

`DenyOverrides` requires every engine to allow — AND, and the default.
`AllowOverrides` needs only one — OR. Reach for `AllowOverrides` carefully: it
means the most permissive engine decides, so adding one later can widen access
everywhere at once.

---

## RBAC

### Roles

```go
type Role struct {
    Name        string
    Permissions []string
    Inherits    []string
    Description string
}
```

`Inherits` names roles whose permissions this role also has:

```go
strategy.DefineRole(&rbac.Role{
    Name:        "viewer",
    Permissions: []string{"docs:read"},
})
strategy.DefineRole(&rbac.Role{
    Name:        "editor",
    Permissions: []string{"docs:write"},
    Inherits:    []string{"viewer"},
})
```

An editor gets `docs:read` without restating it, so the two cannot drift apart
when the viewer grant changes. That drift is the whole reason inheritance
exists — restated permissions get updated in one place and forgotten in the
other, and the forgotten one is usually the more privileged role.

`DefineRole` rejects a definition that would introduce a cycle or name an
undefined parent. The error lands on whoever wrote the definition rather than
surfacing later as an unexplained denial. `rbac.ErrCycle` is the sentinel, and
`MaxInheritanceDepth` (32) bounds how far a pathological chain is followed even
though cycles are detected directly.

**A rejected definition leaves the previous one in place.** Removing it instead
would turn a bad edit into an outage: every identity holding that role would
start failing permission checks at once.

`AddRole` registers a definition *without* validating inheritance. Prefer
`DefineRole`.

### Checking

```go
authz := rbac.NewManager(strategy)

allowed, err := authz.AuthorizePermission(ctx, userID, "docs:write")
allowed, err := authz.Authorize(ctx, userID, "editor")

err := authz.RequirePermission(ctx, userID, "docs:write")
err := authz.RequireRole(ctx, userID, "editor")

roles, err := authz.GetRoles(ctx, userID)
perms, err := authz.GetPermissions(ctx, userID)
```

The `Require*` helpers return an error instead of a boolean, which is the shape
that fits a handler guard. `GetPermissions` includes permissions inherited from
parent roles.

**Always check the error.** A `(bool, error)` pair where the boolean is read and
the error dropped turns a storage failure into a denial — or, if the code is
inverted anywhere, into an allow. This is written down in
[CLAUDE.md](../../CLAUDE.md) as a rule: a wrong `allow` is worse than a crash,
because a crash gets fixed and a silent wrong answer looks identical to a
correct one.

### Wildcards

Permissions are colon-separated segments — `PermissionSeparator` is `":"` — and
they are hierarchical: `billing:invoices:read` names an action within a resource
within a domain.

Two wildcards are honored:

- `*` (`rbac.WildcardSegment`) matches exactly one segment.
- `**` (`rbac.WildcardSuffix`) matches one or more remaining segments, and must
  be the last segment.

```go
rbac.PermissionGranted("users:*", "users:delete")     // true
rbac.PermissionGranted("users:read", "users:delete")  // false
rbac.PermissionGranted("docs:**", "docs:a:b:c")       // true
rbac.PermissionGranted("docs:*", "docs:a:b")          // false — one segment only
rbac.PermissionGranted("*", "anything")               // true
rbac.PermissionGranted("users:read", "users:*")       // false
```

`rbac.AnyPermissionGranted(granted []string, requested string) bool` is the
same test across a slice.

**Wildcards are honored only in the grant, never in the permission being
checked.** That is the last line above, and it is a security property rather
than a convenience. If a wildcard in the *requested* permission matched, a
caller could ask "may I do anything?" — `users:*` — and be told yes because
some narrow grant like `users:read` exists. Every check would then be
satisfiable by finding one unrelated permission the user happens to hold.

**Matching is segment-wise, not a regular expression.** A regex in a permission
string is a denial-of-service vector — a grant written as `(a+)+b` costs an
attacker one string and costs you a pinned CPU on every check. It is also
unclear to whoever writes the grant, since `.` and `*` do not mean what they
look like they mean in a permission.

Segments are compared case-sensitively. `Admin` and `admin` being the same
permission is a surprise nobody asked for, and case-insensitive matching in an
authorization system is how a grant intended for one thing quietly covers
another.

### MemoryStrategy and StorageStrategy

```go
strategy := rbac.NewMemoryStrategy()
strategy.DefineRole(&rbac.Role{Name: "editor", Permissions: []string{"docs:write"}})
strategy.AssignRole(userID, "editor")
```

`MemoryStrategy` holds both role definitions and assignments in process memory.
It is correct for a single instance, and it is what the getting-started example
uses.

`AssignRole` returns an error when the role has no definition, so a typo
surfaces where it was made rather than as an unexplained denial three weeks
later. `UnassignRole` removes one. (`RevokeRole` is the deprecated spelling of
`UnassignRole`.)

For more than one replica:

```go
strategy := rbac.NewStorageStrategy(assignments, roles)
```

```go
type RBACStorage interface {
    GetIdentityRoles(ctx context.Context, identityID any) ([]string, error)
    SetIdentityRoles(ctx context.Context, identityID any, roles []string) error
}

type RoleStore interface {
    GetRole(ctx context.Context, name string) (*Role, error)
    SaveRole(ctx context.Context, role *Role) error
    DeleteRole(ctx context.Context, name string) error
    ListRoles(ctx context.Context) ([]*Role, error)
}
```

**Both halves live in storage, and that is the point.** An earlier version of
`StorageStrategy` read assignments from storage but kept role *definitions* in
process memory. A role created on one replica was unknown to every other, and a
permission check there returned `false` with no error.

That is the worst available failure. A silent wrong denial in a permission
system reports nothing, looks identical to a legitimate refusal, and its
behavior depends on which replica served the request — so it reproduces one
time in four and gets closed as unreproducible.

`MemoryStrategy` also implements `RoleStore` (`GetRole`, `SaveRole`,
`DeleteRole`, `ListRoles`), so it can be used as the definition store in tests
against a real assignment store.

### ErrRoleNotFound

```go
var ErrRoleNotFound = errors.New("rbac: role is not defined")
```

An assignment naming a role with no definition is an error, not a silent
denial. The two cases need different responses: a legitimate refusal is a 403
and a broken configuration is a page. Returning `false, nil` for both means the
second never gets fixed, because nothing distinguishes it from the first.

### BasicStrategy

```go
strategy := rbac.NewBasicStrategy(loader)
```

`BasicStrategy` reads roles and permissions off the subject itself, through the
`RoleSource` and `PermissionSource` interfaces:

```go
type RoleSource interface {
    GetRoles() []string
}

type PermissionSource interface {
    GetPermissions() []string
}
```

Its `IdentityLoader` fetches the subject when only an ID is available. It also
implements `policy.Engine` — note that `Can(ctx, id, action, resource)`
interprets `action` as a **role name**, not a permission, and ignores
`resource`. That asymmetry with the other engines is worth knowing before you
compose it into a hybrid: `Can(ctx, id, "docs:write", doc)` on a `BasicStrategy`
asks whether the user holds a role literally named `docs:write`.

---

## ABAC

```go
engine := policy.NewABACStrategy()

engine.AddRule("documents:read", func(ctx context.Context, subject, resource any, pCtx policy.Context) (bool, error) {
    user, ok := subject.(*User)
    if !ok {
        return false, fmt.Errorf("policy: expected *User, got %T", subject)
    }
    doc, ok := resource.(*Document)
    if !ok {
        return false, fmt.Errorf("policy: expected *Document, got %T", resource)
    }
    return doc.OwnerID == user.ID || user.Role == "admin", nil
})

allowed, err := engine.Can(ctx, user, "documents:read", doc)
```

The rule type:

```go
type Rule func(ctx context.Context, subject any, resource any, context Context) (bool, error)

type Context map[string]any
```

`policy.Context` carries environmental data a rule needs but cannot read from
the subject or resource — source address, time of day, request headers. Put it
in the context with `policy.WithContext(ctx, pCtx)` and the engine passes it to
the rule.

Return the error rather than `false` when a type assertion fails. `false, nil`
from a broken rule is indistinguishable from a considered denial, and the rule
will be broken for as long as nobody notices the denials.

### Rules are Go closures, and that is a real limitation

An ABAC rule is compiled code. It is not data, and this has consequences worth
stating plainly rather than discovering:

**Policy changes require a deploy.** You cannot add a rule from an admin
interface, roll one back without shipping a binary, or let a customer supply
their own. If your product needs runtime-editable policy, ABAC as shipped will
not give it to you — you need a policy language interpreter, and Kayan does not
include one.

**Policies cannot be analyzed.** There is no way to ask "which rules grant
`documents:delete`," to diff two policy versions, or to prove two rules do not
conflict. A rule is an opaque function; the only thing you can do with it is
run it.

**A rule can do anything a Go function can do.** It can query a database, call a
service, or block. There is no timeout, no sandbox, and no resource bound — a
rule that makes a network call adds that latency to every authorization check on
that action, and a rule that hangs hangs the request.

**One rule per action.** `AddRule` stores rules in a map keyed on the action
string, so registering a second rule for the same action replaces the first
rather than combining them. If you want "owner *or* admin *or* on the ACL," that
is one function with three branches, not three registrations. Composing several
independent rule sets is what `HybridStrategy` is for.

What you get in exchange is that a rule is ordinary Go: it type-checks, it is
testable with a normal unit test, it can be stepped through in a debugger, and
it has no expression language whose evaluation semantics you have to learn. For
a policy set that changes at the speed of your deploys, that is the better
trade. For one that changes at the speed of your customers, it is not.

---

## ReBAC

ReBAC stores relationships as tuples and derives permission by walking them.
The design follows Google Zanzibar.

```go
type Tuple struct {
    Subject  SubjectRef
    Relation string
    Object   ObjectRef
}

type ObjectRef struct {
    Type string
    ID   string
}

type SubjectRef struct {
    Object   ObjectRef
    Relation string   // set for usersets like "group:eng#member"
}
```

A tuple reads "subject has relation to object" and prints as
`subject#relation@object`.

```go
mgr := rebac.NewManager(rebac.NewMemoryStore())

// Alice is a viewer of document 123.
err := mgr.Grant(ctx, "user", "alice", "viewer", "document", "123")

// Every member of the engineering group is a viewer of document 123.
err = mgr.GrantUserset(ctx, "group", "engineering", "member", "viewer", "document", "123")

// Bob is in that group.
err = mgr.AddToGroup(ctx, "bob", "engineering")

// Document 123 lives in folder home.
err = mgr.SetParent(ctx, "folder", "home", "document", "123")
```

`Revoke`, `RevokeUserset`, and `RemoveFromGroup` undo each of those.
`GetParent(ctx, childType, childID)` returns the parent.

### Check

```go
allowed, err := mgr.Check(ctx, "user", "bob", "viewer", "document", "123")
err := mgr.RequirePermission(ctx, "user", "bob", "viewer", "document", "123")
```

`Check` traverses the graph: direct tuples, userset expansion (group
membership), computed relations (role inheritance), and tuple-to-userset
(inheriting from a parent object). Bob above is allowed through the group even
though no tuple names him and the document directly.

`Manager` also implements `policy.Engine`:

```go
allowed, err := mgr.Can(ctx,
    rebac.SubjectInfo{Type: "user", ID: "alice"},
    "viewer",
    rebac.ResourceInfo{Type: "document", ID: "123"},
)
```

Bare strings work through `DefaultSubjectExtractor` and
`DefaultObjectExtractor`, defaulting the type to `user` for the subject and
treating the string as an ID for the resource. Prefer `SubjectInfo` and
`ResourceInfo` — an implicit type default in an authorization call is the kind
of thing that is right until somebody introduces a second subject type.

### Schemas and computed relations

```go
mgr := rebac.NewManager(store, rebac.WithSchema(rebac.Schema{
    Type: "document",
    Relations: map[string]rebac.RelationConfig{
        "owner":  {Name: "owner", DirectAllowed: true},
        "editor": {Name: "editor", DirectAllowed: true, ComputedFrom: []rebac.ComputedRule{
            {Relation: "owner"},
        }},
        "viewer": {Name: "viewer", DirectAllowed: true, ComputedFrom: []rebac.ComputedRule{
            {Relation: "editor"},
            {TupleToUserset: &rebac.TupleToUserset{
                TuplesetRelation: "parent",
                ComputedRelation: "viewer",
            }},
        }},
    },
}))
```

An owner is an editor is a viewer, and a viewer of the parent folder is a
viewer of the document. `WithMaxDepth` on the `Checker` bounds traversal;
`DefaultMaxDepth` is 25.

### ListDirectObjects does not walk the graph

This is the most important limitation in the package, and it is listed in the
root [README](../../README.md) as a known gap.

```go
objects, err := mgr.ListDirectObjects(ctx, "user", "bob", "viewer", "document")
```

It returns objects related to the subject **by a stored tuple**. It does not
traverse. Access granted through group membership, a computed relation, or a
parent object is not in the result — so Bob above, who `Check` allows on
document 123 through the engineering group, does not appear.

`ListDirectSubjects(ctx, relation, objectType, objectID)` has the same
limitation, and additionally returns usersets like `group:eng#member` rather
than the individual users they expand to.

**The consequence, stated concretely:** if you build a document list by calling
`ListDirectObjects` and rendering the result, users will not see documents they
have legitimate access to. That is an under-permissive failure — annoying rather
than dangerous — but the inverse mistake is worse. Do not use the absence of an
object from this list to conclude access does not exist, and do not use it as
a permission check. Filter a candidate list with `Check` instead:

```go
var visible []Document
for _, doc := range candidates {
    ok, err := mgr.Check(ctx, "user", userID, "viewer", "document", doc.ID)
    if err != nil {
        return nil, err
    }
    if ok {
        visible = append(visible, doc)
    }
}
```

That is a check per candidate, which is why a traversing implementation is
planned. Until it exists, the method carries the narrower name so the limitation
is visible at the call site rather than in a paragraph somebody did not read.

**`Check` is the authoritative answer.** It evaluates the full graph.

### Stores

`rebac.NewMemoryStore()` implements `Store` in process memory — fine for tests,
development, and a single instance, and it loses every tuple on restart, which
in a ReBAC system means everyone loses access to everything.

`gormstore.NewReBACRepository(db)` is the persistent implementation.

---

## Middleware

Both middlewares implement `Engine` and wrap an `Engine`, so they compose in any
order with each other and with `HybridStrategy`.

### Caching

```go
cached := policy.NewCachingMiddleware(engine, 30*time.Second,
    policy.WithMaxCacheEntries(10_000),
)

allowed, err := cached.Can(ctx, user, "documents:read", doc)
cached.Invalidate()   // clears everything
```

An authorization decision is often the most repeated computation in a request —
the same user against the same resource, several times per page. Caching it for
a few seconds removes most of that.

The cost is staleness. A permission revoked at second zero is still honored
until the TTL expires. Pick the TTL as how long you are willing for a revocation
to take effect, and treat `Invalidate()` as the tool for the cases where that
is too long. Note that `Invalidate` clears the whole cache; there is no
per-subject invalidation.

`WithMaxCacheEntries` bounds the map, defaulting to
`policy.DefaultMaxCacheEntries` (10,000). A value of zero or less disables the
bound, which lets the cache grow without limit — that is an out-of-memory
condition driven by request volume, so leave the bound on unless you have a
specific reason. `WithCacheClock` swaps the clock for tests.

### CacheKeyer, and why unkeyable subjects pass through

```go
type CacheKeyer interface {
    CacheKey() string
}
```

The middleware caches a decision only when it can build an unambiguous key for
both the subject and the resource. Anything it cannot key **passes straight
through to the wrapped engine, uncached**.

The alternative was worse. To cache `Can(ctx, subject, action, resource)` the
middleware needs a string identifying the subject and the resource, and the
only things available for an arbitrary `any` are its pointer address or a
reflective dump. A pointer address is reused after a garbage collection, so two
different users can share a key — and a cache hit under the wrong key is a
wrong authorization decision, returned with no error, for the TTL's duration.
That is the exact failure [CLAUDE.md](../../CLAUDE.md) names as worse than a
crash.

So the middleware requires the type to say what identifies it:

```go
func (u *User) CacheKey() string { return "user:" + u.ID + ":" + u.Role }
```

**The key must cover everything the decision depends on.** The `Role` in that
example is there because the ABAC rule earlier in this document reads
`user.Role` — a key of just `"user:" + u.ID` would serve a cached admin
decision to the same user after their role was downgraded. If a decision depends
on a mutable field, the field belongs in the key, or the TTL is your only
protection.

The key must also be stable for the same logical entity across requests. A
freshly loaded `*User` for the same person must produce the same string, or you
have a cache that never hits.

Silently degrading to uncached is deliberate: a type that has not opted in gets
correct answers at full cost, and the fix — implement `CacheKeyer` — is
additive. Failing the call instead would make adding caching a breaking change
for every type in the system.

**The cache is in-process.** Several replicas each keep their own, so a
revocation takes effect at different times on each. A deployment that needs
shared caching wraps a shared cache in its own `Engine`.

### Audit

```go
audited := policy.NewAuditMiddleware(engine, auditStore,
    policy.WithAuditErrorHandler(func(err error) {
        log.Printf("audit: %v", err)
    }),
)
```

Every decision is recorded. By default the write happens inline, so the request
waits for the store — slower, but the trail is complete.

```go
audited := policy.NewAuditMiddleware(engine, auditStore,
    policy.WithAsyncAudit(),
    policy.WithAuditConcurrency(64),
    policy.WithAuditErrorHandler(reportErr),
)

// During shutdown:
if err := audited.Wait(ctx); err != nil {
    log.Printf("audit flush: %v", err)
}
```

`WithAsyncAudit` moves the write to a background goroutine, bounded by
`WithAuditConcurrency` (default `policy.DefaultAuditConcurrency`, 64). When the
bound is reached the default is to fall back to writing inline, which slows the
request but keeps the record. `WithAuditDropWhenSaturated` discards instead —
choose it only where losing audit records is acceptable, which for most
compliance regimes it is not.

**Call `Wait` during shutdown.** Records still in flight are lost when the
process exits, and a deployment that restarts frequently loses a slice of its
audit trail on every deploy.

**Set an error handler.** Without one, audit write failures are invisible: the
authorization decision still returns, and nothing records that it happened. An
audit trail with silent gaps is worse than no audit trail, because it is
believed.

---

## Ordering the middleware

```go
engine := policy.NewAuditMiddleware(
    policy.NewCachingMiddleware(base, 30*time.Second),
    auditStore,
)
```

Audit outside caching records every decision, including the ones served from
cache. That is usually what you want — the audit question is "what did the
application decide," not "what did the base engine compute."

Caching outside audit records only cache misses, so the trail undercounts. If
you specifically want to measure how often the base engine runs, that is the
order; for compliance, it is the wrong one.

---

## Related

- [Getting Started](../getting-started.md) — the shortest RBAC path
- [Authorization Models](../architecture/authorization-models.md) — how the three engines are built
- [Multi-Tenancy](./multi-tenancy.md) — scoping authorization data per tenant
- [BYOS](./byos.md) — why subject and resource are `any`
- [Security Model](../architecture/security-model.md) — what these controls defend against
