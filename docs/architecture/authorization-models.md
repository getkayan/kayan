# Authorization Models

Kayan ships four authorization engines rather than one. They are not layers of
a single abstraction and they do not share a permission vocabulary. RBAC speaks
in colon-segmented permission strings, ABAC dispatches on an exact action key,
and ReBAC speaks in `type:id#relation@type:id` tuples. The only thing that
unifies them is `policy.Engine`, and it unifies them at a deliberately thin
level: `Can(ctx, subject any, action string, resource any) (bool, error)`.

This document describes how each one actually evaluates a request, including
the parts that are easy to get wrong: what happens on a cycle, what happens at
the depth cap, and which failures are errors rather than denials.

The governing rule across all four is stated in
[AGENTS.md](../../AGENTS.md): **a wrong `allow` is worse than a crash, and a
silent wrong `deny` is nearly as bad.** An authorization path that fails loudly
can be fixed. One that silently denies looks identical to a legitimate refusal
and its behavior may depend on which replica served the request. Several design
choices below only make sense in that light — most visibly `ErrRoleNotFound`,
which turns a broken role definition into a reported error instead of an empty
permission set.

---

## The common contract

`core/policy/engine.go` defines the whole of the shared surface:

```go
type Engine interface {
    // Can checks if the subject can perform the action on the resource within
    // the given context.
    Can(ctx context.Context, subject any, action string, resource any) (bool, error)
}
```

`subject` and `resource` are `any`, not named types. That is the BYOS rule
applied to authorization: your user struct and your resource struct are yours,
and the engine does not require them to embed or implement anything. The
consequence is that each engine asserts what it needs at its own boundary, and
a mismatch is a runtime error rather than a compile error.

Two auxiliary types live alongside it:

```go
type Context map[string]any
type Factory func(config map[string]any) (Engine, error)
```

`policy.Context` is the attribute bag ABAC rules read. It travels through the
Go context rather than through the `Can` signature, which is discussed below.

Note that `rbac.Manager` does **not** implement `policy.Engine`. Its methods are
`Authorize`, `RequireRole`, `AuthorizePermission`, `RequirePermission`,
`GetRoles`, and `GetPermissions`. The `Can` method in the RBAC package belongs
to `rbac.BasicStrategy`. `rebac.Manager` does implement `Can`. This asymmetry
matters when composing a hybrid engine, because only things with `Can` can be
passed to `NewHybridStrategy`.

---

## RBAC

### The pieces

`core/rbac` separates three concerns that are frequently conflated: what a role
*is*, who *holds* a role, and how a question gets *asked*.

A role definition is data:

```go
type Role struct {
    Name        string
    Permissions []string

    // Inherits names roles whose permissions this role also has. An admin
    // inheriting from editor gets every editor permission without restating
    // them, so the two cannot drift apart.
    Inherits []string

    Description string
}
```

Assignment and lookup sit behind `Strategy`, which is the interface everything
else is written against:

```go
type Strategy interface {
    HasRole(ctx context.Context, identityID any, role string) (bool, error)
    GetRoles(ctx context.Context, identityID any) ([]string, error)
    HasPermission(ctx context.Context, identityID any, permission string) (bool, error)
    GetPermissions(ctx context.Context, identityID any) ([]string, error)
}
```

Every method takes `ctx` for the reason given in
[AGENTS.md](../../AGENTS.md): the ambient tenant lives there, and a role lookup
that cannot see the tenant cannot be tenant-scoped.

Two implementations ship:

```go
func NewMemoryStrategy() *MemoryStrategy
func NewStorageStrategy(assignments RBACStorage, roles RoleStore) *StorageStrategy
```

`NewMemoryStrategy` takes no arguments and keeps everything in process memory.
It satisfies both `Strategy` and `RoleStore`. It is correct for a single
instance and wrong for several: each replica holds its own map, so a role
defined on one is undefined on the others, and the same request gets different
answers depending on where it lands. `NewStorageStrategy` splits the two
concerns it needs across separate interfaces:

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

`rbac.Manager` is a thin dispatcher over a `Strategy`:

```go
func NewManager(strategy Strategy) *Manager

func (m *Manager) Authorize(ctx context.Context, identityID any, role string) (bool, error)
func (m *Manager) RequireRole(ctx context.Context, identityID any, role string) error
func (m *Manager) AuthorizePermission(ctx context.Context, identityID any, permission string) (bool, error)
func (m *Manager) RequirePermission(ctx context.Context, identityID any, permission string) error
func (m *Manager) GetRoles(ctx context.Context, identityID any) ([]string, error)
func (m *Manager) GetPermissions(ctx context.Context, identityID any) ([]string, error)
```

The `Authorize`/`Require` pairing exists because the two call sites want
different things. `Authorize` returns a boolean for code that branches on it;
`Require` returns an error for code that wants to abort. A nil strategy is
reported (`rbac strategy not configured`) rather than treated as a universal
deny, on the same principle: a misconfiguration should not be indistinguishable
from a legitimate refusal.

### Inheritance resolution

Permissions resolve by recursive depth-first traversal of the `Inherits` graph,
in `core/rbac/role.go`:

```go
func resolvePermissions(
    ctx context.Context,
    store RoleStore,
    name string,
    visiting map[string]bool,
    depth int,
) ([]string, error) {
    if depth > MaxInheritanceDepth {
        return nil, fmt.Errorf("%w: %q exceeds depth %d", ErrCycle, name, MaxInheritanceDepth)
    }
    if visiting[name] {
        return nil, fmt.Errorf("%w: %q", ErrCycle, name)
    }

    role, err := store.GetRole(ctx, name)
    if err != nil {
        return nil, err
    }

    visiting[name] = true
    defer delete(visiting, name)

    permissions := make([]string, 0, len(role.Permissions))
    permissions = append(permissions, role.Permissions...)

    for _, parent := range role.Inherits {
        inherited, err := resolvePermissions(ctx, store, parent, visiting, depth+1)
        if err != nil {
            // A missing parent is a broken definition, not an absence of
            // permission. Reporting it lets an operator fix the role instead
            // of debugging a mysterious denial.
            return nil, fmt.Errorf("rbac: role %q inherits %q: %w", name, parent, err)
        }
        permissions = append(permissions, inherited...)
    }

    return permissions, nil
}
```

Three details are load-bearing.

**`visiting` is a path set, not a global visited set.** Entries are removed by
`defer delete(visiting, name)` as each frame unwinds, so it tracks the current
root-to-node path rather than everything seen. A diamond — two roles that both
inherit from `base` — is therefore traversed twice rather than pruned, and only
a genuine back-edge on the current path is reported as a cycle. Traversing a
diamond twice costs duplicate permission strings, which callers remove with an
order-preserving `dedupe`. Pruning it instead would be faster but would make
cycle detection depend on traversal order, which is the kind of subtlety that
produces a permission that exists on Tuesday and not on Wednesday.

**The depth cap is `MaxInheritanceDepth = 32`**, checked as
`depth > MaxInheritanceDepth`. Both a cycle and an over-deep chain return an
error wrapping `ErrCycle`, so `errors.Is(err, ErrCycle)` cannot tell them
apart. That is a real if minor wart: the two have different fixes.

**A missing parent is an error, not an empty set.** This is the single most
consequential decision in the package and it propagates all the way out.

### `ErrRoleNotFound` rather than silent denial

```go
var (
    ErrRoleNotFound = errors.New("rbac: role is not defined")
    ErrCycle        = errors.New("rbac: role inheritance contains a cycle")
)
```

`ErrRoleNotFound` originates in exactly two places, both in
`core/rbac/memory_strategy.go`: `GetRole` when the definition is absent, and
`AssignRole` when the role being assigned has never been defined. The second is
worth noting — a typo in a role name surfaces at assignment time rather than
silently creating a user who holds a role that grants nothing.

When an assignment survives the deletion of its definition, the error surfaces
on the read path instead. `GetPermissions` and `HasPermission` wrap it as
`rbac: identity holds role %q: %w`, and `resolvePermissions` wraps a dangling
parent as `rbac: role %q inherits %q: %w`.

The alternative — treating an undefined role as contributing no permissions —
is what most implementations do, and it is wrong for the reason
[getting-started.md](../getting-started.md) gives: the two cases need different
responses. A legitimate refusal means the user should not have access. A
dangling role assignment means the configuration is broken and the answer
cannot be trusted in either direction. Collapsing them into `false` hides the
second behind the first, and the resulting production incident presents as
"permissions randomly stopped working."

`StorageStrategy` never constructs `ErrRoleNotFound` itself; it relies on the
injected `RoleStore` to return it. A custom `RoleStore` that returns
`(nil, nil)` for a missing role, or a bare `sql.ErrNoRows` that nothing checks,
reintroduces exactly the silent-denial behavior this design exists to prevent.
If you implement `RoleStore`, return `rbac.ErrRoleNotFound`.

Both `DefineRole` implementations validate on write and roll back on failure.
`MemoryStrategy.DefineRole` saves the definition, resolves it, and on error
restores the previous definition (or deletes it if there was none);
`StorageStrategy.DefineRole` does the same through the store. So a role that
introduces a cycle is rejected at definition time rather than at the first
check. `MemoryStrategy.AddRole` deliberately bypasses this validation and is
documented as doing so.

### Wildcard permission matching

Matching is segment-based string comparison, not a regular expression. From
`core/rbac/permission.go`:

```go
func PermissionGranted(granted, requested string) bool {
    if granted == "" || requested == "" {
        return false
    }
    if granted == requested {
        return true
    }

    // A wildcard in the request would let a caller probe for any permission at
    // all. Only a grant may widen.
    if strings.Contains(requested, WildcardSegment) {
        return false
    }

    grantedParts := strings.Split(granted, PermissionSeparator)
    requestedParts := strings.Split(requested, PermissionSeparator)

    for i, part := range grantedParts {
        if part == WildcardSuffix {
            // "**" must be last, and covers every remaining segment. It
            // matches at least one, so "docs:**" does not grant bare "docs".
            return i == len(grantedParts)-1 && i < len(requestedParts)
        }

        if i >= len(requestedParts) {
            // The grant is more specific than the request: "users:read:own"
            // does not grant "users:read".
            return false
        }
        if part == WildcardSegment {
            continue
        }
        if part != requestedParts[i] {
            return false
        }
    }

    // Every granted segment matched; the request must not have more.
    return len(grantedParts) == len(requestedParts)
}
```

The constants are `PermissionSeparator = ":"`, `WildcardSegment = "*"`, and
`WildcardSuffix = "**"`.

Precise semantics:

- `*` matches **exactly one** segment. `docs:*` grants `docs:read` but not
  `docs:a:b`, because the trailing length check rejects the extra segment.
- `**` matches **one or more** trailing segments and must be the final segment
  of the grant. `docs:**` grants `docs:a:b:c` but **not** bare `docs` — the
  `i < len(requestedParts)` clause requires at least one segment to consume.
  A `**` that is not last fails the match outright rather than being treated as
  `*`.
- **A wildcard in the requested permission is refused.** Without that guard, a
  caller could ask "may I do `docs:*`?" and be told yes because some narrow
  grant happened to match, converting a specific grant into a general one.
  Note the exact shape: the guard is `strings.Contains(requested, "*")`, so any
  `*` anywhere in the requested string — even as a literal substring — returns
  false. It sits *after* the `granted == requested` fast path, so an exactly
  identical string still matches: `PermissionGranted("users:*", "users:*")` is
  true.
- Matching is **case-sensitive**. `users:Read` does not satisfy `users:read`.

Regular expressions were rejected for two reasons. A regex in a permission
string is a denial-of-service vector — a grant is attacker-influenced data in
any system where roles can be authored — and the semantics of a regex are
unclear to whoever writes the grant, which is precisely the population that
must get it right.

`AnyPermissionGranted(granted []string, requested string) bool` is a plain
disjunction over a slice of grants.

---

## ABAC

`core/policy/abac.go` is the smallest engine in the library. A rule is a Go
function, not a struct and not a serialized policy document:

```go
type Rule func(ctx context.Context, subject any, resource any, context Context) (bool, error)

type ABACStrategy struct {
    mu    sync.RWMutex
    rules map[string]Rule
}

func NewABACStrategy() *ABACStrategy
func (s *ABACStrategy) AddRule(action string, rule Rule)
func (s *ABACStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
```

### Dispatch

Rules live in a `map[string]Rule` keyed by the **exact action string**.
Dispatch is a single map lookup:

```go
    s.mu.RLock()
    rule, ok := s.rules[action]
    s.mu.RUnlock()

    if !ok {
        return false, nil
    }
```

This has consequences worth stating plainly, because they differ sharply from
RBAC:

- **There is no wildcard matching on the action key.** `docs:*` registered as an
  ABAC action matches only the literal string `docs:*`. The segment matcher
  described above belongs to RBAC and is not used here.
- **At most one rule runs per call.** There is no rule list, no evaluation
  order, and therefore no conflict resolution inside ABAC. Combining rules is
  the caller's job — either inside a single Go function, or by composing
  several engines through `HybridStrategy`.
- **`AddRule` overwrites silently.** Registering two rules for the same action
  keeps the last one, with no error and no warning. Registering rules at
  startup, in one place, avoids the class of bug where a later registration
  quietly relaxes an earlier one.
- **No match is a default deny, and it is `(false, nil)` — a denial, not an
  error.** An action with no registered rule is refused. Because it returns nil
  error, a typo'd action name is indistinguishable at the call site from a
  deliberate refusal. If that distinction matters in your deployment, assert at
  startup that every action you intend to authorize has a registered rule.

### The attribute context

`policy.Context` reaches the rule through the Go context rather than through
the `Can` signature:

```go
type Context map[string]any

func WithContext(ctx context.Context, pctx Context) context.Context
```

`Can` extracts it and substitutes an empty map when it is absent or the wrong
type, so a rule never receives a nil map and never needs a nil check. The
tradeoff is that a missing attribute is an absent key rather than a compile
error: a rule reading `context["region"]` from a request where nobody called
`WithContext` sees the zero value and will typically deny. That is the safe
direction, but it is silent, so rules that depend on an attribute should check
for its presence explicitly rather than relying on a zero value to mean
"absent."

Because rules are ordinary Go functions, they can read anything reachable from
their four parameters: subject traits, resource attributes, the ambient tenant
in `ctx`, and whatever device or risk metadata the caller placed in the
`policy.Context`. They are also ordinary Go code for testing purposes, which is
the main argument for this shape over a policy DSL.

**ABAC policies are compiled, not data.** Changing a rule means changing Go
code and redeploying. There is no policy store, no hot reload, and no way for
an administrator to author a rule at runtime. This is a real limitation if your
requirements include tenant-authored policy — that use case needs a policy
language and an evaluator, and Kayan does not provide one. What it provides is
the `Engine` seam: an engine backed by Cedar, OPA, or a custom interpreter
implements the same one-method interface and composes with everything here.

---

## Hybrid

`core/policy/hybrid.go` composes any set of engines under one of two
combinators:

```go
type Combinator int

const (
    DenyOverrides Combinator = iota
    AllowOverrides
)

type HybridStrategy struct {
    engines    []Engine
    combinator Combinator
}

func NewHybridStrategy(c Combinator, engines ...Engine) *HybridStrategy
func (s *HybridStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
```

`HybridStrategy` knows nothing about RBAC or ABAC specifically. It composes
`[]Engine`, and you build the common "role grants the capability, attributes
narrow it" pattern by passing an RBAC-backed engine and an `ABACStrategy` in
the order you want them evaluated.

The combinator is a required first argument. `DenyOverrides` is the zero value
of the `Combinator` type, but there is no defaulting logic — you always state
it.

**`DenyOverrides` is conjunction.** Engines are evaluated in slice order. The
first error short-circuits and is returned as `(false, err)`; the first
`!allowed` short-circuits and returns `(false, nil)`; all-allow returns
`(true, nil)`. This is the combinator to use for the entitlement-then-context
pattern, and it is the one to reach for by default: an engine that fails
loudly denies the request rather than being skipped.

**`AllowOverrides` is disjunction, and it swallows errors.** It returns true on
the first engine that returns `err == nil && allowed`, and an engine that
returns an error is passed over as though it had returned false. That is a
sharp edge worth stating directly: under `AllowOverrides`, a
storage-backed engine whose database is unreachable does not fail the request —
it is silently skipped, and the decision falls to the remaining engines. If one
of those grants access, an unavailable engine has been treated as a
non-objection. Use `AllowOverrides` only when every engine in the set is
in-process and cannot fail for infrastructure reasons.

An empty engine list is an error (`hybrid: no engines configured`) rather than
a deny, and an unrecognized combinator value is likewise an error.

### Middlewares

Two `Engine` decorators live in `core/policy/middleware.go`, and because they
implement `Engine` they compose anywhere an engine is accepted, including
inside a `HybridStrategy`.

`AuditMiddleware` wraps an engine and records every decision as an
`audit.AuditEvent` of type `policy.decision` with status allowed, denied, or
error. Writes are dispatched asynchronously with bounded concurrency
(`DefaultAuditConcurrency = 64`), and `Wait(ctx)` drains outstanding writes —
call it before shutdown or the last decisions of a process are lost.

`CachingMiddleware` memoizes decisions for a TTL, keyed by a length-prefixed
SHA-256 of the decision inputs, bounded by `DefaultMaxCacheEntries = 10_000`.
Length-prefixing the key components matters: without it, distinct inputs can
serialize to the same byte string and one subject's decision can be served to
another. Values that cannot be keyed **bypass** the cache entirely rather than
being keyed approximately, which is the fail-safe direction — a cache miss
costs latency, a wrong key costs a wrong `allow`. `Invalidate()` clears it,
which you must call when roles or rules change, since neither the RBAC strategy
nor the ABAC rule map notifies the cache.

---

## ReBAC

`core/rebac` answers "is this subject related to this object?" by walking a
graph of stored relationship tuples.

### The vocabulary

```go
type ObjectRef struct {
    Type string
    ID   string
}

type SubjectRef struct {
    Object   ObjectRef
    Relation string // Optional: for usersets like "group:eng#member"
}

func (s SubjectRef) IsUserset() bool { return s.Relation != "" }

type Tuple struct {
    Subject  SubjectRef
    Relation string
    Object   ObjectRef
}
```

A tuple prints as `user:alice#viewer@document:123`. When the subject carries a
relation of its own it is a *userset* — `group:eng#member` denotes "every
member of the engineering group" rather than a single principal, and that
indirection is what lets a grant to a group apply to its members without
enumerating them.

Schemas describe relations that are not stored directly:

```go
type RelationConfig struct {
    Name          string
    DirectAllowed bool
    ComputedFrom  []ComputedRule
}

type ComputedRule struct {
    Relation       string
    TupleToUserset *TupleToUserset
}

type TupleToUserset struct {
    TuplesetRelation string // The relation to follow (e.g., "parent")
    ComputedRelation string // The relation to check on the target (e.g., "viewer")
}

type Schema struct {
    Type      string
    Relations map[string]RelationConfig
}
```

`ComputedRule.Relation` expresses implication within one object — an owner is
also an editor. `TupleToUserset` expresses inheritance across objects — a
document's viewers include its parent folder's viewers.

One caveat: `DirectAllowed` is declared but never read by the checker. It is
inert metadata today, so setting it to `false` does not prevent a direct tuple
from granting access. Do not rely on it as a control.

Persistence is behind `Store`, with six methods: `WriteTuple`, `WriteTuples`,
`DeleteTuple`, `DeleteTuples`, `ReadTuples`, and `TupleExists`. The bundled
`MemoryStore` is a flat `[]Tuple` with linear scans on every operation. It is a
correctness reference, not a production store: every `ReadTuples` walks the
entire slice, and traversal issues many of them.

### The traversal

```go
func (c *Checker) Check(ctx context.Context, subject SubjectRef, relation string, object ObjectRef) (bool, error) {
    return c.checkWithDepth(ctx, subject, relation, object, 0, make(map[string]bool))
}

func (c *Checker) checkWithDepth(ctx context.Context, subject SubjectRef, relation string, object ObjectRef, depth int, visited map[string]bool) (bool, error) {
    // Prevent infinite recursion
    if depth > c.maxDepth {
        return false, fmt.Errorf("rebac: max recursion depth exceeded")
    }

    // Cycle detection
    key := fmt.Sprintf("%s#%s@%s", subject.String(), relation, object.String())
    if visited[key] {
        return false, nil
    }
    visited[key] = true

    // Step 1: Check for direct tuple match
    // Step 2: If subject is direct (not userset), check usersets
    // Step 3: Check computed relations (from schema)
}
```

It is a **recursive depth-first search** that short-circuits on the first
`true`. Each node is evaluated in a fixed three-step order:

1. **Direct tuple.** A single `store.TupleExists` for the exact triple.
2. **Userset expansion.** Only when the subject is not itself a userset. Reads
   every tuple on `(relation, object)`, skips non-userset subjects, and for
   each userset asks recursively whether the subject holds that userset's
   relation on that userset's object. This is what makes a grant to
   `group:eng#member` reach Alice.
3. **Computed relations.** If a schema is registered for the object's type and
   defines the relation, each `ComputedRule` is tried in slice order, with
   `Relation` before `TupleToUserset` within a rule. `TupleToUserset` reads the
   tupleset relation on the object, takes the related object from the tuple's
   *subject* position, and recurses on the computed relation there.

Each hop costs one level of depth.

### Cycle detection and the depth cap

**Cycle detection** uses `visited map[string]bool`, keyed on the full check
triple — subject, relation, and object together. A revisit returns
`(false, nil)`.

The important detail, and the one that differs from RBAC: this set is
**per-`Check` and never unwound**. Unlike `resolvePermissions`, which deletes
its path entry as each frame returns, the ReBAC visited set retains every
triple examined for the whole traversal. A given `(subject, relation, object)`
question is therefore answered at most once per `Check`, and a second
encounter on a different branch is treated as a negative rather than
re-evaluated.

Because the traversal returns on the first `true`, a suppressed revisit cannot
turn a true into a false: if the first evaluation of that triple had succeeded,
the whole `Check` would already have returned. The suppression only discards
work that was already determined to be unproductive. It does mean the visited
set grows with the size of the explored subgraph, which is the intended
tradeoff — bounded memory per call in exchange for not re-walking a diamond.

**The depth cap is `DefaultMaxDepth = 25`**, checked as `depth > c.maxDepth`
and configurable with `WithMaxDepth(depth int)`.

Exceeding it **returns an error, not false**:

```go
    if depth > c.maxDepth {
        return false, fmt.Errorf("rebac: max recursion depth exceeded")
    }
```

That error propagates up through every caller and aborts the entire `Check`.
The behavioral consequence deserves stating: a deeply nested branch does not
merely get pruned. If one branch of the search exceeds the cap, the whole
check fails with an error even when a shallower sibling branch would have
returned true. So the answer for a subject with legitimate access can flip from
`true` to an error purely because unrelated deep structure exists elsewhere in
the graph.

This is the deliberate choice, consistent with the rest of the library:
reporting the error is better than returning a `false` that is
indistinguishable from a real denial while actually meaning "gave up." But it
means the depth cap is a correctness parameter, not just a safety valve. If
your object hierarchy is legitimately deeper than 25 hops, raise it with
`WithMaxDepth` rather than accepting intermittent errors.

Note that `rebac.NewManager` constructs its checker with schemas but **never
forwards a `WithMaxDepth`**, so a Manager-created checker is always at the
default 25. Building the `Checker` directly with `NewChecker(store, WithMaxDepth(n))`
is the way to change it.

Two different depth constants exist in the library and should not be
conflated: `rbac.MaxInheritanceDepth = 32` and `rebac.DefaultMaxDepth = 25`.

### `ListDirectObjects` divergence

This is a documented gap, listed in the [README](../../README.md), and it is
the sharpest edge in the package.

```go
func (m *Manager) ListDirectObjects(ctx context.Context, subjectType, subjectID, relation, objectType string) ([]ObjectRef, error) {
    tuples, err := m.store.ReadTuples(ctx, TupleFilter{
        SubjectType: subjectType,
        SubjectID:   subjectID,
        Relation:    relation,
        ObjectType:  objectType,
    })
    // ... dedupe by object ref, return
}
```

It is one filtered store read. It never touches the checker, never recurses,
and never consults a schema. Access granted through group membership, a
computed relation, or a parent object is simply absent from the result.

**`Check` and `ListDirectObjects` therefore disagree by construction.** A
subject that `Check` allows on a document — because they are a member of a
group that was granted viewer, or because they inherit from the parent folder —
does not appear in `ListDirectObjects` for that document. The method name is
narrow on purpose: it states what the method does rather than what a caller
might hope it does.

The practical rule: **`Check` is the authoritative answer.** Use
`ListDirectObjects` to enumerate explicitly stored grants — an administrative
"who was directly granted this" view — and never to build an access list, a
search filter, or a UI that decides what a user may see. Filtering a result set
with it will silently hide objects the user is entitled to.

`ListDirectSubjects` has the same limitation and one more: it does not
deduplicate, and it returns userset references such as `group:eng#member` as
subjects rather than expanding them to the individual users they cover.

`rebac.Manager` does implement `Can`, bridging to `policy.Engine` by mapping
the action string to a relation and extracting subject and object types through
package-level extractor functions. Those extractors are **mutable package-level
variables**, not per-Manager configuration, so replacing them changes behavior
for every `Manager` in the process.

---

## Choosing between them

Use **RBAC** when the rule can be stated as a named role holding named
permissions, and when the set of roles is small enough that a human can audit
it. Its inheritance and wildcards keep grants from being restated, which is
what stops two roles from drifting apart.

Use **ABAC** when the answer depends on facts known only at evaluation time —
the resource's owner, the current tenant, the time of day, a risk score. Rules
are Go, so they are testable with the same tools as the rest of your code.

Use **ReBAC** when the answer depends on the shape of the object graph: nested
folders, team membership, organizational hierarchy. This is the model for "who
can see this document" in a system where documents live inside things that
themselves have members.

Use **Hybrid** with `DenyOverrides` when two of the above must both hold — the
usual arrangement being a role that grants a capability and an attribute rule
that narrows it to a tenant or region.

The one combination to avoid is encoding a hierarchy into flat RBAC permission
strings. `docs:folder-a:folder-b:read` looks like it works until the hierarchy
is reorganized, at which point every grant is wrong and there is no way to
find them. That is what ReBAC is for.

---

## Related

- [Security Model](./security-model.md) — what is enforced across the library,
  and what fails closed
- [Authorization concepts](../concepts/authorization.md) — task-oriented guide
  with worked examples
- [Getting Started](../getting-started.md) — the RBAC walkthrough
- [Architecture Overview](./README.md) — module topology and the dependency rule
- [Extending Kayan](./extending-kayan.md) — adding an authorization engine
- [Storage Layer](./storage-layer.md) — implementing `RoleStore`, `RBACStorage`,
  and the ReBAC `Store`
- [AGENTS.md](../../AGENTS.md) — the "wrong allow is worse than a crash" rule
