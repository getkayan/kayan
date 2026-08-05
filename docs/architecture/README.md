# Architecture Overview

Kayan is a Go multi-module workspace, not a single library with subpackages.
There is no root module holding the code: `core/` is one module, and seven
sibling modules sit beside it. The split is not organizational tidiness. It
determines what ends up in your binary, what ends up in your supply chain, and
what a security advisory in a protocol library can reach.

This document covers the module topology, the one rule that keeps it coherent,
how CI enforces that rule, and the package layout inside `core`.

---

## Module topology

```
core/                    contracts + identity, session, flow, rbac, policy, rebac, tenant
  ├── domain/            Storage, Hasher, Clock, IDGenerator, TokenGenerator
  ├── keys/              Provider, Signer, JWKS
  └── flow/              the authentication engine
kayan-gorm/              GORM storage + tenant isolation callbacks + migrations
kayan-redis/             Redis: sessions, rate limiting, lockout, WebAuthn
kayan-oidc-provider/     OAuth 2.0 + OIDC   (gormstore/ subpackage optional)
kayan-saml/              SAML 2.0 SP and IdP
kayan-scim/              SCIM 2.0           (gormstore/ subpackage optional)
kayan-ldap/              go-ldap implementation of flow.LDAPDialer
kayan-testing/           in-memory stores + storage contract suite (tests only)
```

| Module | Import path | Purpose |
|---|---|---|
| `core` | `github.com/getkayan/kayan/core` | Contracts, identity, sessions, flows, RBAC, ABAC, ReBAC, tenancy, audit |
| `kayan-gorm` | `.../kayan-gorm` | GORM storage, tenant isolation callbacks, versioned migrations |
| `kayan-redis` | `.../kayan-redis` | Sessions, rate limiting, lockout, WebAuthn ceremonies |
| `kayan-oidc-provider` | `.../kayan-oidc-provider` | OAuth 2.0 and OpenID Connect |
| `kayan-saml` | `.../kayan-saml` | SAML 2.0 service provider and identity provider |
| `kayan-scim` | `.../kayan-scim` | SCIM 2.0 provisioning |
| `kayan-ldap` | `.../kayan-ldap` | LDAP directory authentication |
| `kayan-testing` | `.../kayan-testing` | In-memory stores and a storage contract suite — tests only |

All nine entries in `go.work` — the eight above plus the repository root — are
on Go 1.25.5. The root module is three lines with no requirements; its only
code is `cmd/kayan-cli`. The eleven directories under `examples/` are each
their own module and are deliberately **outside** `go.work`, so they resolve
dependencies the way a real consumer would.

Each directory is its own module, so `cd` into it before running anything.
Running `go test ./...` from the workspace root does not do what you want.

```bash
cd core && go test -race ./...
cd kayan-gorm && go test -race ./...
```

---

## The one-way dependency rule

**`core` never imports a sibling module.**

`core` defines contracts; siblings implement them. The arrow points one way and
only one way. Every non-core module's sole in-repo dependency is `core` — there
is not a single sibling-to-sibling edge in the workspace. `kayan-gorm`,
`kayan-oidc-provider`, and `kayan-scim` all use GORM, but they each depend on
`gorm.io/gorm` directly rather than on each other.

Inside `core` the graph is layered too:

```
core/identity  (stdlib only, leaf)
     ↑
core/domain, core/audit, core/events, core/keys
     ↑
core/flow, core/session, core/rbac, core/tenant
     ↑
kayan-*  (siblings — never imported by core/)
```

`core/identity` is the leaf: stdlib only, zero internal dependencies. `core/rbac`,
`core/rebac`, and `core/tenant` never import `core/flow` or `core/session`, which
is what keeps authorization and tenancy usable without pulling in the
authentication engine.

### CI enforces it with `go list -deps`, not grep

The check resolves the actual import graph rather than searching source text:

```yaml
- name: core must not import sibling modules
  working-directory: core
  run: |
    set -euo pipefail
    imports="$(go list -deps ./... | grep '^github.com/getkayan/kayan/' || true)"
    status=0
    for module in kayan-gorm kayan-ldap kayan-oidc-provider kayan-redis kayan-saml kayan-scim kayan-testing; do
      if echo "${imports}" | grep -q "^github.com/getkayan/kayan/${module}"; then
        echo "ERROR: core/ must not import ${module}/"
        echo "${imports}" | grep "^github.com/getkayan/kayan/${module}"
        status=1
      fi
    done
    exit "${status}"
```

The rationale is in a comment above it, and it is worth understanding rather
than just obeying:

> This resolves real imports via `go list`, not grep over source text — doc
> comments in core/domain/storage.go reference kayan-gorm as an example, and a
> lint that fails on documentation is a lint people switch off.

That is the whole argument. `core/domain/storage.go` legitimately mentions
`kayan-gorm` in a doc comment, because naming the reference implementation is
useful to a reader. A grep-based lint would fail on that comment, and the
predictable response would be to weaken the comment or disable the lint —
either of which is worse than the problem. `go list -deps` sees imports, and a
doc comment is not an import.

A second, stricter check guards the leaf:

```yaml
- name: core/identity must have zero internal deps
  working-directory: core
  run: |
    set -euo pipefail
    deps="$(go list -deps ./identity/... | grep '^github.com/getkayan/kayan/core/' | grep -v '^github.com/getkayan/kayan/core/identity$' || true)"
    if [ -n "${deps}" ]; then
      echo "ERROR: core/identity must not import other core/ packages"
      echo "${deps}"
      exit 1
    fi
```

### `kayan-testing` is test-only, and that check is grep

```yaml
# kayan-testing ships in-memory doubles. Importing it from shipping code
# would put a store that loses everything on restart into production.
- name: kayan-testing must only be imported by tests
  run: |
    set -euo pipefail
    offenders="$(grep -rln 'getkayan/kayan/kayan-testing' --include='*.go' . | grep -v '_test\.go$' | grep -v '^\./kayan-testing/' || true)"
    if [ -n "${offenders}" ]; then
      echo "ERROR: kayan-testing imported outside a _test.go file:"
      echo "${offenders}"
      exit 1
    fi
```

This one is grep over source text, which is the opposite tradeoff from the core
check and worth being honest about. The question it asks is *which file* the
import appears in, and `go list` does not answer that — it reports resolved
dependencies, not their file positions. The cost is the usual grep cost: an
import behind a build tag still trips it, and a transitive pull-in through a
non-test package would not be caught. Given that the failure it prevents is
shipping a store that loses everything on restart, false positives are the
tolerable direction.

### Adding a module

A module absent from CI is a module nothing checks. When you add one:

1. `go work use ./newmodule`
2. Add `replace github.com/getkayan/kayan/core => ../core` to its `go.mod`
3. Add it to the matrices in `.github/workflows/{ci,test,security}.yml` —
   specifically the `lint` and `build` matrices in `ci.yml`, the per-module
   steps in `test.yml`, and `govulncheck` in `security.yml`
4. Add it to the module list in the arch-lint script above

---

## Why the protocols were extracted

`core/oauth2`, `core/oidc`, `core/saml`, and `core/scim` used to exist. They are
now `kayan-oidc-provider`, `kayan-saml`, and `kayan-scim`. The extraction
happened in `refactor: extract SAML, SCIM, and OIDC provider into their own
modules`, and there were two reasons.

### A password-auth deployment compiles no OAuth 2.0, SCIM, or SAML

This is the plain version: you compile what you use. A service that
authenticates users with a password and a session cookie needs `core` and a
storage adapter. It does not need an XML canonicalizer, a SCIM filter grammar,
or a JWKS endpoint, and with the protocols inside `core` it would have carried
all three whether or not a single line called them.

```bash
go get github.com/getkayan/kayan/core
go get github.com/getkayan/kayan/kayan-gorm
```

That is the whole dependency set for password authentication.

### `goxmldsig` never enters `core`'s supply chain

This is the version that matters more.

`kayan-saml` depends on `github.com/russellhaering/goxmldsig` and, through it,
`github.com/beevik/etree`. Those are the libraries that parse and canonicalize
XML and verify XML-DSig signatures. XML canonicalization is a notoriously sharp
surface — signature wrapping, entity expansion, namespace confusion — and it is
exactly the kind of dependency that produces advisories.

With SAML inside `core`, every Kayan consumer would appear in that library's
blast radius. A `govulncheck` finding against `goxmldsig` would light up for a
service that has never seen a SAML assertion, and the team would have to
evaluate and likely patch for a code path they do not compile a caller for.
Worse, the reachability analysis is not free: proving "we don't actually call
that" is work, repeated per advisory.

With SAML in its own module, the question does not arise. A service that does
not import `kayan-saml` has no `goxmldsig` in its module graph, no entry in its
SBOM, and no advisory to triage.

The same reasoning puts `go-ldap` in `kayan-ldap` rather than `core`, as
[AGENTS.md](../../AGENTS.md) states:

> Database drivers, ORMs, and protocol libraries belong in sibling modules,
> never in `core/`. `goxmldsig` lives in `kayan-saml` and `go-ldap` in
> `kayan-ldap` for exactly this reason: a consumer using password
> authentication should not carry an XML canonicalization surface.

`core`'s own direct dependencies are fifteen and deliberately unexciting:
`golang-jwt/jwt/v5`, `golang.org/x/crypto`, `golang.org/x/oauth2`,
`google/uuid`, `coreos/go-oidc/v3`, `go-webauthn/webauthn`, `spf13/viper`,
`go.uber.org/zap`, and the OpenTelemetry set. `core/identity` has zero external
dependencies at all.

---

## Why protocol storage ships with its protocol

`kayan-oidc-provider/gormstore` and `kayan-scim/gormstore` are subpackages of
their protocol modules. The OAuth 2.0 client, authorization code, and refresh
token tables are **not** in `kayan-gorm`.

Two reasons.

**It preserves the property the extraction bought.** If `kayan-gorm` carried
the OAuth 2.0 repositories, then every consumer of the storage adapter — which
is nearly all of them — would compile the OAuth 2.0 types those repositories
persist. `kayan-gorm` would import `kayan-oidc-provider`, and the protocol
would be back in everyone's dependency graph through the back door. The
extraction would have moved the code without moving the cost.

**A storage schema and the protocol it serves change together.** Adding refresh
token family tracking meant adding `FamilyID` and `UsedAt` to the
`RefreshToken` type and to the table that stores it. Those are one change. Split
across two modules, they are one change that cannot be made atomically, with a
version skew window in which the protocol expects a column the adapter has not
added. Keeping them together makes the compiler enforce that they agree.

The subpackage is optional. Importing `kayan-oidc-provider` gets you the
protocol; importing `kayan-oidc-provider/gormstore` additionally gets you GORM,
and only then. A deployment backing OAuth 2.0 with something other than a
relational database implements the store interfaces itself and never touches
the subpackage.

The same holds for `kayan-redis`: it is not a system of record, it is shared
ephemeral state — sessions, rate limit counters, lockout state, WebAuthn
ceremony data. Those need to be visible across replicas, which is the one thing
in-process implementations cannot do.

---

## The three principles

These are the design commitments everything else follows from. Breaking one is
a design error rather than a style preference. They are stated at more length
in [CLAUDE.md](../../CLAUDE.md) and the [README](../../README.md); what follows
is what they mean architecturally.

### Headless — the caller owns transport

Kayan has no router and no server. It never reads an `*http.Request` for
routing and never writes to an `http.ResponseWriter`. What it owns is parsing
and validation:

```go
req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
jwks, err := provider.JWKS(ctx)
form, err := idp.PostBindingForm(acsURL, response, relayState)
```

The shape is always `bytes` or `url.Values` → validated struct, or struct →
`bytes`. Accepting an `*http.Request` as input to a pure parser is fine; writing
a response is not.

This is not a limitation presented as a feature. **Security checks belong
inside the parser, not in documentation for the caller.**
`ParseAuthorizeRequest` enforces the `redirect_uri` allowlist, the PKCE policy,
and the supported response types. A caller who hand-parses the query string has
to reimplement all three, and that is precisely where open redirectors come
from. Putting the checks where the parsing happens means they cannot be skipped
by someone who did not know they existed.

The architectural consequence: `core` takes no HTTP framework dependency, ever.
Framework bindings live in separate repositories.

### Nothing is forced — safe default, real seam

Every algorithm, hash, store, and clock sits behind an interface with a secure
default that can be replaced.

```go
// Default: RSA + RS256.
keys.NewStaticProvider(&keys.Key{Method: jwt.SigningMethodRS256, ...})

// Ed25519 instead. Nothing else changes.
keys.NewStaticProvider(&keys.Key{Method: jwt.SigningMethodEdDSA, ...})

// Key never leaves the HSM: implement Signer, Kayan never holds it.
oauth2.NewProvider(..., oauth2.WithSigner(&kmsSigner{}))
```

The same shape covers `domain.Hasher` (bcrypt at cost 12 by default, argon2id
is one line), `saml.SignatureVerifier` (goxmldsig by default),
`saml.ReplayCache`, `domain.Clock`, `domain.TokenGenerator`, `tenant.Scoper`
(row-level by default; schema- or database-per-tenant if you implement it), and
`gormstore.Migrations()` returning an `fs.FS` so the migration runner stays
yours.

**Secure by default, never secure by mandate.** PKCE is required unless you
turn it off. Unsigned SAML assertions are refused unless you allow them. Each
escape hatch documents what it gives up — `WithAllowUnsigned` says outright
that it disables authentication of the assertion entirely and must never be
enabled in production.

`core/keys` is the seam that makes algorithm choice the caller's. Adding a
hardcoded `jwt.SigningMethodRS256` anywhere is a regression.

### BYOS — your identity model stays yours

No generics, no base struct to embed, no reserved column names. Storage works
through `any` plus a factory:

```go
type User struct {          // Your struct. Your fields. Your ID type.
    ID    string
    Email string
}

repo.GetIdentity(ctx, func() any { return &User{} }, id)
```

The only interface a model must implement is `FlowIdentity` (`GetID() any`,
`SetID(any)`). `TraitSource` and `CredentialSource` are optional.

Generics were rejected deliberately. A `Storage[T]` would force a type
parameter through every signature that touches storage, and it would make the
ID type a compile-time constraint — so a service using `string` IDs and one
using `uuid.UUID` could not share an adapter. `any` plus a factory supports any
ID type at the cost of a runtime type assertion at the boundary. See
[BYOS](../concepts/byos.md) for the full argument.

---

## Package layout inside `core`

```
core/
├── identity/       Leaf: Identity, Session, Credential, JSON. Stdlib only.
├── domain/         Storage contracts, Hasher, Clock, IDGenerator, TokenGenerator
├── keys/           Signing keys: Provider, Signer, JWKS — the algorithm seam
├── audit/          Audit event model and AuditStore
├── events/         Event envelope, topics, Dispatcher
├── flow/           Auth flows: strategies, managers, hooks, rate limiting, lockout
├── session/        Session management: JWT and Database strategies
├── rbac/           Roles, inheritance, wildcard permissions
├── rebac/          Relationship tuples, schemas, graph checker
├── policy/         Engine interface, ABAC, Hybrid, audit and caching middleware
├── tenant/         Resolvers, Scoper, Scoped, the isolation contract
├── mfa/            MFA enrollment and challenge orchestration
├── device/         Device trust
├── risk/           Risk signals
├── admin/          Administrative operations
├── compliance/     Data retention, encryption
├── consent/        GDPR consent records
├── telemetry/      OpenTelemetry, Prometheus
├── health/         Health checks
├── logger/         Structured logging
└── config/         Configuration
```

The dependency rules between them, enforced by review and by the
`core/identity` CI check:

```
core/identity   ← stdlib ONLY (zero internal deps)
core/audit      ← stdlib ONLY
core/rbac       ← stdlib ONLY
core/rebac      ← stdlib ONLY
core/tenant     ← stdlib ONLY
core/keys       ← stdlib + golang-jwt ONLY
core/domain     ← core/identity, core/audit ONLY
core/events     ← core/identity
core/policy     ← core/domain, core/audit, core/identity
core/flow       ← core/domain, core/identity, core/audit, core/events
core/session    ← core/domain, core/identity
```

Interfaces are declared **where they are consumed**, not where they are
implemented — the Go convention. `domain.Storage` lives in `core/domain`
because that is where the flow engine consumes it; `policy.Engine` lives in
`core/policy`. This keeps public dependency surfaces narrow: an adapter
implementing `domain.Storage` imports `core/domain` and nothing else from the
library.

### Where the sharp edges are

- **`core/flow`** is the product. Most authentication logic lives there.
- **`kayan-saml`** is where cryptographic correctness is hardest. Claims are
  read **only** from the signature-verified element; `extractUser` takes an
  `*Assertion`, not a `*Response`, so the unsafe path is uncallable rather than
  merely discouraged.
- **`core/keys`** is the algorithm seam. Hardcoding a signing method there
  defeats the point of the package.

---

## Reading the codebase

A path through it that builds understanding in the right order:

1. **`core/identity`** — the value types everything else moves around.
2. **`core/domain`** — the persistence contracts. Read `storage.go` first; the
   comments explain why each method takes `ctx`.
3. **`core/flow`** — the authentication engine. `strategy.go` defines the
   interfaces, `login.go` and `registration.go` are the managers, and the
   `strategy_*.go` files are the methods.
4. **`core/session`** — how a successful authentication becomes a token.
5. **`core/rbac`, `core/policy`, `core/rebac`** — the authorization models.
6. **`core/tenant`** — resolution and the isolation contract.
7. **`kayan-gorm`** — the reference adapter, and how tenant isolation is
   actually enforced.
8. **`kayan-saml`, `kayan-oidc-provider`** — the protocols, once the contracts
   above are familiar.

---

## What belongs where

Put it in `core` when it is headless, broadly reusable, framework-agnostic, and
expressible through stable interfaces.

Put it in a sibling module when it is database-specific, cache-specific,
protocol-specific, tied to an external SDK, or would add a dependency that
consumers who do not use the feature should not carry.

If a feature is tied to one HTTP framework or one persistence technology, it
does not belong in `core` at all.

---

## Related

- [Security Model](./security-model.md) — what is enforced and what fails closed
- [Storage Layer](./storage-layer.md) — the `domain.Storage` contract in full
- [Authentication Flows](./authentication-flows.md) — request paths end to end
- [Authorization Models](./authorization-models.md) — how each engine evaluates
- [Strategy Internals](./strategy-internals.md) — managers, decorators, hooks
- [Extending Kayan](./extending-kayan.md) — adding modules, strategies, adapters
- [BYOS](../concepts/byos.md) · [Multi-Tenancy](../concepts/multi-tenancy.md)
- [Getting Started](../getting-started.md) — the working walkthrough
- [AGENTS.md](../../AGENTS.md) / [CLAUDE.md](../../CLAUDE.md) — contributor rules
