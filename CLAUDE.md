# Kayan

Headless, non-generic, extensible IAM library for Go.

> Detailed architectural rules live in [AGENTS.md](./AGENTS.md). This file is
> the orientation: what the project is, what it refuses to be, and how to work
> in it without breaking the parts that matter.

---

## Mission

Give Go services the security-critical half of identity — authentication
flows, sessions, authorization, federation, provisioning — without dictating
the half that belongs to the application: its HTTP framework, its user schema,
its database, its cryptographic choices.

## Vision

An IAM library that is correct by default and swappable at every layer, so a
team never has to choose between "secure" and "fits our architecture."

Most identity libraries force one of two trades. Frameworks make you adopt
their router, their user table, and their session model. Toolkits hand you
primitives and leave you to assemble the security properties yourself — which
is where authentication bypasses come from, because the assembly is the hard
part.

Kayan takes a third position: **the security decisions live inside the
library; the architectural decisions live in your application.**

---

## The three rules

Everything else follows from these. Breaking one is a design error, not a
style preference.

### 1. Headless — the caller owns transport

Kayan never reads an `*http.Request` for routing and never writes to an
`http.ResponseWriter`. It has no router and no server.

What it does provide is the parsing and validation that transport-agnostic
code can still own:

```go
// Kayan validates. You transport.
req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
form, err := idp.PostBindingForm(acsURL, response, relayState)
jwks, err := provider.JWKS(ctx)
```

The shape is always `bytes`/`url.Values` → validated struct, or struct →
`bytes`. Accepting a `*http.Request` as *input* to a pure parser is fine;
writing a response is not.

**Why this matters more than it sounds:** security checks belong inside the
parser, not in documentation for the caller. `ParseAuthorizeRequest` enforces
the `redirect_uri` allowlist, the PKCE policy, and the response-type check.
A caller who hand-parses the query string has to reimplement all three, and
that is precisely where open redirectors come from.

### 2. Nothing is forced — every choice has a safe default and a seam

Algorithms, hashes, storage, clocks, and token generation are all behind
interfaces. Kayan picks a secure default and lets you replace it.

```go
// Default: RSA + RS256.
keys.NewStaticProvider(&keys.Key{Method: jwt.SigningMethodRS256, ...})

// Ed25519 instead. Nothing else changes.
keys.NewStaticProvider(&keys.Key{Method: jwt.SigningMethodEdDSA, ...})

// Key never leaves the HSM: implement Signer, Kayan never holds it.
oauth2.NewProvider(..., oauth2.WithSigner(&kmsSigner{}))
```

The same pattern covers `domain.Hasher` (bcrypt default, argon2id is one
line), `saml.SignatureVerifier` (goxmldsig default), `tenant.Scoper` (row-level
default; schema- and database-per-tenant reachable), and
`gormstore.Migrations()` returning an `fs.FS` so you keep your own migration
runner.

**Secure by default, never secure by mandate.** PKCE is required unless you
explicitly turn it off. Unsigned SAML assertions are refused unless you
explicitly allow them. The escape hatches exist, and each one documents what
it gives up.

### 3. BYOS — your identity model stays yours

No generics, no embedded base struct, no reserved column names. Storage works
through `any` plus a factory:

```go
type User struct {                 // Your struct. Your fields. Your ID type.
    ID    string
    Email string
}

repo.GetIdentity(ctx, func() any { return &User{} }, id)
```

---

## Module layout

Protocols and their storage live outside `core`, so a deployment compiles only
what it uses. Password authentication pulls in no OAuth 2.0, SCIM, or SAML.

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

**The dependency arrow points one way: `core` never imports a sibling module.**
CI enforces it with `go list -deps`, not a grep, because a doc comment
mentioning a module is not an import.

`kayan-testing` must never be imported outside a `_test.go` file. CI enforces
that too — its stores lose everything on restart.

---

## Working here

### Build and test

Each directory is its own module. `cd` into it first.

```bash
cd core && go test -race ./...
cd kayan-gorm && go test -race ./...
```

### Committing and pushing

**Every change ships as its own commit, pushed when it is done.** One feature
or one fix per commit — not a day's work batched together.

The reason is review, not tidiness. A commit that fixes an authentication
bypass and also renames three files and updates a doc cannot be reviewed for
the part that matters, and cannot be reverted without taking the rest with it.
Security fixes especially must be readable in isolation.

```bash
# After a feature or fix is complete and its tests pass:
git add <the files for this change>
git commit -F - <<'EOF'
<type>(<scope>): <what changed, imperative>

<why it changed, and what breaks without it. Name the failure mode.>

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
git push
```

Types follow the existing history: `feat`, `fix`, `refactor`, `docs`, `test`,
`chore`, `ci`. Append `!` for a breaking change (`refactor!:`).

**What belongs in the message:**

- **The failure mode, concretely.** "Silent wrong denial whose behavior depends
  on which replica served the request" beats "fixes RBAC bug."
- **Why the fix is shaped that way**, when the shape is not obvious — why a
  callback rather than a per-method predicate, why the interface rather than
  the implementation.
- **Corrections to earlier claims.** If a fix turns out narrower than first
  described, say so in the commit rather than leaving an overstated claim in
  the history.

**What does not:**

- Several unrelated changes. Split them.
- A fix whose tests do not pass. Commit the work in progress or keep it local,
  but do not push a red state to `main`.

**Before pushing**, the touched modules must build, vet, and test clean:

```bash
cd <module> && go build ./... && go vet ./... && go test -race ./...
```

For a security fix, also revert it and confirm the test fails. A test that
passes either way proves nothing, and this repository has had several.

### Non-negotiables

**Storage and strategy methods take `context.Context`.** Not for style — the
ambient tenant lives in the context, so a method without one cannot be
tenant-scoped. Isolation is architecturally impossible without it.

**Tenant isolation fails closed.** A scoped query with no tenant in context
returns `tenant.ErrNoTenant`. It must never silently return every tenant's
rows to a caller who believes they asked a narrow question. Deliberate
cross-tenant work uses `tenant.WithSystemContext(ctx)`, which is explicit and
greppable.

**Security tests must be adversarial, and must be able to fail.** A test
asserting `err != nil` often passes for the wrong reason — a dependency
rejecting the input, a nil pointer, an unrelated validation. Assert the
specific error, then verify by reverting the fix and confirming the test
fails. Several tests in this repo were worthless until that check was run on
them.

**A wrong `allow` is worse than a crash.** An authorization path that fails
loudly can be fixed. One that silently denies — or silently permits — looks
identical to correct behavior and depends on which replica served the request.
Report the error.

### Where the sharp edges are

- `core/flow` is the product. Most authentication logic lives there.
- `kayan-saml` is where cryptographic correctness is hardest. Claims are read
  **only** from the signature-verified element; `extractUser` takes an
  `*Assertion`, not a `*Response`, so the unsafe path is uncallable rather than
  merely discouraged.
- `core/keys` is the seam that makes algorithm choice the caller's. Adding a
  hardcoded `jwt.SigningMethodRS256` anywhere is a regression.

---

## Current state

Pre-1.0. The API changes without a deprecation cycle — see
[VERSIONING.md](./VERSIONING.md).

**Solid:** password/session/RBAC path, tenant isolation, SAML signature
verification with structural XSW defense, OAuth 2.0 authorization code and
refresh with reuse detection, SCIM PATCH, versioned migrations.

**Known gaps** are listed in [README.md](./README.md) and kept current. The
list is deliberately specific — an evaluator should learn a limitation from
the README rather than from hitting it.
