# Extending Kayan

Every replaceable part of Kayan is an interface with a secure default behind it.
This document is the working guide to replacing them: the real signatures, code
that compiles, and — for each one — what breaks if the implementation is subtly
wrong, because most of these interfaces have failure modes that produce no error
and pass every functional test.

The interfaces are small on purpose. A `domain.Hasher` is two methods, a
`tenant.Scoper` is one, a `keys.Signer` is one. Small interfaces are easy to
implement and easy to implement *wrongly* in a way nothing catches, so each
section below names the specific mistake to test for.

---

## The rules

Four constraints govern every extension. They are enforced by CI, not by review
alone, and they are listed in [AGENTS.md](../../AGENTS.md).

### `core` never imports a sibling module

`core` declares contracts; siblings implement them. There is no sibling-to-sibling
edge in the workspace either — `kayan-gorm`, `kayan-oidc-provider`, and
`kayan-scim` all use GORM, and each depends on `gorm.io/gorm` directly rather
than on the others.

The practical rule when adding code: if it needs a database driver, an ORM, an
XML canonicalizer, an LDAP client, or any protocol library, it belongs in a
sibling module. A consumer authenticating with a password should not carry an XML
canonicalization surface, which is exactly why `goxmldsig` lives in `kayan-saml`
and `go-ldap` in `kayan-ldap`.

CI resolves the real import graph with `go list -deps` rather than grepping
source text, because `core/domain/storage.go` legitimately names `kayan-gorm` in
a doc comment and a lint that fails on documentation is a lint people switch off.

### `kayan-testing` only in `_test.go`

```yaml
offenders="$(grep -rln 'getkayan/kayan/kayan-testing' --include='*.go' . \
  | grep -v '_test\.go$' | grep -v '^\./kayan-testing/' || true)"
```

This check *is* grep, and that is the opposite tradeoff from the one above. The
question it asks is *which file* the import appears in, and `go list` reports
resolved dependencies rather than their file positions. The cost is the usual
grep cost — an import behind a build tag still trips it. Given that the failure
it prevents is shipping a store that loses everything on restart, false positives
are the tolerable direction.

### Storage and strategy methods take `context.Context`

Not for style. The ambient tenant lives in the context: `tenant.WithTenant` puts
it there, `tenant.RequireID(ctx)` reads it back. A method with no `ctx` cannot
see the tenant and therefore cannot scope its query. Tenant isolation is not
merely inconvenient without `ctx` — it is architecturally impossible, because
there is no path by which the request's tenant can reach the SQL.

The commit history shows the ordering: `refactor!: thread context.Context through
the storage and session contracts` is marked breaking and landed *before*
`feat(tenant): enforce isolation at the storage layer`. The first was the
precondition for the second.

Documentation is checked for this too. `tools/docsample` walks every fenced Go
block under `docs/` and flags a call to `CreateIdentity`, `GetIdentity`,
`FindIdentity`, `ListIdentities`, `UpdateIdentity`, `DeleteIdentity`,
`CreateCredential`, `GetCredentialByIdentifier`, `CreateSession`, `GetSession`,
or `DeleteSession` that is missing its context. It also flags references to the
old `kgorm.` and `kredis.` names and to the pre-extraction `core/oauth2`,
`core/oidc`, `core/saml`, and `core/scim` paths.

### Security tests must be adversarial, and must be able to fail

> A test asserting `err != nil` often passes for the wrong reason — a dependency
> rejecting the input, a nil pointer, an unrelated validation. Assert the
> specific error, then verify by reverting the fix and confirming the test
> fails. Several tests in this repo were worthless until that check was run on
> them.

For a new strategy or store, that means: build a table of hostile inputs rather
than one happy-path negative, assert a specific sentinel with `errors.Is` rather
than `err != nil`, and include a positive control so a matcher that rejects
everything does not pass.

---

## Writing a `LoginStrategy`

```go
type LoginStrategy interface {
    ID() string
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}
```

That is the whole interface.

### `ID()` and why uniqueness matters

`ID()` is the key in the manager's map:

```go
func (m *LoginManager) RegisterStrategy(s LoginStrategy) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.strategies[s.ID()] = s
}
```

Registration is a map assignment, so **registering two strategies with the same
ID silently replaces the first**. There is no error and no warning. If your
strategy returns `"password"` and is registered after the built-in one, every
password login goes through yours; if it is registered before, yours is dead code
that nothing calls. Neither shows up in a test that only exercises the strategy
directly.

Pick a stable, lowercase, method-shaped ID: `"password"`, `"magic_link"`,
`"otp"`, `"totp"`, `"webauthn"`, `"api_key"`, `"ldap"` are taken. The ID also
appears as the `method` argument callers pass to `Authenticate` and, by
convention, as `identity.Credential.Type` for credentials the method owns — so
changing it later invalidates every stored credential.

The decorators deliberately do *not* have their own ID:

```go
func (s *RateLimitStrategy) ID() string { return s.next.ID() }
func (s *LockoutStrategy) ID() string   { return s.next.ID() }
```

Delegating means a wrapped strategy replaces the unwrapped entry rather than
adding a second one under a different name. You cannot accidentally register both
a protected and an unprotected path.

### What `Authenticate` must return

**On success**: the identity, and `nil`. The identity must be the same shape the
manager's `factory` produces, because callers type-assert it:

```go
ident, err := loginManager.Authenticate(ctx, "sms", phone, code)
if err != nil {
    return err
}
user := ident.(*User) // this assertion is the caller's contract
```

Returning a `*identity.Identity` from a deployment whose model is `*User` gives
that caller a panic. (The bundled magic-link and OTP strategies hardcode
`func() any { return &identity.Identity{} }` for their identity lookup, which is
a real BYOS gap in those two — do not copy it.)

**On failure**: `(nil, err)`. Never a non-nil identity with a non-nil error,
unless you are deliberately signalling a partial authentication the way
`ErrMFARequired` does. The manager's own failure path is:

```go
ident, err := strategy.Authenticate(ctx, identifier, secret)
if err != nil {
    // audit TopicLoginFailure with err.Error() as Message
    return nil, err
}
```

Your error text lands in the audit log verbatim. Do not put the submitted secret,
a stored hash, or a token value in it.

**Use one error for "no such user" and "wrong secret".** Two distinguishable
errors turn the endpoint into an account-enumeration oracle. And be aware that
the response *body* is only half of it — if the not-found path returns before
doing the expensive comparison and the wrong-secret path does the work, response
timing distinguishes them anyway. `oauth2.ValidateClient` handles this by
performing a dummy comparison against a fixed valid hash on the unknown-client
path; the bundled `PasswordStrategy` does not, which is a real exposure worth
knowing about before you copy its shape.

**Compare secrets in constant time.** `subtle.ConstantTimeCompare` for a raw
value, or `domain.Hasher.Compare` for a hashed one. A byte-comparing loop leaks
how many leading characters were correct, which reduces a six-digit code from
10^6 guesses to about 60.

### A complete example

An SMS one-time code strategy that stores hashed codes and enforces a per-code
attempt limit:

```go
package smsauth

import (
    "context"
    "crypto/rand"
    "errors"
    "fmt"
    "math/big"
    "time"

    "github.com/getkayan/kayan/core/domain"
)

// ErrInvalidCode is returned for an unknown recipient, an expired code, and a
// wrong code alike. Distinguishing them would let the endpoint enumerate
// accounts.
var ErrInvalidCode = errors.New("smsauth: invalid or expired code")

// Sender delivers a code out of band. Kayan is headless and sends nothing.
type Sender interface {
    Send(ctx context.Context, recipient, code string) error
}

// CodeStore persists pending codes. Delete and Consume must be atomic with
// respect to each other, or two concurrent submissions of the same code both
// succeed.
type CodeStore interface {
    Save(ctx context.Context, recipient, hash string, expiresAt time.Time) error
    // Consume returns the stored hash and increments the attempt counter,
    // reporting an error once MaxAttempts is exceeded.
    Consume(ctx context.Context, recipient string) (hash string, attempts int, err error)
    Delete(ctx context.Context, recipient string) error
}

// Strategy implements flow.LoginStrategy and flow.Initiator.
type Strategy struct {
    codes       CodeStore
    sender      Sender
    hasher      domain.Hasher
    lookup      func(ctx context.Context, recipient string) (any, error)
    ttl         time.Duration
    maxAttempts int
}

func New(codes CodeStore, sender Sender, hasher domain.Hasher,
    lookup func(ctx context.Context, recipient string) (any, error)) *Strategy {
    return &Strategy{
        codes:       codes,
        sender:      sender,
        hasher:      hasher,
        lookup:      lookup,
        ttl:         5 * time.Minute,
        maxAttempts: 5,
    }
}

// ID is the method name callers pass to LoginManager.Authenticate. It must not
// collide with another registered strategy: registration is a map assignment
// and a collision silently replaces the earlier one.
func (s *Strategy) ID() string { return "sms" }

// Initiate generates a code, stores its hash, and delivers the plaintext.
func (s *Strategy) Initiate(ctx context.Context, recipient string) (any, error) {
    // Resolve first so an unknown recipient costs nothing to deliver to. The
    // error is deliberately the same one Authenticate returns.
    if _, err := s.lookup(ctx, recipient); err != nil {
        return nil, ErrInvalidCode
    }

    code, err := numericCode(6)
    if err != nil {
        return nil, fmt.Errorf("smsauth: generate code: %w", err)
    }

    // The code is stored hashed. A database disclosure would otherwise hand
    // over every pending second factor in plaintext.
    hash, err := s.hasher.Hash(code)
    if err != nil {
        return nil, fmt.Errorf("smsauth: hash code: %w", err)
    }
    if err := s.codes.Save(ctx, recipient, hash, time.Now().Add(s.ttl)); err != nil {
        return nil, fmt.Errorf("smsauth: save code: %w", err)
    }

    if err := s.sender.Send(ctx, recipient, code); err != nil {
        // Roll back: a live code nobody received is guessable for the full TTL
        // and invisible to the user, who requests another.
        _ = s.codes.Delete(ctx, recipient)
        return nil, fmt.Errorf("smsauth: send code: %w", err)
    }
    return nil, nil
}

// Authenticate verifies a delivered code.
func (s *Strategy) Authenticate(ctx context.Context, recipient, code string) (any, error) {
    hash, attempts, err := s.codes.Consume(ctx, recipient)
    if err != nil {
        return nil, ErrInvalidCode
    }
    if attempts > s.maxAttempts {
        // Burn the code rather than letting the attacker keep guessing.
        _ = s.codes.Delete(ctx, recipient)
        return nil, ErrInvalidCode
    }

    // Constant-time through the hasher. A direct == on the plaintext would leak
    // the matching prefix length.
    if !s.hasher.Compare(code, hash) {
        return nil, ErrInvalidCode
    }

    ident, err := s.lookup(ctx, recipient)
    if err != nil {
        return nil, ErrInvalidCode
    }

    // Single use. Without this the code stays valid for its whole TTL and every
    // place it was copied is a live credential.
    if err := s.codes.Delete(ctx, recipient); err != nil {
        return nil, fmt.Errorf("smsauth: consume code: %w", err)
    }
    return ident, nil
}

// numericCode returns n uniformly random digits, zero-padded.
//
// crypto/rand over exactly 10^n avoids the modulo bias that n % 1000000 over a
// wider range introduces — a bias that narrows the search space and passes
// every functional test.
func numericCode(n int) (string, error) {
    limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
    value, err := rand.Int(rand.Reader, limit)
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("%0*d", n, value), nil
}
```

### Registering it

```go
base := smsauth.New(codeStore, twilioSender, domain.NewBcryptHasher(0), lookupByPhone)

locked := flow.NewLockoutStrategy(base, lockoutStore, 5, 15*time.Minute, 15*time.Minute)

limited := flow.NewRateLimitStrategy(locked, rateLimiter, flow.RateLimitConfig{
    Limit:  5,
    Window: time.Minute,
})

loginManager.RegisterStrategy(limited)
```

Rate limit outside lockout, not the reverse: with lockout on the outside, an
attacker locks any account by firing enough rate-limited requests to trip the
failure counter without ever guessing a code. See
[Authentication Flows](./authentication-flows.md#rate-limiting-and-lockout-as-decorators).

For a strategy configurable from a `domain.StrategyStore` at runtime, register a
factory instead:

```go
loginManager.Registry().RegisterFactory("sms", func(cfg *domain.StrategyConfig) (flow.LoginStrategy, error) {
    return smsauth.New(codeStore, twilioSender, hasher, lookupByPhone), nil
})
```

`LoginManager.ReloadStrategies(ctx)` then builds enabled strategies from the
store and deletes disabled ones. A factory that returns an error is **logged and
skipped** — `log.Printf` — not propagated, so a misconfigured strategy leaves the
map without it and nothing fails loudly. Check `ListFactories()` and the resulting
map after a reload if that matters.

### Optional interfaces

```go
// Multi-step: magic link, OTP, anything needing a "send" before a "verify".
type Initiator interface {
    Initiate(ctx context.Context, identifier string) (any, error)
}

// Attach this method to an already-authenticated identity.
type Attacher interface {
    Attach(ctx context.Context, ident any, identifier, secret string) error
}
```

---

## Writing a `RegistrationStrategy` and an `Attacher`

```go
type RegistrationStrategy interface {
    ID() string
    Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}
```

`Register` owns validating the secret, hashing it, allocating an ID, and writing
the identity. `RegistrationManager.Submit` runs pre-hooks, schema validation, and
account unification *before* calling it, and audit, events, and post-hooks after.

```go
func (s *Strategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) {
    if len(traits) == 0 {
        return nil, errors.New("smsauth: traits are required")
    }

    var t struct {
        Phone string `json:"phone"`
    }
    if err := json.Unmarshal(traits, &t); err != nil {
        return nil, fmt.Errorf("smsauth: parse traits: %w", err)
    }
    if t.Phone == "" {
        return nil, errors.New("smsauth: phone is required")
    }

    ident := s.factory()

    // Assign an ID only when the caller did not. A caller-supplied ID must
    // survive: some deployments mint IDs upstream.
    if fi, ok := ident.(flow.FlowIdentity); ok {
        if id := fi.GetID(); id == nil || reflect.ValueOf(id).IsZero() {
            fi.SetID(s.generator())
        }
    }
    if ts, ok := ident.(flow.TraitSource); ok {
        ts.SetTraits(traits)
    }

    if err := s.repo.CreateIdentity(ctx, ident); err != nil {
        return nil, fmt.Errorf("smsauth: create identity: %w", err)
    }
    return ident, nil
}
```

Use `domain.IDGenerator` for the record ID, never `domain.TokenGenerator`. They
are separate named types precisely so a sortable, enumerable UUIDv7 cannot be
wired into a credential path by accident — the compiler refuses.

Two behaviors of `Submit` to design against.

**Post-hooks run after the write, with no rollback.** A post-hook that fails
returns an error from a registration that did create the account. Make hooks
idempotent or make their failures non-fatal inside the hook.

**Pre-hooks receive `nil` as the identity**, because the identity does not exist
yet. A registration pre-hook that type-asserts its second argument will not do
what its author expected.

### The `Attacher`

`Attach` links a method to an identity that is already authenticated. It is
reached two ways: `LoginManager.LinkMethod`, and the account-unification path in
`Submit` (through the `Linker`).

```go
func (s *Strategy) Attach(ctx context.Context, ident any, identifier, secret string) error {
    fi, ok := ident.(flow.FlowIdentity)
    if !ok {
        return errors.New("smsauth: identity must implement FlowIdentity")
    }

    hash, err := s.hasher.Hash(secret)
    if err != nil {
        return fmt.Errorf("smsauth: hash secret: %w", err)
    }

    cred := identity.Credential{
        IdentityID: fmt.Sprintf("%v", fi.GetID()),
        Type:       s.ID(),
        Identifier: identifier,
        Secret:     hash,
        CreatedAt:  time.Now(),
        UpdatedAt:  time.Now(),
    }
    if s.generator != nil {
        cred.ID = fmt.Sprintf("%v", s.generator())
    }

    // Prefer the embedded path when the model carries its own credentials, so
    // identity and credential are one write.
    if cs, ok := ident.(flow.CredentialSource); ok {
        cs.SetCredentials(append(cs.GetCredentials(), cred))
        return s.repo.UpdateIdentity(ctx, ident)
    }
    return s.repo.CreateCredential(ctx, &cred)
}
```

**`Attach` must never be reachable without prior authentication.** It attaches a
credential to an identity the caller names, so a handler that takes the identity
from client input rather than from a validated session is an account-takeover
endpoint: name the victim's identity, attach your own credential, log in.
`LinkMethod` does not authenticate for you — it audits the attempt and delegates.

Set `Type` to your `ID()`. `GetCredentialByIdentifier` scopes on it, and a
credential filed under the wrong type either never matches or matches a method it
was not meant for.

---

## Writing a storage backend

```go
type Storage interface {
    IdentityStorage
    SessionStorage
    CredentialStorage
    audit.AuditStore
    TokenStore
}
```

`IdentityStorage` embeds `CredentialStorage`, so the credential methods arrive
twice. That is legal Go and reflects that identity and credential operations
usually share a table.

Implement the narrower sub-interfaces if your component only needs some of it.
Nothing in `core` imports your package; your package imports `core/domain`,
`core/identity`, and `core/audit` and nothing else from the library.

### Order of work

**1. Assert the contract at compile time.**

```go
var _ domain.Storage = (*MongoStore)(nil)
```

This catches a missing or misspelled method at build time rather than at the call
site, where the failure is a nil interface method call in a request path.

**2. Honor the factory.** The store never names your type and never allocates
one:

```go
func (s *MongoStore) GetIdentity(ctx context.Context, factory func() any, id any) (any, error) {
    // The caller's factory allocates. Constructing a concrete type here would
    // break BYOS for every deployment whose model is not that type.
    out := factory()
    err := s.identities.FindOne(ctx, bson.M{"_id": id}).Decode(out)
    if err != nil {
        return nil, fmt.Errorf("mongostore: get identity %v: %w", id, err)
    }
    return out, nil
}
```

**3. Make `FindIdentity` conjunctive.** Every field in the map must match. A store
that ORs the conditions returns the wrong user for a two-field lookup, and no
compile error reveals it. The suite asserts this.

**4. Filter expired tokens in `GetToken`.** This is the contract obligation that
the conformance suite caught `kayan-gorm` violating:

```go
// Before
First(&gt, "token = ?", token)
// After
First(&gt, "token = ? AND expires_at > ?", token, time.Now())
```

The commit message is worth reading in full:

> GetToken returned any auth token matching the value, ignoring ExpiresAt. These
> tokens authenticate password recovery, email verification, and magic-link
> login.
>
> Not currently exploitable: flow/recovery.go:129, flow/strategy_magic.go:45, and
> flow/verification.go all check expiry after loading. The comment at
> strategy_magic.go:44 reads "Store should handle this, but double check", which
> describes a layer that was not in fact there. Any new caller that omits the
> check would inherit an authentication bypass, so the filter belongs in the
> store.

Three callers re-checking expiry was the only defense, and one carried a comment
asserting a layer that did not exist.

**5. Delete both session indexes.** `DeleteSession` must invalidate the ID path
*and* the refresh-token path. A store that deletes the primary row and leaves the
refresh-token index leaves a deleted session refreshable — a logout that did not
log anyone out.

**6. Scope the credential lookup by method.** A credential stored under
`"password"` must not be returned when `"totp"` is requested for the same
identifier. `MemoryStore` builds its key as `method + "\x00" + identifier`, method
first, so an identifier containing the separator cannot forge a key for a
different method. That ordering is deliberate.

**7. Take `ctx` on every method and use it** — for cancellation, and for
`tenant.RequireID` if you support multi-tenancy.

**8. Return `error` for a missing record, not `(nil, nil)`.** `core/domain`
defines no sentinel errors — every error is an inline `fmt.Errorf` with a
`domain:` prefix and adapters return whatever their driver produces. The suite
honors that by asserting only success or failure, never which error value came
back. The tradeoff is real: a caller cannot portably distinguish "no such
identity" from "the database is down", so code needing that distinction has to
know its adapter.

**9. Run the suite.**

### `kayantesting.StorageSuite` as the conformance contract

```go
func StorageSuite(t *testing.T, newStore func() domain.Storage)
func StorageSuiteWithModel(t *testing.T, newStore func() domain.Storage, factory func() any)
```

```go
package mongostore_test

func TestMongoStoreContract(t *testing.T) {
    kayantesting.StorageSuite(t, func() domain.Storage {
        return mongostore.New(freshTestDatabase(t))
    })
}
```

`newStore` must return a **fresh, empty store on each call** — the suite invokes
it once per subtest so a failure in one cannot cascade into the next.

The default model is `kayantesting.SuiteIdentity`, a plain struct with `ID`,
`Email`, `Name`, and `State`. If your adapter can only persist a type it already
knows — one carrying database struct tags, say — use `StorageSuiteWithModel` with
your own factory. The model must have string fields named `ID`, `Email`, and
`Name`; the suite validates this first and fails with a clear message rather than
panicking mid-run.

For a SQL adapter, migrate inside `newStore`:

```go
kayantesting.StorageSuite(t, func() domain.Storage {
    db := openTestDB(t)
    if err := db.AutoMigrate(&kayantesting.SuiteIdentity{}); err != nil {
        t.Fatal(err)
    }
    return mystore.New(db)
})
```

What it asserts:

**Identity** — create/get round-trip; get-missing errors; find by field;
find-with-no-match errors rather than returning empty success; find requires
*every* field to match; update persists; delete makes get error; list paginates
with **1-based** pages and returns an empty page past the end with a **nil
error** (a pagination loop would otherwise treat exhaustion as failure).

**Credential** — create then look up; method scopes the lookup; missing
credential errors; update secret persists.

**Session** — create/get; get by refresh token; delete invalidates **both**
paths; missing session errors.

**Token** — save/get round-trip; delete; an expired token is not returned;
`DeleteExpiredTokens` leaves live tokens alone.

Every one of those is a behavior some plausible implementation gets wrong, and
every failure mode is an authentication defect rather than a cosmetic one.

Where it falls short, stated plainly because a suite trusted beyond its coverage
is worse than one nobody trusts:

- **It does not exercise `audit.AuditStore` at all**, despite `AuditStore` being
  part of the composite. A store passes the whole suite with a `SaveEvent` that
  discards events.
- **It does not cover tenancy.** Every subtest uses a bare `context.Background()`.
- **`DeleteExpiredTokens` is half-asserted** — it checks that a live token
  survives, not that the expired one was removed. A no-op passes that case.

`kayan-gorm` runs the suite through `contract_test.go` and also has dedicated
real-database, audit, and tenancy tests. Anyone writing a new adapter should run
the shared suite and add equivalent tests for the contracts it does not cover.

### Clock injection

```go
func NewFakeClock(t time.Time) *FakeClock
func (c *FakeClock) Advance(d time.Duration)
```

`Advance` accepts a negative duration, which is how clock-skew handling gets
tested. `MemoryStore` accepts a clock through `WithClock`; **`kayan-gorm` does
not** — it calls `time.Now()` directly, so its expiry behavior is not injectable.
Accept a `domain.Clock` in your adapter; it costs one field and makes every
expiry test deterministic.

Note the two bundled stores disagree on a boundary: `MemoryStore` treats a **zero
`ExpiresAt` as never expiring**, while the GORM predicate `expires_at > ?` treats
it as **always expired**. Neither is wrong. Always set `ExpiresAt` explicitly, and
document which convention your store follows.

---

## Writing a session `Strategy`

```go
type Strategy interface {
    Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
    Validate(ctx context.Context, sessionID any) (*identity.Session, error)
    Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
    Delete(ctx context.Context, sessionID any) error
}
```

`session.Manager` delegates all four and adds logout notifiers. Two are bundled:
`DatabaseStrategy` (revocable, one row per session) and `JWTStrategy`
(stateless, not revocable without a `RevocationStore`).

Four obligations on an implementation.

**Pin the algorithm on every parse path, if you parse tokens.** This is the
mistake most worth naming. A service verifying RS256 tokens with an RSA public
key is vulnerable if the library reads `alg` from the token header and picks the
verification method accordingly: an attacker re-signs a valid token with HS256
using the PEM text of the *public* key as the HMAC secret, and it verifies —
because the public key is published, often at a JWKS endpoint.

`JWTStrategy` routes every parse through one `keyFunc` so the check cannot be
present on some paths and missing on others. `Delete` is the one that gets missed
elsewhere, because parsing there only reads the expiry — and an unpinned `Delete`
is a denial-of-service primitive: forge a token naming someone else's session and
revoke it.

If you build on `core/keys`, `keys.Keyfunc` does the pinning for you:

```go
func (s *KMSStrategy) Validate(ctx context.Context, sessionID any) (*identity.Session, error) {
    raw, ok := sessionID.(string)
    if !ok {
        return nil, fmt.Errorf("kmssession: session ID must be a string token")
    }

    // Keyfunc resolves the key by "kid" and rejects any token whose "alg" does
    // not match the algorithm recorded for that key.
    token, err := jwt.Parse(raw, keys.Keyfunc(ctx, s.provider))
    if err != nil || !token.Valid {
        return nil, fmt.Errorf("kmssession: invalid token")
    }
    // ... map claims onto *identity.Session ...
}
```

**`Delete` must actually delete or return an error.** The built-in stateless
strategy returns an error when it has no revocation store; it never reports a
successful logout while the token remains valid. Custom strategies should keep
the same contract.

**Rotate on refresh, and invalidate the old session.** `DatabaseStrategy.Refresh`
issues a new session ID *and* a new refresh token, then deletes the old row:

```go
oldID := sess.ID
sess.ID = uuid.New().String()
sess.RefreshToken = uuid.New().String()
// ... create the new session ...
_ = s.repo.DeleteSession(ctx, oldID)
```

Reusing the session ID across a refresh means a captured token stays valid after
rotation, which defeats the point.

**Use `domain.TokenGenerator` for the token value**, not a record-ID generator.
`DefaultTokenGenerator` is 32 bytes from `crypto/rand`; `NewTokenGenerator`
panics below 16 rather than producing a weak generator quietly. A time-ordered
UUIDv7 as a session token is predictable, produces no error, and passes every
functional test.

One deployment constraint to know: the cross-application SSO store in
`core/session` is **in-memory only**, so single sign-on is single-process.

---

## Writing a `SignatureVerifier` for SAML

```go
type SignatureVerifier interface {
    Verify(ctx context.Context, doc []byte, certs []*x509.Certificate) (*ValidatedDocument, error)
}
```

XML-DSig is the only signature format SAML defines, so the *format* is not
configurable. The *implementation* is. Replace it to verify through an HSM, to
pin a stricter policy, or to use a different library.

The interface documents three obligations, and each is load-bearing:

> - reject a document with no signature;
> - verify the signature against the supplied certificates only;
> - return the *signed* element, so callers cannot read unsigned content.

The third is the one that matters most, and the return type is what enforces it:

```go
type ValidatedDocument struct {
    Element         *etree.Element
    XML             []byte
    SignedAssertion bool
    CoveredResponse bool
}
```

`XML` is the serialization of the element the signature actually covered. **The
unverified tree is not carried alongside it**, so XML Signature Wrapping cannot
be expressed: `ProcessResponse` unmarshals from `verified.XML` and there is no
document B in scope to read from instead.

An HSM-backed verifier:

```go
package hsmsaml

import (
    "context"
    "crypto"
    "crypto/x509"
    "fmt"

    "github.com/beevik/etree"
    saml "github.com/getkayan/kayan/kayan-saml"
)

// Verifier verifies SAML signatures using a hardware-held verification service.
type Verifier struct {
    hsm HSM
}

// HSM is the module-side operation: verify sig over digest with the public key
// of cert. Key material never enters this process.
type HSM interface {
    Verify(ctx context.Context, cert *x509.Certificate, hash crypto.Hash, digest, sig []byte) error
}

var _ saml.SignatureVerifier = (*Verifier)(nil)

func (v *Verifier) Verify(ctx context.Context, doc []byte, certs []*x509.Certificate) (*saml.ValidatedDocument, error) {
    // 1. Refuse an unsigned document. Accepting one means anyone who can reach
    //    the ACS endpoint can assert any identity.
    if len(certs) == 0 {
        return nil, fmt.Errorf("hsmsaml: no certificates configured for this issuer")
    }

    parsed := etree.NewDocument()
    if err := parsed.ReadFromBytes(doc); err != nil {
        return nil, fmt.Errorf("hsmsaml: parse document: %w", err)
    }
    root := parsed.Root()
    if root == nil {
        return nil, fmt.Errorf("hsmsaml: document has no root element")
    }

    // 2. Locate the signed element, canonicalize it, and verify the digest and
    //    signature against the supplied certificates only. Never fall back to a
    //    certificate embedded in the document: that is self-signed data.
    signed, isAssertion, coveredResponse, err := v.verifySignedElement(ctx, root, certs)
    if err != nil {
        return nil, err
    }

    // 3. Return only what the signature covered. Serializing the original doc
    //    here would reintroduce the Signature Wrapping surface the type exists
    //    to remove.
    out := etree.NewDocument()
    out.SetRoot(signed.Copy())
    raw, err := out.WriteToBytes()
    if err != nil {
        return nil, fmt.Errorf("hsmsaml: serialize validated element: %w", err)
    }

    return &saml.ValidatedDocument{
        Element:         signed,
        XML:             raw,
        SignedAssertion: isAssertion,
        CoveredResponse: coveredResponse,
    }, nil
}
```

`CoveredResponse` is not cosmetic. When only the assertion is signed, the
enclosing `Response`'s `Destination`, `InResponseTo`, and `Issuer` are
attacker-controlled — an attacker holding a captured signed assertion can wrap it
in a `Response` of their own construction with any attribute values. Reporting
`CoveredResponse: true` when it is false tells `validateAssertion` to check
attacker-supplied fields, which proves nothing while creating the appearance of a
check. Report it accurately or report `false`.

When a Response and its Assertion are both signed, return the **Assertion** — it
is the element carrying the identity claims, and returning the Response would
leave the Assertion unverified.

Install it:

```go
sp := saml.NewServiceProvider(config, sessionStore, repo, factory,
    saml.WithSignatureVerifier(&hsmsaml.Verifier{hsm: module}),
)
```

The corresponding outbound interface keeps a private key in the module:

```go
type Signer interface {
    Sign(ctx context.Context, doc []byte) ([]byte, error)
}
```

Kayan calls `Sign` and never holds key material. Install with `WithSPSigner`.

**Test a replacement verifier against the wrapping corpus.**
`TestSignatureWrappingRejected` in `attack_test.go` builds a genuinely signed
response, then constructs an unsigned forged assertion naming
`admin@example.com`, and places it three ways: before the signed assertion (for a
parser taking the first match), after it (for one taking the last), and with the
signed assertion relocated into an `<Extensions>` element so the forged one sits
where the schema expects. The assertion is not merely that an error is returned —
accepting is tolerable only if the resulting identity is the signed one, never the
injected one. A test that only checks `err != nil` would pass if the underlying
library started rejecting the payload for an unrelated reason, and would stop
testing your defense.

Do not implement `WithAllowUnsigned` behavior in a production verifier. The
bundled option exists for interoperability testing against a local IdP, and its
doc comment says outright that it disables authentication of the assertion
entirely.

---

## Writing a tenant `Scoper`

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
separated — row-level with a `tenant_id` column, schema-per-tenant, and
database-per-tenant are all valid and the right answer depends on the deployment.
A GORM `Scoper` receives a `*gorm.DB`; a Mongo one receives a filter document;
each asserts the type it expects.

### The fail-closed contract

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
they asked a narrow question and got a broad answer with no error, no log line,
and no symptom.

**The trap adapter authors fall into**: a system context returns `("", true)` —
empty ID, `ok` true. Checking only `ok` and then appending `tenant_id = ""`
silently breaks every system-context operation, of which `DeleteExpiredTokens` is
the canonical one. `gormstore.scopeQuery` avoids it by testing
`tenant.IsSystemContext(ctx)` and returning *before* it calls `RequireID`.

### Schema-per-tenant

```go
package pgtenant

import (
    "context"
    "fmt"
    "regexp"

    "github.com/getkayan/kayan/core/tenant"
    "gorm.io/gorm"
)

// safeSchema bounds a tenant ID to what can appear in an identifier.
//
// A schema name cannot be a bound parameter — it is part of the SQL grammar —
// so the only defense is refusing anything that is not a plain identifier.
var safeSchema = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// SchemaScoper routes each tenant's queries to its own PostgreSQL schema.
type SchemaScoper struct {
    prefix string
}

var _ tenant.Scoper = (*SchemaScoper)(nil)

func (s *SchemaScoper) Scope(ctx context.Context, query any) (any, error) {
    db, ok := query.(*gorm.DB)
    if !ok {
        return nil, fmt.Errorf("pgtenant: expected *gorm.DB, got %T", query)
    }

    // A system context deliberately spans tenants, so there is no schema to
    // select. Test this BEFORE RequireID: a system context returns ("", true),
    // and treating that empty ID as a schema name breaks every cross-tenant job.
    if tenant.IsSystemContext(ctx) {
        return db, nil
    }

    id, ok := tenant.RequireID(ctx)
    if !ok {
        // Fail closed. Proceeding here would query whichever schema happens to
        // be on the search path — usually another tenant's.
        return nil, tenant.ErrNoTenant
    }

    schema := s.prefix + id
    if !safeSchema.MatchString(schema) {
        return nil, fmt.Errorf("pgtenant: tenant %q does not form a valid schema name", id)
    }

    return db.Exec(fmt.Sprintf("SET LOCAL search_path TO %q", schema)), nil
}
```

Two things this gets right that are easy to get wrong. `SET LOCAL` rather than
`SET` scopes the change to the transaction, so a pooled connection returned to
the pool does not carry one tenant's search path into the next request — that
particular bug leaks data across tenants *nondeterministically*, depending on
connection reuse, which makes it nearly impossible to reproduce. And the schema
name is validated against a regexp because it cannot be parameterized; a tenant
ID that reaches an identifier position unvalidated is SQL injection.

### Database-per-tenant

Same shape, resolving a connection instead:

```go
func (s *DatabaseScoper) Scope(ctx context.Context, query any) (any, error) {
    if _, ok := query.(*gorm.DB); !ok {
        return nil, fmt.Errorf("dbtenant: expected *gorm.DB, got %T", query)
    }
    if tenant.IsSystemContext(ctx) {
        // There is no single database that spans tenants. Refuse rather than
        // silently picking one — a cross-tenant job needs a fan-out, and
        // returning an arbitrary connection would answer the wrong question.
        return nil, fmt.Errorf("dbtenant: system context requires an explicit per-tenant fan-out")
    }

    id, ok := tenant.RequireID(ctx)
    if !ok {
        return nil, tenant.ErrNoTenant
    }

    db, err := s.pool.For(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("dbtenant: resolve database for %q: %w", id, err)
    }
    return db, nil
}
```

Refusing the system context here is honest: with one database per tenant there is
no connection that sees everything, so a sweep must iterate tenants explicitly.
Returning some arbitrary connection would let `DeleteExpiredTokens` appear to
succeed while touching one tenant.

### Enforcement placement

Whatever the mode, apply it by **callback rather than per repository method**:

> Isolation is applied by a callback rather than by each repository method
> remembering to add a predicate. Per-method application is how leaks happen: the
> one query somebody forgets is the one that returns another customer's rows, and
> nothing fails until it does.

`kayan-gorm` registers five callbacks with one call:

```go
func RegisterTenantIsolation(db *gorm.DB) error
```

covering query, update, delete, row, and create. Only models implementing
`tenant.Scoped` are affected. Two implementation details there are load-bearing:
`stampTenant` uses `db.Statement.SetColumn` rather than a field assignment so it
applies to every row of a batch insert, and `isScopedModel` reflects into a
destination slice's *element* type so `Find(&[]User{})` is still scoped —
checking only the top-level destination would leave list queries unscoped, which
is the worst possible place to miss.

For an adapter that cannot push a predicate into the query at all — a key-value
store, a cache — enforce on the way out:

```go
if err := tenant.Verify(ctx, record); err != nil {
    return nil, err
}
```

`ErrCrossTenant`'s message deliberately does not name the record's actual tenant:
doing so would confirm the record exists and disclose its owner.

The suite does not cover tenancy, so this path needs your own tests.
`kayan-gorm/tenant_test.go` is a usable template, with cases for cross-tenant
reads, fail-closed behavior, system context, insert stamping, unscoped models,
and caller override attempts.

---

## Writing a `domain.Hasher`

```go
type Hasher interface {
    Hash(password string) (string, error)
    Compare(password, hash string) bool
}
```

`Compare` returns a bare `bool` rather than `(bool, error)`. That is deliberate:
a hash comparison has exactly two useful outcomes, and an error return invites
the caller to write `if err != nil { return true }` or some equivalent inversion.

An argon2id implementation:

```go
package argonhash

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"

    "github.com/getkayan/kayan/core/domain"
    "golang.org/x/crypto/argon2"
)

// Hasher hashes secrets with argon2id.
//
// Unlike bcrypt it has no 72-byte input limit, so a long passphrase is hashed
// in full rather than silently truncated.
type Hasher struct {
    Time    uint32 // passes over memory
    Memory  uint32 // KiB
    Threads uint8
    KeyLen  uint32
    SaltLen uint32
}

var _ domain.Hasher = (*Hasher)(nil)

// New returns a hasher with the RFC 9106 second recommended parameters:
// 64 MiB, three passes. Raise Memory as hardware allows — memory hardness is
// what makes GPU cracking expensive, and it is the parameter that matters.
func New() *Hasher {
    return &Hasher{Time: 3, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}
}

// Hash returns an encoded argon2id hash in the standard PHC string format.
//
// The parameters are embedded in the output, so raising them later does not
// invalidate existing hashes: each verifies with the parameters it was made
// with.
func (h *Hasher) Hash(password string) (string, error) {
    salt := make([]byte, h.SaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", fmt.Errorf("argonhash: read salt: %w", err)
    }

    key := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)

    return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version, h.Memory, h.Time, h.Threads,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(key),
    ), nil
}

// Compare reports whether password matches hash.
//
// It returns false for a malformed hash rather than reporting an error: the
// interface has two outcomes, and "could not parse" is not a match.
func (h *Hasher) Compare(password, hash string) bool {
    params, salt, want, err := decode(hash)
    if err != nil {
        return false
    }

    // Recompute with the stored parameters, not the configured ones, so a hash
    // written before a parameter change still verifies.
    got := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, uint32(len(want)))

    // Constant-time. A bytes.Equal here leaks the matching prefix length of the
    // derived key, which is a usable oracle against a stolen database.
    return subtle.ConstantTimeCompare(got, want) == 1
}

func decode(encoded string) (*Hasher, []byte, []byte, error) {
    parts := strings.Split(encoded, "$")
    if len(parts) != 6 || parts[1] != "argon2id" {
        return nil, nil, nil, errors.New("argonhash: not an argon2id hash")
    }

    var version int
    if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
        return nil, nil, nil, fmt.Errorf("argonhash: parse version: %w", err)
    }
    if version != argon2.Version {
        // A hash from a different argon2 version cannot be recomputed here.
        // Refusing is correct: guessing would silently reject valid passwords.
        return nil, nil, nil, errors.New("argonhash: unsupported argon2 version")
    }

    p := &Hasher{}
    if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
        return nil, nil, nil, fmt.Errorf("argonhash: parse parameters: %w", err)
    }

    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return nil, nil, nil, fmt.Errorf("argonhash: decode salt: %w", err)
    }
    key, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return nil, nil, nil, fmt.Errorf("argonhash: decode key: %w", err)
    }
    return p, salt, key, nil
}
```

Wire it wherever a `domain.Hasher` is accepted:

```go
hasher := argonhash.New()
pw := flow.NewPasswordStrategy(repo, hasher, "Email", func() any { return &User{} })
provider := oauth2.NewProvider(cs, acs, rts, issuer, key, kid,
    oauth2.WithClientSecretHasher(hasher))
```

**The hasher must be the same one used to produce the stored hashes.** Swapping
it on a live database makes every existing password fail to verify. Migration
means detecting the old format in `Compare`, verifying with the old algorithm,
and re-hashing on successful login — which is a `Hasher` that wraps both.

Two mistakes to test against explicitly. **Never embed a fixed salt**: identical
passwords then produce identical hashes, which turns a database disclosure into
a "who else uses this password" index and makes precomputation viable. And
**never `bytes.Equal` the derived key** — the timing leak is small but real, and
`subtle.ConstantTimeCompare` costs nothing.

The bundled `domain.BcryptHasher` rejects secrets over 72 bytes rather than
truncating, because bcrypt silently ignores input past that point and two
passwords sharing a 72-byte prefix would both verify. argon2id has no such limit,
so this implementation does not need the check — but if you wrap another
algorithm that does, reject rather than truncate.

---

## Writing a `keys.Provider` or `keys.Signer` for KMS

Two interfaces, and choosing between them is the decision.

```go
type Provider interface {
    Active(ctx context.Context) (*Key, error)
    ByKID(ctx context.Context, kid string) (*Key, error)
    Verification(ctx context.Context) ([]*Key, error)
}

type Signer interface {
    Sign(ctx context.Context, claims jwt.Claims, header map[string]any) (string, error)
}
```

**`Provider` hands out key material.** It is right when the key is in your
process — a static RSA key, a key loaded from a secret manager at startup, a key
rotated in memory.

**`Signer` never exposes a private key.** It is the one to implement when the key
lives in an HSM or a cloud KMS: Kayan calls `Sign` and never inspects key
material. This is the *whole point* of the seam.

```go
package kmskeys

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"

    "github.com/getkayan/kayan/core/keys"
    "github.com/golang-jwt/jwt/v5"
)

// Signer signs JWTs with a key that never leaves the KMS.
type Signer struct {
    kms   KMS
    keyID string
    alg   jwt.SigningMethod
}

// KMS is the provider-side operation. The private key is a handle, not bytes.
type KMS interface {
    Sign(ctx context.Context, keyID string, message []byte) (signature []byte, err error)
}

var _ keys.Signer = (*Signer)(nil)

// Sign assembles the compact serialization by hand: the JOSE header and payload
// are built here, and only the signing input crosses into the KMS.
func (s *Signer) Sign(ctx context.Context, claims jwt.Claims, header map[string]any) (string, error) {
    joseHeader := map[string]any{
        // alg must describe what the KMS key actually does. A header claiming
        // RS256 over an ES256 signature produces a token nothing can verify,
        // and debugging it means suspecting every layer but this one.
        "alg": s.alg.Alg(),
        "typ": "JWT",
        // kid lets a verifier select the right key from JWKS. Without it,
        // rotation forces every relying party to try every published key.
        "kid": s.keyID,
    }
    for k, v := range header {
        joseHeader[k] = v
    }

    headerJSON, err := json.Marshal(joseHeader)
    if err != nil {
        return "", fmt.Errorf("kmskeys: marshal header: %w", err)
    }
    claimsJSON, err := json.Marshal(claims)
    if err != nil {
        return "", fmt.Errorf("kmskeys: marshal claims: %w", err)
    }

    signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
        "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

    signature, err := s.kms.Sign(ctx, s.keyID, []byte(signingInput))
    if err != nil {
        return "", fmt.Errorf("kmskeys: sign with %q: %w", s.keyID, err)
    }

    return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
```

Signature encoding is where KMS integrations break. ECDSA signatures come back
DER-encoded from most KMS APIs, and JWS requires the raw fixed-width `r || s`
concatenation — 64 bytes for P-256. Passing DER through produces a token that
looks well-formed and fails verification everywhere, with an error message that
says nothing useful. Convert explicitly.

A `Provider` for JWKS publication, where only public keys are needed:

```go
type PublicProvider struct {
    active  *keys.Key
    retired []*keys.Key
}

var _ keys.Provider = (*PublicProvider)(nil)

func (p *PublicProvider) Active(context.Context) (*keys.Key, error) {
    if p.active == nil {
        return nil, keys.ErrNoKey
    }
    return p.active, nil
}

func (p *PublicProvider) ByKID(_ context.Context, kid string) (*keys.Key, error) {
    for _, k := range append([]*keys.Key{p.active}, p.retired...) {
        if k != nil && k.KID == kid {
            return k, nil
        }
    }
    // Reporting the miss rather than falling back to the active key is what
    // stops a token signed with a retired key from verifying against the
    // current one — or vice versa.
    return nil, fmt.Errorf("%w: %q", keys.ErrKeyNotFound, kid)
}

func (p *PublicProvider) Verification(context.Context) ([]*keys.Key, error) {
    // Active first, then retired: tokens issued before a rotation must keep
    // verifying until the old key is dropped.
    return append([]*keys.Key{p.active}, p.retired...), nil
}
```

The `Key` records its own `jwt.SigningMethod`, which is what makes algorithm
choice the caller's. `keys.Keyfunc` uses it to reject any token whose `alg` does
not match the algorithm recorded for that `kid` — which is what prevents an
attacker re-signing an RSA-issued token as HMAC using the public key as the
secret. **A `Provider` whose keys have a nil or wrong `Method` disables that
check.** `Key.Validate()` catches a nil method; a *wrong* one it cannot catch.

Install:

```go
provider := oauth2.NewProvider(cs, acs, rts, issuer, nil, "kms-2026-01",
    oauth2.WithKeyProvider(&kmskeys.PublicProvider{active: publicKey}),
)
set, err := provider.JWKS(ctx)
```

`JWKS` requires a key provider — there is no way to enumerate a bare key. Adding
a hardcoded `jwt.SigningMethodRS256` anywhere in `core/keys` defeats the purpose
of the package and is a regression.

---

## Writing an `rbac.RoleStore`

```go
type RoleStore interface {
    GetRole(ctx context.Context, name string) (*Role, error)
    SaveRole(ctx context.Context, role *Role) error
    DeleteRole(ctx context.Context, name string) error
    ListRoles(ctx context.Context) ([]*Role, error)
}

type Role struct {
    Name        string
    Permissions []string
    Inherits    []string
    Description string
}
```

Definitions live in storage rather than process memory because they are shared
state: a role created on one replica must be visible to the next request,
whichever replica serves it. The bundled `MemoryStrategy` implements `RoleStore`
in memory and its own doc points at `StorageStrategy` with a shared store for
anything running more than one instance.

**The single most important obligation: `GetRole` must return
`rbac.ErrRoleNotFound` for an undefined role, not a zero `*Role` and not
`(nil, nil)`.**

```go
var ErrRoleNotFound = errors.New("rbac: role is not defined")
```

Returning an empty role instead is a silent authorization failure. A dangling
assignment — a role deleted while assignments still name it, or a typo — would
resolve to an empty permission set, and every check against it returns `false`
with no error. That presents to an operator as "permissions randomly stopped
working", with behavior that may differ per replica if roles are cached in
process memory. The resolver says why:

> A missing parent is a broken definition, not an absence of permission.
> Reporting it lets an operator fix the role instead of debugging a mysterious
> denial.

A legitimate refusal and a broken configuration need different responses.
Collapsing both into `false` hides the second behind the first.

```go
package pgroles

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"

    "github.com/getkayan/kayan/core/rbac"
)

type Store struct {
    db *sql.DB
}

var _ rbac.RoleStore = (*Store)(nil)

func (s *Store) GetRole(ctx context.Context, name string) (*rbac.Role, error) {
    var role rbac.Role
    var permissions, inherits []byte

    err := s.db.QueryRowContext(ctx,
        `SELECT name, permissions, inherits, description FROM rbac_roles WHERE name = $1`,
        name,
    ).Scan(&role.Name, &permissions, &inherits, &role.Description)

    switch {
    case errors.Is(err, sql.ErrNoRows):
        // Must be ErrRoleNotFound. An empty *Role here turns a broken
        // definition into a silent denial that looks exactly like a
        // legitimate refusal.
        return nil, fmt.Errorf("%w: %q", rbac.ErrRoleNotFound, name)
    case err != nil:
        return nil, fmt.Errorf("pgroles: get role %q: %w", name, err)
    }

    if err := json.Unmarshal(permissions, &role.Permissions); err != nil {
        return nil, fmt.Errorf("pgroles: decode permissions for %q: %w", name, err)
    }
    if err := json.Unmarshal(inherits, &role.Inherits); err != nil {
        return nil, fmt.Errorf("pgroles: decode inherits for %q: %w", name, err)
    }
    return &role, nil
}

func (s *Store) SaveRole(ctx context.Context, role *rbac.Role) error {
    if role == nil || role.Name == "" {
        return errors.New("pgroles: role must have a name")
    }
    permissions, err := json.Marshal(role.Permissions)
    if err != nil {
        return fmt.Errorf("pgroles: encode permissions: %w", err)
    }
    inherits, err := json.Marshal(role.Inherits)
    if err != nil {
        return fmt.Errorf("pgroles: encode inherits: %w", err)
    }

    _, err = s.db.ExecContext(ctx, `
        INSERT INTO rbac_roles (name, permissions, inherits, description)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (name) DO UPDATE
        SET permissions = EXCLUDED.permissions,
            inherits    = EXCLUDED.inherits,
            description = EXCLUDED.description`,
        role.Name, permissions, inherits, role.Description)
    if err != nil {
        return fmt.Errorf("pgroles: save role %q: %w", role.Name, err)
    }
    return nil
}
```

Two more properties to get right.

**Inheritance resolution walks the graph through `GetRole`.** `resolvePermissions`
tracks the current path in a `visiting` map so a cycle is reported as
`rbac.ErrCycle` rather than followed until the stack runs out, and bounds depth at
`MaxInheritanceDepth = 32`. Your store does not implement that walk — it just has
to answer `GetRole` correctly and consistently, including for the parents. A store
that caches roles with inconsistent invalidation makes the walk return different
answers on different replicas.

**Wildcards are honored only in grants, never in the permission being checked.**
Otherwise a caller could ask "may I do anything?" and be answered yes because some
narrow grant matched. Matching is segment-based string comparison, not regex — a
regex in a permission string is a denial-of-service vector and its semantics are
unclear to whoever authors the grant. See
[Authorization Models](./authorization-models.md) for the matcher.

Wire it up:

```go
strategy := rbac.NewStorageStrategy(assignmentStore, &pgroles.Store{db: db})
```

`AssignRole` refuses to assign an undefined role, so a typo surfaces at write time
rather than as a mysterious denial later.

---

## Adding a new module

A module absent from CI is a module nothing checks. Five steps, and skipping any
one of them produces a module that builds locally and is unverified in CI.

**1. Add it to the workspace.**

```bash
go work use ./kayan-newthing
```

`go.work` currently lists the root plus eight modules, all on Go 1.25.5. The
eleven directories under `examples/` are deliberately **outside** `go.work` so
they resolve dependencies the way a real consumer would — which is also why they
have their own CI job that builds each with `GOWORK=off`.

**2. Point it at `core`.**

```
// kayan-newthing/go.mod
module github.com/getkayan/kayan/kayan-newthing

go 1.25.5

require github.com/getkayan/kayan/core v0.0.0

replace github.com/getkayan/kayan/core => ../core
```

**3. Add it to the CI matrices.** Three files, four places.

`.github/workflows/ci.yml` — both the `lint` and `build` matrices:

```yaml
matrix:
  module: [core, kayan-gorm, kayan-ldap, kayan-newthing, kayan-oidc-provider,
           kayan-redis, kayan-saml, kayan-scim, kayan-testing, cmd/kayan-cli]
```

`.github/workflows/test.yml` — a per-module step, since the test job lists them
individually rather than as a matrix:

```yaml
- name: Run kayan-newthing Tests
  working-directory: kayan-newthing
  run: go test -race ./...
```

If your module has fuzz targets, add it to the `fuzz` matrix too — currently
`[kayan-oidc-provider/oauth2, kayan-saml, kayan-scim]`. Targets are discovered by
grep and each runs for 30 seconds on every push. Anything under `testdata/fuzz/`
is a previously-found crasher and runs as a regression test regardless of the
fuzzing budget. **Do not delete those files.**

`.github/workflows/security.yml` — the `govulncheck` matrix, same module list as
`ci.yml`.

**4. Add it to the arch-lint module list** in `ci.yml`:

```bash
for module in kayan-gorm kayan-ldap kayan-newthing kayan-oidc-provider \
              kayan-redis kayan-saml kayan-scim kayan-testing; do
```

Miss this and `core` can import your module with nothing objecting, which is the
one rule the whole topology rests on.

**5. Add it to `.github/dependabot.yml`:**

```yaml
- package-ecosystem: gomod
  directory: /kayan-newthing
  schedule:
    interval: weekly
  open-pull-requests-limit: 5
```

Each module has its own `go.mod` and therefore its own dependency set. A module
absent here never gets a security update proposed. Note the file also pins
GitHub Actions, with the comment: "An auth library whose CI runs floating action
tags is a supply-chain target" — every action in the workflows is pinned to a
commit SHA, and a new workflow should follow that.

### Protocol storage ships with its protocol

If the new module is a protocol, its storage subpackage belongs **inside it** —
`kayan-oidc-provider/gormstore`, `kayan-scim/gormstore` — not in `kayan-gorm`.

Two reasons. If `kayan-gorm` carried the OAuth 2.0 repositories, every consumer
of the storage adapter would compile the OAuth 2.0 types those repositories
persist; `kayan-gorm` would import `kayan-oidc-provider`, and the protocol would
be back in everyone's dependency graph through the back door. And a storage
schema and the protocol it serves change together — adding refresh token family
tracking meant adding `FamilyID` and `UsedAt` to both the type and the table, one
change that cannot be made atomically across two modules.

### Before pushing

```bash
cd kayan-newthing && go build ./... && go vet ./... && go test -race ./...
```

For a security fix, also revert it and confirm the test fails. A test that passes
either way proves nothing, and this repository has had several.

---

## Documentation is checked

Every fenced Go block under `docs/` is walked by `tools/docsample` in CI:

```bash
cd tools/docsample && GOWORK=off go run . ../../docs
```

It reports blocks that call a storage or session method without a context, and
blocks naming a package that was renamed or moved. Blocks that are deliberately
partial — a bare interface definition, a fragment with no imports — are skipped
rather than reported, so the signal stays meaningful. Mark a block with the
`notest` info string to skip it explicitly:

````
```go notest
// A fragment that is not meant to compile.
```
````

The rationale in the tool's own doc comment:

> A documented signature that does not compile is worse than no documentation:
> it looks authoritative and sends the reader down a path that cannot work.

When you extend Kayan, update the package doc comments, the architecture doc that
places your package in the graph, and the feature docs — and add the tests
alongside, not after.

---

## Related

- [Architecture Overview](./README.md) — module topology, the one-way dependency
  rule, and how CI enforces it
- [Storage Layer](./storage-layer.md) — the `domain.Storage` contract in full and
  the conformance suite
- [Security Model](./security-model.md) — what fails closed, and the honest gap
  list
- [Authentication Flows](./authentication-flows.md) — where each strategy sits in
  a request
- [Authorization Models](./authorization-models.md) — RBAC, ABAC, and ReBAC
  evaluation
- [Strategy Internals](./strategy-internals.md) — managers, decorators, hooks
- [BYOS](../concepts/byos.md) — the factory pattern and why not generics
- [Multi-Tenancy](../concepts/multi-tenancy.md) — resolution and isolation modes
- [AGENTS.md](../../AGENTS.md) / [CLAUDE.md](../../CLAUDE.md) — the
  non-negotiables and the commit conventions
- [VERSIONING.md](../../VERSIONING.md) — pre-1.0, no deprecation cycle
