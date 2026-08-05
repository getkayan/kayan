# `core` API Reference

The `core` module holds everything Kayan needs to authenticate, authorize, and
isolate identities without a router, a UI, or a fixed user schema. Protocols
and their storage live in sibling modules; `core` never imports one, and CI
enforces that with `go list -deps`.

```
github.com/getkayan/kayan/core
```

This document covers every exported type, function, and constant that a caller
is expected to reach for. Signatures are read from the source rather than
paraphrased, because a reference that misstates a signature is worse than no
reference at all.

A note on shape before the details. Nearly every package here follows the same
three-part pattern: an interface describing what the application must supply,
a default implementation that is safe if you accept it, and a manager or
strategy that owns the security decisions in between. When you see `Store`,
`Strategy`, or `Provider`, that is the seam. When you see `New…` returning a
concrete type, that is the default you can keep.

## Contents

1. [`core/domain`](#coredomain) — storage contracts, hashing, clocks, token generation
2. [`core/identity`](#coreidentity) — identity, credential, session, trait mapping
3. [`core/keys`](#corekeys) — signing keys, JWKS, algorithm choice
4. [`core/flow`](#coreflow) — the authentication engine
5. [`core/session`](#coresession) — session strategies and SSO
6. [`core/rbac`](#corerbac) — roles, permissions, wildcards
7. [`core/rebac`](#corerebac) — relationship-based access control
8. [`core/policy`](#corepolicy) — ABAC, hybrid, caching, audit
9. [`core/tenant`](#coretenant) — multi-tenancy and isolation
10. [`core/mfa`, `core/device`, `core/risk`](#coremfa-coredevice-corerisk)
11. [Operational packages](#operational-packages) — audit, events, consent, compliance, health, telemetry, logger, config, admin

---

## `core/domain`

```go
import "github.com/getkayan/kayan/core/domain"
```

`domain` defines the contracts every storage backend must satisfy, plus the
small set of pluggable primitives — hashing, time, ID generation, token
generation — that security decisions elsewhere in Kayan depend on. It is the
lowest layer in the module and imports almost nothing, which is why a type
belongs here when more than one package needs it. `BcryptHasher` lives here,
not in `core/flow`, precisely because the OAuth provider and the admin manager
also hash secrets and could not reach it from a flow package.

Nothing in `domain` is an implementation you are required to use. Everything is
an interface with a default behind it.

### Storage contracts

`Storage` is the composite a general-purpose backend implements. A store that
satisfies it can be handed to any manager in Kayan.

```go
type Storage interface {
    IdentityStorage
    SessionStorage
    CredentialStorage
    audit.AuditStore
    TokenStore
}
```

Most callers implement `Storage` once — the bundled `kayan-gorm` adapter does —
and pass the same value everywhere. The pieces are separate interfaces so a
narrower backend is still usable: a Redis session store implements only
`SessionStorage`, and a manager that needs only sessions accepts only that.

#### `IdentityStorage`

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

This is where BYOS lives. There is no generic parameter and no base struct to
embed. Instead, the caller passes a `factory func() any` that returns a pointer
to an empty instance of their own model, and the implementation scans into it.
Your `User` struct keeps its own fields, its own ID type, and its own column
names.

An implementer must guarantee three things. First, `GetIdentity` and
`FindIdentity` populate the value the factory returned and return that same
value — the caller type-asserts it back to `*User`. Second, `FindIdentity`
treats the query map as an AND of field equality; the keys are field names in
the caller's model, not database columns, unless the adapter chooses to map
them. Third, every method honors the context.

That last point is not stylistic. The ambient tenant lives in the context, so a
method without one cannot be tenant-scoped, and isolation becomes
architecturally impossible rather than merely unimplemented. This is why every
storage and strategy method in Kayan takes a `context.Context` even where it
appears to have nothing to do.

#### `SessionStorage`

```go
type SessionStorage interface {
    CreateSession(ctx context.Context, s *identity.Session) error
    GetSession(ctx context.Context, id any) (*identity.Session, error)
    GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error)
    DeleteSession(ctx context.Context, id any) error
}
```

`GetSessionByRefreshToken` exists as a separate lookup because refresh tokens
are opaque credentials, not session IDs — the caller presenting one does not
know the session ID it maps to. An implementer should index the refresh token
column and must not return a session whose `Active` field is false without the
caller noticing; `session.DatabaseStrategy` checks expiry, but revocation
semantics belong to the store.

#### `CredentialStorage`

```go
type CredentialStorage interface {
    GetCredentialByIdentifier(ctx context.Context, identifier string, method string) (*identity.Credential, error)
    UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
}
```

This is the discrete-credentials path: one identity, many login methods, each
row keyed by `(identifier, method)`. A model that stores its password hash in a
column on the user table does not need this — `flow.PasswordStrategy` can read
the field directly via `MapFields`. Implement `CredentialStorage` when a user
can hold several credentials of different types.

`UpdateCredentialSecret` is what password reset and rotation call. It must be
an update, never an insert-if-missing: creating a credential for an identity
that had none would let a recovery flow mint a login method that never existed.

#### `TokenStore`

```go
type TokenStore interface {
    SaveToken(ctx context.Context, token *AuthToken) error
    GetToken(ctx context.Context, token string) (*AuthToken, error)
    DeleteToken(ctx context.Context, token string) error
    DeleteExpiredTokens(ctx context.Context) error
}
```

Transient credentials — magic links, OTP codes, verification and recovery
tokens — go here rather than in the session store, because they are single-use
and short-lived and the cleanup story is different.

`GetToken` must look up by the token value itself, which is the credential. An
implementer should treat the token column as sensitive: it is a bearer secret,
so it belongs in an indexed column that is not written to query logs.
`DeleteExpiredTokens` is for a background sweep; the flows that consume tokens
delete them explicitly on use and also check `ExpiresAt`, so an implementation
that never runs the sweep is safe but accumulates rows.

#### `AuthToken`

```go
type AuthToken struct {
    Token      string    `json:"token"`
    IdentityID string    `json:"identity_id"`
    Type       string    `json:"type"` // "recovery", "verification", "magic_link"
    ExpiresAt  time.Time `json:"expires_at"`
}
```

`Type` matters more than it looks. A verification token and a password-recovery
token are both random strings in the same table, and a flow that consumes one
without checking `Type` would let a user redeem an email-verification link as a
password reset. Consumers in `core/flow` check it.

### Hashing

```go
type Hasher interface {
    Hash(password string) (string, error)
    Compare(password, hash string) bool
}
```

The argument order is deliberate and worth noticing: `Compare(password, hash)`,
plaintext first. The deprecated `admin.PasswordHasher` took them the other way
round with the same types, which is exactly how a hasher gets wired up
backwards and silently accepts every password. See the note under
[`core/admin`](#coreadmin).

An implementer must make `Compare` constant-time with respect to the hash, and
must return false rather than an error on a malformed hash — a comparison that
errors on garbage input gives an attacker a distinguishable signal.

#### `BcryptHasher`

```go
type BcryptHasher struct {
    Cost int
}

func NewBcryptHasher(cost int) *BcryptHasher
func (h *BcryptHasher) Hash(password string) (string, error)
func (h *BcryptHasher) Compare(password, hash string) bool
```

The default wherever Kayan hashes a secret. A cost of zero selects
`DefaultBcryptCost`.

```go
const DefaultBcryptCost = 12
```

12 is roughly 250ms per hash on current hardware — high enough to make offline
cracking expensive, low enough that a login burst does not exhaust CPU. Raise
it as hardware improves; bcrypt stores the cost inside the hash, so existing
hashes keep verifying at their original cost and users are re-hashed only when
they next authenticate and you choose to upgrade them.

To use argon2id, scrypt, or an external hashing service, implement `Hasher` and
pass it to whichever component accepts one. Nothing about bcrypt is baked in.

### Clocks

```go
type Clock interface {
    Now() time.Time
}

type ClockFunc func() time.Time
func (f ClockFunc) Now() time.Time

var SystemClock Clock = ClockFunc(time.Now)

func ClockOrDefault(c Clock) Clock
```

Every security decision that depends on time — token expiry, assertion validity
windows, lockout durations, cache TTLs — reads the clock through this interface
so tests can drive them deterministically instead of sleeping. A test that
sleeps for a lockout window is a test that takes fifteen minutes and is flaky
on a loaded CI machine.

`ClockOrDefault` returns `SystemClock` when passed nil. Constructors call it so
that a caller who omits the option, or who explicitly passes a nil `Clock`,
gets working behavior rather than a nil-pointer panic on the first
authentication.

Implementations must be safe for concurrent use. A fake clock in a test that is
advanced from one goroutine and read from another needs a mutex.

```go
fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
clock := domain.ClockFunc(func() time.Time { return fixed })
```

### ID and token generation

These are two function types that look identical and must never be
interchanged.

```go
type IDGenerator func() any
type TokenGenerator func() (string, error)
```

`IDGenerator` produces record identifiers. Any scheme works — UUIDv4, UUIDv7,
ULID, a database sequence, a monotonic counter. Nothing about a record ID needs
to be unpredictable; it appears in URLs and logs and is often chosen to sort
well.

`TokenGenerator` produces a security token: an authorization code, a refresh
token, a magic link, a state value. The output is a credential. A sequential or
timestamp-derived value here lets an attacker guess a token belonging to
someone else, which turns a magic-link login into an account takeover.

They are separate named types rather than one shared signature precisely so
that a generator chosen for readable, sortable record IDs cannot be wired into
a credential path by accident. The compiler catches it.

```go
func NewTokenGenerator(n int) TokenGenerator
func TokenGeneratorOrDefault(g TokenGenerator) TokenGenerator

var DefaultTokenGenerator = NewTokenGenerator(DefaultTokenBytes)

const DefaultTokenBytes = 32
```

`NewTokenGenerator` draws `n` bytes from `crypto/rand` and encodes them as
base64url without padding. It **panics if `n` is below 16**. Fewer than 128 bits
is guessable at scale, and a misconfigured generator should fail at process
startup rather than quietly issue weak credentials for months. This is a wiring
mistake, not a runtime condition, so a panic is the correct response — there is
no caller who can recover from it meaningfully.

`DefaultTokenBytes` is 32, giving 256 bits. That is well beyond the 128-bit
floor RFC 6749 section 10.10 sets for authorization codes.

`TokenGeneratorOrDefault` returns `DefaultTokenGenerator` when passed nil,
following the same "omitted option still works" pattern as `ClockOrDefault`.

### Dynamic strategy configuration

```go
type StrategyConfig struct {
    ID       string         `json:"id"`       // Unique identifier (e.g. "google-marketing", "otp-sms")
    Type     string         `json:"type"`     // Strategy implementation type (e.g. "oauth2", "oidc", "password", "magic_link")
    Provider string         `json:"provider"` // Provider identifier (e.g. "google", "github")
    Enabled  bool           `json:"enabled"`  // Is this strategy active?
    Settings map[string]any `json:"settings"` // Type-specific settings (client_id, etc.)
}

type StrategyStore interface {
    GetStrategies(ctx context.Context) ([]*StrategyConfig, error)
    GetStrategy(ctx context.Context, id string) (*StrategyConfig, error)
    SaveStrategy(ctx context.Context, config *StrategyConfig) error
    DeleteStrategy(ctx context.Context, id string) error
}
```

This is for deployments that configure login methods at runtime rather than at
compile time — an admin console that turns on "Sign in with GitHub" without a
redeploy. `ID` and `Type` are distinct because one deployment can run several
instances of the same strategy type against different providers:
`google-marketing` and `google-corp` are both `Type: "oidc"`.

`Settings` is deliberately untyped. The strategy factory registered for that
`Type` in a `flow.StrategyRegistry` is what interprets it, and it is that
factory's job to reject a config it cannot build from.

An implementer should note that `Settings` will contain client secrets. It
belongs in encrypted storage, and a `StrategyStore` that logs its writes is a
credential leak.

---

## `core/identity`

```go
import "github.com/getkayan/kayan/core/identity"
```

`identity` provides the default identity, credential, and session types, plus
the small interfaces that let Kayan work with your model instead of these. The
important thing to understand is that `identity.Identity` is *optional*. It is
a reasonable model if you have no opinion, but the interfaces below are what
the rest of Kayan actually depends on, and your own struct can satisfy them.

### The one required interface

```go
type FlowIdentity interface {
    GetID() any
    SetID(any)
}
```

This is the minimum. Every model used in an authentication flow must implement
it, and it is the *only* required interface — everything else in this package
is optional and detected by type assertion at runtime.

`GetID` returns `any` rather than `string` so your ID type stays yours: a
`uint64` primary key, a `uuid.UUID`, a composite. `SetID` is called after a
registration strategy generates one.

```go
type User struct {
    UserID string `gorm:"primaryKey"`
    Email  string `gorm:"uniqueIndex"`
}

func (u *User) GetID() any   { return u.UserID }
func (u *User) SetID(id any) { u.UserID = id.(string) }
```

The type assertion in `SetID` is yours to get right. If you configure an
`IDGenerator` that returns a `uuid.UUID` and your `SetID` asserts `string`, it
panics on the first registration — loudly, at the point of the mistake, which
is the correct place for it.

### Optional interfaces

Kayan type-asserts for each of these and adapts its behavior when present.
Implementing none of them is valid; you then get only what a `FlowIdentity`
supports.

```go
type TraitSource interface {
    GetTraits() JSON
    SetTraits(JSON)
}
```

Enables trait-based flows: schema validation on registration, OIDC claim
mapping, LDAP attribute sync. Without it, a strategy that receives traits has
nowhere to put them.

```go
type CredentialSource interface {
    GetCredentials() []Credential
}
```

Note that the `identity` package's `CredentialSource` is read-only, while the
one in `core/flow` also has `SetCredentials`. They are different interfaces
with the same name in different packages; `flow.CredentialSource` is the one
the WebAuthn strategy asserts for.

```go
type Linkable interface {
    AddCredential(cred Credential)
    RemoveCredential(id string)
}
```

Required for account linking — attaching a second login method to an existing
identity. See `flow.Linker`.

```go
type Schema interface {
    Validate(traits JSON) error
}
```

Trait validation. `RegistrationManager` calls this before the strategy runs, so
a rejected trait set never reaches storage. An implementer should return a
descriptive error; `Submit` wraps it as `registration: validation failed: %v`.

```go
type MySchema struct{}

func (s MySchema) Validate(traits identity.JSON) error {
    var t struct {
        Email string `json:"email"`
    }
    if err := json.Unmarshal(traits, &t); err != nil {
        return fmt.Errorf("traits are not valid JSON: %w", err)
    }
    if !strings.Contains(t.Email, "@") {
        return errors.New("email is required")
    }
    return nil
}
```

### `Identity`

```go
type Identity struct {
    ID          string     `json:"id"`
    Traits      JSON       `json:"traits"`
    Roles       JSON       `json:"roles,omitempty"`
    Permissions JSON       `json:"permissions,omitempty"`
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
    DeletedAt   *time.Time `json:"-"`
    State       string     `json:"state"` // active, inactive, locked, pending

    MFAEnabled bool   `json:"mfa_enabled"`
    MFASecret  string `json:"-"`

    Verified   bool       `json:"verified"`
    VerifiedAt *time.Time `json:"verified_at"`

    Credentials []Credential `json:"-"`
}
```

The default model, satisfying every interface in this package. Three field tags
deserve attention. `MFASecret` is `json:"-"` because serializing a TOTP secret
into an API response hands out the second factor. `DeletedAt` is `json:"-"`
because soft-delete state is storage bookkeeping, not something a client should
key off. `Credentials` is `json:"-"` because a credential carries a `Secret`
field, and even though that field is itself excluded, shipping the credential
list tells an attacker which login methods exist for an account.

`State` is a plain string with four conventional values — `active`, `inactive`,
`locked`, `pending`. Kayan does not enforce a state machine over it; a strategy
that must refuse locked accounts checks it itself.

Methods:

```go
func (i *Identity) GetID() any
func (i *Identity) SetID(id any)
func (i *Identity) GetTraits() JSON
func (i *Identity) SetTraits(t JSON)
func (i *Identity) GetRoles() []string
func (i *Identity) RoleNames() []string
func (i *Identity) GetPermissions() []string
func (i *Identity) PermissionNames() []string
func (i *Identity) GetCredentials() []Credential
func (i *Identity) SetCredentials(c []Credential)
func (i *Identity) AddCredential(cred Credential)
func (i *Identity) RemoveCredential(id string)
func (i *Identity) MFAConfig() (bool, string)
func (i *Identity) IsVerified() bool
func (i *Identity) IsEmailVerified() bool
func (i *Identity) MarkVerified(at time.Time)
```

`GetRoles` and `RoleNames` both return `[]string`; the first satisfies
`rbac.RoleSource`, the second is the plainly-named accessor. Same relationship
between `GetPermissions` and `PermissionNames`.

`IsVerified` reads the `Verified` field. `IsEmailVerified` is different — it
inspects the traits for a verified-email marker, which is what an OIDC provider
sets when it asserts `email_verified`. A flow that decides whether to trust an
email for account linking wants the second, not the first.

### `Credential`

```go
type Credential struct {
    ID         string    `json:"id"`
    IdentityID string    `json:"identity_id"`
    Type       string    `json:"type"`
    Identifier string    `json:"identifier"`
    Secret     string    `json:"-"`
    Config     JSON      `json:"config"`
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`
}
```

One row per login method per identity. `Type` is the strategy ID
(`"password"`, `"webauthn"`, `"totp"`). `Identifier` is what the user presents
— an email, a username, a WebAuthn credential ID. `Secret` is the hash, never
the plaintext, and is excluded from JSON.

`Config` carries method-specific data that is not a secret: for WebAuthn it
holds a marshalled `flow.WebAuthnCredentialData` with the public key and sign
counter.

### `Session`

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

Shared by every session strategy. For `JWTStrategy` the `ID` field carries the
signed token rather than a database key — the token *is* the session — while
for `DatabaseStrategy` it is a stored primary key. `core/session` re-exports
this as `session.Session`.

Note that `RefreshToken` is *not* excluded from JSON. It is a bearer credential
that the caller must deliver to the client exactly once, so it has to survive
serialization; the responsibility for not logging the struct is the
application's.

### `JSON`

```go
type JSON []byte

func (j *JSON) Scan(value interface{}) error
func (j JSON) Value() (driver.Value, error)
```

A `[]byte` alias implementing `sql.Scanner` and `driver.Valuer`, so the same
type stores as `jsonb` on Postgres, `JSON` on MySQL, and `TEXT` on SQLite
without the caller branching per dialect. Construct it from a literal:

```go
traits := identity.JSON(`{"email":"dev@example.com"}`)
```

### `Mapper` and `ReflectionMapper`

```go
type Mapper interface {
    MapTraits(ident FlowIdentity) (JSON, error)
    UnmapTraits(ident FlowIdentity, traits JSON) error
}
```

`Mapper` bridges the conceptual trait keys Kayan uses (`"email"`) and the
struct fields your model actually has (`EmailAddress`). It exists for models
that do *not* implement `TraitSource` — where there is no traits blob, only
ordinary typed fields.

```go
type ReflectionMapper struct { /* unexported fields */ }

func NewReflectionMapper(factory func() FlowIdentity) *ReflectionMapper
func (m *ReflectionMapper) MapField(key, field string)
func (m *ReflectionMapper) MapTraits(ident FlowIdentity) (JSON, error)
func (m *ReflectionMapper) UnmapTraits(ident FlowIdentity, traits JSON) error
func (m *ReflectionMapper) Validate() error
```

`MapField` registers one key-to-field mapping. `Validate` checks that every
registered field actually exists on the model, and should be called at startup:
a typo in a field name is otherwise a silent no-op at runtime, where traits
quietly fail to populate and the resulting identity is missing its email.

```go
mapper := identity.NewReflectionMapper(func() identity.FlowIdentity { return &User{} })
mapper.MapField("email", "EmailAddress")
mapper.MapField("name", "FullName")
if err := mapper.Validate(); err != nil {
    log.Fatal(err) // a typo here is a startup failure, not a runtime surprise
}
```

Reflection has a cost per call. For a hot path, implement `Mapper` directly with
a hand-written struct conversion.

### Type aliases

```go
type DefaultIdentity = Identity
type DefaultCredential = Credential
type DefaultSession = Session
```

Aliases, not distinct types, so they are interchangeable with the originals.
They exist for readability at call sites where "default" is the point.

---

## `core/keys`

```go
import "github.com/getkayan/kayan/core/keys"
```

`keys` is the seam that makes algorithm choice the caller's. Kayan does not
pick a signing algorithm for you: a `Key` carries its own `jwt.SigningMethod`,
so RS256, ES256, EdDSA, and HS256 are all equally supported, and adding an
algorithm this package has never heard of requires no change here.

Adding a hardcoded `jwt.SigningMethodRS256` anywhere in the codebase is a
regression, not a convenience.

### `Key`

```go
type Key struct {
    // KID identifies the key. It is written to the token header and to JWKS so
    // a verifier can select the right key. Required.
    KID string

    // Method is the JWS algorithm this key signs with. Required.
    Method jwt.SigningMethod

    // Private signs. Required for the active key; may be nil for a key that is
    // retained only to verify already-issued tokens.
    Private any

    // Public verifies. Required for asymmetric algorithms.
    Public any

    // Use is "sig" or "enc". Defaults to "sig" when empty.
    Use string
}
```

`Private` and `Public` are typed as `any` so any algorithm can be carried
without a type parameter. `Private` holds `*rsa.PrivateKey`,
`*ecdsa.PrivateKey`, `ed25519.PrivateKey`, or `[]byte` for HMAC; `Public` holds
the corresponding public key and is unused for symmetric algorithms.

That `Private` may be nil is the rotation mechanism: a retired key keeps its
public half so already-issued tokens still verify, while losing the ability to
sign new ones.

```go
const (
    UseSignature  = "sig"
    UseEncryption = "enc"
)
```

Per RFC 7517 section 4.2.

Methods:

```go
func (k *Key) Algorithm() string  // JWS algorithm name, or "" when Method is nil
func (k *Key) CanSign() bool      // whether k carries private key material
func (k *Key) Validate() error    // whether k is usable
```

Switching algorithms is a one-line change and nothing else moves:

```go
// RSA
k := &keys.Key{KID: "2026-01", Method: jwt.SigningMethodRS256,
    Private: rsaKey, Public: &rsaKey.PublicKey}

// Ed25519 instead
k := &keys.Key{KID: "2026-01", Method: jwt.SigningMethodEdDSA,
    Private: edPriv, Public: edPub}

provider := keys.NewStaticProvider(k)
```

### `Provider`

```go
type Provider interface {
    // Active returns the key that new tokens are signed with. It returns
    // [ErrNoKey] when no key can sign.
    Active(ctx context.Context) (*Key, error)

    // ByKID returns the key with the given ID for verification. Retired keys
    // remain resolvable until they are removed, so tokens issued before a
    // rotation keep verifying. It returns [ErrKeyNotFound] when the ID is
    // unknown.
    ByKID(ctx context.Context, kid string) (*Key, error)

    // Verification returns every key that should be published in JWKS: the
    // active key plus any retired keys still accepted.
    Verification(ctx context.Context) ([]*Key, error)
}
```

An implementer must make these safe for concurrent use — `Active` and `ByKID`
are called on every token operation, so a provider that reloads from a file or
a KMS needs a lock or an atomic swap around the reload.

`ByKID` must keep returning retired keys until they are deliberately dropped.
Removing a key the moment it stops signing invalidates every token issued under
it, which turns a routine rotation into a mass logout.

The three methods are separate rather than one "give me the keys" call because
they answer different questions with different failure modes. `Active` failing
means new logins break. `ByKID` failing means one token is rejected.
`Verification` failing means the JWKS endpoint is empty and every relying party
breaks at once.

### `StaticProvider`

```go
type StaticProvider struct { /* unexported fields */ }

func NewStaticProvider(active *Key, retired ...*Key) *StaticProvider
func NewStaticProviderWithError(active *Key, retired ...*Key) (*StaticProvider, error)

func (p *StaticProvider) Active(context.Context) (*Key, error)
func (p *StaticProvider) ByKID(_ context.Context, kid string) (*Key, error)
func (p *StaticProvider) Verification(context.Context) ([]*Key, error)
func (p *StaticProvider) Rotate(next *Key) error
```

The default `Provider`, serving a fixed set of keys held in memory, safe for
concurrent use.

`NewStaticProvider` **panics** if `active` is unusable or cannot sign, or if any
key is invalid. These are wiring mistakes that should surface at startup rather
than on the first authentication — a provider that constructs successfully and
then fails every login is much harder to diagnose than one that refuses to
start. `NewStaticProviderWithError` is the same constructor returning an error,
for callers assembling keys from configuration that might legitimately be
wrong.

`Rotate` promotes `next` to active and keeps the previous active key for
verification. Tokens already issued keep verifying; new tokens use `next`.
`Verification` returns the active key first.

```go
// Rotation without invalidating outstanding tokens.
provider := keys.NewStaticProvider(current, previous)
// ...later...
if err := provider.Rotate(next); err != nil {
    return err
}
```

### `Signer`

```go
type Signer interface {
    // Sign returns the signed compact serialization of claims. Entries in
    // header are added to the JOSE header; implementations set "alg" and
    // should set "kid" themselves.
    Sign(ctx context.Context, claims jwt.Claims, header map[string]any) (string, error)
}
```

Implement this — rather than `Provider` — when the private key must never leave
an HSM or cloud KMS. Kayan calls `Sign` and never inspects key material. This
is the difference between "Kayan holds your signing key" and "Kayan asks your
KMS to sign," and for a deployment with a hardware key custody requirement it
is the only workable shape.

An implementer must set `alg` in the JOSE header to match what it actually
signed with, and should set `kid` so verifiers can select the key. Entries in
the passed `header` map are applied on top.

```go
type kmsSigner struct{ client *kms.Client }

func (s *kmsSigner) Sign(ctx context.Context, claims jwt.Claims, hdr map[string]any) (string, error) {
    // marshal claims, call KMS to sign the signing input,
    // assemble the compact serialization
}
```

### `JWTSigner`

```go
type JWTSigner struct { /* unexported fields */ }
type SignerOption func(*JWTSigner)

func NewJWTSigner(p Provider, opts ...SignerOption) *JWTSigner
func (s *JWTSigner) Sign(ctx context.Context, claims jwt.Claims, header map[string]any) (string, error)
```

The default `Signer`. It signs with the provider's active key, setting `alg`
from the key's method and `kid` from the key's ID, then applying the passed
`header` on top.

### `Keyfunc`

```go
func Keyfunc(ctx context.Context, p Provider) jwt.Keyfunc
```

Returns a `jwt.Keyfunc` that resolves the verification key by the token's `kid`
header.

This function is the reason algorithm confusion attacks do not work against
Kayan-issued tokens: **it rejects any token whose `alg` does not match the
algorithm recorded for that key.** Without that check, an attacker takes a token
your service signed with RS256, re-signs it as HS256 using your *public* key as
the HMAC secret — which is published in JWKS — and a naive verifier accepts it,
because it trusts the token's own header to say how to verify it.

Any code path in Kayan that parses a JWT goes through pinned-algorithm
verification. A caller writing their own parse path must do the same.

### JWKS publication

```go
type JWK struct {
    Kty string `json:"kty"`
    Use string `json:"use,omitempty"`
    Alg string `json:"alg,omitempty"`
    Kid string `json:"kid,omitempty"`

    // RSA (RFC 7518 section 6.3).
    N string `json:"n,omitempty"`
    E string `json:"e,omitempty"`

    // EC and OKP (RFC 7518 section 6.2, RFC 8037 section 2).
    Crv string `json:"crv,omitempty"`
    X   string `json:"x,omitempty"`
    Y   string `json:"y,omitempty"`
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}

func KeyToJWK(k *Key) (JWK, error)
func BuildJWKS(ctx context.Context, p Provider) (JWKS, error)
func PublicKeyOf(k *Key) (crypto.PublicKey, error)
```

`KeyToJWK` converts the **public half** of a key to a JWK. RSA, ECDSA (P-256,
P-384, P-521), and Ed25519 are supported. Symmetric keys return
`ErrUnsupportedKey`, because publishing an HMAC secret in JWKS would disclose
the signing key to everyone who fetches the endpoint. That refusal is the whole
point of the error.

`BuildJWKS` assembles the set to publish. Keys that cannot be represented —
symmetric keys in particular — are **skipped rather than failing the whole
set**, so an HS256 session key sitting alongside an RS256 token key does not
break the endpoint. This is a case where failing open is correct: the alternative
is a JWKS endpoint that returns an error and takes down every relying party,
in order to protect a key that was going to be omitted anyway.

The caller serves the result; Kayan does not write HTTP responses.

```go
jwks, err := keys.BuildJWKS(ctx, provider)
if err != nil {
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
}
w.Header().Set("Content-Type", "application/jwk-set+json")
json.NewEncoder(w).Encode(jwks)
```

`PublicKeyOf` derives the public key for a key, falling back to deriving it
from the private key when `Public` is unset — convenient when you loaded a PEM
private key and never separated out the public half.

### Errors

```go
var (
    ErrNoKey          = errors.New("keys: no active key")
    ErrKeyNotFound    = errors.New("keys: key not found")
    ErrUnsupportedKey = errors.New("keys: unsupported key type")
    ErrInvalidKey     = errors.New("keys: invalid key")
)
```

`ErrNoKey` from `Active` means signing is impossible — new tokens cannot be
issued. `ErrKeyNotFound` from `ByKID` means a specific token cannot be
verified, which after a rotation that dropped a key too early is the expected
symptom. Match on these with `errors.Is`.

---

## `core/flow`

```go
import "github.com/getkayan/kayan/core/flow"
```

`flow` is the authentication engine. Everything a user does to prove who they
are — register, log in, present a second factor, redeem a magic link, click
through an OIDC redirect, bind against LDAP — is a strategy registered with a
manager here. The package owns the security decisions that surround a strategy:
which hooks run, when the schema validates, whether a failed attempt counts
toward a lockout, and what an unauthenticated caller is allowed to learn from
the error.

The shape is the same everywhere. A strategy is a small interface you can
implement in twenty lines. A manager holds a set of strategies, dispatches to
one by ID, and runs the surrounding machinery. Decorators — lockout, rate
limiting — wrap a strategy and satisfy the same interface, so they compose in
any order and a strategy never has to know it is being protected.

### `IdentityRepository`

```go
type IdentityRepository = domain.IdentityStorage
```

An alias, not a distinct type, so a `domain.IdentityStorage` and a
`flow.IdentityRepository` are interchangeable at every call site. It exists
because "repository" reads better than "storage" in a constructor argument list
that already has a `TokenStore` and a `SessionStorage` in it. See
[`domain.IdentityStorage`](#identitystorage) for the contract an implementer
must satisfy.

### Identity interfaces

`flow` re-declares the identity interfaces rather than importing
`core/identity`'s, so a model can satisfy the flow contract without depending
on the `identity` package's types beyond `identity.JSON`.

```go
type FlowIdentity interface {
    GetID() any
    SetID(any)
}
```

The only required interface. A model that implements nothing else can still
register and log in with a password; it just cannot carry traits, hold discrete
credentials, or participate in MFA or verification flows.

```go
type TraitSource interface {
    GetTraits() identity.JSON
    SetTraits(identity.JSON)
}
```

Detected by type assertion. A registration strategy that receives traits checks
for this and calls `SetTraits`; a model without it silently drops them, which is
why an OIDC login against a model that does not implement `TraitSource` produces
an identity with no email.

```go
type CredentialSource interface {
    GetCredentials() []identity.Credential
    SetCredentials([]identity.Credential)
}
```

Note the difference from `identity.CredentialSource`, which has only the getter.
This is the one the WebAuthn strategy asserts for, because finishing a
registration ceremony means writing a new credential back onto the model. A
model that implements only the read half cannot store a passkey.

```go
type MFAIdentity interface {
    MFAConfig() (enabled bool, secret string)
}

type VerificationIdentity interface {
    IsVerified() bool
    MarkVerified(time.Time)
}
```

`MFAIdentity` is what `LoginManager.Authenticate` asserts for when deciding
whether to return `ErrMFARequired`. A model that does not implement it is never
challenged for a second factor, regardless of what is stored in the database —
the manager has no way to ask.

`VerificationIdentity` is what `VerificationManager` writes through. Without
it, a verification token can be consumed but the result cannot be recorded, so
the same link works forever.

### Strategy interfaces

```go
type LoginStrategy interface {
    ID() string
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}

type RegistrationStrategy interface {
    ID() string
    Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}
```

Two arguments, both strings, both opaque to the manager. The strategy decides
what they mean: for `PasswordStrategy` it is an email and a password; for
`APIKeyStrategy` the identifier is ignored entirely and the secret is the raw
key; for `KayanOIDCStrategy` the identifier is the `state` query parameter and
the secret is the authorization code. Keeping them untyped is what lets a
two-legged redirect flow and a username-password form share one manager.

An implementer of `Authenticate` must not distinguish "no such identity" from
"wrong secret" in the error it returns. A caller that can tell the two apart has
a user-enumeration oracle: they submit a list of email addresses and learn which
ones have accounts, which is the reconnaissance step before a credential-stuffing
run.

```go
type Initiator interface {
    Initiate(ctx context.Context, identifier string) (any, error)
}
```

Optional, for strategies that are two-step. Magic link, OTP, and Kayan-OIDC
implement it: `Initiate` sends the mail, delivers the SMS, or builds the
authorization URL, and `Authenticate` consumes what comes back.
`LoginManager.InitiateLogin` type-asserts for it and returns an error when the
named strategy does not implement it.

```go
type Attacher interface {
    Attach(ctx context.Context, ident any, identifier, secret string) error
}
```

Optional, for strategies that can bind a new credential to an identity that
already exists. `PasswordStrategy` and `OIDCManager` implement it, and
`LoginManager.LinkMethod` dispatches through it. The distinction from `Register`
matters: `Register` creates an identity, `Attach` adds a login method to one the
caller has already authenticated. A strategy that implemented `Attach` as
"upsert" would let an unauthenticated request create the account it claims to be
linking to.

```go
type Hook func(ctx context.Context, ident any) error
```

Pre-hooks run before the strategy and can abort by returning an error;
post-hooks run after success. A pre-hook returning an error stops the flow, which
is the mechanism for "refuse logins from suspended accounts" or "require a
signed terms-of-service version" without modifying a strategy.

Hooks run synchronously and in registration order. A hook that calls out to a
slow service adds that latency to every login, so long work belongs in an event
subscriber, not a hook.

```go
type StrategyFactory func(config *domain.StrategyConfig) (LoginStrategy, error)
type RegistrationStrategyFactory func(config *domain.StrategyConfig) (RegistrationStrategy, error)
type ClaimMapper func(claims map[string]any) identity.JSON
```

### `LoginManager`

```go
type LoginManager struct { /* unexported fields */ }

func NewLoginManager(repo IdentityRepository, factory func() any, opts ...LoginOption) *LoginManager
```

Holds the registered login strategies and runs the surrounding machinery:
pre-hooks, the strategy call, the MFA check, audit records, event dispatch,
post-hooks.

The `factory` returns a pointer to an empty instance of your model, the same
BYOS mechanism `domain.IdentityStorage` uses. `NewLoginManager` type-asserts the
`repo` for `audit.AuditStore` and wires audit logging automatically when the
same backend satisfies both — which the bundled adapter does — so a caller who
passes one `Storage` value gets an audit trail without asking for it.

```go
func (m *LoginManager) RegisterStrategy(s LoginStrategy)
func (m *LoginManager) Authenticate(ctx context.Context, method, identifier, secret string) (any, error)
func (m *LoginManager) InitiateLogin(ctx context.Context, method, identifier string) (any, error)
func (m *LoginManager) FindIdentity(ctx context.Context, identifier string) (any, error)
func (m *LoginManager) LinkMethod(ctx context.Context, ident any, method, identifier, secret string) error
func (m *LoginManager) VerifyMFA(ctx context.Context, ident any, code string) (bool, error)
func (m *LoginManager) AddPreHook(h Hook)
func (m *LoginManager) AddPostHook(h Hook)
func (m *LoginManager) Registry() *StrategyRegistry
func (m *LoginManager) ReloadStrategies(ctx context.Context) error
```

`Authenticate` dispatches to the strategy registered under `method`. Its return
convention has one property that is easy to miss and important to get right:

```go
ident, err := login.Authenticate(ctx, "password", email, password)
if errors.Is(err, flow.ErrMFARequired) {
    // ident is non-nil. The first factor succeeded.
    // Do not issue a session yet; challenge for the second factor.
    return challengeMFA(ident)
}
if err != nil {
    return err // first factor failed
}
```

**`ErrMFARequired` is returned alongside a non-nil identity.** The first factor
passed and the identity is real; only the second factor is outstanding. A caller
who treats every non-nil error as a failure will lock out every MFA-enabled
user. A caller who ignores the error and issues a session on a non-nil identity
has disabled MFA entirely. Both mistakes are silent, which is why this is worth
stating plainly.

The condition is reached when the model implements `MFAIdentity` and its
`MFAConfig` reports enabled. A model that does not implement `MFAIdentity` is
never challenged.

`VerifyMFA` is the second half: pass the identity returned alongside
`ErrMFARequired` and the code the user supplied. It reads the secret from
`MFAConfig` and verifies it with a stateless TOTP check. Being stateless, it
does **not** enforce replay protection — a code is accepted for the whole
30-second window and can be presented twice. Where replay matters, register a
`TOTPStrategy` backed by a `TOTPRepository` and authenticate through it instead;
that path records the matched time-step counter.

`InitiateLogin` requires the named strategy to implement `Initiator` and errors
otherwise. `LinkMethod` requires `Attacher`. `Registry` exposes the
`StrategyRegistry` for dynamic configuration, and `ReloadStrategies` rebuilds
the strategy set from the configured `domain.StrategyStore`.

#### `LoginOption`

```go
type LoginOption func(*LoginManager)

func WithLoginDispatcher(d events.Dispatcher) LoginOption
func WithLoginPreHook(h Hook) LoginOption
func WithLoginPostHook(h Hook) LoginOption
func WithStrategyStore(s domain.StrategyStore) LoginOption
```

`WithLoginDispatcher` sets the event dispatcher. Login success, failure, blocked,
and MFA-challenge events are published to it, which is how audit logging,
webhooks, and metrics attach without the manager knowing about them.

`WithStrategyStore` enables runtime strategy configuration — the store is read
by `ReloadStrategies` and built through the manager's `StrategyRegistry`.

Two setters predate the options and remain for compatibility:

```go
func (m *LoginManager) SetDispatcher(d events.Dispatcher)     // Deprecated: use WithLoginDispatcher
func (m *LoginManager) SetStrategyStore(s domain.StrategyStore) // Deprecated: use WithStrategyStore
```

They are deprecated because they mutate a manager that may already be serving
requests. An option applies before the constructor returns, so there is no window
in which some requests see the dispatcher and others do not.

### `RegistrationManager`

```go
type RegistrationManager struct { /* unexported fields */ }

func NewRegistrationManager(repo IdentityRepository, factory func() any, opts ...RegistrationOption) *RegistrationManager

func (m *RegistrationManager) RegisterStrategy(s RegistrationStrategy)
func (m *RegistrationManager) Submit(ctx context.Context, method string, traits identity.JSON, secret string) (any, error)
func (m *RegistrationManager) AddPreHook(h Hook)
func (m *RegistrationManager) AddPostHook(h Hook)
```

`Submit` runs the schema validation, then the pre-hooks, then the strategy, then
the post-hooks. The order is deliberate: an invalid trait set never reaches a
strategy and never reaches storage, so a rejected registration leaves nothing
behind to clean up. Validation failure is wrapped as
`registration: validation failed: %v`.

#### `RegistrationOption`

```go
type RegistrationOption func(*RegistrationManager)

func WithSchema(s identity.Schema) RegistrationOption
func WithLinker(l Linker) RegistrationOption
func WithRegDispatcher(d events.Dispatcher) RegistrationOption
func WithRegPreHook(h Hook) RegistrationOption
func WithRegPostHook(h Hook) RegistrationOption
func WithAllowPasswordCapture() RegistrationOption
func WithPreventPasswordCapture() RegistrationOption // deprecated: no-op
```

`WithAllowPasswordCapture` is the one that enables an attack rather than
configuring a behavior. By default, password registration against an address
that already has an identity — one created through Google OIDC, say — returns
`ErrIdentityAlreadyExists`. With the option set, it returns that existing
identity instead, and the submitted password is discarded without ever being
compared against the stored credential. An attacker who knows a victim's email
address registers with a password of their choosing and receives the victim's
identity; a handler that issues a session on "registration succeeded" logs them
in as the victim.

It exists for callers migrating off the previous default, where this was the
behavior unless `WithPreventPasswordCapture` was passed. Enable it only if you
prove control of the address before acting on the result.

`WithPreventPasswordCapture` is now a deprecated no-op — it opted into what is
unconditional. Remove the call.

The reason it is opt-in rather than the default is that the permissive behavior
is genuinely wanted in some deployments — a user who signed up with Google and
now wants a password should be able to set one. The safe version of that flow
sends a verification mail first; the option exists so that a deployment which
has not built that flow does not get the unsafe shortcut by accident.

```go
func (m *RegistrationManager) SetSchema(s identity.Schema)      // Deprecated: use WithSchema
func (m *RegistrationManager) SetLinker(l Linker)               // Deprecated: use WithLinker
func (m *RegistrationManager) SetDispatcher(d events.Dispatcher) // Deprecated: use WithRegDispatcher
```

Deprecated for the same reason as their `LoginManager` counterparts: post-hoc
mutation of a live manager. A `SetSchema` call that lands after the first
registration means the first user bypassed validation.

### `PasswordAuth`

```go
func PasswordAuth(repo IdentityRepository, factory func() any, identifierField string, opts ...QuickOption) (*RegistrationManager, *LoginManager)
```

The one-call wiring for the common case. It constructs a `BcryptHasher`, a
`PasswordStrategy` mapped to `identifierField`, a UUIDv4 `IDGenerator`, and a
registration and login manager with the strategy registered on both.

```go
reg, login := flow.PasswordAuth(repo, func() any { return &User{} }, "Email")

ident, err := reg.Submit(ctx, "password", traits, "hunter2")
ident, err = login.Authenticate(ctx, "password", "dev@example.com", "hunter2")
```

An empty `identifierField` falls back to `"email"`. Note that the default bcrypt
cost here is **10**, not `domain.DefaultBcryptCost`'s 12 — the convenience
constructor favors a faster development loop. Raise it with `WithHasherCost` for
production, or construct the strategy yourself.

#### `QuickOption`

```go
type QuickOption func(*quickConfig)

func WithHasherCost(cost int) QuickOption
func WithIDGenerator(gen domain.IDGenerator) QuickOption
func WithPasswordPolicy(p *PasswordPolicy) QuickOption
func WithQuickDispatcher(d events.Dispatcher) QuickOption
func WithRegHook(pre, post Hook) QuickOption
func WithLoginHook(pre, post Hook) QuickOption
```

`WithRegHook` and `WithLoginHook` take both hooks in one call, and either may be
nil. `WithQuickDispatcher` sets the same dispatcher on both managers, which is
almost always what you want — an audit trail that records registrations but not
logins is not an audit trail.

### `PasswordStrategy`

```go
type PasswordStrategy struct { /* unexported fields */ }

func NewPasswordStrategy(repo IdentityRepository, hasher domain.Hasher, identifierField string, factory func() any) *PasswordStrategy

func (s *PasswordStrategy) ID() string
func (s *PasswordStrategy) Register(ctx context.Context, traits identity.JSON, password string) (any, error)
func (s *PasswordStrategy) Authenticate(ctx context.Context, identifier, password string) (any, error)
func (s *PasswordStrategy) Attach(ctx context.Context, ident any, identifier, secret string) error
func (s *PasswordStrategy) MapFields(identifiers []string, password string)
func (s *PasswordStrategy) SetIDGenerator(g domain.IDGenerator)
func (s *PasswordStrategy) SetPasswordPolicy(p *PasswordPolicy)
```

Satisfies `LoginStrategy`, `RegistrationStrategy`, and `Attacher`. Its ID is
`"password"`.

`MapFields` is the BYOS seam. The constructor takes a single identifier field;
`MapFields` replaces it with a list and names the field holding the hash:

```go
type User struct {
    ID           string
    Email        string
    Username     string
    PasswordHash string
}

pw := flow.NewPasswordStrategy(repo, hasher, "Email", func() any { return &User{} })
pw.MapFields([]string{"Email", "Username"}, "PasswordHash")
```

With several identifier fields, a login attempt is tried against each in turn, so
the same form accepts either an email or a username. The names are struct field
names on your model, not database columns — the storage adapter maps those.

This is why a model that keeps its hash in a column does not need
`domain.CredentialStorage`: `PasswordStrategy` reads and writes the field
directly. Implement `CredentialStorage` only when one identity holds several
credentials of different types.

`SetIDGenerator` supplies the generator called on registration before `SetID`.
Pass a `domain.IDGenerator`, never a `domain.TokenGenerator` — the two are
separate types precisely to stop that substitution, and the compiler enforces it.

`SetPasswordPolicy` installs validation applied on `Register`. Passing nil
selects `DefaultPasswordPolicy`.

### `PasswordPolicy`

```go
type PasswordPolicy struct {
    MinLength        int
    MaxLength        int
    RequireUppercase bool
    RequireLowercase bool
    RequireDigit     bool
    RequireSpecial   bool
    CustomValidator  func(string) error
}

func (p *PasswordPolicy) Validate(password string) error

var DefaultPasswordPolicy = PasswordPolicy{
    MinLength: 8,
    MaxLength: 128,
}
```

The default enforces length and nothing else. That is a deliberate reading of
NIST SP 800-63B, which recommends length as the primary strength signal and
advises against composition rules: forcing an uppercase letter and a digit
reliably produces `Password1!` rather than a stronger secret, and the predictable
shape helps an attacker more than the entropy hurts them.

`MaxLength` is not there to weaken the password. It bounds the input bcrypt sees,
because a very long password submitted repeatedly is a cheap way to burn server
CPU — each attempt costs a full bcrypt round regardless of whether it succeeds.
Note that bcrypt itself truncates at 72 bytes, so a limit above that adds no
strength.

Sentinel errors, matchable with `errors.Is`:

```go
var (
    ErrPasswordTooShort  = errors.New("flow: password too short")
    ErrPasswordTooLong   = errors.New("flow: password too long")
    ErrPasswordNoUpper   = errors.New("flow: password must contain an uppercase letter")
    ErrPasswordNoLower   = errors.New("flow: password must contain a lowercase letter")
    ErrPasswordNoDigit   = errors.New("flow: password must contain a digit")
    ErrPasswordNoSpecial = errors.New("flow: password must contain a special character")
)
```

These are distinct so a registration form can tell the user which rule they
missed. They are safe to surface during registration; they are not safe to
surface during login, where any detail about the stored secret is a leak.

`CustomValidator` is the hook for a breached-password check against a local
Pwned Passwords set, or a dictionary check against the user's own name.

### `MagicLinkStrategy`

```go
type MagicLinkStrategy struct { /* unexported fields */ }

func NewMagicLinkStrategy(repo IdentityRepository, store domain.TokenStore) *MagicLinkStrategy

func (s *MagicLinkStrategy) ID() string
func (s *MagicLinkStrategy) Initiate(ctx context.Context, identifier string) (any, error)
func (s *MagicLinkStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error)
```

`LoginStrategy` plus `Initiator`. `Initiate` generates a token, persists it via
the `domain.TokenStore`, and returns the `*domain.AuthToken`. It does **not**
send anything — Kayan is headless and has no mailer. Delivering the link is the
caller's job, either from the returned token or from an event subscriber.

`Authenticate` takes the token as the secret. It checks the token's `Type` as
well as its value, so a verification token cannot be redeemed as a login, and
deletes it on use.

The link you build is a bearer credential in a URL. It belongs in the path or
fragment of a page that does not forward its URL to third parties, and it should
be short-lived: an email account compromised a week later should not still
contain a working login.

### `OTPStrategy`

```go
type OTPStrategy struct { /* unexported fields */ }
type OTPOption func(*OTPStrategy)

func NewOTPStrategy(repo IdentityRepository, tokenStore domain.TokenStore, sender OTPSender, opts ...OTPOption) *OTPStrategy

func WithOTPTTL(ttl time.Duration) OTPOption        // default 5 minutes
func WithOTPCodeLength(length int) OTPOption        // default 6

func (s *OTPStrategy) ID() string
func (s *OTPStrategy) Initiate(ctx context.Context, identifier string) (any, error)
func (s *OTPStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error)
```

`LoginStrategy` plus `Initiator`. It is deliberately not a
`RegistrationStrategy`: an OTP proves control of a channel, not the intent to
create an account, and a flow that registered on first OTP would let anyone mint
accounts against arbitrary phone numbers.

```go
type OTPSender interface {
    Send(ctx context.Context, recipient, code string) error
}
```

The delivery seam. Kayan never sends an SMS, places a call, or writes an email;
it hands the code to your implementation.

```go
type TwilioSender struct{ client *twilio.Client }

func (s *TwilioSender) Send(ctx context.Context, recipient, code string) error {
    _, err := s.client.SendSMS(recipient, "Your code is: "+code)
    return err
}
```

Codes are short and numeric, which makes them guessable by brute force in a way
a 256-bit token is not. A six-digit code has a million possibilities; an attacker
who can submit unlimited attempts inside the five-minute window will find it.
An OTP strategy that is not wrapped in a `RateLimitStrategy` or a
`LockoutStrategy` is not safe to expose. The five-minute default TTL and the
single-use consumption bound the window, but they do not bound the attempt rate.

### `TOTPStrategy`

```go
type TOTPStrategy struct { /* unexported fields */ }

func NewTOTPStrategy(repo TOTPRepository, factory func() any, identifierField string) *TOTPStrategy

func (s *TOTPStrategy) ID() string
func (s *TOTPStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error)
func (s *TOTPStrategy) Verify(secret string, code string) bool
```

```go
type TOTPRepository interface {
    FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
    FindTOTPSecret(ctx context.Context, identityID any) (string, error)
    MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error
}
```

`Authenticate` accepts a code from the current, previous, or next 30-second
window — one step of drift tolerance in each direction, which covers a phone
whose clock is slightly off without widening the window enough to matter.

`MarkTOTPUsed` is the replay defense and the reason the repository interface
exists at all. An implementer **must return an error when the counter was
already used for that identity**. Without it, a code observed over the user's
shoulder, read from a phishing page, or captured from a logged request body
stays valid for the remainder of its window, and a second party can present it.
The counter is the time step, so a unique index on `(identity_id, counter)` is
the whole implementation.

`Verify` is the stateless helper `LoginManager.VerifyMFA` calls. It checks the
code against a secret and nothing else — **no replay protection**. A zero-value
`TOTPStrategy` is usable for `Verify` alone. Where replay matters, go through
`Authenticate`.

Sentinels:

```go
var (
    ErrTOTPCodeInvalid    = errors.New("totp: code invalid")
    ErrTOTPReplay         = errors.New("totp: code already used")
    ErrTOTPSecretNotFound = errors.New("totp: secret not found")
)
```

### `WebAuthnStrategy`

```go
type WebAuthnStrategy struct { /* unexported fields */ }

func NewWebAuthnStrategy(
    repo IdentityRepository,
    config WebAuthnConfig,
    factory func() any,
    sessionStore WebAuthnSessionStore,
) (*WebAuthnStrategy, error)

func (s *WebAuthnStrategy) ID() string
func (s *WebAuthnStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error)
func (s *WebAuthnStrategy) SetHooks(hooks WebAuthnHooks)
func (s *WebAuthnStrategy) SetIDGenerator(g domain.IDGenerator)
func (s *WebAuthnStrategy) SetSessionTTL(ttl time.Duration)
```

Passkeys and FIDO2 hardware keys. WebAuthn is a two-round-trip ceremony in both
directions, so the ceremony methods are the real interface and `Authenticate`
exists to satisfy `LoginStrategy` for callers that can pack an assertion and a
session ID into one string.

```go
func (s *WebAuthnStrategy) BeginRegistration(
    ctx context.Context,
    ident any,
    userName, displayName string,
) (*protocol.CredentialCreation, string, error)

func (s *WebAuthnStrategy) FinishRegistration(
    ctx context.Context,
    ident any,
    sessionID string,
    userName, displayName string,
    response *protocol.ParsedCredentialCreationData,
) (*identity.Credential, error)

func (s *WebAuthnStrategy) BeginLogin(
    ctx context.Context,
    identifier string,
) (*protocol.CredentialAssertion, string, error)

func (s *WebAuthnStrategy) FinishLogin(
    ctx context.Context,
    identifier string,
    sessionID string,
    response *protocol.ParsedCredentialAssertionData,
) (any, error)
```

Each `Begin` returns the options to serialize to the browser and a session ID.
The session ID is the server's handle on the challenge it issued; the matching
`Finish` call needs it back. That handle exists because the challenge must be
verified against the one the server generated, not against whatever the client
echoes — a ceremony that accepted the client's own challenge would verify
nothing.

```go
type WebAuthnConfig struct {
    RPDisplayName string   // Relying Party display name (e.g., "Kayan Auth")
    RPID          string   // Relying Party ID (e.g., "example.com")
    RPOrigins     []string // Allowed origins (e.g., ["https://example.com"])
    SessionTTL    time.Duration
    Hooks         WebAuthnHooks
}
```

`RPID` and `RPOrigins` are what bind a credential to your site, and getting them
wrong is the classic WebAuthn misconfiguration. The authenticator refuses to
produce an assertion for an origin that does not match, which is precisely what
makes a passkey unphishable: a credential minted for `example.com` cannot be
used against `examp1e.com`, no matter how convincing the page. Setting `RPID`
too broadly — to a registrable suffix you do not fully control — extends that
trust to every host under it.

`SessionTTL` defaults to five minutes. A challenge is single-use and short-lived
for the same reason as any other nonce.

```go
type WebAuthnSessionStore interface {
    SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error
    GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error)
    DeleteSession(ctx context.Context, sessionID string) error
}

type WebAuthnSessionData struct {
    Challenge        string    `json:"challenge"`
    UserID           []byte    `json:"user_id"`
    AllowedCredIDs   [][]byte  `json:"allowed_cred_ids,omitempty"`
    UserVerification string    `json:"user_verification"`
    ExpiresAt        time.Time `json:"expires_at"`
}

type MemoryWebAuthnSessionStore struct { /* unexported fields */ }

func NewMemoryWebAuthnSessionStore() *MemoryWebAuthnSessionStore
func (s *MemoryWebAuthnSessionStore) SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error
func (s *MemoryWebAuthnSessionStore) GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error)
func (s *MemoryWebAuthnSessionStore) DeleteSession(ctx context.Context, sessionID string) error
```

The memory store is for a single process. Behind a load balancer, `BeginLogin`
and `FinishLogin` can land on different replicas, and the second one will not
find the challenge — every passkey login fails intermittently and in proportion
to your replica count. Use Redis or another shared store in production.

```go
type WebAuthnCredentialData struct {
    CredentialID    []byte `json:"credential_id"`
    PublicKey       []byte `json:"public_key"`
    AttestationType string `json:"attestation_type"`
    AAGUID          []byte `json:"aaguid"`
    SignCount       uint32 `json:"sign_count"`
    CloneWarning    bool   `json:"clone_warning"`
    BackupEligible  bool   `json:"backup_eligible"`
    BackupState     bool   `json:"backup_state"`
}
```

Marshalled into `identity.Credential.Config`. `SignCount` is the authenticator's
monotonic counter: a counter that goes backwards or repeats means two
authenticators are presenting the same credential, which is the signature of a
cloned key. That sets `CloneWarning` and fires the `OnCloneWarning` hook. It is
a signal, not a proof — some legitimate authenticators do not maintain a counter
at all — so the appropriate response is to log it and consider requiring
re-enrollment, not to hard-fail the login.

`WebAuthnHooks` provides extension points across the ceremony:

```go
type WebAuthnHooks struct {
    BeforeBeginRegistration  func(ctx context.Context, ident any, userName string) error
    AfterBeginRegistration   func(ctx context.Context, ident any, sessionID string) error
    BeforeFinishRegistration func(ctx context.Context, ident any, sessionID string) error
    AfterFinishRegistration  func(ctx context.Context, ident any, cred *identity.Credential) error
    BeforeBeginLogin         func(ctx context.Context, identifier string) error
    AfterBeginLogin          func(ctx context.Context, identifier string, sessionID string) error
    BeforeFinishLogin        func(ctx context.Context, identifier string, sessionID string) error
    AfterFinishLogin         func(ctx context.Context, ident any) error
    OnCloneWarning           func(ctx context.Context, ident any, credentialID string)
    CredentialFilter         func(cred *identity.Credential) bool
    CreateSessionID          func() string
    UserLoader               func(ctx context.Context, identifier string) (any, error)
    CredentialSaver          func(ctx context.Context, ident any, cred *identity.Credential) error
}
```

`CreateSessionID`, if supplied, replaces the default random generation. It must
produce unpredictable values: a guessable session ID lets an attacker complete a
ceremony the server started for someone else.

### `LDAPStrategy`

```go
type LDAPStrategy struct { /* unexported fields */ }

func NewLDAPStrategy(dialer LDAPDialer, config LDAPConfig, factory func() any) *LDAPStrategy

func (s *LDAPStrategy) ID() string
func (s *LDAPStrategy) Authenticate(ctx context.Context, username, password string) (any, error)
```

Authenticates against LDAP or Active Directory in three steps: bind as the
service account, search for the user's DN, then re-bind as that user with the
supplied password. The password is verified by the directory server and never
stored on Kayan's side — that re-bind *is* the verification.

```go
type LDAPDialer interface {
    DialTLS(ctx context.Context, addr string) (LDAPConn, error)
}

type LDAPConn interface {
    Bind(dn, password string) error
    Search(req LDAPSearchRequest) ([]LDAPEntry, error)
    Close() error
}

type LDAPSearchRequest struct {
    BaseDN     string
    Filter     string // e.g. "(uid=alice)"
    Attributes []string
}

type LDAPEntry struct {
    DN         string
    Attributes map[string][]string
}
```

`core` does not import `github.com/go-ldap/ldap/v3`; you supply the dialer, and
the adapter that wraps the real library lives outside `core`. That is the same
dependency rule the whole module follows, and here it has a second benefit: the
strategy is testable without a directory server.

The interface is `DialTLS`, not `Dial`. An LDAP simple bind sends the password in
the clear, so a plaintext connection hands every credential to anyone on the
path. An implementer should reject a non-TLS connection outright rather than
falling back.

```go
type LDAPConfig struct {
    Addr                   string
    BaseDN                 string
    UsernameAttribute      string
    ServiceAccountDN       string
    ServiceAccountPassword string
    TraitAttributes        map[string]string
}
```

`UsernameAttribute` is `uid` on most OpenLDAP directories and `sAMAccountName`
on Active Directory. `TraitAttributes` maps Kayan trait names to directory
attributes — `{"email": "mail"}` — and is what populates traits on first login.

The service account should be read-only and scoped to the search base. It is a
long-lived credential held in your process configuration; anything it can do, a
compromise of that configuration can do.

Sentinels:

```go
var (
    ErrLDAPInvalidCredentials = errors.New("ldap: invalid credentials")
    ErrLDAPUserNotFound       = errors.New("ldap: user not found")
    ErrLDAPConnectionFailed   = errors.New("ldap: connection failed")
)
```

`ErrLDAPUserNotFound` and `ErrLDAPInvalidCredentials` are distinct because the
strategy needs to tell them apart internally — a directory that cannot find the
user is a different operational condition from a directory that rejected the
bind. Do not pass that distinction to an unauthenticated caller; collapse both to
one message at your transport boundary, or you have built the enumeration oracle
back.

### `APIKeyStrategy`

```go
type APIKeyStrategy struct { /* unexported fields */ }

func NewAPIKeyStrategy(repo APIKeyRepository, factory func() any) *APIKeyStrategy

func (s *APIKeyStrategy) ID() string
func (s *APIKeyStrategy) Authenticate(ctx context.Context, _ string, rawKey string) (any, error)
```

```go
type APIKeyRepository interface {
    FindIdentityByAPIKeyHash(ctx context.Context, keyHash string, factory func() any) (any, error)
}
```

Machine-to-machine authentication. The identifier argument is ignored entirely —
callers may pass the first few characters of the key as a logging prefix — and
the secret is the raw key.

Three invariants hold and are worth stating because each prevents a specific
failure. Only the SHA-256 hash of the key is ever looked up or compared, so a
database dump does not yield working credentials. The comparison uses
`subtle.ConstantTimeCompare`, so an attacker cannot recover a key byte by byte
from response timing. Neither the raw key nor its hash is logged.

```go
func GenerateAPIKey(byteLen int) (rawKey, keyHash string, err error)
func HashAPIKey(rawKey string) string
```

`GenerateAPIKey` returns both halves at once: show `rawKey` to the user exactly
once and store `keyHash`. There is no way to recover the raw key afterwards,
which is the point — a "show me my key again" feature requires storing the key,
and then the dump is a credential leak.

`HashAPIKey` returns the hex-encoded SHA-256 of a raw key, for storing a key the
caller generated. Note that SHA-256 is correct here and would be wrong for a
password: an API key is 256 bits of `crypto/rand` output, so there is no
dictionary to attack and no reason to pay bcrypt's cost on every request. A
user-chosen password has neither property.

Sentinels:

```go
var (
    ErrAPIKeyInvalid           = errors.New("api_key: invalid or expired key")
    ErrAPIKeyExpired           = errors.New("api_key: key expired")
    ErrAPIKeyScopeInsufficient = errors.New("api_key: insufficient scope")
)
```

### `RecoveryCodeStrategy`

```go
type RecoveryCodeStrategy struct { /* unexported fields */ }

func NewRecoveryCodeStrategy(repo RecoveryCodeRepository, hasher domain.Hasher, factory func() any, identifierField string) *RecoveryCodeStrategy

func (s *RecoveryCodeStrategy) ID() string
func (s *RecoveryCodeStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error)
```

```go
type RecoveryCodeRepository interface {
    FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
    FindUnusedRecoveryCode(ctx context.Context, identityID any) (*RecoveryCodeRecord, error)
    MarkRecoveryCodeUsed(ctx context.Context, identityID any, codeID string) error
}

type RecoveryCodeRecord struct {
    ID   string // unique record ID
    Hash string // bcrypt hash of the plaintext code
}
```

The escape hatch for a user who has lost their authenticator. Each code is
single-use; `Authenticate` marks it used on success.

```go
func GenerateRecoveryCodes(hasher domain.Hasher, n int) (plaintexts []string, hashes []string, err error)
```

Generates `n` random hex codes and their hashes. Same contract as
`GenerateAPIKey`: display the plaintexts once, store only the hashes. Here the
hashing is bcrypt rather than SHA-256 because recovery codes are short enough
that an offline attack on a leaked table is worth an attacker's time.

Recovery codes are a full bypass of the second factor. They deserve the same
handling as the password: rate-limited, logged when used, and ideally paired with
a notification to the user, because a recovery code redeemed by someone else is
exactly the event the user needs to hear about.

Sentinels:

```go
var (
    ErrRecoveryCodeInvalid      = errors.New("recovery_code: invalid code")
    ErrRecoveryCodeAlreadyUsed  = errors.New("recovery_code: code already used")
    ErrNoRecoveryCodesRemaining = errors.New("recovery_code: no unused codes remaining")
)
```

### `KayanOIDCStrategy`

```go
type KayanOIDCStrategy struct { /* unexported fields */ }

func NewKayanOIDCStrategy(
    issuer, clientID, redirectURI string,
    oauthConfig OAuthConfiger,
    tokenParser IDTokenParser,
    repo KayanOIDCRepository,
    factory func() any,
) *KayanOIDCStrategy

func (s *KayanOIDCStrategy) ID() string
func (s *KayanOIDCStrategy) Initiate(ctx context.Context, _ string) (any, error)
func (s *KayanOIDCStrategy) Authenticate(ctx context.Context, state, code string) (any, error)
```

The client side of "Log in with Kayan" — one Kayan instance authenticating
against another acting as the OIDC provider. `LoginStrategy` plus `Initiator`.

`Initiate` generates the `state`, PKCE verifier, and `nonce`, stores them, and
returns the authorization URL to redirect to. `Authenticate` handles the
callback: its `identifier` argument is the `state` query parameter and its
`secret` is the authorization code.

Four controls are enforced, each closing a specific hole:

- `state` is at least 32 random bytes, single-use, and validated on callback.
  Without it, an attacker completes their own authorization flow and feeds the
  resulting callback URL to the victim, logging the victim into the attacker's
  account — where anything the victim then does is visible to the attacker.
- PKCE S256 on every flow. An authorization code intercepted in transit or from
  a redirect log is useless without the verifier, which never leaves the
  initiating client.
- The `nonce` claim in the ID token is checked against the one issued. This is
  what stops an ID token captured from one session being replayed into another.
- The provider's access token is never stored. Kayan issues its own session; the
  upstream token has done its job once the ID token is verified, and keeping it
  would be holding a credential with no use for it.

```go
type KayanOIDCRepository interface {
    StoreOIDCState(ctx context.Context, state, codeVerifier, nonce string, expiry time.Duration) error
    ConsumeOIDCState(ctx context.Context, state string) (codeVerifier, nonce string, err error)
    FindOrCreateByProviderSub(ctx context.Context, sub string, traits identity.JSON, factory func() any) (any, error)
}
```

`ConsumeOIDCState` must be atomically single-use — read and delete in one
operation. An implementation that reads, validates, then deletes leaves a window
in which two concurrent callbacks both succeed, which defeats the replay
protection the `state` exists to provide. It returns `ErrKayanOIDCStateInvalid`
for an unknown or expired state.

`FindOrCreateByProviderSub` keys on the provider's subject claim, not on the
email. Emails change hands and providers reassign them; `sub` is stable and
unique per provider. Matching on email is how one user inherits another's
account after an address is recycled.

```go
type IDTokenParser interface {
    ParseAndVerify(rawIDToken, issuer, audience, expectedNonce string) (*IDTokenClaims, error)
}

type IDTokenClaims struct {
    Sub   string
    Email string
}

type OAuthConfiger interface {
    AuthCodeURL(state string, opts ...AuthCodeOption) string
    Exchange(ctx context.Context, code string, opts ...AuthCodeOption) (OAuthToken, error)
}

type OAuthToken interface {
    Extra(key string) any
}

type AuthCodeOption interface { /* unexported methods */ }
```

`OAuthConfiger` and `OAuthToken` are minimal interfaces over
`golang.org/x/oauth2` so `core` does not import it. `AuthCodeOption` is a
placeholder for the same reason: concrete options are constructed outside `core`
and passed through.

An implementer of `IDTokenParser` must verify the signature against the issuer's
JWKS with the algorithm pinned, check `iss` and `aud`, check expiry, and compare
`nonce` to `expectedNonce`. A parser that decodes the token without verifying it
accepts any ID token an attacker cares to write.

Sentinels:

```go
var (
    ErrKayanOIDCStateInvalid   = errors.New("kayan_oidc: state invalid or expired")
    ErrKayanOIDCStateExpired   = errors.New("kayan_oidc: state expired")
    ErrKayanOIDCMissingIDToken = errors.New("kayan_oidc: id_token missing from response")
    ErrKayanOIDCTokenInvalid   = errors.New("kayan_oidc: id token invalid")
    ErrKayanOIDCNonceMismatch  = errors.New("kayan_oidc: nonce mismatch")
)
```

### `OIDCManager`

```go
type OIDCManager struct { /* unexported fields */ }

func NewOIDCManager(repo domain.Storage, configs map[string]config.OIDCProvider, factory func() any) (*OIDCManager, error)

func (m *OIDCManager) GetAuthURL(providerID, state string) (string, error)
func (m *OIDCManager) HandleCallback(ctx context.Context, providerID, code string) (any, error)
func (m *OIDCManager) Attach(ctx context.Context, ident any, identifier, secret string) error
func (m *OIDCManager) SetClaimMapper(mapper ClaimMapper)
func (m *OIDCManager) SetIDGenerator(g domain.IDGenerator)
func (m *OIDCManager) SetLinker(l Linker)

type OIDCProviderData struct {
    Provider    *oidc.Provider
    OAuthConfig *oauth2.Config
}
```

Social login against third-party providers — Google, GitHub, Microsoft — keyed by
provider ID. `configs` maps a provider ID to a `config.OIDCProvider`, so one
manager serves several providers and `GetAuthURL`/`HandleCallback` select
between them.

Note that `GetAuthURL` takes the `state` as a parameter rather than generating
it: the manager does not own state storage, so it cannot validate on the way
back either. Generating an unpredictable state, persisting it, and checking it in
your callback handler is the caller's responsibility here. This is the main
difference from `KayanOIDCStrategy`, which owns the whole ceremony including
state and PKCE.

`Attach` implements `Attacher` for account linking, where `identifier` is the
provider subject and `secret` is the provider ID.

`SetClaimMapper` controls how provider claims become traits. The default mapping
is unlikely to match your model; a `ClaimMapper` is where you decide that
Google's `picture` claim becomes your `avatar_url` trait, and where you decide
whether to trust `email_verified`.

That last decision matters for linking. An identity provider that lets a user
set an arbitrary unverified email, combined with a linker that matches on email,
lets an attacker claim someone else's account by registering that address with a
provider that does not check it. `identity.Identity.IsEmailVerified` exists for
exactly this check.

### `Linker`

```go
type Linker interface {
    FindExisting(ctx context.Context, traits identity.JSON) (any, error)
    Link(ctx context.Context, ident any, method string, identifier, secret string) error
}

func NewDefaultLinker(repo IdentityRepository, factory func() any, strategies ...map[string]LoginStrategy) Linker
```

Account unification: recognizing that the person signing in with Google is the
person who already registered with a password, and attaching the new method to
the existing identity rather than creating a second account.

`FindExisting` is the matching rule and the security-sensitive half. It typically
matches on a verified email or phone number. Matching on an *unverified* trait
is an account takeover: an attacker registers with the victim's email at a
provider that does not verify it, the linker finds the victim's identity, and the
attacker's credential is attached to it.

`Link` attaches the method. The optional `strategies` map passed to
`NewDefaultLinker` supplies the strategies `Link` dispatches through; without
it, the returned linker supports `FindExisting` only.

`RegistrationManager` uses the linker through `WithLinker`. Password
registration against an existing identity is refused regardless; unification
applies to methods where an identity provider vouched for the address.

### Rate limiting

```go
type RateLimiter interface {
    Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
    Reset(ctx context.Context, key string) error
}
```

The storage seam. Three implementations ship, all in-process:

```go
type MemoryRateLimiter struct { /* unexported fields */ }
func NewMemoryRateLimiter() *MemoryRateLimiter
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error)
func (r *MemoryRateLimiter) Reset(ctx context.Context, key string) error

type FixedWindowRateLimiter struct { /* unexported fields */ }
func NewFixedWindowRateLimiter() *FixedWindowRateLimiter
func (r *FixedWindowRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error)
func (r *FixedWindowRateLimiter) Reset(ctx context.Context, key string) error

type TokenBucketRateLimiter struct { /* unexported fields */ }
func NewTokenBucketRateLimiter() *TokenBucketRateLimiter
func (r *TokenBucketRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error)
func (r *TokenBucketRateLimiter) Reset(ctx context.Context, key string) error
```

`MemoryRateLimiter` uses a sliding window, which gives the most accurate
enforcement of "N per window" at the cost of remembering individual timestamps.
`FixedWindowRateLimiter` is cheaper but allows a burst of up to twice the limit
across a window boundary — the last instant of one window and the first of the
next. `TokenBucketRateLimiter` permits a deliberate burst up to capacity and then
enforces a steady refill rate, which suits an API where clients legitimately
arrive in clusters.

All three are per-process. Behind N replicas, an attacker gets N times the limit,
because each replica counts only what it saw. For anything user-facing, back the
`RateLimiter` interface with Redis so the counter is shared.

```go
type RateLimitStrategy struct { /* unexported fields */ }

func NewRateLimitStrategy(next LoginStrategy, limiter RateLimiter, config RateLimitConfig) *RateLimitStrategy

func (s *RateLimitStrategy) ID() string
func (s *RateLimitStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error)
func (s *RateLimitStrategy) Initiate(ctx context.Context, identifier string) (any, error)
func (s *RateLimitStrategy) SetHooks(hooks RateLimitHooks)
func (s *RateLimitStrategy) SetKeyFunc(fn func(ctx context.Context, identifier string) string)
func (s *RateLimitStrategy) SetSkipFunc(fn func(ctx context.Context, identifier string) bool)
func (s *RateLimitStrategy) SetDynamicLimit(fn func(ctx context.Context, identifier string) (int, time.Duration))
```

A decorator satisfying `LoginStrategy`, so it wraps any strategy and reports the
wrapped strategy's `ID()`. It also forwards `Initiate`, so decorating a two-step
strategy does not break the initiation half.

```go
type RateLimitConfig struct {
    Limit        int
    Window       time.Duration
    KeyFunc      func(ctx context.Context, identifier string) string
    DynamicLimit func(ctx context.Context, identifier string) (limit int, window time.Duration)
    SkipFunc     func(ctx context.Context, identifier string) bool
    FailOpen     bool
    Hooks        RateLimitHooks
}
```

`FailOpen` decides what happens when the limiter itself errors — a Redis outage,
say. **It defaults to false, meaning deny.** That is the right default for a
login path: an attacker who can take down your Redis should not thereby remove
your brute-force protection. It is the wrong default for a rate limiter guarding
something non-security-sensitive, where the outage would take the whole feature
down with it. Choose deliberately.

`SkipFunc` bypasses limiting entirely for a request. Anything it keys on must be
something the caller cannot forge — an internal service identity, not a header.

`DynamicLimit` overrides the static limit per request, for tiered plans.

```go
type RateLimitHooks struct {
    OnAllow     func(ctx context.Context, info *RateLimitInfo) error
    OnDeny      func(ctx context.Context, info *RateLimitInfo)
    OnError     func(ctx context.Context, err error, info *RateLimitInfo) error
    CreateError func(info *RateLimitInfo) error
}

type RateLimitInfo struct {
    Key        string
    Identifier string
    Limit      int
    Window     time.Duration
    Remaining  int
    Allowed    bool
    RetryAfter time.Duration
}
```

`OnAllow` can still reject by returning an error — a second gate after the
limiter agreed. `OnError` returning nil fails open for that request regardless of
`FailOpen`, so it is a per-error escape hatch; returning an error overrides the
default handling.

```go
type RateLimitError struct {
    RetryAfter time.Duration
    Remaining  int
    Message    string
}

func (e *RateLimitError) Error() string
func AsRateLimitError(err error) (*RateLimitError, bool)
func IsRateLimitError(err error) bool
```

`AsRateLimitError` gives you `RetryAfter` for a `Retry-After` header.
`IsRateLimitError` is the boolean form.

Key functions compose the rate limit key:

```go
func PrefixKeyFunc(prefix string) func(context.Context, string) string
func IPKeyFunc(separator string) func(context.Context, string) string
func ContextKeyFunc(ctxKey ContextKey, separator string) func(context.Context, string) string
func CompositeKeyFunc(fns ...func(context.Context, string) string) func(context.Context, string) string

type ContextKey string
```

`PrefixKeyFunc` namespaces keys so a password limiter and an OTP limiter do not
share a counter. `IPKeyFunc` extracts the IP from an `"email:ip"`-shaped
identifier. `ContextKeyFunc` pulls a value from the context — the tenant ID, for
instance, so one tenant's traffic cannot exhaust another's budget.
`CompositeKeyFunc` chains them.

The key choice is the whole design. Limiting by email alone lets an attacker
spread a credential-stuffing run across a million addresses at full speed.
Limiting by IP alone punishes everyone behind one NAT and does nothing against a
botnet. Most deployments want both counters, with different limits.

```go
type ConfigurableRateLimiter struct { /* unexported fields */ }

func NewConfigurableRateLimiter(inner RateLimiter) *ConfigurableRateLimiter

func (r *ConfigurableRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error)
func (r *ConfigurableRateLimiter) Reset(ctx context.Context, key string) error
func (r *ConfigurableRateLimiter) OnAllow(fn func(ctx context.Context, key string, remaining int)) *ConfigurableRateLimiter
func (r *ConfigurableRateLimiter) OnDeny(fn func(ctx context.Context, key string)) *ConfigurableRateLimiter
func (r *ConfigurableRateLimiter) OnRequest(fn func(ctx context.Context, key string, limit int, window time.Duration)) *ConfigurableRateLimiter
```

Wraps any `RateLimiter` with callbacks, chainable. Useful for metrics on a
limiter you did not write.

### Lockout

Rate limiting bounds the request rate; lockout bounds the number of failures
before the account stops accepting attempts at all. They address different
attacks and are usually both wanted.

```go
type LockoutStore interface {
    RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)
    ClearFailures(ctx context.Context, identifier string) error
    Lock(ctx context.Context, identifier string, duration time.Duration) error
    IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
}

type MemoryLockoutStore struct { /* unexported fields */ }

func NewMemoryLockoutStore() *MemoryLockoutStore
func (s *MemoryLockoutStore) RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)
func (s *MemoryLockoutStore) ClearFailures(ctx context.Context, identifier string) error
func (s *MemoryLockoutStore) Lock(ctx context.Context, identifier string, duration time.Duration) error
func (s *MemoryLockoutStore) IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
```

The memory store carries the same replica caveat as the memory rate limiters, and
it matters more here: a five-failure lockout across four replicas is a
twenty-failure lockout.

```go
type LockoutStrategy struct { /* unexported fields */ }

func NewLockoutStrategy(next LoginStrategy, store LockoutStore, maxFailures int, lockoutDuration, failureWindow time.Duration) *LockoutStrategy
func NewLockoutStrategyWithConfig(next LoginStrategy, store LockoutStore, config LockoutConfig) *LockoutStrategy

func (s *LockoutStrategy) ID() string
func (s *LockoutStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error)
func (s *LockoutStrategy) Initiate(ctx context.Context, identifier string) (any, error)
func (s *LockoutStrategy) SetHooks(hooks LockoutHooks)
```

```go
type LockoutConfig struct {
    MaxFailures     int
    LockoutDuration time.Duration
    FailureWindow   time.Duration
    FailOpen        bool
    Hooks           LockoutHooks
}
```

`FailureWindow` is how long a failure is remembered. Without it, five typos
spread over a year would eventually lock the account, which is a support ticket
rather than a defense.

`LockoutDuration` is a temporary lock rather than a permanent one on purpose. A
permanent lock hands an attacker a denial-of-service: they submit six wrong
passwords for every address they can name and lock out your user base at no cost.
A fifteen-minute lock stops the brute force — it cuts the attempt rate to a few
per hour — while limiting the damage a malicious lockout can do.

`FailOpen` defaults to false. When the store errors, the request is denied. Same
reasoning as the rate limiter: an attacker who can break your store should not
thereby disable the lockout.

```go
type LockoutInfo struct {
    Identifier      string
    FailureCount    int
    MaxFailures     int
    LockedUntil     time.Time
    LockoutDuration time.Duration
}

type LockoutHooks struct {
    OnFailure            func(ctx context.Context, info *LockoutInfo) error
    OnLocked             func(ctx context.Context, info *LockoutInfo)
    OnUnlocked           func(ctx context.Context, identifier string)
    OnLockoutCheck       func(ctx context.Context, identifier string) (locked bool, until time.Time, handled bool)
    CreateLockError      func(info *LockoutInfo) error
    KeyFunc              func(ctx context.Context, identifier string) string
    ShouldRecordFailure  func(ctx context.Context, identifier string, err error) bool
    ShouldClearOnSuccess func(ctx context.Context, identifier string) bool
}
```

`OnLocked` is the alerting hook — a burst of lockouts across many accounts is a
credential-stuffing run in progress, and it is one of the few signals that shows
it clearly.

`ShouldRecordFailure` decides whether a given error counts. A storage timeout is
not an authentication failure and should not count toward a lock; a wrong
password is. Returning false for infrastructure errors stops a database blip
from locking out your users.

`CreateLockError` customizes the error. Whatever it produces, do not include the
remaining lock duration in a response to an unauthenticated caller: an error
saying "locked for 14 more minutes" confirms the account exists.

### Step-up authentication

```go
type StepUpLevel string

const (
    StepUpNone     StepUpLevel = "none"
    StepUpRecent   StepUpLevel = "recent"
    StepUpMFA      StepUpLevel = "mfa"
    StepUpPassword StepUpLevel = "password"
)
```

Assurance levels for an action. A session good enough to read a profile is not
good enough to transfer money, and step-up is the mechanism for saying so without
forcing MFA on every request.

```go
type StepUpPolicy interface {
    RequiredLevel(ctx context.Context, action string, resource any) StepUpLevel
}
```

Your rules. The policy is an interface rather than a configuration table because
the required level often depends on the resource, not only the action —
transferring ten dollars and transferring ten thousand are the same action.

```go
type BankingPolicy struct{}

func (p *BankingPolicy) RequiredLevel(ctx context.Context, action string, resource any) StepUpLevel {
    switch action {
    case "transfer_funds", "change_password":
        return flow.StepUpPassword
    case "view_transactions":
        return flow.StepUpRecent
    default:
        return flow.StepUpNone
    }
}
```

```go
type StepUpManager struct { /* unexported fields */ }
type StepUpManagerOption func(*StepUpManager)

func NewStepUpManager(store StepUpStore, opts ...StepUpManagerOption) *StepUpManager

func WithStepUpPolicy(policy StepUpPolicy) StepUpManagerOption
func WithRecencyWindow(d time.Duration) StepUpManagerOption   // default 15 minutes

func (m *StepUpManager) Evaluate(ctx context.Context, sessionID, action string, resource any) (*StepUpResult, error)
func (m *StepUpManager) RecordStepUp(ctx context.Context, sessionID string, level StepUpLevel) error
```

```go
type StepUpResult struct {
    Allowed       bool        `json:"allowed"`
    RequiredLevel StepUpLevel `json:"required_level"`
    CurrentLevel  StepUpLevel `json:"current_level"`
    ChallengeType string      `json:"challenge_type,omitempty"`
}

type StepUpRecord struct {
    SessionID   string      `json:"session_id"`
    Level       StepUpLevel `json:"level"`
    CompletedAt time.Time   `json:"completed_at"`
}

type StepUpStore interface {
    SaveStepUp(ctx context.Context, record *StepUpRecord) error
    GetStepUp(ctx context.Context, sessionID string) (*StepUpRecord, error)
    DeleteStepUp(ctx context.Context, sessionID string) error
}

type MemoryStepUpStore struct { /* unexported fields */ }

func NewMemoryStepUpStore() *MemoryStepUpStore
func (s *MemoryStepUpStore) SaveStepUp(ctx context.Context, record *StepUpRecord) error
func (s *MemoryStepUpStore) GetStepUp(ctx context.Context, sessionID string) (*StepUpRecord, error)
func (s *MemoryStepUpStore) DeleteStepUp(ctx context.Context, sessionID string) error
```

The flow is: call `Evaluate` before the sensitive action, and if `Allowed` is
false, challenge the user for the method `ChallengeType` suggests, then call
`RecordStepUp` after they pass.

```go
result, err := mgr.Evaluate(ctx, sessionID, "transfer_funds", nil)
if err != nil {
    return err
}
if !result.Allowed {
    return challenge(result.ChallengeType)
}
// ...perform the transfer...
```

`WithRecencyWindow` bounds how long a completed step-up stays valid. Fifteen
minutes is the default: long enough that a user completing a multi-step task is
not asked twice, short enough that an unattended machine does not stay
privileged. The step-up is recorded against the session, so it does not survive
a logout.

### Recovery and verification

```go
type RecoveryManager struct { /* unexported fields */ }
type RecoveryOption func(*RecoveryManager)

func NewRecoveryManager(repo IdentityRepository, store domain.TokenStore, hasher domain.Hasher, opts ...RecoveryOption) *RecoveryManager

func WithRecoveryTTL(ttl time.Duration) RecoveryOption   // default 1 hour
func WithRecoveryRateLimit(limiter RateLimiter, limit int, window time.Duration) RecoveryOption

func (m *RecoveryManager) Initiate(ctx context.Context, identifier string) (*domain.AuthToken, error)
func (m *RecoveryManager) ResetPassword(ctx context.Context, tokenStr string, newPassword string) error
```

Password reset. `Initiate` generates a token and returns it; delivering it is
yours. `ResetPassword` consumes the token and writes the new hash through
`domain.CredentialStorage.UpdateCredentialSecret`.

The one-hour default TTL is short for a reason. A reset token is a full account
takeover in one string, and it lives in an email inbox — a medium that is
frequently compromised long after the message was sent, and frequently forwarded.

`WithRecoveryRateLimit` applies to both initiation and reset. It is worth setting.
Unlimited initiation is a mail-bombing tool aimed at your users and a reputation
problem for your sending domain; unlimited reset attempts turn the token into
something guessable at scale.

```go
var ErrRecoveryRateLimited = errors.New("recovery: rate limited")
```

Note also that `Initiate` for an unknown identifier must not report that fact to
the caller. The visible behavior for "no such account" and "mail sent" has to be
identical, or the reset form is an account-enumeration endpoint.

```go
type VerificationManager struct { /* unexported fields */ }

func NewVerificationManager(repo IdentityRepository, store domain.TokenStore, factory func() any) *VerificationManager

func (m *VerificationManager) Initiate(ctx context.Context, ident any) (*domain.AuthToken, error)
func (m *VerificationManager) Verify(ctx context.Context, tokenStr string) error
```

Email or phone verification. `Verify` consumes the token and calls
`MarkVerified` through the `VerificationIdentity` interface — a model that does
not implement it cannot record the result, and the same link keeps working.

`Initiate` takes the identity rather than an identifier, because verification is
initiated for a user you already have, usually right after registration.

Both managers write to the same `domain.TokenStore` and both check
`AuthToken.Type`, which is what stops a verification link from being redeemed as
a password reset.

### `StrategyRegistry`

```go
type StrategyRegistry struct { /* unexported fields */ }

func NewStrategyRegistry() *StrategyRegistry

func (r *StrategyRegistry) RegisterFactory(typeKey string, factory StrategyFactory)
func (r *StrategyRegistry) RegisterRegistrationFactory(typeKey string, factory RegistrationStrategyFactory)
func (r *StrategyRegistry) Build(config *domain.StrategyConfig) (LoginStrategy, error)
func (r *StrategyRegistry) BuildRegistration(config *domain.StrategyConfig) (RegistrationStrategy, error)
func (r *StrategyRegistry) ListFactories() []string
```

Turns a `domain.StrategyConfig` into a live strategy, which is what makes
runtime-configured login methods possible: an admin enables "Sign in with GitHub"
and `LoginManager.ReloadStrategies` builds it without a redeploy.

`typeKey` matches `StrategyConfig.Type`, not `ID` — several configured strategies
of the same type can point at different providers.

A factory must reject a config it cannot build from. Returning a partially
configured strategy means the failure surfaces as a broken login for real users
rather than as an error the admin sees when they save.

`ListFactories` returns the sorted union of login and registration factory keys,
for an admin UI listing what can be configured.

### Flow state

```go
type FlowType string

const (
    FlowTypeRegistration FlowType = "registration"
    FlowTypeLogin        FlowType = "login"
)

type Flow struct {
    ID        uuid.UUID `json:"id"`
    Type      FlowType  `json:"type"`
    ExpiresAt time.Time `json:"expires_at"`
    Active    bool      `json:"active"`
    IssuedAt  time.Time `json:"issued_at"`
    Methods   []string  `json:"methods"`
}

func NewFlow(t FlowType, methods []string) *Flow
```

Transient state for a multi-step authentication process, for callers building a
UI that needs to know which methods are offered at a given step.

### Deprecated aliases

```go
type BcryptHasher = domain.BcryptHasher
func NewBcryptHasher(cost int) *domain.BcryptHasher
```

Both deprecated in favor of `domain.BcryptHasher` and `domain.NewBcryptHasher`.
The type moved because it is a `domain.Hasher` implementation with no dependency
on `flow`, and packages that also hash secrets — the OAuth provider, the admin
manager — could not reach it from a flow package without importing the
authentication engine. These are aliases rather than new types, so existing
wiring compiles unchanged.

---

## `core/session`

```go
import "github.com/getkayan/kayan/core/session"
```

`session` turns a successful authentication into something a client can present
on subsequent requests. It offers two default strategies with genuinely
different trade-offs — a stateless JWT and a stored database record — plus the
SSO machinery for a session that spans several applications. The choice between
stateless and stored is the one architectural decision this package asks you to
make, and it comes down to whether you need immediate revocation.

### `Strategy`

```go
type Strategy interface {
    Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
    Validate(ctx context.Context, sessionID any) (*identity.Session, error)
    Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
    Delete(ctx context.Context, sessionID any) error
}
```

`sessionID` is `any` because it means different things per strategy. For
`DatabaseStrategy` it is a stored primary key. For `JWTStrategy` it is the signed
token itself — the token *is* the session, and there is no server-side record to
key. Implementations assert the type they expect.

### `Manager`

```go
type Manager struct { /* unexported fields */ }

func NewManager(strategy Strategy) *Manager

func (m *Manager) Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
func (m *Manager) Validate(ctx context.Context, sessionID any) (*identity.Session, error)
func (m *Manager) Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
func (m *Manager) Delete(ctx context.Context, sessionID any) error
func (m *Manager) AddLogoutNotifier(n LogoutNotifier)
```

A thin wrapper that delegates to the strategy and adds logout notification.

`Delete` notifies registered notifiers **synchronously**, and that is deliberate.
Spawning a goroutine per notifier would leave every in-flight notification
unfinished when the process exits, so a relying party would keep serving a
session the user believes they ended. A logout that returns before it has taken
effect is a logout that did not happen.

```go
type LogoutNotifier interface {
    NotifyLogout(sid string, identityID string) error
}
```

Implement it to propagate a logout: clearing a cache, notifying an OIDC relying
party through back-channel logout, writing an audit record. Because notification
is synchronous, a slow notifier makes logout slow — which is the correct
trade-off, but means a notifier that calls a remote service needs its own
timeout.

### `JWTStrategy`

```go
type JWTStrategy struct { /* unexported fields */ }

func NewJWTStrategy(config JWTConfig) *JWTStrategy
func NewHS256Strategy(secret string, expiry time.Duration) *JWTStrategy

func (s *JWTStrategy) Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
func (s *JWTStrategy) Validate(ctx context.Context, sessionID any) (*identity.Session, error)
func (s *JWTStrategy) Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
func (s *JWTStrategy) Delete(ctx context.Context, sessionID any) error
func (s *JWTStrategy) WithRevocationStore(store RevocationStore) *JWTStrategy
func (s *JWTStrategy) SetRefreshTokenValidator(v func(token *jwt.Token) error)
```

Stateless sessions. Nothing is written on `Create` and nothing is read on
`Validate`, so session checks cost a signature verification and scale without a
session store.

```go
type JWTConfig struct {
    SigningMethod jwt.SigningMethod
    SigningKey    any // e.g. []byte for HMAC, *rsa.PrivateKey for RSA
    VerifyingKey  any // e.g. []byte for HMAC (same as SigningKey), *rsa.PublicKey for RSA
    Expiry        time.Duration

    // Token Rotation
    RefreshSigningMethod  jwt.SigningMethod
    RefreshSigningKey     any
    RefreshVerifyingKey   any
    RefreshExpiry         time.Duration
    RefreshTokenValidator func(token *jwt.Token) error
}
```

`SigningKey` and `VerifyingKey` are `any` so any algorithm works without a type
parameter. For HMAC they are the same `[]byte`; for asymmetric algorithms they
are the private and public halves.

The refresh fields are separate so an access token and a refresh token can be
signed with different keys and different algorithms. That separation is worth
using: a refresh token is long-lived and higher-value, and keying it separately
means a leaked access-token verification key does not let an attacker mint
refresh tokens. When `RefreshSigningMethod` is unset, the access token's method
is used.

`RefreshTokenValidator` — settable at construction or afterwards through
`SetRefreshTokenValidator` — runs on parse. It is where you check a `jti` against
a used-token list to detect refresh-token reuse: a refresh token presented twice
means the first presentation was replayed, and the correct response is to revoke
the whole token family.

If `SigningMethod` is left unset, the strategy defaults to HS256 for both access
and refresh tokens.

#### Algorithm pinning

**Every JWT parse in this package pins the expected algorithm.** The key
function rejects a token whose `alg` header does not match the configured
`SigningMethod.Alg()`, and it returns an error rather than a key when no method
is configured.

This is the defense against algorithm confusion. Without it, a service signing
with RS256 publishes its public key. An attacker takes a token, changes the
header to HS256, and signs it using that public key as the HMAC secret. A
verifier that trusts the token's own header to say how to verify it computes an
HMAC with the public key, gets a match, and accepts a token the attacker forged
in full — including the identity claim.

The check is in one place — a shared `keyFunc` used by `Validate`, `Refresh`, and
`Delete` alike — specifically so it cannot be present on some paths and missing
on others. `Delete` parses the token too, and pins there as well: without it, a
forged token would let an attacker revoke an arbitrary session.

The same guarantee is available to callers parsing tokens themselves through
`keys.Keyfunc`.

#### Revocation

```go
type RevocationStore interface {
    Revoke(ctx context.Context, sessionID string, expiresAt time.Time) error
    IsRevoked(ctx context.Context, sessionID string) (bool, error)
}

type MemoryRevocationStore struct { /* unexported fields */ }

func NewMemoryRevocationStore() *MemoryRevocationStore
func (s *MemoryRevocationStore) Revoke(ctx context.Context, sessionID string, expiresAt time.Time) error
func (s *MemoryRevocationStore) IsRevoked(ctx context.Context, sessionID string) (bool, error)
```

**Without a revocation store, `JWTStrategy.Delete` is a no-op that returns nil.**
There is nothing on the server to delete: the token holds its own validity, and
the client keeps working until the token expires. A "log out everywhere" button
wired to `Delete` on a bare `JWTStrategy` reports success and changes nothing.

This is the fundamental cost of stateless sessions, not an oversight, and the
usual mitigation is a short access-token expiry so the window is small. When
immediate revocation is required — a compromised account, a fired employee, a
user who clicked "sign out of all devices" — attach a store:

```go
strategy := session.NewJWTStrategy(cfg).
    WithRevocationStore(redisRevocationStore)
```

With a store attached, `Delete` parses the token (algorithm pinned), reads its
expiry, and records it as revoked until then; `Validate` checks the store on
every call. Note that this reintroduces a lookup on the validation path, which is
the very cost stateless sessions were chosen to avoid — but only a fast
existence check, not a full session read.

Entries only need to be kept until the token's own expiry, which is why `Revoke`
takes `expiresAt`. An implementation backed by Redis should set a TTL from it, so
the revocation list stays proportional to tokens in flight rather than growing
forever.

`MemoryRevocationStore` is per-process, so a token revoked on one replica stays
valid on the others. Use it for development only.

```go
type JWTClaims struct {
    SessionID string `json:"sid"`
    jwt.RegisteredClaims
}
```

`sid` carries the session identifier alongside the standard registered claims.

### `DatabaseStrategy`

```go
type DatabaseStrategy struct {
    RefreshHook func(refreshToken string) (*identity.Session, error)
    // unexported fields
}

func NewDatabaseStrategy(repo domain.SessionStorage) *DatabaseStrategy

func (s *DatabaseStrategy) Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
func (s *DatabaseStrategy) Validate(ctx context.Context, sessionID any) (*identity.Session, error)
func (s *DatabaseStrategy) Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
func (s *DatabaseStrategy) Delete(ctx context.Context, sessionID any) error
```

Stored sessions. `Delete` genuinely deletes, so revocation is immediate and
free — the opposite trade-off from JWT. The cost is a storage read on every
request, which is the reason JWT exists.

`Validate` checks expiry. Revocation semantics beyond that belong to the store:
the strategy will not second-guess a store that returns a session whose `Active`
field is false.

`RefreshHook` is an exported field rather than an option, letting a caller
substitute the refresh lookup — for a store that keeps refresh tokens somewhere
other than the session row.

### SSO

```go
type SSOSession struct {
    ID          string       `json:"id"`
    IdentityID  string       `json:"identity_id"`
    AppSessions []AppSession `json:"app_sessions"`
    CreatedAt   time.Time    `json:"created_at"`
    ExpiresAt   time.Time    `json:"expires_at"`
    Active      bool         `json:"active"`
}

type AppSession struct {
    AppID     string    `json:"app_id"`
    SessionID string    `json:"session_id"`
    CreatedAt time.Time `json:"created_at"`
}
```

One authentication, several applications. The SSO session is the parent; each
application the user reaches gets a child `AppSession`.

```go
type SSOManager struct { /* unexported fields */ }
type SSOManagerOption func(*SSOManager)

func NewSSOManager(store SSOStore, opts ...SSOManagerOption) *SSOManager

func WithSSOTTL(ttl time.Duration) SSOManagerOption   // default 8 hours

func (m *SSOManager) CreateSession(ctx context.Context, identityID, appID string) (*SSOSession, error)
func (m *SSOManager) JoinSession(ctx context.Context, ssoSessionID, appID string) (*AppSession, error)
func (m *SSOManager) GetSession(ctx context.Context, ssoSessionID string) (*SSOSession, error)
func (m *SSOManager) GetSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error)
func (m *SSOManager) Logout(ctx context.Context, ssoSessionID string) ([]AppSession, error)
func (m *SSOManager) LogoutApp(ctx context.Context, ssoSessionID, appID string) error
```

`Logout` deactivates the SSO session and **returns the app sessions rather than
tearing them down**. Kayan is headless and does not know how to invalidate a
session in an application it has never heard of, so it hands you the list and
the invalidation is yours:

```go
apps, err := ssoManager.Logout(ctx, ssoSessionID)
if err != nil {
    return err
}
for _, app := range apps {
    if err := appSessionManager.Delete(ctx, app.SessionID); err != nil {
        // Do not stop. A failure here leaves one application still logged in;
        // continue and report, rather than abandoning the rest.
        log.Error("sso logout failed", "app", app.AppID, "err", err)
    }
}
```

The failure mode to watch for is a partial global logout: the SSO session is
inactive, so the user cannot start new app sessions, but an application whose
teardown failed keeps honoring the one it has. Treat this loop's errors as
something to report, not to swallow.

`LogoutApp` removes one application and leaves the SSO session active for the
rest.

The eight-hour default TTL is a working day. It bounds how long a single
authentication remains good across every application at once, which is a larger
blast radius than a single app session and deserves a shorter life than one.

```go
type SSOStore interface {
    CreateSSOSession(ctx context.Context, session *SSOSession) error
    GetSSOSession(ctx context.Context, id string) (*SSOSession, error)
    GetSSOSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error)
    UpdateSSOSession(ctx context.Context, session *SSOSession) error
    DeleteSSOSession(ctx context.Context, id string) error
}

type MemorySSOStore struct { /* unexported fields */ }

func NewMemorySSOStore() *MemorySSOStore
func (s *MemorySSOStore) CreateSSOSession(ctx context.Context, session *SSOSession) error
func (s *MemorySSOStore) GetSSOSession(ctx context.Context, id string) (*SSOSession, error)
func (s *MemorySSOStore) GetSSOSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error)
func (s *MemorySSOStore) UpdateSSOSession(ctx context.Context, session *SSOSession) error
func (s *MemorySSOStore) DeleteSSOSession(ctx context.Context, id string) error
```

`UpdateSSOSession` is called on every join, so an implementer should make the
read-modify-write safe against concurrent joins — two applications joining at
once through a naive implementation lose one of the app sessions, and that
application then survives a global logout.

### `NewSession` and `Session`

```go
type Session = identity.Session

func NewSession(sessionID, identityID any) *identity.Session
```

`Session` is an alias for `identity.Session`, so the two are interchangeable.

`NewSession` builds one with a **hardcoded 24-hour expiry** and `Active` set to
true, formatting both IDs through `fmt.Sprintf("%v", …)`. It is a convenience for
tests and for strategies that manage expiry themselves. It is not a general
constructor — the fixed lifetime ignores whatever expiry you configured — so
prefer `Manager.Create`, which goes through the strategy.

---

## `core/rbac`

```go
import "github.com/getkayan/kayan/core/rbac"
```

`rbac` answers "does this identity hold this role, or this permission?" It is
the simplest of the three authorization packages and the right default when
access depends on who someone is rather than on their relationship to a specific
object. When access depends on the object — this document, that folder — reach
for [`core/rebac`](#corerebac) instead.

The package stays transport-agnostic. There is no middleware here; call `Manager`
from your own HTTP or RPC layer.

### `Strategy` and `Manager`

```go
type Strategy interface {
    HasRole(ctx context.Context, identityID any, role string) (bool, error)
    GetRoles(ctx context.Context, identityID any) ([]string, error)
    HasPermission(ctx context.Context, identityID any, permission string) (bool, error)
    GetPermissions(ctx context.Context, identityID any) ([]string, error)
}
```

```go
type Manager struct { /* unexported fields */ }

func NewManager(strategy Strategy) *Manager

func (m *Manager) Authorize(ctx context.Context, identityID any, role string) (bool, error)
func (m *Manager) AuthorizePermission(ctx context.Context, identityID any, permission string) (bool, error)
func (m *Manager) GetRoles(ctx context.Context, identityID any) ([]string, error)
func (m *Manager) GetPermissions(ctx context.Context, identityID any) ([]string, error)
func (m *Manager) RequireRole(ctx context.Context, identityID any, role string) error
func (m *Manager) RequirePermission(ctx context.Context, identityID any, permission string) error
```

The `Require…` variants return an error instead of a boolean. Prefer them at call
sites: a boolean that is ignored is a check that did not happen, and Go will not
warn you about an unused `bool` the way it will about an unused `error`.

### `Role`

```go
type Role struct {
    Name        string
    Permissions []string

    // Inherits names roles whose permissions this role also has. An admin
    // inheriting from editor gets every editor permission without restating
    // them, so the two cannot drift apart.
    Inherits []string

    // Description is for administrative interfaces.
    Description string
}
```

`Inherits` is the reason this is more than a map. Restating an editor's
permissions inside the admin role means the two definitions drift the moment
someone adds a permission to one and forgets the other — and the drift is silent,
surfacing as an admin who cannot do something an editor can.

Inheritance is followed transitively, bounded by `MaxInheritanceDepth`, and
cycles are rejected at definition time.

### `RoleStore` and `RBACStorage`

```go
type RoleStore interface {
    GetRole(ctx context.Context, name string) (*Role, error)
    SaveRole(ctx context.Context, role *Role) error
    DeleteRole(ctx context.Context, name string) error
    ListRoles(ctx context.Context) ([]*Role, error)
}
```

Persists role *definitions*. They belong in storage rather than process memory
because they are shared state: a role created on one replica must be visible to
the next request, whichever replica serves it.

`GetRole` returns `ErrRoleNotFound` for an undefined role.

```go
type RBACStorage interface {
    GetIdentityRoles(ctx context.Context, identityID any) ([]string, error)
    SetIdentityRoles(ctx context.Context, identityID any, roles []string) error
}
```

Persists *assignments* — which identities hold which roles. The two are separate
interfaces because they are separate concerns with different access patterns:
assignments are read on every request and often live on the identity row, while
definitions change rarely and are shared across every identity.

### `MemoryStrategy`

```go
type MemoryStrategy struct { /* unexported fields */ }

func NewMemoryStrategy() *MemoryStrategy

func (s *MemoryStrategy) DefineRole(role *Role) error
func (s *MemoryStrategy) AddRole(role *Role)
func (s *MemoryStrategy) AssignRole(identityID any, role string) error
func (s *MemoryStrategy) UnassignRole(identityID any, role string)
func (s *MemoryStrategy) RevokeRole(identityID any, role string)   // Deprecated: use UnassignRole

func (s *MemoryStrategy) HasRole(_ context.Context, identityID any, role string) (bool, error)
func (s *MemoryStrategy) GetRoles(_ context.Context, identityID any) ([]string, error)
func (s *MemoryStrategy) HasPermission(ctx context.Context, identityID any, permission string) (bool, error)
func (s *MemoryStrategy) GetPermissions(ctx context.Context, identityID any) ([]string, error)

// RoleStore implementation
func (s *MemoryStrategy) GetRole(_ context.Context, name string) (*Role, error)
func (s *MemoryStrategy) SaveRole(_ context.Context, role *Role) error
func (s *MemoryStrategy) DeleteRole(_ context.Context, name string) error
func (s *MemoryStrategy) ListRoles(_ context.Context) ([]*Role, error)
```

Correct for a single process. Several replicas each keep their own copy, so a
role defined on one is unknown to the others — and a permission check there
returns false with no error, which is a silent wrong denial that nothing reports.
Use `StorageStrategy` with a shared `RoleStore` for anything running more than
one instance.

`DefineRole` rejects a definition that would introduce a cycle or name an
undefined parent, so the failure lands on whoever wrote it rather than on a
permission check hours later. A rejected definition **leaves the previous one in
place**: removing it would turn a bad edit into an outage, because every identity
holding that role would immediately start failing checks.

`AddRole` registers without validating inheritance. Prefer `DefineRole`.

`AssignRole` errors when the role has no definition, so a typo surfaces where it
was made rather than as an unexplained denial later.

`RevokeRole` is deprecated in favor of `UnassignRole`. The old name was the odd
one out — the rest of the package says "assign" and "unassign", and "revoke"
already means something else in the session and token vocabulary.

### `StorageStrategy`

```go
type StorageStrategy struct { /* unexported fields */ }

func NewStorageStrategy(assignments RBACStorage, roles RoleStore) *StorageStrategy

func (s *StorageStrategy) HasRole(ctx context.Context, identityID any, role string) (bool, error)
func (s *StorageStrategy) GetRoles(ctx context.Context, identityID any) ([]string, error)
func (s *StorageStrategy) HasPermission(ctx context.Context, identityID any, permission string) (bool, error)
func (s *StorageStrategy) GetPermissions(ctx context.Context, identityID any) ([]string, error)
func (s *StorageStrategy) DefineRole(ctx context.Context, role *Role) error
func (s *StorageStrategy) DeleteRole(ctx context.Context, name string) error
```

The production strategy. Both halves of the model live in storage: assignments
through `RBACStorage`, definitions through `RoleStore`.

Holding definitions in process memory — as this type previously did — means a
role created on one replica is unknown to every other. The resulting permission
check returns false with no error, so nothing logs it, nothing alerts, and the
behavior depends on which replica served the request. A silent wrong denial in a
permission system is worse than a loud failure for exactly that reason.

`GetPermissions` includes permissions inherited from parent roles.

### `BasicStrategy`

```go
type IdentityLoader func(identityID any) (any, error)

type BasicStrategy struct { /* unexported fields */ }

func NewBasicStrategy(loader IdentityLoader) *BasicStrategy

func (s *BasicStrategy) HasRole(ctx context.Context, identityID any, role string) (bool, error)
func (s *BasicStrategy) GetRoles(ctx context.Context, identityID any) ([]string, error)
func (s *BasicStrategy) HasPermission(ctx context.Context, identityID any, permission string) (bool, error)
func (s *BasicStrategy) GetPermissions(ctx context.Context, identityID any) ([]string, error)
func (s *BasicStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
```

Reads roles and permissions directly off the model through `RoleSource` and
`PermissionSource`, loading the identity through the `IdentityLoader` when only
an ID is available. This is the strategy for a model that stores its roles in a
column and does not need a separate role table.

`Can` implements `policy.Engine` so a `BasicStrategy` can be composed into a
`policy.HybridStrategy`. Note the argument reinterpretation: the `action`
parameter is treated as **the required role**, and `resource` is ignored.
`Can(ctx, identityID, "admin", nil)` asks whether the identity has the `admin`
role. Passing a permission string where a role is expected produces a denial
rather than an error, so get this right at the call site.

```go
type RoleSource interface {
    GetRoles() []string
}

type PermissionSource interface {
    GetPermissions() []string
}
```

Implement these on your model to skip a lookup where roles are already loaded.
`identity.Identity` implements both.

### Permission matching

```go
const PermissionSeparator = ":"

const (
    WildcardSegment = "*"   // matches exactly one segment
    WildcardSuffix  = "**"  // matches one or more remaining segments; must be last
)

const MaxInheritanceDepth = 32

func PermissionGranted(granted, requested string) bool
func AnyPermissionGranted(granted []string, requested string) bool
```

Permissions are hierarchical strings: `billing:invoices:read` names an action
within a resource within a domain.

Matching is segment-wise, not by regular expression. A regex in a permission
string is a denial-of-service vector — a crafted pattern makes every check
expensive — and its semantics are unclear to whoever writes the grant. Segments
compare case-sensitively, because `Admin` and `admin` silently being the same
permission is a surprise nobody asked for.

| Granted | Requested | Result | Why |
|---|---|---|---|
| `users:*` | `users:delete` | `true` | `*` matches exactly one segment |
| `users:read` | `users:delete` | `false` | different action |
| `docs:**` | `docs:a:b:c` | `true` | `**` matches one or more remaining segments |
| `docs:*` | `docs:a:b` | `false` | `*` matches one segment, not two |
| `*` | `anything` | `true` | single-segment request, single-segment wildcard |
| `users:read` | `users:*` | `false` | **wildcards in the request are never expanded** |

The last row is the security-relevant one. **Wildcards are honored only in a
grant, never in the permission being checked.** If a request could contain a
wildcard, a caller could ask "may I do anything under `users`?" and be told yes
on the strength of holding a single narrow permission. The check would be
answering a different question from the one the call site believes it asked.

`MaxInheritanceDepth` bounds how far inheritance is followed. Cycles are detected
directly, so this only stops a pathological chain from costing more than it is
worth.

### Errors

```go
var (
    ErrRoleNotFound = errors.New("rbac: role is not defined")
    ErrCycle        = errors.New("rbac: role inheritance contains a cycle")
)
```

`ErrRoleNotFound` is an error rather than a silent denial on purpose. A
permission check that quietly returns false because the definition is missing
looks identical to a legitimate refusal, and the two need different responses:
one is a user without access, the other is a broken configuration. Collapsing
them means a deployment mistake presents as a support ticket about permissions.

`ErrCycle` is reported at definition time by `DefineRole`, not at check time.

---

## `core/rebac`

```go
import "github.com/getkayan/kayan/core/rebac"
```

`rebac` implements relationship-based access control in the style of Google
Zanzibar. Where RBAC asks "what is this user?", ReBAC asks "how is this user
connected to this object?" — which is the question you actually have when a
document can be shared with an individual, with a group, or inherited from the
folder it sits in.

Authorization data is a set of tuples: *(subject, relation, object)*. Permissions
are derived by walking the graph those tuples form.

### `Tuple`, `ObjectRef`, `SubjectRef`

```go
type ObjectRef struct {
    Type string // "document", "folder", "user"
    ID   string
}

func NewObjectRef(objectType, id string) ObjectRef
func (o ObjectRef) String() string   // "type:id"

type SubjectRef struct {
    Object   ObjectRef
    Relation string // Optional: for usersets like "group:eng#member"
}

func NewSubjectRef(subjectType, id string) SubjectRef
func NewUsersetRef(objectType, id, relation string) SubjectRef
func (s SubjectRef) IsUserset() bool
func (s SubjectRef) String() string

type Tuple struct {
    Subject  SubjectRef
    Relation string
    Object   ObjectRef
}

func NewTuple(subjectType, subjectID, relation, objectType, objectID string) Tuple
func NewUsersetTuple(subjectType, subjectID, subjectRelation, relation, objectType, objectID string) Tuple
func (t Tuple) String() string   // "subject#relation@object"
```

A subject is either a direct reference (`user:alice`) or a **userset** — a
reference to everyone holding a relation on another object
(`group:engineering#member`). The userset is what makes the model scale: granting
a document to a group is one tuple, and it stays correct as people join and leave
the group, with no fan-out write.

```go
type TupleFilter struct {
    SubjectType     string
    SubjectID       string
    SubjectRelation string
    Relation        string
    ObjectType      string
    ObjectID        string
}

func (f TupleFilter) Matches(t Tuple) bool
```

All non-empty fields are ANDed.

### `Store`

```go
type Store interface {
    WriteTuple(ctx context.Context, tuple Tuple) error
    WriteTuples(ctx context.Context, tuples []Tuple) error
    DeleteTuple(ctx context.Context, tuple Tuple) error
    DeleteTuples(ctx context.Context, filter TupleFilter) error
    ReadTuples(ctx context.Context, filter TupleFilter) ([]Tuple, error)
    TupleExists(ctx context.Context, tuple Tuple) (bool, error)
}

type StoreOption func(any)
```

`WriteTuple` is a no-op when the tuple already exists, which makes grants
idempotent — a retried request does not create a duplicate.

`WriteTuples` must be **atomic**. A partially applied batch leaves the graph in a
state nobody wrote: half a permission change is not a smaller permission change,
it is a different and unintended one.

```go
type MemoryStore struct { /* unexported fields */ }

func NewMemoryStore() *MemoryStore
func (s *MemoryStore) WriteTuple(ctx context.Context, tuple Tuple) error
func (s *MemoryStore) WriteTuples(ctx context.Context, tuples []Tuple) error
func (s *MemoryStore) DeleteTuple(ctx context.Context, tuple Tuple) error
func (s *MemoryStore) DeleteTuples(ctx context.Context, filter TupleFilter) error
func (s *MemoryStore) ReadTuples(ctx context.Context, filter TupleFilter) ([]Tuple, error)
func (s *MemoryStore) TupleExists(ctx context.Context, tuple Tuple) (bool, error)
```

Single-instance only. Authorization data held per-replica means two replicas
disagree about who may do what, and the answer a user gets depends on which one
they reached.

### Schema

```go
type Schema struct {
    Type      string
    Relations map[string]RelationConfig
}

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
    TuplesetRelation string // The relation to follow (e.g. "parent")
    ComputedRelation string // The relation to check on the target (e.g. "viewer")
}
```

The schema is what turns stored tuples into derived permissions.

`ComputedRule.Relation` is direct inheritance: owners are automatically editors,
without a second tuple per owner.

`TupleToUserset` is "follow the pointer" inheritance — a document's viewers
include its parent folder's viewers:

```go
schema := rebac.Schema{
    Type: "document",
    Relations: map[string]rebac.RelationConfig{
        "owner":  {Name: "owner", DirectAllowed: true},
        "editor": {Name: "editor", DirectAllowed: true,
            ComputedFrom: []rebac.ComputedRule{{Relation: "owner"}}},
        "viewer": {Name: "viewer", DirectAllowed: true,
            ComputedFrom: []rebac.ComputedRule{
                {Relation: "editor"},
                {TupleToUserset: &rebac.TupleToUserset{
                    TuplesetRelation: "parent",
                    ComputedRelation: "viewer",
                }},
            }},
    },
}
```

`DirectAllowed: false` marks a relation that may only be derived. Use it for
relations that name a capability rather than an assignment — nobody should be
granted `viewer` directly if `viewer` is meant to be the union of editors and
folder viewers, because a direct grant bypasses the rule you wrote.

### `Checker`

```go
type Checker struct { /* unexported fields */ }
type CheckerOption func(*Checker)

func NewChecker(store Store, opts ...CheckerOption) *Checker

func WithSchemas(schemas []Schema) CheckerOption
func WithMaxDepth(depth int) CheckerOption

func (c *Checker) Check(ctx context.Context, subject SubjectRef, relation string, object ObjectRef) (bool, error)

const DefaultMaxDepth = 25
```

The graph traversal. `Check` evaluates direct tuples, userset expansion, computed
relations, and tuple-to-userset inheritance.

`WithMaxDepth` bounds recursion. A deeply nested folder hierarchy, or a schema
whose computed rules refer to each other, would otherwise let one check walk an
unbounded number of edges — the authorization equivalent of a query with no
limit, and a denial-of-service risk on a request path that runs for every access.
25 is deep enough for realistic hierarchies.

### `Manager`

```go
type Manager struct { /* unexported fields */ }
type ManagerOption func(*Manager)

func NewManager(store Store, opts ...ManagerOption) *Manager

func WithSchema(schema Schema) ManagerOption
```

The application-facing API, wrapping a store and a checker with string arguments
instead of struct references.

```go
func (m *Manager) Check(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) (bool, error)
func (m *Manager) RequirePermission(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error
func (m *Manager) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
```

`Check` is the authoritative answer. It evaluates the full graph: direct tuples,
group membership, computed relations, and parent inheritance.

`RequirePermission` is the error-returning form; prefer it at call sites.

`Can` implements `policy.Engine`, so a ReBAC manager composes into
`policy.HybridStrategy`. Subjects and resources are converted through extractors:

```go
manager.Can(ctx,
    rebac.SubjectInfo{Type: "user", ID: "alice"},
    "viewer",
    rebac.ResourceInfo{Type: "document", ID: "123"})
```

```go
type SubjectInfo struct{ Type, ID string }
type ResourceInfo struct{ Type, ID string }

type SubjectExtractor func(subject any) (subjectType, subjectID string, err error)
type ObjectExtractor func(resource any) (objectType, objectID string, err error)

func DefaultSubjectExtractor(subject any) (subjectType, subjectID string, err error)
func DefaultObjectExtractor(resource any) (objectType, objectID string, err error)
```

The default extractors handle `SubjectInfo`/`ResourceInfo` and bare strings,
treating a string as an ID with the default type. Passing a bare string is
convenient and slightly risky: `"alice"` becomes `user:alice`, so a call site
that meant a service account gets a user check. Pass the explicit struct where
the type is not obvious.

#### Writes

```go
func (m *Manager) Grant(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error
func (m *Manager) GrantUserset(ctx context.Context, subjectType, subjectID, subjectRelation, relation, objectType, objectID string) error
func (m *Manager) Revoke(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error
func (m *Manager) RevokeUserset(ctx context.Context, subjectType, subjectID, subjectRelation, relation, objectType, objectID string) error
```

`Grant("user", "alice", "viewer", "document", "123")` creates
`user:alice#viewer@document:123`.

`GrantUserset("group", "engineering", "member", "viewer", "document", "123")`
creates `group:engineering#member#viewer@document:123` — every member of the
engineering group is a viewer of document 123. One tuple, and it tracks group
membership automatically.

`Revoke` removes exactly the tuple named. Revoking a direct grant does **not**
remove access that also arrives through a group or a parent folder; `Check` will
still return true. Removing all of a subject's access means finding every path,
which is what makes ReBAC powerful and what makes "why can this person still see
this?" a real question. `Check` is the tool for answering it.

#### Convenience helpers

```go
func (m *Manager) AddToGroup(ctx context.Context, userID, groupID string) error
func (m *Manager) RemoveFromGroup(ctx context.Context, userID, groupID string) error
func (m *Manager) SetParent(ctx context.Context, parentType, parentID, childType, childID string) error
func (m *Manager) GetParent(ctx context.Context, childType, childID string) (*ObjectRef, error)
```

`AddToGroup` is shorthand for `Grant("user", userID, "member", "group", groupID)`.

`SetParent("folder", "home", "document", "123")` creates
`folder:home#parent@document:123` — document 123's parent is folder home. That
`parent` relation is what a `TupleToUserset` rule follows.

#### Listing

```go
func (m *Manager) ListDirectObjects(ctx context.Context, subjectType, subjectID, relation, objectType string) ([]ObjectRef, error)
func (m *Manager) ListDirectSubjects(ctx context.Context, relation, objectType, objectID string) ([]SubjectRef, error)
```

**Neither of these walks the relation graph.** They read stored tuples and
nothing else.

`ListDirectObjects` returns only objects the subject is related to by a tuple
written directly against them. Access granted through group membership, a
computed relation, or a parent object **is not returned**, so an object that
`Check` would allow the subject to reach can be absent from this list. Building a
"documents you can see" page from it will hide documents the user can in fact
open — and, worse, a call site that inverts the logic and treats absence as
denial has built an access control check that disagrees with the real one.

Use it to enumerate direct grants: an admin screen showing what was explicitly
assigned, or an audit of who was given something by hand. To decide whether
access exists, call `Check`.

`ListDirectSubjects` has the same limitation, plus one more: the subjects it
returns may be usersets such as `group:eng#member` rather than the individual
users those expand to. A "who has access to this document" report built from it
lists the group, not its members.

The names state the limitation deliberately. A traversing implementation is
planned; until it lands, the narrower name is what stops a caller from assuming
the broader behavior.

---

## `core/policy`

```go
import "github.com/getkayan/kayan/core/policy"
```

`policy` is the common shape every authorization paradigm in Kayan reduces to,
plus the attribute-based engine and the middleware that wraps any of them. RBAC,
ReBAC, and ABAC all satisfy one interface here, which is what lets them compose:
a hybrid strategy can require that a user holds a role *and* owns the record,
without either engine knowing the other exists.

### `Engine`

```go
type Engine interface {
    Can(ctx context.Context, subject any, action string, resource any) (bool, error)
}
```

One method, three `any` parameters. The looseness is the point: `rbac.Manager`,
`rebac.Manager`, and an ABAC strategy answer very different questions, and a
typed interface would have to commit to one of them.

`rbac.BasicStrategy.Can` and `rebac.Manager.Can` both implement it.

```go
type Factory func(config map[string]any) (Engine, error)
```

For dependency injection or configuration-driven engine selection.

### ABAC

```go
type Rule func(ctx context.Context, subject any, resource any, context Context) (bool, error)

type Context map[string]any

type ABACStrategy struct { /* unexported fields */ }

func NewABACStrategy() *ABACStrategy
func (s *ABACStrategy) AddRule(action string, rule Rule)
func (s *ABACStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
```

Attribute-based access control: the decision is a function of the subject's
attributes, the resource's attributes, and the environment.

```go
engine := policy.NewABACStrategy()
engine.AddRule("documents:read", func(ctx context.Context, subject, resource any, pCtx policy.Context) (bool, error) {
    user, ok := subject.(*User)
    if !ok {
        return false, fmt.Errorf("expected *User, got %T", subject)
    }
    doc, ok := resource.(*Document)
    if !ok {
        return false, fmt.Errorf("expected *Document, got %T", resource)
    }
    return doc.OwnerID == user.ID || user.Role == "admin", nil
})
```

Two things about rules deserve care. First, return an error rather than `false`
when a type assertion fails — a rule that denies on a wiring mistake is a rule
that will be debugged as a permissions problem instead of as the bug it is.
Second, a rule runs on every check for its action, so anything it does — a
database read, an HTTP call — is on the request path. Keep them pure over data
already loaded.

An action with no registered rule denies.

```go
var PolicyContextKey = contextKey{}

func WithContext(ctx context.Context, pCtx Context) context.Context
```

`WithContext` attaches a `policy.Context` to the request context; `ABACStrategy`
reads it back and passes it to the rule. This is how environmental attributes —
client IP, time of day, request headers — reach a rule that only receives a
subject and a resource.

Nothing in the context is trustworthy unless the code that put it there made it
so. A rule that grants access based on an IP taken from a client-supplied header
is granting access to anyone who can set that header.

### `HybridStrategy`

```go
type Combinator int

const (
    // DenyOverrides: if any engine denies, the result is false. All must allow.
    DenyOverrides Combinator = iota
    // AllowOverrides: if any engine allows, the result is true.
    AllowOverrides
)

type HybridStrategy struct { /* unexported fields */ }

func NewHybridStrategy(c Combinator, engines ...Engine) *HybridStrategy
func (s *HybridStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
```

Composes several engines under one combinator.

`DenyOverrides` is AND and is the conservative choice: adding an engine can only
narrow access, so a misconfigured or empty new engine fails closed. Use it for
"must hold the role *and* own the record".

`AllowOverrides` is OR and is genuinely useful — "an admin, or the owner" — but
adding an engine can only widen access. An engine that returns true too readily
grants everything it is composed with, and the other engines' denials become
invisible. Reach for `DenyOverrides` unless you specifically want the union.

```go
hybrid := policy.NewHybridStrategy(policy.DenyOverrides, rbacEngine, abacEngine)
allowed, err := hybrid.Can(ctx, subject, action, resource)
```

### `CachingMiddleware`

```go
type CachingMiddleware struct { /* unexported fields */ }
type CachingOption func(*CachingMiddleware)

func NewCachingMiddleware(next Engine, ttl time.Duration, opts ...CachingOption) *CachingMiddleware

func WithMaxCacheEntries(n int) CachingOption
func WithCacheClock(c domain.Clock) CachingOption

func (m *CachingMiddleware) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
func (m *CachingMiddleware) Invalidate()

const DefaultMaxCacheEntries = 10_000
```

Caches decisions for a bounded time. It is an `Engine` itself, so it drops in
front of any other.

```go
type CacheKeyer interface {
    CacheKey() string
}
```

**Only subjects and resources that implement `CacheKeyer` are cached.**
Everything else passes straight through to the wrapped engine. That refusal is
the design: a cache hit under the wrong key is a wrong authorization decision,
and there is no safe way to derive a key from an arbitrary `any` — two different
users could produce the same default key and inherit each other's answers.

The key must identify **everything the decision depends on**, and must be stable
for the same logical entity across requests:

```go
func (u *User) CacheKey() string { return "user:" + u.ID + ":" + u.Role }
```

Including the role matters. A key of `"user:" + u.ID` alone means a user demoted
from admin keeps their cached allow until the TTL expires — the demotion appears
not to have taken effect, for as long as the cache lives. Anything the rule reads
belongs in the key.

That is also the reason to keep the TTL short. It is the maximum time a
permission change can go unobserved, and `Invalidate` — which clears everything —
is a blunt instrument for a change affecting one user.

`WithMaxCacheEntries` bounds the cache; the default is 10,000. **A value of zero
or less disables the bound**, letting the cache grow without limit, which turns
a per-request cache into a memory leak on a system with many distinct subjects.

`WithCacheClock` sets the clock used for expiry, defaulting to
`domain.SystemClock`. Pass a fake clock to test expiry without sleeping.

The cache is in-process. Several replicas either accept per-replica caching —
which means the observable delay after a permission change varies by which
replica you hit — or wrap a shared cache in their own `Engine`.

### `AuditMiddleware`

```go
type AuditMiddleware struct { /* unexported fields */ }
type AuditOption func(*AuditMiddleware)

func NewAuditMiddleware(next Engine, store audit.AuditStore, opts ...AuditOption) *AuditMiddleware

func WithAsyncAudit() AuditOption
func WithAuditConcurrency(n int) AuditOption
func WithAuditDropWhenSaturated() AuditOption
func WithAuditErrorHandler(fn func(error)) AuditOption

func (m *AuditMiddleware) Can(ctx context.Context, subject any, action string, resource any) (bool, error)
func (m *AuditMiddleware) Wait(ctx context.Context) error

const DefaultAuditConcurrency = 64
```

Records every authorization decision to an `audit.AuditStore`. Also an `Engine`,
so it composes with the caching middleware — put audit *outside* caching if you
want every check recorded, or *inside* if you only want the ones that reached the
real engine.

By default, recording is **inline**: the check waits for the store. That is
slower and keeps the trail complete.

`WithAsyncAudit` moves recording to a background goroutine, bounded by
`WithAuditConcurrency` (default 64). The bound exists because unbounded goroutines
against a slow store is how a latency spike becomes an out-of-memory kill.

When the bound is reached, the default is to fall back to recording inline —
slowing the request but losing nothing. `WithAuditDropWhenSaturated` discards the
record instead. Choose it only where losing audit records is acceptable, which
for a compliance trail it generally is not: the records most likely to be dropped
are the ones from a traffic burst, and a traffic burst is exactly when you want
the trail.

**Call `Wait` during shutdown.** Without it, records still in flight are lost when
the process exits, and the gap in the trail lines up with every deploy.

```go
audited := policy.NewAuditMiddleware(engine, store,
    policy.WithAsyncAudit(),
    policy.WithAuditErrorHandler(func(err error) {
        log.Error("audit write failed", "err", err)
    }),
)
defer audited.Wait(shutdownCtx)
```

`WithAuditErrorHandler` reports write failures. Without one they are **invisible**:
the decision still returns normally, and nothing anywhere records that the record
was not recorded. An audit trail failing silently is worse than having no audit
trail, because you believe you have one.

---

## `core/tenant`

```go
import "github.com/getkayan/kayan/core/tenant"
```

`tenant` supports SaaS deployments where one process serves many customers whose
data must never mix. It splits the problem in two: **resolution**, deciding which
tenant a request belongs to, and **isolation**, making sure storage honors that
decision. This package owns resolution completely and provides the contracts for
isolation, but the enforcement lives in your storage adapter — because how
tenants are separated (a `tenant_id` column, a schema per tenant, a database per
tenant) is a deployment decision Kayan should not make for you.

The governing rule is that **isolation fails closed**. A scoped query with no
tenant in the context is an error, not an unscoped read.

### `Tenant` and settings

```go
type Tenant struct {
    ID        string          `json:"id"`
    Name      string          `json:"name"`
    Domain    string          `json:"domain,omitempty"`   // For domain-based resolution
    Slug      string          `json:"slug,omitempty"`     // URL-friendly identifier
    Settings  json.RawMessage `json:"settings,omitempty"` // Flexible settings storage
    Metadata  json.RawMessage `json:"metadata,omitempty"` // Custom metadata
    Active    bool            `json:"active"`
    CreatedAt time.Time       `json:"created_at"`
    UpdatedAt time.Time       `json:"updated_at"`
}
```

`Settings` is `json.RawMessage` rather than a struct so a deployment can store
whatever it needs without this package knowing the shape. `TenantSettings` is the
suggested shape:

```go
type TenantSettings struct {
    AllowedStrategies []string      `json:"allowed_strategies,omitempty"`
    SessionTTL        time.Duration `json:"session_ttl,omitempty"`
    MFARequired       bool          `json:"mfa_required,omitempty"`
    PasswordPolicy    *PasswordPolicy  `json:"password_policy,omitempty"`
    RateLimitOverride *RateLimitConfig `json:"rate_limit_override,omitempty"`
    LogoURL           string `json:"logo_url,omitempty"`
    PrimaryColor      string `json:"primary_color,omitempty"`
    Custom            json.RawMessage `json:"custom,omitempty"`
}

type PasswordPolicy struct {
    MinLength        int  `json:"min_length"`
    RequireUppercase bool `json:"require_uppercase"`
    RequireLowercase bool `json:"require_lowercase"`
    RequireNumbers   bool `json:"require_numbers"`
    RequireSymbols   bool `json:"require_symbols"`
    MaxAgeDays       int  `json:"max_age_days"`  // 0 = no expiry
    HistoryCount     int  `json:"history_count"` // Prevent reuse of N previous passwords
}

func DefaultPasswordPolicy() *PasswordPolicy

type RateLimitConfig struct {
    LoginLimit  int           `json:"login_limit"`
    LoginWindow time.Duration `json:"login_window"`
}
```

Note this `PasswordPolicy` is a distinct type from `flow.PasswordPolicy` — it is
a per-tenant configuration record, not the validator. Converting between them is
the caller's job.

`AllowedStrategies` is worth applying. A tenant that has mandated SSO expects
password login to be off for their users; leaving it enabled means an account
provisioned before the mandate still has a working password nobody is watching.

### `Store` and `Manager`

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

type ListFilter struct {
    Active *bool
    Limit  int
    Offset int
}
```

`GetByDomain` and `GetBySlug` are separate lookups because they back different
resolvers and both are on the request path — each wants its own index.

```go
type Manager struct {
    DefaultTenantID string
    RequireTenant   bool
    LoadFullTenant  bool
    // unexported fields
}
type ManagerOption func(*Manager)

func NewManager(store Store, resolver Resolver, opts ...ManagerOption) *Manager

func WithDefaultTenant(id string) ManagerOption
func WithOptionalTenant() ManagerOption
func WithLightweight() ManagerOption
func WithHooks(hooks Hooks) ManagerOption

func (m *Manager) Resolve(ctx context.Context, info ResolveInfo) (*Tenant, context.Context, error)
func (m *Manager) ResolveFromRequest(ctx context.Context, r *http.Request) (*Tenant, context.Context, error)
func (m *Manager) Create(ctx context.Context, tenant *Tenant) error
func (m *Manager) Get(ctx context.Context, id string) (*Tenant, error)
func (m *Manager) GetByDomain(ctx context.Context, domain string) (*Tenant, error)
func (m *Manager) Update(ctx context.Context, tenant *Tenant) error
func (m *Manager) Delete(ctx context.Context, id string) error
func (m *Manager) List(ctx context.Context, filter ListFilter) ([]*Tenant, error)
func (m *Manager) HTTPMiddleware(next http.Handler) http.Handler
func (m *Manager) HTTPMiddlewareFunc(next http.HandlerFunc) http.HandlerFunc
```

`Resolve` returns the tenant **and a new context carrying it**. Use the returned
context for everything downstream; discarding it means the tenant was resolved
and then thrown away, and every subsequent scoped query fails with `ErrNoTenant`
— or, in a wrongly built adapter, silently returns everything.

`WithOptionalTenant` sets `RequireTenant` to false, so a request that resolves no
tenant proceeds. Combine with `WithDefaultTenant` to name a fallback. Be
deliberate: the combination means an unrecognized host quietly lands in the
default tenant rather than being rejected, which is fine for a single-tenant
deployment with a stub resolver and dangerous for a real multi-tenant one.

`WithLightweight` stores only the tenant ID in context, skipping the full object
load. Cheaper, and enough when nothing downstream reads settings.

`HTTPMiddleware` is the one HTTP-aware piece in the package, provided because
tenant resolution is inherently about incoming requests. Everything else is
transport-agnostic through `ResolveInfo`.

### Resolvers

```go
type Resolver interface {
    Resolve(ctx context.Context, info ResolveInfo) (string, error)
}

type ResolverFunc func(ctx context.Context, info ResolveInfo) (string, error)
func (f ResolverFunc) Resolve(ctx context.Context, info ResolveInfo) (string, error)
```

Returns the tenant identifier, or an empty string when none can be determined.

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
func (i ResolveInfo) HeaderValue(name string) string
func (i ResolveInfo) QueryValue(name string) string
```

`ResolveInfo` is what keeps the package transport-agnostic: a gRPC or message-queue
caller populates it by hand and uses the same resolvers as an HTTP one.

The bundled resolvers:

```go
type SubdomainResolver struct {
    BaseDomain string
    Position   int   // 0 = first, -1 = last before base
}
func NewSubdomainResolver(baseDomain string) *SubdomainResolver

type HeaderResolver struct {
    HeaderName string   // default: X-Tenant-ID
}
func NewHeaderResolver(headerName string) *HeaderResolver

type PathResolver struct {
    PathPrefix string
    Position   int
}
func NewPathResolver(prefix string, position int) *PathResolver

type QueryResolver struct {
    ParamName string   // default: tenant
}
func NewQueryResolver(paramName string) *QueryResolver

type JWTClaimResolver struct {
    ClaimName        string   // default: tenant_id
    ClaimsContextKey any
}
func NewJWTClaimResolver(claimName string, claimsKey any) *JWTClaimResolver

type StaticResolver struct {
    TenantID string
}
func NewStaticResolver(tenantID string) *StaticResolver
```

Each has `Resolve(ctx context.Context, info ResolveInfo) (string, error)`.

The security difference between these is large and easy to overlook.
`SubdomainResolver` reads the `Host` header, which is attacker-controlled unless
your proxy rejects unknown hosts — so a request claiming
`Host: victim-tenant.example.com` resolves to that tenant. `HeaderResolver`,
`QueryResolver`, and `PathResolver` all read values the client supplies outright.
None of them authenticate anything: they say which tenant is being *requested*,
not which the caller is *entitled to*.

`JWTClaimResolver` is different in kind. It reads a claim from a token your
service already verified, so the tenant is asserted by something you signed. It
requires the JWT to be parsed and placed in the context first.

The practical rule: resolve from whatever is convenient, then **verify the
authenticated session belongs to the resolved tenant** before doing anything with
it. Resolution alone is not authorization.

Composition wrappers:

```go
type ChainResolver struct {
    Resolvers []Resolver
}
func NewChainResolver(resolvers ...Resolver) *ChainResolver

type ValidatingResolver struct {
    Inner Resolver
    Store Store
}
func NewValidatingResolver(inner Resolver, store Store) *ValidatingResolver

type CacheResolver struct {
    Inner   Resolver
    Cache   Cache
    KeyFunc func(ResolveInfo) string
    TTL     int   // seconds
}
func NewCacheResolver(inner Resolver, cache Cache, keyFunc func(ResolveInfo) string) *CacheResolver

type Cache interface {
    Get(ctx context.Context, key string) (string, bool)
    Set(ctx context.Context, key string, value string, ttlSeconds int) error
}
```

`ChainResolver` tries each in order until one succeeds — subdomain first, header
as a fallback for API clients.

`ValidatingResolver` confirms the resolved tenant exists in the store. Worth
wrapping: it turns a request for a nonexistent tenant into a resolution failure
rather than a context carrying a tenant ID nothing recognizes, which downstream
becomes a query that matches no rows and looks like an empty account.

`CacheResolver` caches the lookup. `KeyFunc` must derive the key from whatever
the inner resolver reads — a key that ignores the host while the inner resolver
reads the host will serve one tenant's ID for another tenant's request, which is
a cross-tenant leak created by the cache.

### Isolation

```go
type Scoped interface {
    TenantID() string
    SetTenantID(id string)
}
```

Implemented by records that belong to a tenant. The adapter stamps the tenant on
write and verifies it on read, so a record cannot be created without one or
returned across a boundary.

```go
type User struct {
    Tenant string
}

func (u *User) TenantID() string      { return u.Tenant }
func (u *User) SetTenantID(id string) { u.Tenant = id }
```

```go
type TenantAware interface {
    GetTenantID() string
    SetTenantID(string)
}

func AsScoped(v any) (Scoped, bool)
```

`TenantAware` is **deprecated** in favor of `Scoped`. It is the same contract
under a different name, and the reason for the change is worth stating: nothing
ever called `GetTenantID`. `TenantAware` had no call sites anywhere in Kayan, so
the "automatic scoping" it advertised did not exist. A model implementing it was
not isolated, and looked isolated. `Scoped` is the name the isolation machinery
actually uses.

`AsScoped` adapts a value implementing either interface, returning false when it
implements neither. Use it in an adapter that must accept both during a
migration.

```go
type Scoper interface {
    Scope(ctx context.Context, query any) (any, error)
}

type ScoperFunc func(ctx context.Context, query any) (any, error)
func (f ScoperFunc) Scope(ctx context.Context, query any) (any, error)
```

Applies isolation to a query. The query type is opaque — a GORM adapter receives
a `*gorm.DB`, a Mongo adapter a filter document — because row-level,
schema-per-tenant, and database-per-tenant are all valid strategies and the
decision belongs to the adapter.

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

```go
func RequireID(ctx context.Context) (string, bool)
func Verify(ctx context.Context, record Scoped) error
func WithSystemContext(ctx context.Context) context.Context
func IsSystemContext(ctx context.Context) bool
```

`RequireID` is the function every adapter calls. The second result is false when
there is no tenant **and** the context was not marked as a system context. An
adapter that gets false **must fail the operation, not proceed unscoped**.

```go
id, ok := tenant.RequireID(ctx)
if !ok {
    return tenant.ErrNoTenant
}
db = db.Where("tenant_id = ?", id)
```

The alternative — treating a missing tenant as "no filter" — is how one
customer's data reaches another. It also fails in the worst possible way: quietly,
returning more rows than expected, in a code path that looks correct.

`Verify` checks a record on the way out. It exists for adapters that cannot push
isolation into the query — a key-value store, a cache — so they can still enforce
it after the read. Returns `ErrCrossTenant` when the record belongs elsewhere.

`WithSystemContext` marks a context as deliberate cross-tenant work. Because
isolation fails closed, genuine platform-wide operations — an administrator
listing every tenant, a job sweeping expired tokens — need a way to say so, and
it should be explicit and greppable rather than implied by an absent value.

```go
// Deliberately spans tenants: this job expires tokens everywhere.
ctx = tenant.WithSystemContext(ctx)
```

Every call to it is a place where isolation is off. That is the point of making
it a named function: `grep WithSystemContext` is a complete list of them.

```go
func WithTenant(ctx context.Context, t *Tenant) context.Context
func WithTenantID(ctx context.Context, id string) context.Context
func FromContext(ctx context.Context) *Tenant
func IDFromContext(ctx context.Context) string
```

`WithTenantID` is the lightweight form, storing only the ID. `IDFromContext`
returns just the ID — note it returns an empty string rather than a boolean when
absent, which is why `RequireID` is the right function for an adapter.

### Errors

```go
var (
    ErrNoTenant   = errors.New("tenant: no tenant in context")
    ErrCrossTenant = errors.New("tenant: record belongs to a different tenant")
)
```

`ErrNoTenant` must be treated as a failure by storage adapters rather than as
"return everything". Silently widening a scoped query is the single worst
failure this package exists to prevent.

`ErrCrossTenant` reports an attempt to reach another tenant's record — worth
alerting on, since it is either a bug in scoping or someone probing for one.

### `Hooks`

```go
type Hooks struct {
    BeforeCreate    func(ctx context.Context, tenant *Tenant) error
    AfterCreate     func(ctx context.Context, tenant *Tenant)
    BeforeResolve   func(ctx context.Context, info ResolveInfo) (string, bool)
    AfterResolve    func(ctx context.Context, tenant *Tenant, info ResolveInfo)
    OnResolveFailed func(ctx context.Context, info ResolveInfo, err error)
    ValidateTenant  func(ctx context.Context, tenant *Tenant) error
}
```

`BeforeResolve` returning `(id, true)` skips normal resolution entirely — an
override for a special host or an internal caller.

`ValidateTenant` rejects a resolved tenant. This is where a suspended or
past-due account is turned away, and doing it here rather than in each handler
means it cannot be forgotten in one of them.

`OnResolveFailed` is the alerting hook. A burst of resolution failures is either
a misconfigured DNS record or someone enumerating tenant names.

---

## `core/mfa`, `core/device`, `core/risk`

These three packages are standalone — `mfa` has no dependency on `core/flow` or
`core/session`, `device` and `risk` use only the standard library — and they
compose into adaptive authentication: assess the risk, evaluate the device,
challenge for a second factor when either warrants it.

### `core/mfa`

```go
import "github.com/getkayan/kayan/core/mfa"
```

Method-agnostic MFA orchestration. It separates enrollment, challenge, and
verification from any particular second factor, so TOTP, SMS OTP, WebAuthn, and
anything custom go through one manager.

```go
type Method interface {
    ID() string
    Enroll(ctx context.Context, identityID string) (*Enrollment, error)
    Challenge(ctx context.Context, enrollment *Enrollment) (*Challenge, error)
    Verify(ctx context.Context, enrollment *Enrollment, challenge *Challenge, response string) (bool, error)
}
```

The interface a caller implements. It is declared here rather than in `core/flow`
specifically to keep this package standalone; an adapter in `core/flow` can wrap
an existing strategy to satisfy it.

```go
type EnrollmentStatus string

const (
    EnrollmentPending  EnrollmentStatus = "pending"
    EnrollmentActive   EnrollmentStatus = "active"
    EnrollmentDisabled EnrollmentStatus = "disabled"
)

type Enrollment struct {
    ID         string           `json:"id"`
    IdentityID string           `json:"identity_id"`
    MethodID   string           `json:"method_id"`
    Status     EnrollmentStatus `json:"status"`
    Config     any              `json:"config,omitempty"` // Method-specific (TOTP secret URI, etc.)
    CreatedAt  time.Time        `json:"created_at"`
}

type Challenge struct {
    ID           string    `json:"id"`
    EnrollmentID string    `json:"enrollment_id"`
    MethodID     string    `json:"method_id"`
    ExpiresAt    time.Time `json:"expires_at"`
    Metadata     any       `json:"metadata,omitempty"` // Method-specific hint (masked phone, etc.)
}
```

The `Pending` → `Active` transition is the important part of the state machine.
An enrollment is pending until the user proves the method works, which is what
`ConfirmEnrollment` does. Activating on enrollment instead would let a user
scan a QR code, misconfigure their authenticator, and lock themselves out on the
next login — with a second factor they have never successfully used.

`Challenge.Metadata` is a hint for the UI, like a masked phone number. It is sent
to a party who has passed only the first factor, so it must not reveal anything
useful: the last two digits, not the whole number.

`Enrollment.Config` carries the TOTP secret URI. It is `any` and it is a
credential — do not serialize it into a response after enrollment is confirmed,
and do not log it.

```go
type Manager struct { /* unexported fields */ }
type ManagerOption func(*Manager)

func NewManager(store MFAStore, opts ...ManagerOption) *Manager

func WithChallengeTTL(d time.Duration) ManagerOption   // default 5 minutes
func WithMaxEnrollments(n int) ManagerOption           // default 0 (unlimited)

func (m *Manager) RegisterMethod(method Method)
func (m *Manager) Enroll(ctx context.Context, identityID, methodID string) (*Enrollment, error)
func (m *Manager) ConfirmEnrollment(ctx context.Context, enrollmentID, response string) error
func (m *Manager) ListEnrollments(ctx context.Context, identityID string) ([]*Enrollment, error)
func (m *Manager) DisableMethod(ctx context.Context, enrollmentID string) error
func (m *Manager) Challenge(ctx context.Context, identityID string) (*Challenge, error)
func (m *Manager) ChallengeWithMethod(ctx context.Context, identityID, methodID string) (*Challenge, error)
func (m *Manager) Verify(ctx context.Context, challengeID, response string) (bool, error)
func (m *Manager) GenerateRecoveryCodes(ctx context.Context, identityID string, count int) ([]string, error)
func (m *Manager) VerifyRecoveryCode(ctx context.Context, identityID, code string) (bool, error)
```

`Challenge` uses the first active enrollment; `ChallengeWithMethod` lets the user
pick, which matters when someone has a phone and a hardware key and only one of
them is to hand.

`GenerateRecoveryCodes` returns plaintext codes once and persists only bcrypt
hashes. `VerifyRecoveryCode` checks and consumes.

```go
type MFAStore interface {
    SaveEnrollment(ctx context.Context, enrollment *Enrollment) error
    GetEnrollment(ctx context.Context, id string) (*Enrollment, error)
    GetEnrollmentsByIdentity(ctx context.Context, identityID string) ([]*Enrollment, error)
    UpdateEnrollment(ctx context.Context, enrollment *Enrollment) error
    DeleteEnrollment(ctx context.Context, id string) error

    SaveChallenge(ctx context.Context, challenge *Challenge) error
    GetChallenge(ctx context.Context, id string) (*Challenge, error)
    DeleteChallenge(ctx context.Context, id string) error

    SaveRecoveryCodes(ctx context.Context, identityID string, codes []string) error
    GetRecoveryCodes(ctx context.Context, identityID string) ([]string, error)
    ConsumeRecoveryCode(ctx context.Context, identityID, code string) error
}

type MemoryStore struct { /* unexported fields */ }
func NewMemoryStore() *MemoryStore
```

`MemoryStore` implements every `MFAStore` method and is for development. A
challenge issued on one replica and verified on another will not be found.

`ConsumeRecoveryCode` must be atomic — check and mark used in one operation.
Split into a read and a write, two concurrent submissions of the same code both
succeed, which defeats single-use.

### `core/device`

```go
import "github.com/getkayan/kayan/core/device"
```

Device trust. Recognizing that a login is coming from a machine the user has used
before is one of the cheapest useful signals available: it lets you skip a
challenge for the familiar case and require one for the new device, which is both
better security and less friction than challenging everyone equally.

```go
type TrustLevel string

const (
    TrustUnknown TrustLevel = "unknown"  // first-time device, no history
    TrustLow     TrustLevel = "low"      // recently registered, unverified
    TrustMedium  TrustLevel = "medium"   // verified, normal trust
    TrustHigh    TrustLevel = "high"     // long-standing, frequently used, verified
    TrustBlocked TrustLevel = "blocked"  // explicitly blocked
)

type Device struct {
    ID          string     `json:"id"`
    IdentityID  string     `json:"identity_id"`
    Name        string     `json:"name,omitempty"`
    Fingerprint string     `json:"fingerprint"`
    UserAgent   string     `json:"user_agent,omitempty"`
    IPAddress   string     `json:"ip_address,omitempty"`
    TrustLevel  TrustLevel `json:"trust_level"`
    LastSeenAt  time.Time  `json:"last_seen_at"`
    CreatedAt   time.Time  `json:"created_at"`
    Verified    bool       `json:"verified"`
}

type DeviceInfo struct {
    Fingerprint string `json:"fingerprint"`
    UserAgent   string `json:"user_agent,omitempty"`
    IPAddress   string `json:"ip_address,omitempty"`
    Name        string `json:"name,omitempty"`
}

type EvaluationResult struct {
    Device      *Device    `json:"device,omitempty"`
    TrustLevel  TrustLevel `json:"trust_level"`
    IsNewDevice bool       `json:"is_new_device"`
    RequiresMFA bool       `json:"requires_mfa"`
}
```

A fingerprint is a **signal, not a credential**. It is computed from data the
client supplies, so it can be copied by anyone who observed it and forged by
anyone who wants to. A known fingerprint is a reason to lower friction, never a
reason to skip authentication — a system that logs a user in because it
recognized the device has made the fingerprint into a password that is written
into every request.

`EvaluationResult.RequiresMFA` is a recommendation the caller may act on. Nothing
here enforces it.

```go
type Manager struct { /* unexported fields */ }
type ManagerOption func(*Manager)

func NewManager(store Store, opts ...ManagerOption) *Manager

func WithMaxDevices(n int) ManagerOption          // default 0 (unlimited)
func WithAutoTrustAfter(d time.Duration) ManagerOption   // default 0 (no auto-upgrade)

func (m *Manager) Register(ctx context.Context, identityID string, info DeviceInfo) (*Device, error)
func (m *Manager) Evaluate(ctx context.Context, identityID string, info DeviceInfo) (*EvaluationResult, error)
func (m *Manager) Verify(ctx context.Context, deviceID string) error
func (m *Manager) Block(ctx context.Context, deviceID string) error
func (m *Manager) ListDevices(ctx context.Context, identityID string) ([]*Device, error)
func (m *Manager) RevokeAll(ctx context.Context, identityID string) error
```

`Register` is idempotent on the fingerprint: a known fingerprint updates
`LastSeenAt` and returns the existing device.

`Verify` marks a device verified and raises it to `TrustMedium`. Call it after
the user has confirmed the device out of band — clicked a link in an email, or
completed an MFA challenge — not merely because they logged in.

`WithMaxDevices` caps registrations per identity, returning an error at the
limit. It bounds an attacker's ability to accumulate trusted devices, but it
also means a legitimate user who reaches the cap cannot log in from a new
machine until they prune. Set it high enough to accommodate a phone, a laptop, a
work machine, and a browser that clears its storage.

`WithAutoTrustAfter` upgrades a verified device to `TrustHigh` after a duration.

`RevokeAll` is the "I lost my laptop" action. Pair it with session revocation —
forgetting the device does not end a session already issued to it.

```go
type Store interface {
    SaveDevice(ctx context.Context, device *Device) error
    GetDevice(ctx context.Context, id string) (*Device, error)
    GetDeviceByFingerprint(ctx context.Context, identityID, fingerprint string) (*Device, error)
    GetDevicesByIdentity(ctx context.Context, identityID string) ([]*Device, error)
    UpdateDevice(ctx context.Context, device *Device) error
    DeleteDevice(ctx context.Context, id string) error
    DeleteDevicesByIdentity(ctx context.Context, identityID string) error
}

type MemoryStore struct { /* unexported fields */ }
func NewMemoryStore() *MemoryStore
```

`GetDeviceByFingerprint` is keyed by `(identityID, fingerprint)`, not by
fingerprint alone — two users on identical corporate laptops produce the same
fingerprint, and a lookup by fingerprint alone would hand one user the other's
device record.

### `core/risk`

```go
import "github.com/getkayan/kayan/core/risk"
```

Adaptive risk scoring. Rules produce weighted signals; the engine sums them and
maps the total to a level the caller acts on.

```go
type Input struct {
    ActorID        string
    TenantID       string
    IPAddress      string
    UserAgent      string
    DeviceID       string
    GeoCountry     string
    GeoRegion      string
    GeoCity        string
    FailedAttempts int
    NewDevice      bool
    ImpossibleTrip bool
    GeoChanged     bool
    Attributes     map[string]any
}
```

Transport-neutral and schema-neutral. `Attributes` carries anything the built-in
fields do not.

```go
type Signal struct {
    Name      string         `json:"name"`
    Triggered bool           `json:"triggered"`
    Weight    int            `json:"weight"`
    Reason    string         `json:"reason,omitempty"`
    Metadata  map[string]any `json:"metadata,omitempty"`
}

type Level string

const (
    LevelLow      Level = "low"
    LevelMedium   Level = "medium"
    LevelHigh     Level = "high"
    LevelCritical Level = "critical"
)

type Assessment struct {
    Score     int       `json:"score"`
    Level     Level     `json:"level"`
    Signals   []Signal  `json:"signals"`
    Reasons   []string  `json:"reasons,omitempty"`
    Timestamp time.Time `json:"timestamp"`
}
```

`Assessment` carries the individual signals and reasons, not only the score. That
matters operationally: "risk score 65" is unactionable, while "new device plus
impossible travel" tells a support agent what happened and gives an auditor
something to review. Store the whole assessment, not just the number.

```go
type Rule interface {
    Name() string
    Evaluate(ctx context.Context, input *Input) Signal
}

type RuleFunc struct {
    RuleName string
    Fn       func(ctx context.Context, input *Input) Signal
}

func (r RuleFunc) Name() string
func (r RuleFunc) Evaluate(ctx context.Context, input *Input) Signal
```

Note `Evaluate` returns a `Signal` with no error. A rule that cannot decide
returns an untriggered signal. That is deliberate: risk assessment runs on the
login path, and a rule failing should not fail the login — it should contribute
nothing and let the other rules decide.

Bundled rules:

```go
func NewFailedAttemptsRule(threshold, weight int) Rule
func NewNewDeviceRule(weight int) Rule
func NewImpossibleTripRule(weight int) Rule
func NewGeoChangedRule(weight int) Rule
```

```go
type Engine struct { /* unexported fields */ }
type Option func(*Engine)

func NewEngine(opts ...Option) *Engine

func WithThresholds(thresholds Thresholds) Option

func (e *Engine) Register(rule Rule)
func (e *Engine) RegisterFunc(name string, fn func(ctx context.Context, input *Input) Signal)
func (e *Engine) Assess(ctx context.Context, input *Input) (*Assessment, error)

type Thresholds struct {
    Medium   int
    High     int
    Critical int
}
```

```go
engine := risk.NewEngine()
engine.Register(risk.NewFailedAttemptsRule(3, 30))
engine.Register(risk.NewNewDeviceRule(15))

assessment, err := engine.Assess(ctx, &risk.Input{
    FailedAttempts: 4,
    NewDevice:      true,
})
if err != nil {
    return err
}
if assessment.Level == risk.LevelHigh {
    // Require MFA or block.
}
```

Weights and thresholds are yours to tune, and the tuning is the hard part. Set
them so that high risk is rare and means something: a threshold that fires on
half of all logins trains users to click through the challenge without reading
it, which is worse than not challenging at all because it also trains them to
approve a challenge they did not initiate.

---

## Operational packages

### `core/audit`

```go
import "github.com/getkayan/kayan/core/audit"
```

Structured security event recording, shaped for SOC 2 and ISO 27001 evidence:
who did what to whom, from where, with what result, and how risky it was.

```go
type AuditEvent struct {
    ID        string        `json:"id"`
    Type      string        `json:"type"`
    ActorID   string        `json:"actor_id"`
    SubjectID string        `json:"subject_id"`
    Status    string        `json:"status"`
    Message   string        `json:"message"`
    Metadata  identity.JSON `json:"metadata"`
    CreatedAt time.Time     `json:"created_at"`

    TenantID     string        `json:"tenant_id,omitempty"`
    IPAddress    string        `json:"ip_address,omitempty"`
    UserAgent    string        `json:"user_agent,omitempty"`
    GeoLocation  *GeoLocation  `json:"geo_location,omitempty"`
    DeviceID     string        `json:"device_id,omitempty"`
    SessionID    string        `json:"session_id,omitempty"`
    ResourceType string        `json:"resource_type,omitempty"`
    ResourceID   string        `json:"resource_id,omitempty"`
    OldValue     identity.JSON `json:"old_value,omitempty"`
    NewValue     identity.JSON `json:"new_value,omitempty"`
    Risk         RiskLevel     `json:"risk,omitempty"`
    RequestID    string        `json:"request_id,omitempty"`
}
```

`ActorID` and `SubjectID` are separate because the two differ in exactly the
events that matter most: an administrator disabling someone else's account is one
actor and a different subject, and an audit schema that conflates them cannot
answer "who did this to this user?"

`OldValue` and `NewValue` capture change tracking. Never put a secret in either —
a password change should record that it happened, not what changed to what.

```go
type RiskLevel string

const (
    RiskLow      RiskLevel = "low"
    RiskMedium   RiskLevel = "medium"
    RiskHigh     RiskLevel = "high"
    RiskCritical RiskLevel = "critical"
)

type GeoLocation struct {
    Country   string  `json:"country,omitempty"`
    Region    string  `json:"region,omitempty"`
    City      string  `json:"city,omitempty"`
    Latitude  float64 `json:"latitude,omitempty"`
    Longitude float64 `json:"longitude,omitempty"`
}
```

```go
type AuditStore interface {
    SaveEvent(ctx context.Context, event *AuditEvent) error
    Query(ctx context.Context, filter Filter) ([]AuditEvent, error)
    Count(ctx context.Context, filter Filter) (int64, error)
    Export(ctx context.Context, filter Filter, format ExportFormat) (io.Reader, error)
    Purge(ctx context.Context, olderThan time.Time) (int64, error)
}

type ExportFormat string

const (
    ExportJSON ExportFormat = "json"
    ExportCSV  ExportFormat = "csv"
)

type Filter struct {
    TenantID     string
    ActorID      string
    SubjectID    string
    Types        []string
    Statuses     []string
    RiskLevels   []RiskLevel
    ResourceType string
    ResourceID   string
    StartTime    time.Time
    EndTime      time.Time
    IPAddress    string
    SessionID    string
    Limit        int
    Offset       int
    OrderBy      string // "created_at", "-created_at" (desc)
}
```

The interface a caller implements. `Export` returns an `io.Reader` rather than a
slice so a year of records can stream to a compliance auditor without loading
into memory.

`Purge` is the retention mechanism, driven by `compliance.RetentionManager`.
Audit records should be **append-only** in storage: there is no update method
here, and an implementation that offers one has built a way to rewrite the trail
after the fact.

```go
type EventBuilder struct { /* unexported fields */ }

func NewEvent(eventType string) *EventBuilder

func (b *EventBuilder) ID(id string) *EventBuilder
func (b *EventBuilder) Actor(actorID string) *EventBuilder
func (b *EventBuilder) Subject(subjectID string) *EventBuilder
func (b *EventBuilder) Tenant(tenantID string) *EventBuilder
func (b *EventBuilder) Status(status string) *EventBuilder
func (b *EventBuilder) Success() *EventBuilder
func (b *EventBuilder) Failure() *EventBuilder
func (b *EventBuilder) Blocked() *EventBuilder
func (b *EventBuilder) Message(msg string) *EventBuilder
func (b *EventBuilder) Metadata(meta identity.JSON) *EventBuilder
func (b *EventBuilder) IP(ip string) *EventBuilder
func (b *EventBuilder) UserAgent(ua string) *EventBuilder
func (b *EventBuilder) Geo(loc *GeoLocation) *EventBuilder
func (b *EventBuilder) Device(deviceID string) *EventBuilder
func (b *EventBuilder) Session(sessionID string) *EventBuilder
func (b *EventBuilder) Resource(resourceType, resourceID string) *EventBuilder
func (b *EventBuilder) Change(oldValue, newValue identity.JSON) *EventBuilder
func (b *EventBuilder) Risk(level RiskLevel) *EventBuilder
func (b *EventBuilder) RequestID(id string) *EventBuilder
func (b *EventBuilder) Build() *AuditEvent
func (b *EventBuilder) Save(ctx context.Context, store AuditStore) error
```

```go
err := audit.NewEvent(audit.EventLoginSuccess).
    Actor(userID).
    IP(clientIP).
    UserAgent(ua).
    Success().
    Save(ctx, store)
```

```go
type Logger struct { /* unexported fields */ }

func NewLogger(store AuditStore, hooks Hooks) *Logger

func (l *Logger) Log(ctx context.Context, event *AuditEvent) error
func (l *Logger) Query(ctx context.Context, filter Filter) ([]AuditEvent, error)
func (l *Logger) Store() AuditStore
func (l *Logger) SubscribeToDispatcher(d events.Dispatcher)

type Hooks struct {
    BeforeSave  func(ctx context.Context, event *AuditEvent) error
    AfterSave   func(ctx context.Context, event *AuditEvent)
    EnrichEvent func(ctx context.Context, event *AuditEvent) error
    AlertOnRisk func(ctx context.Context, event *AuditEvent)
    IDGenerator func() string
}
```

`SubscribeToDispatcher` wires the logger to an `events.Dispatcher` so events
published anywhere in Kayan become audit records automatically. That is the
recommended setup: an audit trail assembled from explicit `Log` calls has gaps
wherever someone forgot one.

`EnrichEvent` is where a geo-IP lookup belongs. Note it runs on the write path,
so an enricher that calls a remote service adds that latency to every event —
and if `Log` is called inline from a request, to every request.

`AlertOnRisk` fires for high and critical events.

Event type constants cover authentication, identity lifecycle, RBAC, consent,
data access, admin actions, and security events. Most alias the corresponding
`events.Topic`, so an audit filter and an event subscription use the same string:

```go
const (
    EventLoginSuccess    = string(events.TopicLoginSuccess)
    EventLoginFailure    = string(events.TopicLoginFailure)
    EventLoginBlocked    = string(events.TopicLoginBlocked)
    EventLogout          = string(events.TopicLogout)
    EventSessionCreated  = string(events.TopicSessionCreated)
    EventSessionRevoked  = string(events.TopicSessionRevoked)
    EventSessionExpired  = string(events.TopicSessionExpired)
    EventPasswordChanged = string(events.TopicPasswordChanged)
    EventPasswordReset   = string(events.TopicPasswordReset)
    EventMFAEnabled      = "auth.mfa.enabled"
    EventMFADisabled     = "auth.mfa.disabled"
    EventMFAChallenge    = string(events.TopicLoginMFARequired)

    EventUserCreated   = string(events.TopicIdentityCreated)
    EventUserUpdated   = string(events.TopicIdentityUpdated)
    EventUserDeleted   = string(events.TopicIdentityDeleted)
    EventUserSuspended = string(events.TopicIdentitySuspended)
    EventUserActivated = string(events.TopicIdentityActivated)

    EventRoleCreated       = string(events.TopicRoleCreated)
    EventRoleUpdated       = string(events.TopicRoleUpdated)
    EventRoleDeleted       = string(events.TopicRoleDeleted)
    EventRoleAssigned      = string(events.TopicRoleAssigned)
    EventRoleRevoked       = string(events.TopicRoleRevoked)
    EventPermissionGranted = string(events.TopicPermissionGranted)
    EventPermissionRevoked = string(events.TopicPermissionRevoked)

    EventConsentGranted = "consent.granted"
    EventConsentRevoked = "consent.revoked"
    EventConsentExpired = "consent.expired"

    EventDataAccessed = "data.accessed"
    EventDataExported = "data.exported"
    EventDataDeleted  = "data.deleted"

    EventAdminAction     = "admin.action"
    EventConfigChanged   = "admin.config.changed"
    EventTenantCreated   = string(events.TopicTenantCreated)
    EventTenantUpdated   = string(events.TopicTenantUpdated)
    EventTenantSuspended = "admin.tenant.suspended"

    EventRateLimited     = string(events.TopicSecurityRateLimited)
    EventSuspiciousLogin = string(events.TopicSecuritySuspiciousLogin)
    EventTokenRevoked    = string(events.TopicSecurityTokenRevoked)
)
```

### `core/events`

```go
import "github.com/getkayan/kayan/core/events"
```

The publish-subscribe seam. Managers throughout Kayan dispatch events; audit
logging, webhooks, analytics, and notifications subscribe. This is what lets
"send a welcome email on registration" exist without the registration manager
knowing anything about email.

```go
type Dispatcher interface {
    Dispatch(ctx context.Context, event Event) error
    Subscribe(topic Topic, handler Handler)
}

type Handler func(ctx context.Context, event Event) error

type Topic string
```

Subscribe to `"*"` for every topic.

```go
type Event struct {
    ID        string        `json:"id"`
    Topic     Topic         `json:"topic"`
    Code      int           `json:"code"`
    ActorID   any           `json:"actor_id"`
    SubjectID any           `json:"subject_id"`
    Status    string        `json:"status"`
    Metadata  identity.JSON `json:"metadata"`
    CreatedAt time.Time     `json:"created_at"`
    TenantID  string        `json:"tenant_id,omitempty"`
}

func NewEvent(topic Topic, code int) Event
```

```go
type DefaultDispatcher struct { /* unexported fields */ }
type DispatcherOption func(*DefaultDispatcher)

func NewDispatcher(opts ...DispatcherOption) *DefaultDispatcher

func WithAsync() DispatcherOption
func WithErrorHandler(h func(error)) DispatcherOption

func (d *DefaultDispatcher) Dispatch(ctx context.Context, event Event) error
func (d *DefaultDispatcher) Subscribe(topic Topic, handler Handler)
```

Thread-safe and in-memory. **Synchronous by default**, which means a slow handler
slows the operation that published the event — a registration waiting on a
welcome email.

`WithAsync` runs handlers in separate goroutines and returns immediately. That
moves the latency off the request path and moves the failures out of sight, which
is why `WithErrorHandler` is not optional in practice: without it, an async
handler that fails does so silently, and the email nobody received leaves no
trace.

Async dispatch also has no delivery guarantee across a restart. Events in flight
when the process exits are gone. For anything that must not be lost, have the
handler write to a durable queue and do the work from there.

```go
const (
    CodeOK            = 200
    CodeCreated       = 201
    CodeAccepted      = 202 // e.g. MFA challenge initiated
    CodeBadRequest    = 400
    CodeUnauthorized  = 401
    CodeForbidden     = 403
    CodeNotFound      = 404
    CodeConflict      = 409
    CodeRateLimited   = 429
    CodeInternalError = 500
)
```

Machine-readable status codes on the event, deliberately mirroring HTTP so a
subscriber can branch without parsing `Status`.

Topics cover authentication, identity lifecycle, RBAC, security, and tenants:

```go
const (
    TopicLoginInitiated   Topic = "auth.login.initiate"
    TopicLoginSuccess     Topic = "auth.login.success"
    TopicLoginFailure     Topic = "auth.login.failure"
    TopicLoginBlocked     Topic = "auth.login.blocked"
    TopicLoginMFARequired Topic = "auth.login.mfa_challenge"
    TopicLogout           Topic = "auth.logout"
    TopicSessionCreated   Topic = "auth.session.created"
    TopicSessionRevoked   Topic = "auth.session.revoked"
    TopicSessionExpired   Topic = "auth.session.expired"
    TopicPasswordChanged  Topic = "auth.password.changed"
    TopicPasswordReset    Topic = "auth.password.reset"

    TopicIdentityCreated   Topic = "identity.created"
    TopicIdentityUpdated   Topic = "identity.updated"
    TopicIdentityDeleted   Topic = "identity.deleted"
    TopicIdentityFailure   Topic = "identity.registration.failure"
    TopicIdentityActivated Topic = "identity.activated"
    TopicIdentitySuspended Topic = "identity.suspended"

    TopicRoleCreated       Topic = "rbac.role.created"
    TopicRoleUpdated       Topic = "rbac.role.updated"
    TopicRoleDeleted       Topic = "rbac.role.deleted"
    TopicRoleAssigned      Topic = "rbac.role.assigned"
    TopicRoleRevoked       Topic = "rbac.role.revoked"
    TopicPermissionGranted Topic = "rbac.permission.granted"
    TopicPermissionRevoked Topic = "rbac.permission.revoked"

    TopicSecurityRateLimited     Topic = "security.rate_limited"
    TopicSecuritySuspiciousLogin Topic = "security.suspicious_login"
    TopicSecurityTokenRevoked    Topic = "security.token.revoked"

    TopicTenantCreated Topic = "admin.tenant.created"
    TopicTenantUpdated Topic = "admin.tenant.updated"
)
```

### `core/consent`

```go
import "github.com/getkayan/kayan/core/consent"
```

GDPR and CCPA consent tracking: what a user agreed to, when, under which policy
version, and from where.

```go
type Purpose string

const (
    PurposeMarketing       Purpose = "marketing"
    PurposeAnalytics       Purpose = "analytics"
    PurposeThirdParty      Purpose = "third_party_sharing"
    PurposePersonalization Purpose = "personalization"
    PurposeEssential       Purpose = "essential"       // Cannot be revoked
    PurposeCommunications  Purpose = "communications"
    PurposeDataProcessing  Purpose = "data_processing"
)
```

`Purpose` is a string type, so application-specific purposes are just more
values.

```go
type Consent struct {
    ID         string    `json:"id"`
    IdentityID string    `json:"identity_id"`
    TenantID   string    `json:"tenant_id,omitempty"`
    Purpose    Purpose   `json:"purpose"`
    Granted    bool      `json:"granted"`
    GrantedAt  time.Time `json:"granted_at,omitempty"`
    RevokedAt  time.Time `json:"revoked_at,omitempty"`
    ExpiresAt  time.Time `json:"expires_at,omitempty"`
    Version    string    `json:"version"`
    Source     string    `json:"source"`
    IPAddress  string    `json:"ip_address"`
    UserAgent  string    `json:"user_agent"`
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`
    Metadata   json.RawMessage `json:"metadata,omitempty"`
}
```

`Version`, `Source`, `IPAddress`, and `UserAgent` exist because consent must be
*demonstrable*, not merely recorded. GDPR Article 7(1) puts the burden of proof
on the controller, and "the flag was true" does not discharge it. "Granted from
this address on this date at registration, under policy v1.2.0" does.

`Version` is also what drives re-consent: when the policy changes, consent
recorded under the old version is evidence of agreement to a document that no
longer applies.

```go
type ConsentRequest struct {
    IdentityID string          `json:"identity_id"`
    Purpose    Purpose         `json:"purpose"`
    Granted    bool            `json:"granted"`
    Source     string          `json:"source"`
    IPAddress  string          `json:"ip_address"`
    UserAgent  string          `json:"user_agent"`
    ExpiresIn  time.Duration   `json:"expires_in,omitempty"`
    Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type GDPRExport struct {
    IdentityID string     `json:"identity_id"`
    Consents   []*Consent `json:"consents"`
    ExportedAt time.Time  `json:"exported_at"`
    Format     string     `json:"format"`
}
```

```go
type Manager struct {
    EssentialPurposes []Purpose
    // unexported fields
}
type ManagerOption func(*Manager)

func NewManager(store Store, version string, opts ...ManagerOption) *Manager

func WithEssentialPurposes(purposes ...Purpose) ManagerOption
func WithHooks(hooks Hooks) ManagerOption

func (m *Manager) Grant(ctx context.Context, req *ConsentRequest) (*Consent, error)
func (m *Manager) Revoke(ctx context.Context, identityID string, purpose Purpose) error
func (m *Manager) Check(ctx context.Context, identityID string, purpose Purpose) (bool, error)
func (m *Manager) GetAll(ctx context.Context, identityID string) ([]*Consent, error)
func (m *Manager) GetHistory(ctx context.Context, identityID string, purpose Purpose) ([]*Consent, error)
func (m *Manager) ExportConsents(ctx context.Context, identityID string) (*GDPRExport, error)
func (m *Manager) DeleteAll(ctx context.Context, identityID string) error
func (m *Manager) ProcessExpired(ctx context.Context) error
func (m *Manager) UpdateVersion(version string)
```

`WithEssentialPurposes` names purposes that cannot be revoked — `Revoke` returns
`ErrEssentialConsent` for them. Use it narrowly. A purpose marked essential is one
the user cannot say no to, and marking analytics essential to avoid handling the
"no" is the kind of thing a regulator reads as a dark pattern.

`Check` returns whether consent is *currently* granted, accounting for revocation
and expiry.

`DeleteAll` is for GDPR erasure. Note the tension: erasing the consent records
also erases the evidence that consent was given, which is why `ExportConsents`
exists and why an erasure workflow usually exports before deleting.

`ProcessExpired` is a background sweep firing the `OnExpired` hook.

```go
type Store interface {
    Save(ctx context.Context, consent *Consent) error
    Get(ctx context.Context, identityID string, purpose Purpose) (*Consent, error)
    GetAll(ctx context.Context, identityID string) ([]*Consent, error)
    GetHistory(ctx context.Context, identityID string, purpose Purpose) ([]*Consent, error)
    Delete(ctx context.Context, identityID string) error
    FindExpired(ctx context.Context, before time.Time) ([]*Consent, error)
}
```

`GetHistory` returns every state a purpose has been through, which is what makes
the trail auditable. An implementation that overwrites on `Save` rather than
appending has a current value and no history, and cannot answer "was this user
opted in last March?"

```go
type Hooks struct {
    BeforeGrant     func(ctx context.Context, req *ConsentRequest) error
    AfterGrant      func(ctx context.Context, consent *Consent)
    BeforeRevoke    func(ctx context.Context, consent *Consent) error
    AfterRevoke     func(ctx context.Context, consent *Consent)
    OnExpired       func(ctx context.Context, consent *Consent)
    ValidatePurpose func(ctx context.Context, purpose Purpose) error
    IDGenerator     func() string
}
```

`AfterRevoke` is where downstream propagation belongs — removing the user from a
mailing list, stopping an analytics pipeline. Revoking consent in your database
while a third party keeps processing is the compliance failure the record was
meant to prevent.

HTTP helpers, the one transport-aware part of the package:

```go
type MiddlewareConfig struct {
    Manager           *Manager
    IdentityExtractor func(ctx context.Context) (string, error)
    Purpose           Purpose
    OnMissing         func(ctx context.Context, identityID string, purpose Purpose) error
    Skip              func(ctx context.Context, r *http.Request) bool
}

type PreloadConfig struct {
    Manager           *Manager
    IdentityExtractor func(ctx context.Context) (string, error)
    Purposes          []Purpose   // nil = all
}

func RequireConsent(cfg MiddlewareConfig) func(http.Handler) http.Handler
func PreloadConsents(cfg PreloadConfig) func(http.Handler) http.Handler

func WithConsents(ctx context.Context, consents map[Purpose]bool) context.Context
func ConsentsFromContext(ctx context.Context) map[Purpose]bool
func HasConsent(ctx context.Context, purpose Purpose) bool

type ConsentHandlerFunc func(ctx context.Context, identityID string) (any, error)

func RequireConsentFunc(manager *Manager, purpose Purpose, fn ConsentHandlerFunc) ConsentHandlerFunc
```

`PreloadConsents` loads consent into the context once so downstream `HasConsent`
calls are free. `RequireConsentFunc` is the non-HTTP equivalent, wrapping a
function with a consent check.

```go
var (
    ErrConsentNotFound  = &ConsentError{Code: "consent_not_found", Message: "consent record not found"}
    ErrEssentialConsent = &ConsentError{Code: "essential_consent", Message: "essential consent cannot be revoked"}
    ErrConsentExpired   = &ConsentError{Code: "consent_expired", Message: "consent has expired"}
    ErrInvalidPurpose   = &ConsentError{Code: "invalid_purpose", Message: "invalid consent purpose"}
)

type ConsentError struct {
    Code    string
    Message string
}

func (e *ConsentError) Error() string
```

### `core/compliance`

```go
import "github.com/getkayan/kayan/core/compliance"
```

Retention, field-level encryption, and security headers.

```go
type RetentionPolicy struct {
    TenantID           string
    AuditLogDays       int
    SessionHistoryDays int
    ConsentRecordDays  int
    FailedLoginDays    int
    DeletedUserDays    int
}

func DefaultRetentionPolicy() *RetentionPolicy
```

Retention has two opposing failure modes and the policy sits between them. Too
short and you cannot investigate an incident or produce evidence an auditor
wants — SOC 2 generally expects a year of audit logs. Too long and you are
holding personal data past the purpose that justified collecting it, which is a
GDPR problem and a larger breach when one happens.

```go
type RetentionStore interface {
    PurgeAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
    PurgeSessions(ctx context.Context, olderThan time.Time) (int64, error)
    PurgeConsents(ctx context.Context, olderThan time.Time) (int64, error)
    PurgeFailedLogins(ctx context.Context, olderThan time.Time) (int64, error)
    PurgeDeletedUsers(ctx context.Context, deletedBefore time.Time) (int64, error)
}

type RetentionManager struct { /* unexported fields */ }

func NewRetentionManager(store RetentionStore, defaultPolicy *RetentionPolicy) *RetentionManager

func (m *RetentionManager) RunCleanup(ctx context.Context) (*CleanupReport, error)
func (m *RetentionManager) SetPolicy(tenantID string, policy *RetentionPolicy)
func (m *RetentionManager) GetPolicy(tenantID string) *RetentionPolicy
func (m *RetentionManager) SetHooks(hooks RetentionHooks)

type CleanupReport struct {
    StartTime           time.Time `json:"start_time"`
    EndTime             time.Time `json:"end_time"`
    AuditLogsDeleted    int64     `json:"audit_logs_deleted"`
    SessionsDeleted     int64     `json:"sessions_deleted"`
    ConsentsDeleted     int64     `json:"consents_deleted"`
    FailedLoginsDeleted int64     `json:"failed_logins_deleted"`
    DeletedUsersRemoved int64     `json:"deleted_users_removed"`
    Errors              []string  `json:"errors,omitempty"`
}

type RetentionHooks struct {
    BeforePurge func(ctx context.Context, dataType string, count int64)
    AfterPurge  func(ctx context.Context, dataType string, count int64, err error)
    OnError     func(ctx context.Context, dataType string, err error)
}
```

`RunCleanup` is a job you schedule; nothing here runs it for you. `CleanupReport`
carries per-type counts and a non-fatal `Errors` slice, so one failing purge does
not abandon the others — and the report is itself evidence that the retention
policy is being applied, which is what an auditor asks for.

`SetPolicy` overrides per tenant, for a customer with a contractual retention
requirement.

```go
type EncryptionProvider interface {
    Encrypt(plaintext []byte) ([]byte, error)
    Decrypt(ciphertext []byte) ([]byte, error)
    RotateKey(ctx context.Context) error
}

type AESEncryption struct { /* unexported fields */ }

func NewAESEncryption(key []byte) (*AESEncryption, error)
func NewAESEncryptionFromBase64(keyBase64 string) (*AESEncryption, error)
func GenerateAESKey() ([]byte, error)

func (e *AESEncryption) Encrypt(plaintext []byte) ([]byte, error)
func (e *AESEncryption) Decrypt(ciphertext []byte) ([]byte, error)
func (e *AESEncryption) RotateKey(ctx context.Context) error
```

AES-256-GCM for field-level encryption of data that is sensitive beyond what
disk encryption covers — a national ID number, a bank account. GCM is
authenticated, so tampering with a ciphertext is detected on decryption rather
than silently yielding different plaintext.

The key must not live in the same store as the ciphertext. Encrypting a column
with a key held in a config file next to the database credentials protects
against a stolen backup tape and nothing else.

`GenerateAESKey` produces a random 32-byte key.

```go
type SecurityHeadersConfig struct {
    ContentSecurityPolicy   string
    StrictTransportSecurity string
    XContentTypeOptions     string
    XFrameOptions           string
    XXSSProtection          string
    ReferrerPolicy          string
    PermissionsPolicy       string
    CustomHeaders           map[string]string
}

func DefaultSecurityHeadersConfig() *SecurityHeadersConfig
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) func(next http.Handler) http.Handler
```

Passing nil uses the defaults. `ReferrerPolicy` is the one to check against your
own flows: a permissive referrer policy on a page whose URL contains a magic-link
or reset token leaks that token to every third-party resource the page loads.

### `core/health`

```go
import "github.com/getkayan/kayan/core/health"
```

Kubernetes-shaped health checking.

```go
type Status string

const (
    StatusHealthy   Status = "healthy"
    StatusDegraded  Status = "degraded"
    StatusUnhealthy Status = "unhealthy"
)

type Check struct {
    Name      string        `json:"name"`
    Status    Status        `json:"status"`
    Message   string        `json:"message,omitempty"`
    Latency   time.Duration `json:"-"`
    LatencyMs int64         `json:"latency_ms"`
    Timestamp time.Time     `json:"timestamp"`
}

type Report struct {
    Status    Status    `json:"status"`
    Version   string    `json:"version"`
    Timestamp time.Time `json:"timestamp"`
    Checks    []Check   `json:"checks"`
}

type Checker interface {
    Name() string
    Check(ctx context.Context) *Check
}

type CheckFunc struct {
    CheckName string
    Fn        func(ctx context.Context) *Check
}

func (c CheckFunc) Name() string
func (c CheckFunc) Check(ctx context.Context) *Check
```

```go
type Manager struct { /* unexported fields */ }
type ManagerOption func(*Manager)

func NewManager(version string, opts ...ManagerOption) *Manager

func WithTimeout(d time.Duration) ManagerOption

func (m *Manager) Register(checker Checker)
func (m *Manager) RegisterFunc(name string, fn func(ctx context.Context) *Check)
func (m *Manager) Check(ctx context.Context) *Report
func (m *Manager) IsHealthy(ctx context.Context) bool
func (m *Manager) IsReady(ctx context.Context) bool
func (m *Manager) LiveHandler() http.HandlerFunc
func (m *Manager) ReadyHandler() http.HandlerFunc
func (m *Manager) FullHandler() http.HandlerFunc
```

Liveness and readiness are different questions and wiring them to the same
handler causes outages. Liveness asks "is this process wedged?" — a failing
liveness probe gets the container killed. Readiness asks "should traffic come
here right now?" — a failing readiness probe removes it from the load balancer.
A database outage should fail readiness, not liveness: restarting every replica
does not bring the database back, and a restart loop across the fleet turns a
recoverable dependency failure into a total one.

`WithTimeout` bounds each check. Checks run concurrently.

```go
type DatabaseChecker struct { /* unexported fields */ }
func NewDatabaseChecker(name string, pingFn func(ctx context.Context) error) *DatabaseChecker
func (c *DatabaseChecker) Name() string
func (c *DatabaseChecker) Check(ctx context.Context) *Check

type RedisChecker struct { /* unexported fields */ }
func NewRedisChecker(name string, pingFn func(ctx context.Context) error) *RedisChecker
func (c *RedisChecker) Name() string
func (c *RedisChecker) Check(ctx context.Context) *Check

type MemoryChecker struct { /* unexported fields */ }
func NewMemoryChecker(threshold float64) *MemoryChecker
func (c *MemoryChecker) Name() string
func (c *MemoryChecker) Check(ctx context.Context) *Check
```

The database and Redis checkers take a ping function rather than a client, so
`core` does not import a driver.

The full report names your dependencies and their latencies. It is an internal
diagnostic — serving it unauthenticated tells an attacker your infrastructure
topology.

### `core/telemetry`

```go
import "github.com/getkayan/kayan/core/telemetry"
```

OpenTelemetry tracing and metrics.

```go
type Config struct {
    ServiceName    string
    ServiceVersion string
    Environment    string
    OTLPEndpoint   string
    InsecureOTLP   bool
    SamplingRate   float64
    Enabled        bool
}

func DefaultConfig() Config

type Provider struct { /* unexported fields */ }

func NewProvider(cfg Config) (*Provider, error)

func (p *Provider) Tracer() trace.Tracer
func (p *Provider) Meter() metric.Meter
func (p *Provider) Shutdown(ctx context.Context) error
```

`InsecureOTLP` allows plaintext OTLP transport and is for local development only.
Traces carry identity IDs, session IDs, and client IPs; shipping them
unencrypted puts that on the wire for anyone on the path.

`SamplingRate` between 0.0 and 1.0. Full sampling on a busy authentication
service is expensive at the collector, but be aware that sampling loses the
individual failed login you wanted to investigate — sample traces, and rely on
metrics and the audit trail for completeness.

**Call `Shutdown` on exit** or buffered spans are lost.

```go
func (p *Provider) RecordLogin(ctx context.Context, strategy string, success bool, tenant string)
func (p *Provider) RecordRegistration(ctx context.Context, strategy string, success bool, tenant string)
func (p *Provider) RecordMFA(ctx context.Context, mfaType string, success bool)
func (p *Provider) RecordRateLimit(ctx context.Context, action string, key string)
func (p *Provider) RecordLockout(ctx context.Context, action string)
func (p *Provider) RecordAuthDuration(ctx context.Context, strategy string, duration time.Duration)
func (p *Provider) SessionCreated(ctx context.Context, tenant string)
func (p *Provider) SessionDestroyed(ctx context.Context, tenant string)
```

Pre-defined metrics: `kayan.login.total`, `kayan.registration.total`,
`kayan.mfa.total`, `kayan.rate_limit.total`, `kayan.lockout.total`,
`kayan.auth.duration`, `kayan.sessions.active`.

Note that `RecordRateLimit` takes a `key`. If your key is an email address or an
IP, it becomes a metric label — high-cardinality, which will overwhelm a
Prometheus backend, and personal data in a system that was not designed to hold
it. Pass a bucketed or hashed value.

```go
func (p *Provider) StartSpan(ctx context.Context, name string, opts SpanOptions) (context.Context, trace.Span)
func (p *Provider) SpanLogin(ctx context.Context, identifier, strategy string) (context.Context, trace.Span)
func (p *Provider) SpanRegistration(ctx context.Context, strategy string) (context.Context, trace.Span)
func (p *Provider) SpanMFA(ctx context.Context, mfaType, identityID string) (context.Context, trace.Span)
func (p *Provider) SpanOIDC(ctx context.Context, provider string) (context.Context, trace.Span)
func (p *Provider) SpanSAML(ctx context.Context, idpID string) (context.Context, trace.Span)
func (p *Provider) SpanWebAuthn(ctx context.Context, operation string) (context.Context, trace.Span)
func (p *Provider) SpanSessionCreate(ctx context.Context, identityID string) (context.Context, trace.Span)
func (p *Provider) SpanSessionValidate(ctx context.Context, sessionID string) (context.Context, trace.Span)
func (p *Provider) SpanSessionRefresh(ctx context.Context, sessionID string) (context.Context, trace.Span)
func (p *Provider) SpanPolicyCheck(ctx context.Context, action, resource string) (context.Context, trace.Span)
func (p *Provider) SpanRateLimit(ctx context.Context, key string) (context.Context, trace.Span)

type SpanOptions struct {
    TenantID   string
    IdentityID string
    Strategy   string
    SessionID  string
    IPAddress  string
    UserAgent  string
}

func AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue)
func SetSpanError(span trace.Span, err error)
func SetSpanSuccess(span trace.Span)
func EndSpan(span trace.Span, err error)

const (
    AttrIdentityID = "kayan.identity.id"
    AttrTenantID   = "kayan.tenant.id"
    AttrStrategy   = "kayan.auth.strategy"
    AttrSessionID  = "kayan.session.id"
    AttrIPAddress  = "kayan.client.ip"
    AttrUserAgent  = "kayan.client.user_agent"
)
```

`EndSpan` ends a span and records the error if there is one — the common
`defer` pattern in a single call.

Never put a password, a token, or a raw API key into a span attribute. A trace
backend is generally less protected than your database and retains data for a
long time.

### `core/logger`

```go
import "github.com/getkayan/kayan/core/logger"
```

```go
var Log *zap.Logger

func InitLogger(level string)
```

A thin wrapper over zap with a package-level logger. Levels are `debug`, `info`,
`warn`, `error`, configured through `InitLogger` or the `LOG_LEVEL` environment
variable.

```go
logger.InitLogger("info")

logger.Log.Info("user logged in",
    zap.String("user_id", userID),
    zap.String("ip", clientIP),
)
```

`Log` is nil until `InitLogger` runs, so call it early in `main`.

Being a package-level variable, it is shared process-wide and cannot carry
per-request context. For request-scoped fields, keep your own logger in the
context. And the usual rule applies with more force in an IAM system: passwords,
tokens, secrets, and API keys do not belong in log fields, and neither does a
struct that contains one — `zap.Any` on a credential-bearing struct will happily
serialize it.

### `core/config`

```go
import "github.com/getkayan/kayan/core/config"
```

```go
type Config struct {
    DBType          string                  `mapstructure:"DB_TYPE"` // sqlite, postgres, mysql
    DSN             string                  `mapstructure:"DSN"`
    SkipAutoMigrate bool                    `mapstructure:"SKIP_AUTO_MIGRATE"`
    LogLevel        string                  `mapstructure:"LOG_LEVEL"`
    OIDCProviders   map[string]OIDCProvider `mapstructure:"OIDC_PROVIDERS"`
}

type OIDCProvider struct {
    Issuer       string `mapstructure:"issuer"`
    ClientID     string `mapstructure:"client_id"`
    ClientSecret string `mapstructure:"client_secret"`
    RedirectURL  string `mapstructure:"redirect_url"`
}

func LoadConfig() (*Config, error)
```

Environment-based configuration loaded through Viper, with development defaults:
`DB_TYPE` defaults to `sqlite`, `DSN` to `kayan.db`, `LOG_LEVEL` to `info`.

OIDC providers are configured by prefix:

```
OIDC_PROVIDERS_GOOGLE_ISSUER=https://accounts.google.com
OIDC_PROVIDERS_GOOGLE_CLIENT_ID=your-client-id
OIDC_PROVIDERS_GOOGLE_CLIENT_SECRET=your-secret
```

This struct holds two secrets — the DSN, which usually embeds a database
password, and every provider's `ClientSecret`. Logging a `*Config`, dumping it
into an error message, or exposing it from a debug endpoint discloses both.

`SkipAutoMigrate` should be true in production. Automatic migration on startup
means a deploy silently alters your schema, and a rolled-back binary meets a
schema it does not expect.

### `core/admin`

```go
import "github.com/getkayan/kayan/core/admin"
```

A framework-agnostic administrative API: user, tenant, role, session, and audit
operations as plain Go functions, with a caller and a permission on every call.

```go
type Manager struct { /* unexported fields */ }
type ManagerOption func(*Manager)

func NewManager(opts ...ManagerOption) *Manager

func WithUserStore(s UserStore) ManagerOption
func WithTenantStore(s TenantStore) ManagerOption
func WithRoleStore(s RoleStore) ManagerOption
func WithSessionStore(s SessionStore) ManagerOption
func WithAuditStore(s AuditStore) ManagerOption
func WithPasswordHasher(h domain.Hasher) ManagerOption
func WithIDGenerator(g domain.IDGenerator) ManagerOption
```

Every store is optional; a manager without one returns `ErrNotConfigured` for the
operations that need it. That is deliberate — an admin surface that only manages
users should not have to supply a tenant store.

```go
func (m *Manager) ListUsers(ctx context.Context, caller *Caller, opts ListOptions) (*UserListResult, error)
func (m *Manager) GetUser(ctx context.Context, caller *Caller, id any) (*User, error)
func (m *Manager) CreateUser(ctx context.Context, caller *Caller, input CreateUserInput) (*User, error)
func (m *Manager) UpdateUser(ctx context.Context, caller *Caller, id any, input UpdateUserInput) (*User, error)
func (m *Manager) DeleteUser(ctx context.Context, caller *Caller, id any) error
func (m *Manager) LockUser(ctx context.Context, caller *Caller, id any, reason string) error
func (m *Manager) UnlockUser(ctx context.Context, caller *Caller, id any) error

func (m *Manager) ListTenants(ctx context.Context, caller *Caller, opts ListOptions) (*TenantListResult, error)
func (m *Manager) GetTenant(ctx context.Context, caller *Caller, id string) (*Tenant, error)
func (m *Manager) CreateTenant(ctx context.Context, caller *Caller, input CreateTenantInput) (*Tenant, error)
func (m *Manager) DeleteTenant(ctx context.Context, caller *Caller, id string) error

func (m *Manager) ListRoles(ctx context.Context, caller *Caller, opts ListOptions) (*RoleListResult, error)
func (m *Manager) GetRole(ctx context.Context, caller *Caller, id string) (*Role, error)
func (m *Manager) CreateRole(ctx context.Context, caller *Caller, input CreateRoleInput) (*Role, error)
func (m *Manager) DeleteRole(ctx context.Context, caller *Caller, id string) error
func (m *Manager) AssignRoleToUser(ctx context.Context, caller *Caller, userID any, roleID string) error
func (m *Manager) GetUserRoles(ctx context.Context, caller *Caller, userID any) ([]Role, error)

func (m *Manager) ListUserSessions(ctx context.Context, caller *Caller, userID any) ([]Session, error)
func (m *Manager) RevokeUserSessions(ctx context.Context, caller *Caller, userID any) error

func (m *Manager) QueryAudit(ctx context.Context, caller *Caller, query AuditQuery) (*AuditEventListResult, error)
```

**Every method takes a `*Caller`** and checks its permissions before acting. That
is the design decision worth noticing: authorization is a parameter of the
operation, not something a middleware layer is trusted to have done. A route
mounted without the middleware still cannot delete a user.

```go
type Caller struct {
    ID           string   `json:"id"`
    Roles        []string `json:"roles"`
    Permissions  []string `json:"permissions"`
    TenantID     string   `json:"tenant_id,omitempty"`
    IsSuperAdmin bool     `json:"is_super_admin"`
}
```

The `Caller` must be constructed from a verified session. Building one from
request-supplied fields means anyone can claim `IsSuperAdmin: true`.

Permission constants and defaults:

```go
const (
    PermUsersRead      = "users:read"
    PermUsersWrite     = "users:write"
    PermUsersDelete    = "users:delete"
    PermTenantsRead    = "tenants:read"
    PermTenantsWrite   = "tenants:write"
    PermTenantsDelete  = "tenants:delete"
    PermRolesRead      = "roles:read"
    PermRolesWrite     = "roles:write"
    PermRolesDelete    = "roles:delete"
    PermSessionsRead   = "sessions:read"
    PermSessionsRevoke = "sessions:revoke"
    PermAuditRead      = "audit:read"
    PermAuditExport    = "audit:export"
)

var DefaultRolePermissions = map[string][]string{
    "admin":    { /* every permission above */ },
    "operator": {PermUsersRead, PermTenantsRead, PermSessionsRead, PermSessionsRevoke, PermAuditRead},
    "viewer":   {PermUsersRead, PermTenantsRead, PermRolesRead, PermSessionsRead, PermAuditRead},
}
```

Read and write are separate permissions for every resource, so an operator can
investigate an incident without being able to change anything — the separation
that makes an audit trail meaningful.

Stores a caller implements:

```go
type UserStore interface {
    List(ctx context.Context, opts ListOptions) (*UserListResult, error)
    Get(ctx context.Context, id any) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Create(ctx context.Context, user *User) error
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id any) error
    UpdateState(ctx context.Context, id any, state UserState) error
}

type TenantStore interface {
    List(ctx context.Context, opts ListOptions) (*TenantListResult, error)
    Get(ctx context.Context, id string) (*Tenant, error)
    Create(ctx context.Context, tenant *Tenant) error
    Update(ctx context.Context, tenant *Tenant) error
    Delete(ctx context.Context, id string) error
}

type RoleStore interface {
    List(ctx context.Context, opts ListOptions) (*RoleListResult, error)
    Get(ctx context.Context, id string) (*Role, error)
    Create(ctx context.Context, role *Role) error
    Update(ctx context.Context, role *Role) error
    Delete(ctx context.Context, id string) error
    AssignToUser(ctx context.Context, userID any, roleID string) error
    RemoveFromUser(ctx context.Context, userID any, roleID string) error
    GetUserRoles(ctx context.Context, userID any) ([]Role, error)
}

type SessionStore interface {
    ListByUser(ctx context.Context, userID any) ([]Session, error)
    Revoke(ctx context.Context, id any) error
    RevokeByUser(ctx context.Context, userID any) error
}

type AuditStore interface {
    Query(ctx context.Context, query AuditQuery) (*AuditEventListResult, error)
}
```

Note this `admin.AuditStore` is a narrower, read-only interface than
`audit.AuditStore` — the admin surface queries the trail and never writes to it.
Likewise `admin.User`, `admin.Tenant`, `admin.Role`, and `admin.Session` are
admin-facing projections, not the `identity` or `tenant` types.

HTTP helpers:

```go
type AdminIdentity struct {
    ID           string   `json:"id"`
    Email        string   `json:"email"`
    Roles        []string `json:"roles"`
    Permissions  []string `json:"permissions"`
    TenantID     string   `json:"tenant_id,omitempty"`
    IsSuperAdmin bool     `json:"is_super_admin"`
}

type AdminContextKey struct{}

func GetAdminFromContext(ctx context.Context) *AdminIdentity

type Authenticator interface {
    Authenticate(r *http.Request) (*AdminIdentity, error)
}

type Authorizer interface {
    Authorize(ctx context.Context, admin *AdminIdentity, permission string) bool
}

type BearerTokenAuthenticator struct {
    ValidateToken func(token string) (*AdminIdentity, error)
}

func (a *BearerTokenAuthenticator) Authenticate(r *http.Request) (*AdminIdentity, error)

type RoleBasedAuthorizer struct {
    RolePermissions map[string][]string
}

func (a *RoleBasedAuthorizer) Authorize(ctx context.Context, admin *AdminIdentity, permission string) bool

func AuthMiddleware(auth Authenticator) func(http.Handler) http.Handler
func RequirePermission(authz Authorizer, permission string) func(http.Handler) http.Handler
func RequireAnyPermission(authz Authorizer, permissions ...string) func(http.Handler) http.Handler
func RequireSuperAdmin() func(http.Handler) http.Handler
```

`BearerTokenAuthenticator.ValidateToken` is where the verification lives, and it
must genuinely verify — signature, expiry, and algorithm pinned. A function that
decodes the token and trusts its claims accepts an admin identity the caller
wrote themselves.

Input and result types:

```go
type ListOptions struct {
    Limit    int    `json:"limit"`
    Offset   int    `json:"offset"`
    Query    string `json:"query,omitempty"`
    TenantID string `json:"tenant_id,omitempty"`
}

type CreateUserInput struct {
    Email    string         `json:"email"`
    Password string         `json:"password,omitempty"`
    Traits   map[string]any `json:"traits,omitempty"`
    TenantID string         `json:"tenant_id,omitempty"`
    Roles    []string       `json:"roles,omitempty"`
}

type UpdateUserInput struct {
    Email  *string        `json:"email,omitempty"`
    Traits map[string]any `json:"traits,omitempty"`
    State  *UserState     `json:"state,omitempty"`
}

type CreateTenantInput struct {
    Name     string         `json:"name"`
    Domain   string         `json:"domain,omitempty"`
    Settings map[string]any `json:"settings,omitempty"`
}

type UpdateTenantInput struct {
    Name     *string        `json:"name,omitempty"`
    Domain   *string        `json:"domain,omitempty"`
    Settings map[string]any `json:"settings,omitempty"`
}

type CreateRoleInput struct {
    Name        string   `json:"name"`
    Description string   `json:"description,omitempty"`
    Permissions []string `json:"permissions"`
    TenantID    string   `json:"tenant_id,omitempty"`
}

type AuditQuery struct {
    TenantID  string    `json:"tenant_id,omitempty"`
    UserID    string    `json:"user_id,omitempty"`
    Types     []string  `json:"types,omitempty"`
    StartTime time.Time `json:"start_time,omitempty"`
    EndTime   time.Time `json:"end_time,omitempty"`
    Limit     int       `json:"limit"`
    Offset    int       `json:"offset"`
}
```

The update inputs use pointer fields so "set this to empty" is distinguishable
from "leave this alone" — with plain strings, an update that meant to change only
the state would blank the email.

```go
type UserState string

const (
    UserStateActive   UserState = "active"
    UserStateInactive UserState = "inactive"
    UserStateLocked   UserState = "locked"
    UserStatePending  UserState = "pending"
)
```

Errors:

```go
var (
    ErrNoToken        = &AdminError{Code: "no_token", Message: "no authentication token provided"}
    ErrInvalidToken   = &AdminError{Code: "invalid_token", Message: "invalid authentication token"}
    ErrUnauthorized   = &AdminError{Code: "unauthorized", Message: "unauthorized"}
    ErrForbidden      = &AdminError{Code: "forbidden", Message: "insufficient permissions"}
    ErrNotFound       = &AdminError{Code: "not_found", Message: "not found"}
    ErrAlreadyExists  = &AdminError{Code: "already_exists", Message: "already exists"}
    ErrInvalidInput   = &AdminError{Code: "invalid_input", Message: "invalid input"}
    ErrNotConfigured  = &AdminError{Code: "not_configured", Message: "service not configured"}
    ErrUserNotFound   = &AdminError{Code: "user_not_found", Message: "user not found"}
    ErrTenantNotFound = &AdminError{Code: "tenant_not_found", Message: "tenant not found"}
    ErrRoleNotFound   = &AdminError{Code: "role_not_found", Message: "role not found"}
)

type AdminError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

func (e *AdminError) Error() string
```

#### Deprecated interfaces

```go
type PasswordHasher interface {
    Hash(password string) (string, error)
    Verify(hash, password string) bool
}

func WithLegacyPasswordHasher(h PasswordHasher) ManagerOption
```

**Deprecated: use `domain.Hasher` with `WithPasswordHasher`.**

This is the argument-order trap. `PasswordHasher.Verify(hash, password)` takes
its arguments in the opposite order from `domain.Hasher.Compare(password, hash)`
— same types, no compile-time distinction between them. An implementation wired
up against the wrong convention compiles cleanly, then compares the password
against itself or the hash against itself, and **silently accepts every
password**. Nothing in the type system catches it and no test that only exercises
the happy path catches it either, because the correct password also passes.
`domain.Hasher` is the one shape, and existing wiring migrates through
`WithLegacyPasswordHasher`.

```go
type IDGenerator interface {
    Generate() any
}

func WithLegacyIDGenerator(g IDGenerator) ManagerOption
```

**Deprecated: use `domain.IDGenerator` with `WithIDGenerator`.** Two interfaces
of the same name with different shapes — an interface here, a function type in
`domain` — is a trap for anyone wiring them up, and the compiler error it
produces points at the wrong thing.

`WithIDGenerator` is for **record identifiers only**. Use `domain.TokenGenerator`
for anything an attacker must not be able to predict.

---

## Related

- [`core/domain`](#coredomain) — the storage and primitive contracts every package
  here builds on
- [`core/identity`](#coreidentity) — the default identity model and the optional
  interfaces your own model can satisfy
- [`core/keys`](#corekeys) — signing keys, JWKS, and the pinned-algorithm key
  function that `core/session` relies on
- Protocol modules — OAuth 2.0, OIDC provider, SAML, and SCIM live outside
  `core` and depend on it, never the other way round. CI enforces the direction
  with `go list -deps`.
- Storage adapters — `kayan-gorm` implements `domain.Storage` in full; a narrower
  backend can implement one interface and be used by the managers that need only
  that.
