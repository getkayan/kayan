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
