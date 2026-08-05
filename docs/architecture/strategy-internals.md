# Strategy Internals

This document is for maintainers and integrators who need to know how
`core/flow` is put together: what a strategy is, how managers dispatch to them,
how decorators compose, and where hooks and events fire. It describes the code
as it is, including the places where the shape is uneven.

If you are adding an authentication method, read
[Extending Kayan](./extending-kayan.md) alongside this.

---

## What a strategy is

A strategy is the method-specific half of authentication. It knows how to turn
an identifier and a secret into an identity, or a set of traits and a secret
into a new one. It does not know about hooks, audit, events, MFA gating, or
session issuance — those belong to the manager.

That split is what keeps password, OTP, magic link, TOTP, WebAuthn, API keys,
recovery codes, and LDAP composable without any of them knowing the others
exist. Adding a method is a new file, not an edit to a switch statement.

The two core interfaces, from `core/flow/strategy.go`:

```go
type RegistrationStrategy interface {
    ID() string
    Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}

type LoginStrategy interface {
    ID() string
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}
```

A method implements one or both. `ID()` returns the stable lowercase key the
manager dispatches on — `"password"`, `"magic_link"`, `"otp"`, `"totp"`,
`"webauthn"`, `"api_key"`, `"recovery_code"`, `"ldap"`, `"kayan_oidc"`.

Both take `ctx` as the first parameter. As with storage, this is not stylistic:
the ambient tenant lives there, and a strategy that reaches storage without a
context cannot be tenant-scoped.

### Optional strategy interfaces

```go
// Multi-step methods: send a link, deliver a code, redirect to a provider.
type Initiator interface {
    Initiate(ctx context.Context, identifier string) (any, error)
}

// Attach this method to an identity that already exists.
type Attacher interface {
    Attach(ctx context.Context, ident any, identifier, secret string) error
}
```

`Initiator` is what makes magic links and OTP work: `Initiate` creates and
stores the artifact, and `Authenticate` consumes it later.
`Attacher` is what lets an existing password user add WebAuthn, or an OIDC user
gain a password.

### Optional identity interfaces

Your model implements only what it needs. The single required interface is:

```go
type FlowIdentity interface {
    GetID() any
    SetID(any)
}
```

Everything else is opt-in:

```go
type TraitSource interface {
    GetTraits() identity.JSON
    SetTraits(identity.JSON)
}

type CredentialSource interface {
    GetCredentials() []identity.Credential
    SetCredentials([]identity.Credential)
}

type MFAIdentity interface {
    MFAConfig() (enabled bool, secret string)
}

type VerificationIdentity interface {
    IsVerified() bool
    MarkVerified(time.Time)
}
```

The manager probes with a type assertion and skips the behavior when the model
does not implement the interface. That is BYOS applied to behavior: you opt in
to MFA gating by implementing `MFAIdentity`, not by inheriting from a base type
that has it whether you want it or not.

### Method-specific storage interfaces

Rather than one wide repository, each strategy declares the narrowest
persistence contract it needs, in the package that consumes it. A few examples:

```go
type TOTPRepository interface {
    FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
    FindTOTPSecret(ctx context.Context, identityID any) (string, error)
    MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error
}

type APIKeyRepository interface {
    FindIdentityByAPIKeyHash(ctx context.Context, keyHash string, factory func() any) (any, error)
}

type OTPSender interface {
    Send(ctx context.Context, recipient, code string) error
}

type LDAPDialer interface {
    DialTLS(ctx context.Context, addr string) (LDAPConn, error)
}
```

`LDAPDialer` is the seam that keeps `go-ldap` out of `core`: `core/flow`
declares the interface, and `kayan-ldap` implements it. `IdentityRepository` is
an alias for `domain.IdentityStorage`.

---

## Managers

A manager owns strategy registration, hook ordering, audit, events, and
cross-strategy policy such as MFA gating. Managers delegate; they never
implement authentication logic themselves.

Both managers use `sync.RWMutex` and follow the same concurrency discipline:
**take an RLock, copy everything needed, release, then do the work unlocked.**
Hook slices are copied with `append([]Hook(nil), ...)` rather than aliased.
This matters because hooks call arbitrary user code — holding a lock across a
hook that itself registers a strategy would deadlock, and holding one across a
network call would serialize every login in the process.

### RegistrationManager

```go
func NewRegistrationManager(repo IdentityRepository, factory func() any, opts ...RegistrationOption) *RegistrationManager
```

Options: `WithRegDispatcher`, `WithSchema`, `WithLinker`, `WithRegPreHook`,
`WithRegPostHook`, `WithAllowPasswordCapture`. The constructor type-asserts
`repo.(audit.AuditStore)` — if your storage implements audit, it is used
automatically.

`Submit(ctx, method, traits, secret)` runs this exact sequence:

1. **RLock, snapshot, RUnlock.** Strategy, copied hook slices, audit store,
   dispatcher, schema, linker, and the password-capture flag.
2. **Resolve the strategy.** Unknown method → `registration: unknown method %q`.
3. **Pre-hooks**, in registration order. Each is called as `h(ctx, nil)` — the
   identity does not exist yet, so pre-hooks always receive nil. First error
   aborts.
4. **Schema validation**, if a schema is configured.
5. **Implicit unification**, if a `Linker` is configured. Described below.
6. **`strategy.Register(ctx, traits, secret)`.** On error: audit
   `identity.registration.failure`, dispatch the same topic with
   `CodeBadRequest`, return.
7. **Audit success** as `identity.created`.
8. **Dispatch** `identity.created` with `CodeCreated`, setting `SubjectID` from
   `FlowIdentity.GetID()` when available.
9. **Post-hooks**, in order, as `h(ctx, ident)`.

Hook placement determines what your application code sees. Pre-hooks run before
anything is persisted; post-hooks run after the identity exists. A post-hook
returning an error aborts `Submit` **but the identity is already stored** — the
error does not roll it back. Post-hooks that can fail should be idempotent, or
should do their work elsewhere.

#### Implicit unification and password capture

When a `Linker` is configured, `Submit` asks it whether the traits match an
existing identity before creating a new one:

```go
type Linker interface {
    FindExisting(ctx context.Context, traits identity.JSON) (any, error)
    Link(ctx context.Context, ident any, method string, identifier, secret string) error
}
```

On a match, behavior depends on the method and the flag:

- **`method == "password"`** → `ErrIdentityAlreadyExists`. Nothing is written.
- **`method == "password"` with `WithAllowPasswordCapture`** → the existing
  identity is returned, and **no password is written**. No audit event, no
  dispatch, no post-hooks.
- **Any other method** → `linker.Link(...)`, and on success the existing
  identity is returned. If `Link` fails, execution falls through to step 6 and
  a new identity is created.

The default is the account-capture defense: someone registering with
`ada@example.com` when that address already has an account does not get to set
its password — and, just as importantly, does not get handed the account. The
submitted password is never compared against the stored credential, so
returning the existing identity would mean a registration endpoint that hands
out other people's accounts to whoever types their address.
`WithAllowPasswordCapture` restores that for callers migrating off the previous
default, and should be paired with proof of control over the address.

Note the two quiet edges. The silent-return path emits **no audit event**, so
"registration succeeded" in your handler does not always correspond to an
`identity.created` record. And the `Link`-failure fallthrough means a linker
error results in a duplicate identity rather than a reported failure. Both are
worth knowing before relying on a `Linker` in production.

`NewDefaultLinker` only auto-links when `traits["email_verified"] == true` —
linking on an unverified email address would let an attacker claim an account
by asserting its address.

### LoginManager

```go
func NewLoginManager(repo IdentityRepository, factory func() any, opts ...LoginOption) *LoginManager
```

Options: `WithLoginDispatcher`, `WithStrategyStore`, `WithLoginPreHook`,
`WithLoginPostHook`.

`Authenticate(ctx, method, identifier, secret)`:

1. **RLock, snapshot, RUnlock.**
2. **Resolve the strategy.** Unknown → `login: unknown method %q`.
3. **Pre-hooks**, `h(ctx, nil)`. First error aborts.
4. **`strategy.Authenticate(ctx, identifier, secret)`.** On error: audit
   `auth.login.failure` with `ActorID: identifier`, dispatch with
   `CodeUnauthorized`, return.
5. **MFA gating.** If the identity implements `MFAIdentity` and reports
   enabled: audit `auth.login.mfa_challenge`, dispatch with `CodeAccepted`, and
   **return `(ident, ErrMFARequired)`** — identity *and* error. Post-hooks are
   skipped.
6. **Audit** `auth.login.success`.
7. **Dispatch** `auth.login.success` with `ActorID` and `SubjectID`.
8. **Post-hooks**, `h(ctx, ident)`.

```go
var ErrMFARequired = errors.New("login: mfa required")
```

Returning the identity alongside the error is deliberate — the caller needs it
to run the second factor. It is also the trap: `if err != nil { return }` in a
handler will correctly refuse the login, but a handler that treats a non-nil
identity as success has bypassed MFA. Check the error first, always.

`InitiateLogin(ctx, method, identifier)` asserts the strategy implements
`Initiator` and calls it, auditing `auth.login.initiate`. **It runs no pre- or
post-hooks and emits no failure event.** A rate-limiting pre-hook applies to
`Authenticate` and not to `InitiateLogin` — put abuse controls for the
initiation path in the decorator layer, not in hooks.

`LinkMethod(ctx, ident, method, identifier, secret)` resolves the strategy,
asserts `Attacher`, and calls `Attach`, auditing around it.

`VerifyMFA(ctx, ident, code)` deserves an explicit warning. It asserts
`MFAIdentity`, returns `true` when MFA is not enabled, and otherwise constructs
a **zero-value `&TOTPStrategy{}`** and calls its stateless `Verify`. That means
MFA verification through this method is hardcoded to TOTP and **has no replay
protection** — the same code works repeatedly within its window. The
replay-protected path is `TOTPStrategy.Authenticate`, which calls
`MarkTOTPUsed`. Use the strategy directly for second-factor verification if
replay matters to you, which it should.

### Dynamic strategies

`LoginManager` can rebuild its strategy set from the database:

```go
type StrategyFactory func(config *domain.StrategyConfig) (LoginStrategy, error)

func (r *StrategyRegistry) RegisterFactory(typeKey string, factory StrategyFactory)
func (m *LoginManager) ReloadStrategies(ctx context.Context) error
```

`domain.StrategyConfig` carries `ID`, `Type`, `Provider`, `Enabled`, and a
`Settings map[string]any`. `ReloadStrategies` reads them, deletes disabled
entries from the map, and builds the rest by `Type` through the registry,
keying the result by `ID`.

Three behaviors to know before enabling this. A factory that fails is **logged
and skipped**, not surfaced as an error from `ReloadStrategies` — a
misconfigured provider silently disappears. A strategy absent from the store
entirely is **not** removed, only ones explicitly marked `Enabled: false`.
And configuration becomes a live security control, so it needs the same
versioning and audit as code.

---

## Decorators

Two decorators wrap a `LoginStrategy` and are themselves `LoginStrategy`
implementations. Both delegate `ID()` to the wrapped strategy, so wrapping is
transparent to `RegisterStrategy` — the manager dispatches on the same key.

```go
func NewRateLimitStrategy(next LoginStrategy, limiter RateLimiter, config RateLimitConfig) *RateLimitStrategy
func NewLockoutStrategy(next LoginStrategy, store LockoutStore, maxFailures int, lockoutDuration, failureWindow time.Duration) *LockoutStrategy
func NewLockoutStrategyWithConfig(next LoginStrategy, store LockoutStore, config LockoutConfig) *LockoutStrategy
```

They compose:

```go
strategy := flow.NewLockoutStrategy(
    flow.NewRateLimitStrategy(passwordStrategy, limiter, rateConfig),
    lockoutStore, 5, 15*time.Minute, time.Hour,
)
loginManager.RegisterStrategy(strategy)
```

Rate limiting caps request *frequency*; lockout tracks failed *attempts* over a
window and denies further tries. They answer different questions and are
usually both wanted.

### Rate limiting

```go
type RateLimiter interface {
    Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
    Reset(ctx context.Context, key string) error
}
```

`RateLimitConfig` supplies `Limit`, `Window`, a `KeyFunc` (default: the
identifier itself), an optional `DynamicLimit` that overrides both limit and
window per caller, a `SkipFunc`, and `FailOpen`.

Key composition helpers exist because the right key is rarely just the
identifier: `IPKeyFunc`, `PrefixKeyFunc`, `ContextKeyFunc`, and
`CompositeKeyFunc` for combining them. Limiting by identifier alone lets an
attacker spray one attempt across many accounts; limiting by IP alone punishes
a shared NAT.

**`FailOpen` is a security decision.** When the limiter itself errors — Redis
unreachable — `FailOpen: true` allows the request. That trades availability for
protection, and the correct answer depends on whether you would rather be down
or unprotected during an outage. The default is closed.

Three in-memory limiters ship: `NewMemoryRateLimiter` (sliding window),
`NewFixedWindowRateLimiter`, and `NewTokenBucketRateLimiter`. All are
per-process; use `kayan-redis` across replicas.

### Lockout

```go
type LockoutStore interface {
    RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)
    ClearFailures(ctx context.Context, identifier string) error
    Lock(ctx context.Context, identifier string, duration time.Duration) error
    IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
}
```

`Authenticate` checks the lock, delegates, then either clears failures on
success or records one on failure and locks when the count reaches
`MaxFailures`. Failures expire over `FailureWindow`, so lockout is
window-based rather than lifetime-cumulative — a user with four failures spread
over a year is not one attempt from being locked out.

Extensive hooks are available (`OnFailure`, `OnLocked`, `OnUnlocked`,
`OnLockoutCheck`, `CreateLockError`, `ShouldRecordFailure`,
`ShouldClearOnSuccess`) for integrating an existing abuse system.

Two sharp edges. **`Initiate` delegates without any lockout check**, so a
locked account can still trigger magic-link or OTP delivery — wrap the
initiation path separately if that matters. And **neither decorator emits any
event**: `TopicLoginBlocked` and `TopicSecurityRateLimited` exist as constants
but are never dispatched from `core/flow`. If you need alerting on lockout,
use the hooks.

`MemoryLockoutStore.ClearFailures` deletes the whole record including an active
lock, so a successful authentication during a lock would clear it — reachable
only if something calls it directly, since `Authenticate` refuses before
delegating.

---

## Hooks

There is one hook type, shared by both managers:

```go
type Hook func(ctx context.Context, ident any) error
```

There is no separate `PreHook`/`PostHook` type. The distinction is where it is
registered, and what `ident` contains: **pre-hooks always receive `nil`**,
because no identity exists yet on either path. Post-hooks receive the resolved
identity.

Registration is by option at construction or by `AddPreHook`/`AddPostHook` at
runtime. Hooks run in registration order and the first error aborts the flow.

Hooks over inheritance is a deliberate choice recorded in
[AGENTS.md](../../AGENTS.md): it keeps the API surface flat and composable, and
keeps call paths explicit. There is no subclass whose overridden method you
have to find.

Practical guidance:

- **Pre-hooks** are for admission control: is this IP allowed, is registration
  open, is this tenant provisioned. They cannot inspect the identity.
- **Post-hooks** are for consequences: provision a workspace, send a welcome
  email, warm a cache. Remember that a post-hook error does not undo the write.
- **Do not put MFA logic in a hook.** MFA gating is manager behavior driven by
  `MFAIdentity`; a hook cannot participate in the `ErrMFARequired` return.
- Hooks run inline and unlocked. A slow hook is slow login latency.

`ServiceProvider` in `kayan-saml` and `WebAuthnStrategy` use a different,
struct-of-function-fields hook shape rather than this one. Note that
`WebAuthnHooks` fields are currently **declared but never invoked** — the
struct is assigned and then not read. Do not rely on them.

---

## Events

`core/events` is the observability seam. It is separate from audit: audit is
the durable compliance record, events are the in-process pub/sub for reacting.

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

type Handler func(ctx context.Context, event Event) error

type Dispatcher interface {
    Dispatch(ctx context.Context, event Event) error
    Subscribe(topic Topic, handler Handler)
}
```

`NewEvent(topic, code)` sets `Status` to `"success"`, flipping to `"failure"`
when `code >= 400`, and stamps `CreatedAt`. It does **not** populate `ID`.

The topics `core/flow` actually dispatches:

| Topic | Constant | Code |
|---|---|---|
| `auth.login.initiate` | `TopicLoginInitiated` | 202 |
| `auth.login.failure` | `TopicLoginFailure` | 401 |
| `auth.login.mfa_challenge` | `TopicLoginMFARequired` | 202 |
| `auth.login.success` | `TopicLoginSuccess` | 200 |
| `identity.registration.failure` | `TopicIdentityFailure` | 400 |
| `identity.created` | `TopicIdentityCreated` | 201 |

More topics are defined than are emitted. `TopicLoginBlocked`,
`TopicSecurityRateLimited`, `TopicSessionCreated`, `TopicLogout`,
`TopicPasswordChanged`, and the RBAC and tenant topics exist as a shared
vocabulary for your own code to dispatch — they are not all produced by
`core/flow`. Do not assume subscribing to `auth.login.blocked` will fire.

`NewDispatcher` supports `WithAsync()` and `WithErrorHandler(func(error))`, and
handlers can subscribe to `Topic("*")` for everything.

**Sync dispatch swallows handler errors and always returns nil.** A handler
that fails does not fail the login, and nothing surfaces unless you are in
async mode with an error handler. That is the right default — an analytics sink
being down should not block authentication — but it means events are
best-effort. Anything that must not be lost belongs in `audit.AuditStore`,
which is checked and returns errors.

Audit is opt-in throughout: every call site checks `if auditStore != nil`
first, so a missing audit store degrades to no audit rather than a panic.

---

## The convenience constructor

```go
func PasswordAuth(repo IdentityRepository, factory func() any, identifierField string, opts ...QuickOption) (*RegistrationManager, *LoginManager)
```

`flow.PasswordAuth` wires a `PasswordStrategy` into both managers and registers
the **same instance** on each, so registration and login agree on hashing and
field mapping by construction.

Options: `WithHasherCost`, `WithIDGenerator`, `WithQuickDispatcher`,
`WithRegHook(pre, post)`, `WithLoginHook(pre, post)`, `WithPasswordPolicy`.
`identifierField` defaults to `"email"` when empty.

One thing to know: **its default bcrypt cost is 10**, not
`domain.DefaultBcryptCost` (12). If you want 12, pass `WithHasherCost(12)` or
build the strategy yourself. It also leaves `passwordField` unset, so it wires
the credential-table path rather than the BYOS reflection path — call
`MapFields` on a directly-constructed strategy if you store the hash on your
own model.

---

## Thread safety

Managers are safe for concurrent use. Strategy maps and hook slices are guarded
by `sync.RWMutex`, and all work happens outside the lock.

Register strategies and hooks at startup where possible. Runtime mutation is
supported, but treat a configuration change that enables or disables an
authentication method as an operational event deserving audit and
observability — it is a change to the security posture of a running system.

Not everything is safe. `MemoryWebAuthnSessionStore` has **no mutex** and is
documented as development-only. The in-memory rate limiters and lockout store
are concurrency-safe but per-process.

---

## Related

- [Extending Kayan](./extending-kayan.md) — writing a strategy end to end
- [Authentication Flows](./authentication-flows.md) — the request paths these
  pieces assemble into
- [Architecture Overview](./README.md) — module topology and the dependency rule
- [Security Model](./security-model.md) — what each check defends against
- [Strategies](../concepts/strategies.md) — task-oriented guide to the bundled
  methods
- [Storage Layer](./storage-layer.md) — the repository contracts strategies use
- [AGENTS.md](../../AGENTS.md) — strategy and manager pattern rules
