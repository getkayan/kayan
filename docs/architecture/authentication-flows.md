# Authentication Flows

This document traces each authentication path in Kayan from the first call to
the last, naming where every check happens and what an attacker gains if a
given step is skipped. It describes what the code does today, including the
places where the implementation is weaker than the design intends.

Two structural facts shape everything below.

**A flow authenticates; it does not issue a session.** `core/flow` returns an
identity. `core/session` turns that into a token. Nothing in `core/flow` writes
a session, which is why `ErrMFARequired` can return an identity that is
authenticated on the first factor and not yet entitled to a session.

**The caller owns transport and delivery.** Kayan generates a magic-link token
but does not send the email. It generates an OTP but hands the code to an
`OTPSender` you wrote. It builds the SAML redirect URL but does not redirect.
That boundary is deliberate, and it means several security properties in this
document depend on what the caller does with what Kayan returns.

---

## Password registration

`RegistrationManager.Submit` is the entry point:

```go
func (m *RegistrationManager) Submit(ctx context.Context, method string, traits identity.JSON, secret string) (any, error)
```

The steps, in the order `core/flow/registration.go` runs them.

### 1. Strategy lookup

The manager takes a read lock, copies the strategy map entry, the hook slices,
the audit store, the dispatcher, the schema, the linker, and the
`preventPasswordCapture` flag, then releases the lock. Everything after that
point operates on a snapshot.

That copy is not incidental. `RegisterStrategy` and `AddPreHook` take a write
lock and may be called at runtime — `ReloadStrategies` rebuilds the map from a
`domain.StrategyStore` — so a `Submit` that held references into the live map
would race a reconfiguration. Copying the hook slices with
`append([]Hook(nil), m.preHooks...)` rather than aliasing them is the same
concern: a hook appended mid-flight must not appear halfway through a
registration that already started.

An unknown method returns `fmt.Errorf("registration: unknown method %q", method)`
before anything else runs. Nothing is written, no hook fires.

### 2. Pre-hooks

```go
for _, h := range preHooks {
    if err := h(ctx, nil); err != nil {
        return nil, err
    }
}
```

Note the `nil`. A registration pre-hook runs **before an identity exists**, so
it receives no identity — only the context. It can read the tenant, a request
ID, or an IP address you placed in the context and refuse; it cannot inspect
the user, because there is not one yet. A hook that type-asserts its second
argument will panic or silently skip. Post-hooks receive the created identity.

The first hook error aborts the whole submission.

### 3. Schema validation

```go
if schema != nil {
    if err := schema.Validate(traits); err != nil {
        return nil, fmt.Errorf("registration: validation failed: %v", err)
    }
}
```

Only when a schema was configured through `WithSchema`. **With no schema,
traits are not validated at all** — whatever JSON the caller passes is stored.
This validates traits, not the password; the password policy is enforced inside
the strategy, one step later.

### 4. Account unification

This is the step most likely to surprise, and it runs **before** the strategy:

```go
if linker != nil {
    existing, err := linker.FindExisting(ctx, traits)
    if err == nil && existing != nil {
        if method == "password" {
            if !allowPasswordCapture {
                return nil, ErrIdentityAlreadyExists
            }
            return existing, nil
        }
        err := linker.Link(ctx, existing, method, "", secret)
        if err == nil {
            return existing, nil
        }
    }
}
```

Three distinct outcomes when the traits match an existing identity:

- **`method == "password"`** — `ErrIdentityAlreadyExists`. Nothing is written.
- **`method == "password"` with `WithAllowPasswordCapture()`** — the existing
  identity is returned **and the submitted password is discarded**. No
  credential is created, no hash is computed, and no error is raised. The
  caller receives a valid-looking identity from a registration that did not
  register anything.
- **Any other method** — `Link` attaches the method to the existing identity.
  If `Link` fails, control falls through to the strategy, which will attempt to
  create a second identity.

The password case is the one to understand, and it is why the refusal is the
default. Consider an attacker who submits a registration for
`victim@example.com` with a password of their choosing. If the flow returned the
victim's identity and the handler issued a session on the strength of
"registration succeeded", the attacker would be logged in as the victim without
ever proving control of the address. The password is never checked against the
stored credential, so this is not credential capture — it is a registration
endpoint that returns other people's accounts.

`WithAllowPasswordCapture()` restores that behaviour for callers migrating off
the previous default. It should not be enabled unless the caller separately
proves control of the address before acting on the result. Treat a successful
registration as an identity to verify rather than an identity to authenticate.

`WithPreventPasswordCapture()` is a deprecated no-op — it enabled what is now
unconditional. Remove the call.

Note also that `FindExisting` matching on an *unverified* email is the same
problem in a different place: unification decides two records are one person, and
if the evidence for that is an unverified trait, the decision is attacker-chosen.
`NewDefaultLinker` does not itself distinguish verified from unverified traits;
that check belongs in the `Linker` you supply.

### 5. Strategy dispatch

`PasswordStrategy.Register` in `core/flow/strategy_password.go` does the actual
work.

**Traits are required:**

```go
if len(traits) == 0 {
    return nil, errors.New("traits are required")
}
```

**Password policy, before hashing:**

```go
policy := s.policy
if policy == nil {
    p := DefaultPasswordPolicy
    policy = &p
}
if err := policy.Validate(password); err != nil {
    return nil, err
}
```

The policy is never absent. When none was set, `DefaultPasswordPolicy` applies:
`MinLength: 8`, `MaxLength: 128`, no complexity requirements. `Validate`
measures `len(password)` — **bytes, not runes** — so a passphrase of five
emoji passes a minimum of 8 while five ASCII characters does not. Complexity
classes are checked with `unicode.IsUpper`/`IsLower`/`IsDigit`/`IsPunct`/
`IsSymbol` in a `switch`, so each rune contributes to exactly one class.
`CustomValidator` runs last and its return value is returned directly — that is
where a breached-password list or a zxcvbn-style estimator belongs.

Skipping the policy costs you the floor: `MaxLength: 128` also matters, because
the bundled `domain.BcryptHasher` **refuses** a secret over 72 bytes rather
than truncating it. Without a maximum, a long passphrase produces a hashing
error at registration rather than a silent truncation at which two passwords
sharing a 72-byte prefix both verify.

**Hashing:**

```go
hashed, err := s.hasher.Hash(password)
```

The hasher is whatever was passed to `NewPasswordStrategy`. `PasswordAuth`
wires `domain.NewBcryptHasher(10)` by default — note that this is cost **10**,
not `domain.DefaultBcryptCost` (12); pass `WithHasherCost(12)` if you want the
`core/domain` default. See [Extending Kayan](./extending-kayan.md) for an
argon2id implementation.

**Identity creation**, in one of two shapes:

*BYOS with field mapping* (`MapFields` was called, so `passwordField != ""`).
The hash is written into the named struct field by reflection, and each
identifier field named in `identifierFields` is copied out of the traits JSON
into the matching struct field. A field that does not exist returns
`field %s not found`; an unexported field returns `field %s cannot be set`.
`reflect.Value.Set` will panic on a type mismatch — a trait that unmarshals to
`float64` assigned to an `int` field is a panic, not an error — so the trait
schema and the struct need to agree.

*Classic* (no `passwordField`). Traits are stored through `TraitSource` if the
model implements it, and an `identity.Credential` with `Type: "password"` is
appended through `CredentialSource`:

```go
cred := identity.Credential{
    IdentityID: fmt.Sprintf("%v", fi.GetID()),
    Type:       "password",
    Identifier: identifier,
    Secret:     hashed,
}
```

The identifier comes from the first entry in `identifierFields`; with no
identifier fields configured it falls back to `string(traits)` — the entire
traits JSON as the credential identifier, which will not match anything a login
looks up. Configure the identifier field.

**ID assignment** happens before either branch stores anything:

```go
if fi, ok := ident.(FlowIdentity); ok {
    if isZeroIdentityID(fi.GetID()) {
        if s.generator != nil {
            fi.SetID(s.generator())
        } else {
            fi.SetID(uuid.NewString())
        }
    }
}
```

Only a zero ID is replaced, so a caller-assigned ID survives. The fallback is
UUIDv4. This is a record identifier, not a credential — the `domain.IDGenerator`
/ `domain.TokenGenerator` split described in the
[Security Model](./security-model.md#token-entropy) exists precisely so a
sortable ID generator cannot be wired into a token path.

**Persistence** is a single `s.repo.CreateIdentity(ctx, ident)`. In the classic
shape the credential travels inside the identity through `CredentialSource`, so
identity and credential are one write. In the BYOS shape the hash is a column on
the identity row. Either way there is no window in which an identity exists
without its credential.

### 6. Audit and events

On strategy failure:

```go
auditStore.SaveEvent(ctx, &audit.AuditEvent{
    Type:    string(events.TopicIdentityFailure),
    Status:  "failure",
    Message: err.Error(),
})
```

On success, `TopicIdentityCreated` with `Status: "success"`, and a dispatched
event carrying `SubjectID` when the identity implements `FlowIdentity`.

Two honest limitations. The audit store is only present if the repository you
passed to `NewRegistrationManager` also implements `audit.AuditStore` — the
constructor type-asserts it and leaves the field nil otherwise, so a storage
adapter that does not implement `AuditStore` produces a flow that audits
nothing, silently. And `SaveEvent`'s error is discarded: an audit backend that
is down does not fail the registration. If audit is a compliance control for
you, that is a property to check rather than assume.

The failure event records `err.Error()` in `Message`. Strategy errors here are
policy and validation messages rather than secrets, but a custom strategy that
puts sensitive detail in its error text puts it in the audit log.

### 7. Post-hooks

```go
for _, h := range postHooks {
    if err := h(ctx, ident); err != nil {
        return nil, err
    }
}
```

These receive the created identity. A post-hook error propagates to the caller
**after the identity has already been written** — there is no transaction and
no rollback. A post-hook that sends a welcome email and fails on SMTP returns an
error from a registration that did in fact create the account. Design hooks to
be idempotent, or make the failure non-fatal inside the hook.

---

## Password login

```go
func (m *LoginManager) Authenticate(ctx context.Context, method, identifier, secret string) (any, error)
```

### 1. Snapshot and dispatch

Same locking discipline as registration: strategy, hooks, audit store, and
dispatcher are copied under a read lock. An unknown method errors immediately
with `login: unknown method %q`.

### 2. Pre-hooks

Again called as `h(ctx, nil)`. A login pre-hook does not know who is logging in
— the identifier is not passed to it. Device trust and risk scoring, which need
the identifier, belong either in a decorator around the strategy (where the
identifier is a parameter) or in a post-hook (where the identity is available).

### 3. Strategy

`PasswordStrategy.Authenticate` has the same two shapes as registration.

*Classic:*

```go
cred, err := s.repo.GetCredentialByIdentifier(ctx, identifier, "password")
if err != nil || cred == nil {
    return nil, errors.New("invalid identifier or password")
}
if !s.hasher.Compare(password, cred.Secret) {
    return nil, errors.New("invalid identifier or password")
}
return s.repo.GetIdentity(ctx, s.factory, cred.IdentityID)
```

The method argument `"password"` scopes the lookup. A store that ignores it and
returns any credential for the identifier would let a TOTP secret or a WebAuthn
credential blob be presented as a password hash — which is why
`kayantesting.StorageSuite` asserts that method scopes the lookup, and why
`MemoryStore` builds its key as `method + "\x00" + identifier` with the method
first, so an identifier containing the separator cannot forge a key for a
different method.

The error string is identical for "no such credential" and "wrong password", so
the endpoint does not enumerate accounts through its response body. **Timing
still does.** There is no dummy comparison on the not-found path — the code
returns before touching bcrypt, so a request for an unknown identifier returns
in microseconds while a request for a known one spends the bcrypt cost. That is
a measurable oracle. `kayan-oidc-provider`'s `ValidateClient` does perform a
dummy `Compare` against a fixed hash for exactly this reason; the password
strategy does not, and if account enumeration matters in your deployment you
should add the equalizing work in a decorator or accept the exposure knowingly.

`hasher.Compare` for bcrypt is `bcrypt.CompareHashAndPassword`, which is
constant-time with respect to hash contents. A custom `domain.Hasher` that
compares with `==` reintroduces a byte-at-a-time timing leak against the stored
hash.

*BYOS:*

```go
for _, field := range s.identifierFields {
    query := map[string]any{field: identifier}
    ident, err := s.repo.FindIdentity(ctx, s.factory, query)
    if err == nil && ident != nil {
        hash := s.getField(ident, s.passwordField)
        if s.hasher.Compare(password, fmt.Sprintf("%v", hash)) {
            return ident, nil
        }
    }
}
return nil, errors.New("invalid identifier or password")
```

Each configured identifier field is tried in turn, so a deployment can accept
either an email or a username at one endpoint. Two consequences worth naming.
The loop performs one bcrypt comparison per matching field, so response time
varies with how many fields matched — another timing signal. And
`fmt.Sprintf("%v", hash)` on a missing or nil field yields `"<nil>"`, which
`Compare` will reject; a misspelled `passwordField` therefore fails closed
rather than authenticating, but it fails closed for every user at once and looks
like "everyone's password is wrong".

### 4. Failure path

```go
if err != nil {
    auditStore.SaveEvent(ctx, &audit.AuditEvent{
        Type:    string(events.TopicLoginFailure),
        ActorID: identifier,
        Status:  "failure",
        Message: err.Error(),
    })
    dispatcher.Dispatch(ctx, events.NewEvent(events.TopicLoginFailure, events.CodeUnauthorized))
    return nil, err
}
```

The identifier is recorded as `ActorID` on failures. That is what makes a
failure log useful for detection — and it also means a login endpoint writes
attacker-controlled strings into your audit store. Bound the identifier length
at the handler.

### 5. MFA check

```go
if mfaIdent, ok := ident.(MFAIdentity); ok {
    enabled, _ := mfaIdent.MFAConfig()
    if enabled {
        // audit TopicLoginMFARequired, dispatch, then:
        return ident, ErrMFARequired
    }
}
```

`MFAIdentity` is optional:

```go
type MFAIdentity interface {
    MFAConfig() (enabled bool, secret string)
}
```

A model that does not implement it never triggers this branch. That is the
correct default for a deployment with no second factor, and it is a trap for one
that adds MFA later: if the interface is implemented on `User` but the handler
still checks only `err != nil`, MFA is enforced. If the interface is *not*
implemented, MFA is silently absent no matter what is stored in the database.

**Why `ErrMFARequired` returns the identity alongside the error.** Go's
convention is that a non-nil error means the other return values are
meaningless. This function deliberately breaks that convention, and the reason
is that the alternative is worse.

The handler needs to know *who* passed the first factor in order to run the
second. If `Authenticate` returned `(nil, ErrMFARequired)`, the handler would
have to look the user up again by identifier to find their TOTP secret — a second
unauthenticated lookup, keyed on a string the client supplied, in a code path
that has already decided the credential was correct. That lookup is where a
second-factor bypass gets built: it is trivial to write it against the
*submitted* identifier rather than the one that actually authenticated, and then
an attacker who knows any valid password can present a different identifier at
the MFA step.

Returning the identity means the handler holds the exact object the password
check produced. It can read the TOTP secret from that object, store its ID in a
partial-session record, and never re-resolve the user from client input.

The obligation this places on the caller is absolute: **`ErrMFARequired` is not
success.** The handler must branch on it explicitly.

```go
ident, err := loginManager.Authenticate(ctx, "password", email, password)
switch {
case errors.Is(err, flow.ErrMFARequired):
    // First factor passed. Issue a partial session that is not a session:
    // it carries the identity ID and grants nothing but the MFA endpoint.
    challengeID, err := challenges.Begin(ctx, ident)
    if err != nil {
        return err
    }
    return respondMFARequired(w, challengeID)

case err != nil:
    return respondUnauthorized(w)

default:
    sess, err := sessions.Create(ctx, newSessionID(), identityOf(ident))
    if err != nil {
        return err
    }
    return respondSession(w, sess)
}
```

A handler written as `if err != nil { return unauthorized }` is correct here —
it refuses. A handler written as `ident, _ := Authenticate(...)` followed by a
session issuance **is a complete MFA bypass**: the discarded error was the only
thing standing between the first factor and a full session. That is the failure
mode this shape trades against, and it is why the check must be `errors.Is`
rather than a truthiness test.

### 6. Success path

`TopicLoginSuccess` audit and event, the event carrying `SubjectID` from
`FlowIdentity`, then post-hooks receiving the identity. A post-hook error is
returned to the caller — and unlike registration, nothing was persisted, so
refusing here genuinely refuses the login.

### 7. Session issuance

Not part of the flow. `core/session` handles it:

```go
manager := session.NewManager(session.NewHS256Strategy(secret, 24*time.Hour))
sess, err := manager.Create(ctx, sessionID, identityID)
```

Every JWT parse path in `core/session` pins the signing algorithm — `Validate`,
`Refresh`, and `Delete` — because an unpinned `Delete` is a denial-of-service
primitive: forge a token naming someone else's session with the public key as an
HMAC secret and revoke it. See the
[Security Model](./security-model.md#sessions) for the full argument.

---

## Rate limiting and lockout as decorators

Both are `LoginStrategy` implementations that wrap another `LoginStrategy`.
Neither lives in the manager, so the manager has no concept of either, and a
strategy that is not wrapped is not protected.

```go
type LoginStrategy interface {
    ID() string
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}
```

Both decorators delegate `ID()` to the wrapped strategy:

```go
func (s *RateLimitStrategy) ID() string { return s.next.ID() }
func (s *LockoutStrategy) ID() string   { return s.next.ID() }
```

That is what makes the wrapping invisible to the manager. `RegisterStrategy`
keys the map on `s.ID()`, so registering a decorated password strategy replaces
the `"password"` entry rather than adding a second one — you cannot accidentally
end up with both a protected and an unprotected path registered under different
names.

### The wrapping order

```go
base := flow.NewPasswordStrategy(repo, hasher, "email", factory)

locked := flow.NewLockoutStrategy(
    base,
    flow.NewMemoryLockoutStore(),
    5,              // max failures
    15*time.Minute, // lockout duration
    15*time.Minute, // failure window
)

limited := flow.NewRateLimitStrategy(locked, flow.NewMemoryRateLimiter(), flow.RateLimitConfig{
    Limit:  10,
    Window: time.Minute,
})

loginManager.RegisterStrategy(limited)
```

Reading outward: rate limit wraps lockout wraps password. A request travels
rate limit → lockout → password, and the result travels back out.

**Why that order and not the reverse.** Lockout has to record failures, and a
failure is only meaningful if a credential was actually checked. With lockout on
the outside, a burst of requests that the rate limiter refuses never reaches the
lockout store, so an attacker cannot lock out a victim's account by firing
enough requests to trip the counter without ever guessing a password. Put rate
limiting inside lockout instead and every rate-limited request becomes a
recorded failure — which turns a rate limiter into a remote account-disable
button, since the attacker only needs to send `MaxFailures` requests to lock any
identifier they can name.

The reverse composition also wastes the expensive work in the wrong place. The
cheap check should run first.

### Rate limiting

`RateLimitStrategy.Authenticate` calls `checkRateLimit` before delegating:

```go
func (s *RateLimitStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
    if err := s.checkRateLimit(ctx, identifier); err != nil {
        return nil, err
    }
    return s.next.Authenticate(ctx, identifier, secret)
}
```

`checkRateLimit` in order: `SkipFunc` (bypass entirely), `KeyFunc` (the key
defaults to the identifier itself), `DynamicLimit` (overrides limit and window),
then `limiter.Allow(ctx, key, limit, window)`.

The key is the control that matters. Keying on the identifier alone limits
attempts per account, which does nothing against credential stuffing — one
attempt each across ten thousand accounts from one source stays under every
per-account limit. Keying on the source address alone punishes shared NAT and
does nothing against a distributed attacker. `CompositeKeyFunc` and
`ContextKeyFunc` exist to build a composite key from the identifier plus
something you put in the context:

```go
const remoteIPKey flow.ContextKey = "remote_ip"

config := flow.RateLimitConfig{
    Limit:   10,
    Window:  time.Minute,
    KeyFunc: flow.ContextKeyFunc(remoteIPKey, "|"),
}
```

`ContextKeyFunc` returns `identifier|value`, and falls back to the bare
identifier when the context value is absent — so a handler that forgets to
populate the context degrades to per-identifier limiting rather than failing.
That is a quiet degradation worth testing for.

**Failure behavior is configurable and defaults to closed.** When
`limiter.Allow` returns an error, `FailOpen: false` (the zero value) turns it
into `rate limit check failed: %w` and the login is refused. Setting
`FailOpen: true` means a Redis outage disables rate limiting entirely — a
deliberate availability-over-security trade, and one to make consciously. The
`Hooks.OnError` hook takes precedence over `FailOpen`, and returning `nil` from
it fails open regardless of the config field.

Three in-process limiters ship: `MemoryRateLimiter` (sliding window, exact but
stores a timestamp per request), `FixedWindowRateLimiter` (cheaper, allows up to
`2*limit` across a window boundary), and `TokenBucketRateLimiter` (allows bursts
up to `limit`). All three are per-process. Four replicas behind a load balancer
give an attacker four times the configured limit. Use `kayan-redis` for anything
running more than one instance.

`RateLimitStrategy` also implements `Initiate`, and it checks the rate limit
there too — which matters, because magic link and OTP initiation are the
endpoints that send messages and cost money.

### Lockout

`LockoutStrategy.Authenticate` runs four phases.

**1. Check locked.** `store.IsLocked(ctx, key)`, or `Hooks.OnLockoutCheck` when
supplied and it reports `handled`. A store error respects `FailOpen`: false (the
default) returns `lockout check failed: %v` and refuses. A locked account
returns `account is locked until %v` — which discloses that the account exists
and is locked. `Hooks.CreateLockError` is how you replace that with something
generic at a public endpoint.

**2. Delegate.**

**3. Success.** `ClearFailures` unless `Hooks.ShouldClearOnSuccess` says
otherwise, then `OnUnlocked`. Clearing on success is the default and is usually
right; `ShouldClearOnSuccess` returning false gives an accumulating counter,
which is what you want if a successful login after four failures should not
reset the window.

**4. Failure.**

```go
count, rErr := s.store.RecordFailure(ctx, key, failureWindow)
if rErr != nil {
    return nil, authErr
}
// ... OnFailure hook ...
if count >= maxFailures {
    _ = s.store.Lock(ctx, key, lockoutDuration)
    // ... OnLocked hook ...
}
return nil, authErr
```

The original authentication error is always what the caller sees. Lockout never
substitutes its own error on the failure path, so a caller cannot distinguish
"wrong password, 4th attempt" from "wrong password, 5th attempt, now locked" —
which is the right shape, since the difference would tell an attacker exactly
where the threshold sits.

Note `RecordFailure`'s error is swallowed: a lockout store that is down stops
counting failures without failing the login. That is fail-open on the *recording*
path even when `FailOpen` is false, which only governs the *checking* path.

**`LockoutStrategy.Initiate` does not check lockout.** It delegates straight to
the wrapped `Initiator`:

```go
func (s *LockoutStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
    if initiator, ok := s.next.(Initiator); ok {
        return initiator.Initiate(ctx, identifier)
    }
    return nil, fmt.Errorf("underlying strategy does not support initiation")
}
```

A locked account can still trigger magic-link and OTP sends. Whether that is
correct is arguable — the initiation itself proves nothing — but it is a real
asymmetry with `RateLimitStrategy.Initiate`, which does check. If you need
locked accounts to stop receiving codes, put that check in your `OTPSender` or
in an `Initiate` wrapper of your own.

**Lockout is a denial-of-service primitive against your own users.** Anyone who
knows an identifier can lock it by submitting `MaxFailures` wrong passwords.
That is inherent to lockout, not a defect here, and the mitigations are the
usual ones: key on identifier *and* source so a single source cannot lock
everyone, keep `LockoutDuration` short, and prefer rate limiting as the primary
control with lockout as the backstop.

`MemoryLockoutStore` is per-process, and its own comment concedes it never
evicts records — `ClearFailures` deletes on success, but an identifier that only
ever fails leaves a record behind forever. It is a development store.

---

## Magic link

Two calls, with an unbounded gap between them that the caller owns.

### Initiate

```go
result, err := loginManager.InitiateLogin(ctx, "magic_link", "user@example.com")
```

`InitiateLogin` requires the strategy to implement `Initiator`, audits
`TopicLoginInitiated` with the identifier as `ActorID`, and dispatches an event.
`MagicLinkStrategy.Initiate` then:

```go
cred, err := s.repo.GetCredentialByIdentifier(ctx, identifier, "")
if err != nil {
    return nil, fmt.Errorf("magic_link: user not found")
}

tokenVal := uuid.New().String()
token := &domain.AuthToken{
    Token:      tokenVal,
    IdentityID: cred.IdentityID,
    Type:       "magic_link",
    ExpiresAt:  time.Now().Add(s.ttl),
}
if err := s.tokenStore.SaveToken(ctx, token); err != nil {
    return nil, err
}
return token, nil
```

The credential lookup passes `""` as the method, so it matches a credential of
any type for that identifier — a user who registered with a password can receive
a magic link at that address. Whether an empty method actually means "any" is a
property of your store; the `domain.CredentialStorage` contract does not define
it, and `MemoryStore` keys on `method + "\x00" + identifier`, so an empty method
matches only credentials stored with an empty method. Verify this against your
adapter before relying on it.

**`magic_link: user not found` is returned for an unknown address.** That is an
account enumeration oracle on an unauthenticated endpoint: submit an address,
learn whether it has an account. Return a uniform "if that address is
registered, we have sent a link" from your handler regardless of the error.

**The token is `uuid.New().String()`, not `domain.TokenGenerator`.** UUIDv4 from
`google/uuid` is 122 bits of `crypto/rand`, which is above RFC 6749's 128-bit
recommendation for authorization codes only if you count the version and variant
bits, and it is not — 122 bits is comfortably unguessable in practice, and this
is not a weakness in the sense of being brute-forceable. It is nonetheless
inconsistent with the rest of the library: the `domain.TokenGenerator` seam
exists so token entropy is a configurable property, and this strategy bypasses
it. The token is not settable through an option, so a deployment that standardizes
on 32-byte tokens cannot apply that here.

**Delivery is entirely the caller's.** `Initiate` returns the `*domain.AuthToken`
and sends nothing. You build the URL and send the mail:

```go
result, err := loginManager.InitiateLogin(ctx, "magic_link", email)
if err != nil {
    // Do not surface this. Respond identically whether or not the user exists.
    return respondGenericAccepted(w)
}
token := result.(*domain.AuthToken)
link := fmt.Sprintf("https://app.example.com/auth/magic?token=%s", url.QueryEscape(token.Token))
if err := mailer.Send(ctx, email, link); err != nil {
    return err
}
return respondGenericAccepted(w)
```

Two things this places on you. **The token must not appear in a URL that leaks.**
A `Referer` header carries it to any third-party resource the landing page loads,
and it lands in web server access logs at every hop. Consume it immediately on
arrival and redirect without it. And **the address you send to must be the
address the credential belongs to** — `cred.IdentityID` is the binding Kayan
made, and if your mailer sends to a different address than the one that was
looked up, you have handed the identity to whoever controls that address.

### Consume

```go
ident, err := loginManager.Authenticate(ctx, "magic_link", "", token)
```

The identifier argument is unused by this strategy; the token is the secret.

```go
token, err := s.tokenStore.GetToken(ctx, secret)
if err != nil {
    return nil, fmt.Errorf("magic_link: invalid or expired token")
}
if token.Type != "magic_link" {
    return nil, fmt.Errorf("magic_link: invalid token type")
}
if token.ExpiresAt.Before(time.Now()) {
    s.tokenStore.DeleteToken(ctx, secret)
    return nil, fmt.Errorf("magic_link: token expired")
}
ident, err := s.repo.GetIdentity(ctx, func() any { return &identity.Identity{} }, token.IdentityID)
if err != nil {
    return nil, fmt.Errorf("magic_link: identity not found")
}
s.tokenStore.DeleteToken(ctx, secret)
return ident, nil
```

**The type check is load-bearing.** All of `AuthToken` — recovery, verification,
magic link, OTP — share one table and one lookup by value. Without
`token.Type != "magic_link"`, an email-verification token would authenticate a
login. Verification tokens have a 24-hour TTL and are sent to addresses that may
not have been proven yet; treating one as a login credential is a full
authentication bypass. Every token-consuming path in `core/flow` performs this
check, and any new one must.

**Expiry is checked twice.** The store is contractually required not to return
an expired token, and the strategy checks anyway. The comment in the source
reads "Store should handle this, but double check" — and the
[Storage Layer](./storage-layer.md#the-bug-it-found) documents that this comment
was, for a period, describing a layer that did not exist: `kayan-gorm`'s
`GetToken` ignored `ExpiresAt` entirely. The three callers that re-checked were
the only thing preventing an authentication bypass, and the fix moved the filter
into the store where it belongs. Keep both.

**Single-use deletion.** `DeleteToken` after a successful lookup. Without it the
token stays valid for its whole TTL, and every place the link was copied —
mail server logs, a forwarded message, a shared inbox, the browser history of a
kiosk — is a live credential for fifteen minutes.

Two gaps in the current implementation. The deletion is **not atomic with the
read**: two concurrent presentations both call `GetToken`, both succeed, and
both are authenticated before either `DeleteToken` lands. For a magic link the
practical impact is small (both requests belong to the same user), but a store
offering an atomic get-and-delete is strictly better. And the `DeleteToken`
error is discarded — a delete that fails leaves a reusable token with no signal.

Note also `GetIdentity` is called with `func() any { return &identity.Identity{} }`,
a hardcoded factory rather than the manager's. A BYOS deployment whose model is
not `identity.Identity` gets a `*identity.Identity` back from this path, not
their own type, and a handler that type-asserts to `*User` will fail. That is a
real BYOS gap in the magic-link and OTP strategies.

---

## OTP

Same two-step shape, with delivery pushed onto an interface you implement.

```go
type OTPSender interface {
    Send(ctx context.Context, recipient, code string) error
}
```

Kayan sends nothing. `Send` receives the recipient and the plaintext code and is
responsible for getting it there — Twilio, SNS, SMTP, a push notification. The
consequence is that the code passes through your process in plaintext, so
whatever you log inside `Send` is a live credential in your log aggregator for
the TTL.

### Initiate

```go
sender := &TwilioSender{client: twilioClient}
otp := flow.NewOTPStrategy(repo, tokenStore, sender,
    flow.WithOTPTTL(5*time.Minute),
    flow.WithOTPCodeLength(6),
)
loginManager.RegisterStrategy(otp)
```

`Initiate` refuses if `sender == nil`, looks up the credential (again with
`""` as the method, and again returning `otp: user not found` for an unknown
recipient — the same enumeration oracle), generates the code, stores it as an
`AuthToken` with `Type: "otp"`, and delivers it.

**Code generation:**

```go
func (s *OTPStrategy) generateCode() (string, error) {
    max := new(big.Int)
    max.SetInt64(1)
    for i := 0; i < s.codeLength; i++ {
        max.Mul(max, big.NewInt(10))
    }
    n, err := rand.Int(rand.Reader, max)
    if err != nil {
        return "", err
    }
    format := fmt.Sprintf("%%0%dd", s.codeLength)
    return fmt.Sprintf(format, n.Int64()), nil
}
```

`rand` is `crypto/rand`. `rand.Int` over `10^codeLength` is uniform — no modulo
bias — and the result is zero-padded, so `000042` is a legitimate six-digit code
and the space really is 10^6. Using `math/rand` here, or `n % 1000000` over a
non-power-of-ten range, would both narrow the space in ways that pass every
functional test.

**Six digits is 10^6 = one in a million per guess, and that is not much.** The
security of an OTP is the entropy of the code *multiplied by* the number of
guesses an attacker is allowed. Without rate limiting, a million requests
against a five-minute window is entirely achievable, and the code is not
single-attempt — a wrong code does not consume the token. **An OTP strategy that
is not wrapped in a rate limiter is not a second factor.** Wrap it, key the limit
on the recipient, and set the limit in single digits.

Note also `int64` overflow: `n.Int64()` on a code length above 18 digits is
undefined behavior for this code. Six to eight is the useful range.

**TTL** defaults to five minutes and is set through `WithOTPTTL`. Longer means a
larger brute-force window; shorter means legitimate SMS delivery latency starts
failing users.

**Delivery failure rolls back:**

```go
if err := s.sender.Send(ctx, identifier, code); err != nil {
    s.tokenStore.DeleteToken(ctx, code)
    return nil, fmt.Errorf("otp: failed to send code: %w", err)
}
```

Without that cleanup, a failed send leaves a live code nobody received —
guessable for the full TTL and invisible to the user, who sees nothing arrive
and requests another. The cleanup is best-effort; its error is discarded.

### Authenticate

Identical structure to magic link: `GetToken` by the code value, check
`Type != "otp"`, check expiry, load the identity, `DeleteToken`.

Two properties this shape has that are easy to miss. The lookup is **by code
value, not by recipient** — the `identifier` argument is never used. Two users
holding the same six-digit code at the same moment is a collision that resolves
to whichever record the store returns, and a code guessed blindly authenticates
as whoever it belongs to rather than as the account under attack. With a large
enough user base and a long enough TTL, guessing *any* valid code becomes far
easier than guessing a specific one. Bind the check to the recipient if that
matters: look the credential up yourself and compare `token.IdentityID` before
trusting the result.

And a successful authentication consumes the token, but a **failed** one does
not. There is no per-code attempt counter. Rate limiting is the only thing
bounding guesses.

---

## TOTP and step-up

TOTP appears in two places that do different things.

### `TOTPStrategy` as a `LoginStrategy`

```go
strategy := flow.NewTOTPStrategy(repo, func() any { return &User{} }, "Email")
loginManager.RegisterStrategy(strategy)
```

`Authenticate` looks the identity up by field, loads the base32 secret, decodes
it, finds a matching counter, and records the counter as used:

```go
counter, ok := s.findMatchingCounter(key, code)
if !ok {
    return nil, ErrTOTPCodeInvalid
}
if err := s.repo.MarkTOTPUsed(ctx, fi.GetID(), counter); err != nil {
    return nil, ErrTOTPReplay
}
return ident, nil
```

`findMatchingCounter` walks three 30-second windows — previous, current, next:

```go
now := time.Now().Unix() / 30
for i := int64(-1); i <= 1; i++ {
    counter := uint64(now + i)
    generated := s.generateCode(key, counter)
    if subtle.ConstantTimeCompare([]byte(generated), []byte(code)) == 1 {
        return counter, true
    }
}
```

`subtle.ConstantTimeCompare` rather than `==`. A byte-comparing loop leaks how
many leading digits were correct, which reduces a six-digit search from 10^6 to
about 60 guesses.

Drift tolerance of one step is a real cost: three windows means three valid
codes at any instant, so the effective space is 3-in-10^6 rather than 1-in-10^6.
Zero tolerance would reject users whose phone clock is a few seconds off, which
is most of them.

**Replay protection is delegated to the store**, and the contract is explicit:

```go
// MarkTOTPUsed records that the given time-step counter has been used for the
// identity. Implementations must return an error if that counter was already
// used (replay protection).
MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error
```

Without it a TOTP code is replayable for its whole window — up to 90 seconds
given the drift tolerance. Anyone who observes the code over the user's shoulder,
in a phishing proxy, or in a log line can present it again. A `MarkTOTPUsed` that
returns nil unconditionally passes every functional test and provides no replay
protection at all; a conformance test for it must assert that the *second* call
with the same counter errors.

`generateCode` implements HOTP over HMAC-SHA1 with dynamic truncation
(RFC 4226) and `% 1000000`. SHA-1 here is the standard's choice and is fine —
HMAC-SHA1 is not affected by the collision attacks that retired SHA-1 for
signatures.

### `Verify` as a stateless helper

```go
func (s *TOTPStrategy) Verify(secret string, code string) bool
```

Used by `LoginManager.VerifyMFA`. Its doc comment says what it does not do:
**"It does not enforce replay protection."** And `VerifyMFA` has one more
behavior worth knowing:

```go
enabled, secret := mfaIdent.MFAConfig()
if !enabled {
    return true, nil
}
```

**A disabled MFA config returns `(true, nil)` — success.** That is coherent
inside a flow where `Authenticate` only returned `ErrMFARequired` when
`enabled` was true, but it is dangerous if called on its own: a handler that
uses `VerifyMFA` as a standalone authorization gate before a sensitive action
gets `true` for every user who has not enrolled. Use it only to complete a
challenge that `ErrMFARequired` began.

### Step-up

`core/flow/stepup.go` is a separate mechanism for re-authentication before a
sensitive action on an *existing* session. It does not authenticate anything
itself — it records and evaluates assurance levels.

```go
const (
    StepUpNone     StepUpLevel = "none"
    StepUpRecent   StepUpLevel = "recent"
    StepUpMFA      StepUpLevel = "mfa"
    StepUpPassword StepUpLevel = "password"
)
```

Ordered `none < recent < mfa < password` by `levelSatisfies`. `Evaluate`:

```go
result, err := mgr.Evaluate(ctx, sessionID, "transfer_funds", nil)
if !result.Allowed {
    // result.ChallengeType names what to prompt for.
}
```

The path through `Evaluate`, and what each branch means:

- **No policy configured** → `ErrStepUpNoPolicy`. A `StepUpManager` built
  without `WithStepUpPolicy` cannot decide anything, so it does not decide
  "allowed". This used to return `Allowed: true`, which meant a manager wired
  in front of a sensitive action and missing its policy authorized everything
  while reporting success.
- **`RequiredLevel` returns `StepUpNone`** → `Allowed: true`. Correct: the
  action needs no step-up.
- **No record, or the store errored** → `Allowed: false` with a challenge type.
  Note that a store failure and an absent record are the same outcome here, which
  is fail-closed and right, but means an outage presents to users as "please
  re-authenticate" rather than as an error.
- **Record older than `recencyWindow`** (default 15 minutes) → `Allowed: false`.
  Recency is checked *before* level, so a password step-up from an hour ago does
  not satisfy an `mfa` requirement.
- **Recorded level satisfies the requirement** → `Allowed: true`.

`RecordStepUp` is what the handler calls after the re-authentication succeeds:

```go
if _, err := loginManager.Authenticate(ctx, "password", email, password); err != nil {
    return respondUnauthorized(w)
}
if err := mgr.RecordStepUp(ctx, sessionID, flow.StepUpPassword); err != nil {
    return err
}
```

**`RecordStepUp` performs no verification.** It writes whatever level it is
given for whatever session ID it is given. It is a record of a decision your
handler made, not a check. Calling it on a path that did not actually
re-authenticate grants the level for free, and calling it with a session ID
taken from client input rather than from the validated session grants it for
someone else's session. Both are the caller's to get right.

`MemoryStepUpStore` is per-process: a step-up recorded on one replica is not
visible to the next request if it lands elsewhere, which presents as users being
challenged repeatedly.

### The partial session

Kayan does not provide a partial-session type. The shape the flow expects is:

1. `Authenticate` returns `(ident, ErrMFARequired)`.
2. The handler stores a **challenge record** — identity ID, expiry, a
   single-use opaque ID from `domain.DefaultTokenGenerator` — and returns the
   challenge ID.
3. The client posts the challenge ID and the TOTP code.
4. The handler loads the challenge, resolves the identity **from the stored
   identity ID, not from client input**, verifies the code, deletes the
   challenge, and issues the real session.

Three properties that partial session must have. It must **grant nothing** —
if it is accepted as a bearer token anywhere except the MFA completion endpoint,
MFA is optional. It must be **short-lived**, minutes rather than hours, because
it represents a completed first factor sitting unused. And the identity must
come from the record rather than from the request, which is the whole reason
`ErrMFARequired` returns the identity in the first place.

---

## WebAuthn

`WebAuthnStrategy` wraps `github.com/go-webauthn/webauthn`. The cryptographic
work — attestation parsing, signature verification, origin and RP ID checking,
challenge comparison — is that library's; Kayan owns identity lookup, ceremony
session storage, and credential persistence.

### Why it is not really a `LoginStrategy`

It does implement the interface:

```go
func (s *WebAuthnStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
    var authData struct {
        SessionID string                                  `json:"session_id"`
        Response  *protocol.ParsedCredentialAssertionData `json:"response"`
    }
    if err := json.Unmarshal([]byte(secret), &authData); err != nil {
        return nil, errors.New("webauthn: invalid authentication data")
    }
    return s.FinishLogin(ctx, identifier, authData.SessionID, authData.Response)
}
```

But the fit is an adapter, not a home. `LoginStrategy` is
`(identifier, secret string) → identity` — one round trip, one secret. WebAuthn
is a **two-message ceremony**: the server issues a challenge, the authenticator
signs it, the server verifies the signature against that specific challenge. The
first message has no place in a single-call interface, so `BeginLogin` is a
method on the concrete type that `LoginManager` cannot reach. `Initiator` does
not fit either — `Initiate(ctx, identifier) (any, error)` returns `any`, but
the caller needs a typed `*protocol.CredentialAssertion` **and** a session ID,
and the interface has one return slot for both.

So `Authenticate` smuggles both the session ID and the parsed assertion through
the `secret` string as JSON. That works, at two costs. `*protocol.ParsedCredentialAssertionData`
is the go-webauthn library's *parsed* type, and round-tripping it through
`encoding/json` is not the same as parsing a raw client response with
`protocol.ParseCredentialRequestResponseBody` — fields that library computes
during parsing are being reconstructed from whatever JSON the caller supplies.
And it means the decorators are less useful than they look: a rate limiter
wrapping this strategy sees the identifier, which is fine, but a lockout store
counting failures counts JSON unmarshal errors alongside real signature
failures.

**Call `BeginLogin` and `FinishLogin` directly.** Register the strategy with the
manager only if you want the decorators and the audit events, and know what
`Authenticate` is doing underneath.

### Registration ceremony

```go
options, sessionID, err := strategy.BeginRegistration(ctx, ident, userName, displayName)
```

The identity must implement `FlowIdentity`; its ID becomes the WebAuthn user
handle via `[]byte(fmt.Sprintf("%v", fi.GetID()))`. Existing WebAuthn
credentials are collected from `CredentialSource` and passed to the library so it
can populate `excludeCredentials` — without that, a user can register the same
authenticator twice and end up with duplicate credentials for one device.

`webAuthn.BeginRegistration(user)` produces the options and a
`webauthn.SessionData` containing the challenge. Kayan stores the pieces it
needs:

```go
sessionID := s.generateSessionID()
sessionData := &WebAuthnSessionData{
    Challenge:        session.Challenge,
    UserID:           session.UserID,
    UserVerification: string(session.UserVerification),
    ExpiresAt:        time.Now().Add(s.sessionTTL),
}
if err := s.sessionStore.SaveSession(ctx, sessionID, sessionData); err != nil {
    return nil, "", fmt.Errorf("webauthn: failed to save session: %w", err)
}
```

**The session store is the security boundary of the ceremony.** A WebAuthn
challenge is single-use, server-generated, and must be compared against exactly
what the server issued. If the challenge were carried in a client-supplied
cookie or in a hidden form field, an attacker could replay a captured
authenticator response against a challenge of their own choosing, and the
signature would verify. Server-side storage keyed by an opaque ID is what makes
the comparison meaningful.

```go
type WebAuthnSessionStore interface {
    SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error
    GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error)
    DeleteSession(ctx context.Context, sessionID string) error
}
```

`generateSessionID` reads 32 bytes from `crypto/rand` and base64url-encodes them.
It ignores `rand.Read`'s error — on a platform where the entropy source fails,
this returns a session ID of 32 zero bytes rather than failing.

`MemoryWebAuthnSessionStore` is a bare map **with no mutex**. Concurrent
ceremonies from different users race on it, and the Go race detector will report
it. Use `kayan-redis` or a database-backed store for anything with more than one
concurrent user — the doc comment says "Use Redis in production" and it means it.

```go
cred, err := strategy.FinishRegistration(ctx, ident, sessionID, userName, displayName, response)
```

`FinishRegistration` loads the session, **defers its deletion**, and checks
expiry:

```go
sessionData, err := s.sessionStore.GetSession(ctx, sessionID)
if err != nil {
    return nil, fmt.Errorf("webauthn: session not found or expired")
}
defer s.sessionStore.DeleteSession(ctx, sessionID)

if time.Now().After(sessionData.ExpiresAt) {
    return nil, errors.New("webauthn: session expired")
}
```

The `defer` placement matters: the ceremony session is consumed whether or not
the credential validates. Deleting only on success would leave a live challenge
after a failed attempt, and a challenge that can be retried is one an attacker
can work against. The default TTL is five minutes.

`webAuthn.CreateCredential(user, waSession, response)` does the verification.
The resulting credential is serialized into `identity.Credential`:

```go
cred := &identity.Credential{
    IdentityID: fmt.Sprintf("%v", fi.GetID()),
    Type:       "webauthn",
    Identifier: base64.RawURLEncoding.EncodeToString(credential.ID),
    Config:     identity.JSON(configBytes),
    CreatedAt:  time.Now(),
    UpdatedAt:  time.Now(),
}
```

`Config` holds the public key, AAGUID, sign count, and backup flags. There is no
secret here — the private key never leaves the authenticator, which is why a
WebAuthn credential database disclosure does not yield anything an attacker can
authenticate with.

One gap: persistence happens **only** if the identity implements
`CredentialSource`:

```go
if cs, ok := ident.(CredentialSource); ok {
    cs.SetCredentials(append(cs.GetCredentials(), *cred))
    if err := s.repo.CreateIdentity(ctx, ident); err != nil {
        return nil, fmt.Errorf("webauthn: failed to save credential: %w", err)
    }
}
return cred, nil
```

An identity that does not implement it gets the credential **returned and never
stored**, with no error. The registration appears to succeed and the user has no
passkey. `Hooks.CredentialSaver` exists for custom persistence but is not
consulted on this path in the current code — if your model is not a
`CredentialSource`, save the returned credential yourself.

### Login ceremony

```go
options, sessionID, err := strategy.BeginLogin(ctx, identifier)
```

Looks up the credential by identifier (method `""`), loads the identity,
collects its WebAuthn credentials, and refuses when there are none:

```go
if len(existingCreds) == 0 {
    return nil, "", errors.New("webauthn: no credentials registered")
}
```

`webAuthn.BeginLogin(user)` produces the assertion options and the allowed
credential IDs, which are stored in the session alongside the challenge. Storing
`AllowedCredIDs` server-side is what stops a client from answering with a
credential that was not offered.

`webauthn: user not found` for an unknown identifier is, again, an enumeration
oracle at an unauthenticated endpoint.

```go
ident, err := strategy.FinishLogin(ctx, identifier, sessionID, response)
```

Load session, defer delete, check expiry, resolve the identity from the
identifier, rebuild the `webauthn.SessionData`, then:

```go
credential, err := s.webAuthn.ValidateLogin(user, waSession, response)
if err != nil {
    return nil, fmt.Errorf("webauthn: login validation failed: %w", err)
}
s.updateSignCount(ctx, ident, credential)
return ident, nil
```

`ValidateLogin` verifies the signature against the stored public key, checks the
challenge matches, checks the origin is in `RPOrigins`, checks the RP ID hash,
and enforces the user-verification requirement. **Origin checking is the
anti-phishing property of WebAuthn** — it is what makes a credential registered
for `app.example.com` useless to a page served from `app-example.com`. Getting
`RPID` or `RPOrigins` wrong is the one configuration mistake that gives away
that property.

**Sign count is where the clone check lives.** An authenticator increments a
counter on each assertion; a counter that goes backwards or repeats indicates
two copies of a credential in circulation. go-webauthn sets `CloneWarning` when
it detects this, `updateSignCount` persists the flag, and `FinishLogin` then
calls `Hooks.OnCloneWarning` and refuses with `ErrWebAuthnClonedCredential`.

The order matters: the flag is written before the refusal, so the evidence is
not lost when the attempt is rejected. `Hooks.AllowClonedAuthenticators` lets
the login proceed anyway, at the cost of clone detection across every
credential.

This previously recorded the warning and returned the identity regardless, with
`OnCloneWarning` declared but never called — the protocol’s one clone-detection
mechanism logged the break-in and opened the door.

`updateSignCount` also discards `UpdateIdentity`'s error, so a failed write means
the sign count silently stops advancing — which turns off clone detection for
that credential entirely.

---

## OAuth 2.0 authorization code with PKCE

`kayan-oidc-provider/oauth2`. Two endpoints, four calls.

### `ParseAuthorizeRequest`

```go
req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
```

Checks in order:

**1. `client_id` present**, then resolved through `clientStore.GetClient`. An
unknown client is `ErrInvalidClient`.

**2. `redirect_uri`.** Omitted is permitted only when exactly one is registered:

```go
if redirectURI == "" {
    if len(client.RedirectURIs) != 1 {
        return nil, ErrInvalidRequest.WithDescription("redirect_uri is required")
    }
    redirectURI = client.RedirectURIs[0]
}
if !client.AllowsRedirectURI(redirectURI) {
    // Never redirect this error: sending it to an unregistered URI is the
    // open redirect the allowlist exists to prevent.
    return nil, ErrInvalidRequest.WithDescription("redirect_uri is not registered for this client")
}
```

`AllowsRedirectURI` is exact byte equality against the registered list. Skip it
and the authorization endpoint delivers authorization codes to an
attacker-chosen address — the attacker sends the victim through a genuine
authorization request at the genuine provider, the victim genuinely
authenticates, and the code arrives at the attacker. Every relaxation of exact
matching has produced a real vulnerability somewhere; the
[Security Model](./security-model.md#redirect_uri-is-an-exact-match-allowlist)
walks the fourteen-entry adversarial corpus, including the Cyrillic homoglyph
case that defeats any scheme normalizing before comparing.

The comment about never redirecting this particular error is the second half of
the same defense: reporting "your redirect_uri is not registered" *by
redirecting to it* is the open redirect.

**3. `response_type`.** Exactly `code`:

```go
if len(responseType) != 1 || responseType[0] != ResponseTypeCode {
    return nil, ErrUnsupportedResponseType.
        WithDescription("only the authorization code response type is supported")
}
```

`token` and `id_token` are refused rather than ignored. Silently ignoring them
would advertise an implicit flow that does not exist, and a client built against
that misreading would put tokens in URL fragments and find nothing there.

**4. PKCE.**

```go
if challenge == "" {
    if p.requirePKCE || client.IsPublic() {
        return nil, ErrInvalidRequest.WithDescription("code_challenge is required")
    }
} else {
    resolved := normalizeChallengeMethod(method)
    switch {
    case resolved == "":
        return nil, ErrInvalidRequest.WithDescription("unsupported code_challenge_method")
    case resolved == challengeMethodPlain && !p.allowPlainCC:
        return nil, ErrInvalidRequest.WithDescription("code_challenge_method must be S256")
    }
    method = resolved
}
```

`requirePKCE` defaults to true. A public client is required to use PKCE
regardless, because it holds no secret and PKCE is then the only thing binding
the code to the party that requested it.

The `method = resolved` assignment is the important line. `normalizeChallengeMethod`
returns `""` for anything it does not recognize, and the request is refused —
so an empty or unknown method never reaches storage. Without PKCE, an attacker
who can intercept the authorization response (a malicious app registered for the
same custom URI scheme on a mobile device, a compromised intermediate) captures
the code and redeems it themselves. PKCE means redeeming requires the verifier,
which never left the legitimate client.

**5. Scopes.** `checkScopes` enforces only when the client declares any:

```go
if len(client.Scopes) == 0 || len(requested) == 0 {
    return nil, nil
}
```

A client registered with no scopes is unrestricted. That keeps existing
registrations working and is a real gap — populate `Scopes` and `GrantTypes` on
every client record.

### Code issue

```go
code, err := provider.GenerateAuthCodeFor(ctx, req, identityID)
```

Prefer this over `GenerateAuthCode`: the request has already been validated and
the nonce is carried through to the ID token. The stored `AuthCode` binds the
client ID, the identity, the redirect URI, the scopes, the challenge, the
resolved challenge method, the nonce, and an expiry of `p.clock.Now().Add(10 * time.Minute)`
per RFC 6749 section 4.1.2.

`GenerateAuthCode` — the lower-level entry point taking raw parameters —
re-runs the redirect URI and PKCE checks itself, so a caller who reaches it
without `ParseAuthorizeRequest` still gets them. It does not carry a nonce.

The code value comes from `p.tokens()`, which is
`domain.DefaultTokenGenerator` unless replaced: 32 bytes of `crypto/rand`,
unpadded base64url. `NewTokenGenerator` panics below 16 bytes rather than
quietly producing a weak generator. A predictable authorization code is a total
compromise that produces no error and passes every functional test.

### `ParseTokenRequest`

```go
req, err := provider.ParseTokenRequest(ctx, formValues, r.Header.Get("Authorization"))
```

`grant_type` first, then credential extraction. The `Authorization` header wins
when present:

```go
decodedID, idErr := url.QueryUnescape(id)
decodedSecret, secretErr := url.QueryUnescape(secret)
```

RFC 6749 section 2.3.1 requires the credentials be form-urlencoded before
base64. Skipping that unescape rejects any secret containing a reserved
character — an interoperability bug, not a security one, but the kind that is
diagnosed as "our secret does not work" rather than as an encoding mismatch.

With no header, `client_id` comes from the body and an absent one is
`ErrInvalidClient` — client authentication is never optional.

**Then `p.authenticate` runs, before any grant-specific parsing.**

### Client authentication

```go
func (p *Provider) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
    client, err := p.clientStore.GetClient(ctx, clientID)
    if err != nil {
        if clientSecret != "" {
            _ = p.hasher.Compare(clientSecret, dummyBcryptHash)
        }
        return nil, ErrInvalidClient.WithDescription("client authentication failed").WithCause(err)
    }

    if client.IsPublic() {
        if clientSecret != "" {
            return nil, ErrInvalidClient.WithDescription("client authentication failed")
        }
        return client, nil
    }

    if clientSecret == "" {
        return nil, ErrInvalidClient.WithDescription("client authentication failed")
    }
    if client.SecretHash == "" {
        return nil, ErrInvalidClient.WithDescription("client authentication failed")
    }
    if !p.hasher.Compare(clientSecret, client.SecretHash) {
        return nil, ErrInvalidClient.WithDescription("client authentication failed")
    }
    return client, nil
}
```

Five things happen here that each prevent a distinct failure.

**The dummy comparison** gives the unknown-client path the same bcrypt work as a
real verification, so response timing does not distinguish "no such client" from
"wrong secret". This is the equalizing work that `PasswordStrategy` does not do.

**A public client presenting a secret is refused**, not ignored. Presenting one
means the caller misunderstands the registration, and accepting it would let a
confidential-looking request succeed against a client that authenticates on
nothing.

**An empty secret on a confidential client is refused.** The source comment
records that this once skipped verification entirely — impersonating any
confidential client required *omitting* a parameter rather than guessing one.

**An empty stored hash is refused.** A client registered as confidential but with
no hash recorded is a broken registration; treating it as "no secret required"
authenticates anyone who names it.

**Every failure returns the same error text.** Preserve that at your handler.

`authenticate` then checks `client.AllowsGrantType(grantType)`. Like scopes,
this enforces only when the client declares grant types.

`Exchange` and `Refresh` both call `authenticate` again as their first act,
before touching the code or token store — so they are safe whether or not the
caller went through `ParseTokenRequest`, and an unauthenticated caller learns
nothing about whether a code exists.

### `Exchange`

```go
tokens, err := provider.Exchange(ctx, code, clientID, clientSecret, redirectURI, verifier)
```

In order:

1. **Authenticate the client.** Failure audits `oauth2.exchange.failure`.
2. **Load the code.** Unknown is `ErrInvalidGrant`.
3. **`defer` the deletion:**

```go
defer func() { _ = p.authCodeStore.DeleteAuthCode(ctx, code) }()
```

   The placement is the point. The code is consumed whether the exchange
   succeeds or fails on expiry, client mismatch, redirect URI mismatch, or PKCE.
   Deleting only on success would leave a live code an attacker could keep
   presenting with different verifiers — turning PKCE into a brute-forceable
   check rather than a one-shot one.

4. **Expiry**: `!p.clock.Now().Before(authCode.ExpiresAt)`.
5. **Client binding:**

```go
if authCode.ClientID != clientID {
    // The code belongs to another client: this is a code injection
    // attempt, not a mistake.
    return nil, ErrInvalidGrant.WithDescription("invalid authorization code")
}
```

   Without it, a malicious client that obtains a code issued to a legitimate one
   redeems it with its own credentials and receives tokens for the victim's user.

6. **Redirect URI binding** to the value from the authorization request.
7. **PKCE:**

```go
func (p *Provider) verifyCodeChallenge(authCode *AuthCode, verifier string) error {
    if authCode.CodeChallenge == "" {
        if p.requirePKCE {
            return ErrInvalidGrant.WithDescription("code_challenge is required")
        }
        return nil
    }
    if verifier == "" {
        return ErrInvalidGrant.WithDescription("code_verifier is required")
    }
    if !p.verifyPKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, verifier) {
        return ErrInvalidGrant.WithDescription("invalid code_verifier")
    }
    return nil
}
```

   Enforced at **both** ends — request parsing and code verification — so a
   client cannot opt out by omitting the challenge at one of them. `verifyPKCE`
   fails closed on an unknown or absent method rather than degrading to a
   plaintext comparison, and `plain` is checked a second time against
   `allowPlainCC` so a stored `plain` code cannot be verified by a provider not
   built to allow it. Both comparisons use `subtle.ConstantTimeCompare`.

   The downgrade this prevents: with S256 the challenge is `SHA256(verifier)`,
   and an attacker intercepting the authorization request sees only the hash. If
   verification treated an absent method as plain, the attacker would strip
   `code_challenge_method` and present the *challenge itself* as the verifier —
   a plain comparison of the challenge against itself succeeds.

8. **Issue.** `GenerateAccessToken` produces an RS256 JWT with `iss`, `sub`,
   `aud`, `exp` (one hour), `iat`, a UUID `jti`, and `scp`, with `kid` in the
   header. `issueRefreshToken` generates a token and a new family ID.

### Refresh with reuse detection

```go
tokens, err := provider.Refresh(ctx, refreshToken, clientID, clientSecret)
```

Authenticate, load, check `gr.ClientID != clientID`, then:

```go
if gr.IsUsed() {
    p.logAudit(ctx, "oauth2.refresh.reuse", clientID, gr.IdentityID, "failure",
        "refresh token replayed; revoking the token family")
    if hasFamily && gr.FamilyID != "" {
        if err := family.RevokeFamily(ctx, gr.FamilyID); err != nil {
            return nil, ErrServerError.WithCause(err)
        }
    } else {
        _ = p.refreshTokenStore.DeleteRefreshToken(ctx, tokenValue)
    }
    return nil, ErrInvalidGrant.WithDescription("invalid refresh token")
}
```

**Rotation alone is not theft detection.** If a stolen token is redeemed and the
spent one deleted, the thief holds the only valid token and the legitimate
client's next refresh merely fails — indistinguishable from expiry.

Keeping the spent token *resolvable* is what creates the signal. Two parties
holding tokens from one chain means one of them will eventually present a spent
one: either the thief replaying, or the legitimate client whose token was stolen
after it rotated. Either way the chain is compromised, and revoking the whole
family is correct in both cases. The user re-authenticates; the thief loses
everything.

This requires a store implementing `RefreshTokenFamilyStore`. With a plain
`RefreshTokenStore`, rotation still happens and the spent token is deleted, so
**a replay is reported as invalid but the thief's own token keeps working**.
Reuse detection is a property of your store, not of the provider — check it in
your deployment.

Expiry is checked after reuse, so a replayed *expired* token still triggers
family revocation. Rotation then marks the old token used (family store) or
deletes it (plain store), and a new token is issued into the same family.

Lifetimes: `accessTokenTTL = time.Hour`, `refreshTokenTTL = 7 * 24 * time.Hour`.

---

## SAML SP-initiated SSO

`kayan-saml`. This is the most adversarial path in the library: the assertion is
a bearer credential delivered through the user's browser, so the attacker
controls the transport, can modify the message, and can replay it.

### `InitiateLogin`

```go
redirectURL, err := sp.InitiateLogin(ctx, "okta", "/dashboard")
```

Resolves the IdP (unconfigured is an error), generates a request ID from 16
bytes of `crypto/rand`, builds the `AuthnRequest` with `Destination`,
`AssertionConsumerServiceURL`, and `Issuer`, runs `BeforeAuthnRequest`, marshals
to XML, and **saves the session before returning**:

```go
session := &Session{
    ID:         requestID,
    RequestID:  req.ID,
    IdPID:      idpID,
    ReturnURL:  returnURL,
    CreateTime: time.Now(),
    ExpiresAt:  time.Now().Add(sp.config.SessionTTL),
}
if err := sp.sessionStore.Save(ctx, session); err != nil {
    return "", fmt.Errorf("failed to save session: %w", err)
}
```

Saving before redirecting is what makes the response correlatable. A response
whose relay state matches no stored session cannot be tied to anything this SP
started. Default TTL is five minutes.

### DEFLATE and the redirect binding

```go
encoded, err := deflateAndEncode(xmlBytes)
// ...
query.Set("SAMLRequest", encoded)
query.Set("RelayState", session.ID)
```

`deflateAndEncode` runs the XML through `compress/flate` and then standard
base64. The comment states why:

> The message must be DEFLATE-compressed before base64 encoding (SAML 2.0
> Bindings section 3.4.4.1); base64 of the raw XML is rejected by real identity
> providers.

This is raw DEFLATE with no zlib or gzip wrapper, which is what the binding
specifies. `RelayState` carries the session ID — the IdP echoes it back
verbatim, and that echo is the correlation.

The inverse, `ParseRedirectBinding`, is where the denial-of-service surface is,
because the ACS endpoint is reachable by anyone:

```go
const maxDecodedMessageSize = 5 << 20 // 5 MiB

message, err := io.ReadAll(io.LimitReader(reader, maxDecodedMessageSize+1))
if err != nil {
    return nil, fmt.Errorf("saml: inflate %s: %w", parameter, err)
}
if len(message) > maxDecodedMessageSize {
    return nil, fmt.Errorf("saml: %s exceeds %d bytes when decompressed", parameter, maxDecodedMessageSize)
}
```

DEFLATE expands a tiny payload enormously — a few hundred bytes of highly
compressible input inflates to gigabytes. An unbounded `io.ReadAll` on an
unauthenticated endpoint is an out-of-memory kill with a single request. The
`+1` on the limit is what makes the size check able to detect "at least one byte
over" rather than "exactly at the limit".

`TestRedirectBindingRejectsDecompressionBomb` covers it, and
`FuzzParseRedirectBinding` runs against the parser in CI.

### At the IdP

Outside Kayan entirely. The user authenticates however that IdP requires, and
the IdP POSTs a `SAMLResponse` and the echoed `RelayState` to the ACS URL.

### `ProcessResponse`

```go
user, err := sp.ProcessResponse(ctx, samlResponse, relayState)
```

**1. Base64 decode**, then parse the envelope — for routing only:

```go
// The envelope is parsed only to read routing fields — the relay state
// correlation and the status code. Nothing from it reaches the identity.
var envelope Response
if err := xml.Unmarshal(responseBytes, &envelope); err != nil {
    return nil, fmt.Errorf("saml: parse response: %w", err)
}
```

**2. `BeforeProcessResponse` hook**, receiving the unverified envelope. A hook
that reads identity claims from it is reading attacker-controlled data.

**3. Status code.** Anything other than
`urn:oasis:names:tc:SAML:2.0:status:Success` is refused.

**4. Correlate the session:**

```go
session, err := sp.sessionStore.Get(ctx, relayState)
if err != nil || session == nil {
    if !sp.config.AllowIdPInitiated {
        return nil, fmt.Errorf("%w: no pending request matches this response", ErrUnsolicited)
    }
    session = nil
} else {
    if !session.ExpiresAt.IsZero() && !sp.clock.Now().Before(session.ExpiresAt) {
        _ = sp.sessionStore.Delete(ctx, session.ID)
        return nil, fmt.Errorf("saml: authentication request expired")
    }
    defer func() { _ = sp.sessionStore.Delete(ctx, session.ID) }()
}
```

The session is deleted on the way out regardless of outcome, so the request is
single-use. Without that, a captured response could be presented repeatedly
against the same pending request.

`AllowIdPInitiated` is off by default. An IdP-initiated response has no
`InResponseTo` to correlate, so nothing ties it to anything the user started —
which makes it a login CSRF primitive: an attacker triggers an IdP-initiated
sign-on for *their own* account against the victim's browser, and the victim is
now silently operating as the attacker.

**5. Resolve the IdP — before any certificate is used:**

```go
func (sp *ServiceProvider) resolveIdP(session *Session, envelope *Response) (*IdPConfig, error) {
    if session != nil {
        idp, ok := sp.GetIdP(session.IdPID)
        if !ok {
            return nil, fmt.Errorf("saml: identity provider %q is no longer configured", session.IdPID)
        }
        return idp, nil
    }
    issuer := envelope.Issuer.Value
    if issuer == "" {
        return nil, fmt.Errorf("%w: response has no issuer", ErrWrongIssuer)
    }
    for _, candidate := range sp.idps {
        if candidate.EntityID == issuer {
            return candidate, nil
        }
    }
    return nil, fmt.Errorf("%w: unknown issuer %q", ErrWrongIssuer, issuer)
}
```

For a solicited response the IdP comes from the session — from what *this SP*
recorded when it made the request, not from anything in the response. That is
the strongest form: the attacker cannot choose which certificate their forgery is
checked against.

For an unsolicited one the issuer is read from the envelope, and an unknown
issuer is **refused rather than falling back to a default**. Falling back would
mean any configured certificate could vouch for any issuer — in a deployment
with Okta and Azure AD both registered, Okta's key could assert an Azure AD
user.

**6. Verify the signature:**

```go
var certs []*x509.Certificate
if idp != nil {
    if idp.Certificate != nil {
        certs = append(certs, idp.Certificate)
    }
    certs = append(certs, idp.ExtraCertificates...)
}
verified, err := sp.verifier.Verify(ctx, doc, certs)
```

Certificates come from the resolved IdP only, including `ExtraCertificates` for
signing-key rollover. The verifier is installed automatically when none was
supplied, because signature verification is the only thing authenticating an
assertion and must be opted *out* of rather than in to.
`WithAllowUnsigned` exists, and its doc comment says outright that it disables
authentication of the assertion entirely.

**7. Parse ONLY the verified bytes:**

```go
assertion, verifiedResponse, err := parseVerified(verified)
```

This is the XML Signature Wrapping defense, and it is structural rather than a
check that could be forgotten. `ValidatedDocument` carries `XML` — the
serialization of the element the signature actually covered — and **does not
carry the unverified tree**. `parseVerified` unmarshals from `verified.XML`,
never from `responseBytes`.

XSW is the attack where a document carries a legitimately signed element *and* an
attacker-injected one, arranged so the verifier checks the genuine element while
the application parses the forged one. Every implementation broken this way was
broken the same way: verified a signature over document A, read claims from
document B. Here there is no document B in scope.

The final link is `extractUser`'s signature:

```go
// It deliberately takes an *Assertion rather than a *Response: the signed
// element is the only thing that may contribute identity claims, and taking
// the envelope here would make it possible to read unverified content.
func (sp *ServiceProvider) extractUser(assertion *Assertion, idp *IdPConfig) *SAMLUser
```

A contributor who wants to read an attribute from the envelope cannot do it by
accident — there is no `*Response` in scope. Making it possible requires changing
the signature, which is a visible, reviewable act.

**8. Validate the assertion.** First, which envelope attributes are trustworthy:

```go
envelopeForValidation := verifiedResponse
if envelopeForValidation == nil && verified.CoveredResponse {
    envelopeForValidation = &envelope
}
```

SAML permits signing the `Response`, the `Assertion`, or both. When only the
assertion is signed, the enclosing `Response` is attacker-controlled — its
`Destination`, `InResponseTo`, and `Issuer` carry no authentication at all, and
checking them would prove nothing while creating the appearance of a check. In
that case `envelopeForValidation` stays nil and the envelope-level checks are
skipped, deliberately. The bindings are not lost: `SubjectConfirmationData` lives
*inside* the signed assertion and carries `Recipient`, `NotOnOrAfter`, and
`InResponseTo`, all covered by the signature.

Then `validateAssertion`, whose doc comment names what each check prevents:

- **Issuer** — compared against the resolved IdP's `EntityID`. Without it, any
  IdP whose certificate is configured can assert users belonging to another.
- **`NotBefore` / `NotOnOrAfter`** — against the injectable `domain.Clock` with
  `DefaultClockSkew = time.Minute` of tolerance. Without them an assertion is
  valid forever.
- **Audience** — and this is where Kayan is deliberately stricter than the spec:

```go
func (c Conditions) allowsAudience(audience string) bool {
    if len(c.AudienceRestrictions) == 0 {
        return false
    }
    // ...
}
```

  SAML 2.0 section 2.5.1.4 says an assertion with no audience restriction is
  unrestricted. Kayan refuses it. An unrestricted assertion is one that *any*
  service provider will accept, which makes it a universal credential — the
  spec-compliant reading is the insecure one.

- **Destination and Recipient** — the envelope `Destination` only when the
  envelope is trustworthy; the `SubjectConfirmationData.Recipient` inside the
  signed assertion unconditionally when present. Either catches an assertion
  captured at one ACS endpoint and replayed at another.
- **`InResponseTo`** — three cases:

```go
switch {
case opts.ExpectedInResponseTo != "":
    if response.InResponseTo != opts.ExpectedInResponseTo {
        return fmt.Errorf("saml: InResponseTo %q does not match request %q", ...)
    }
case response.InResponseTo != "":
    return fmt.Errorf("%w: InResponseTo %q matches no pending request", ErrUnsolicited, response.InResponseTo)
case !opts.AllowUnsolicited:
    return ErrUnsolicited
}
```

  The middle case is the one implementations miss. A response claiming to answer
  a request this SP never made is refused **even when unsolicited flows are
  permitted**, because it is not an unsolicited response — it is a forged answer
  to a nonexistent question.

**9. Replay check:**

```go
if replay != nil {
    if a.ID == "" {
        return ErrMissingAssertionID
    }
    expiry := a.Conditions.NotOnOrAfter
    if expiry.IsZero() {
        expiry = now.Add(time.Hour)
    }
    if err := replay.CheckAndStore(ctx, a.ID, expiry.Add(skew)); err != nil {
        return err
    }
}
```

An assertion with no ID is refused rather than allowed through unchecked — an
untrackable assertion is an infinitely replayable one. The `ReplayCache`
contract requires the check and store to be **atomic**, because a check-then-store
implemented as two operations loses to two concurrent presentations of the same
captured assertion.

The replay check runs **last**, after every other validation. That ordering is
right: recording the ID of an assertion that was going to be rejected anyway
would let an attacker burn IDs, and it would mean a legitimate assertion rejected
for a transient reason could never be retried.

`MemoryReplayCache` is per-process. Four replicas means a captured assertion
works four times. Use a shared cache.

**10. Reconcile the identity:**

```go
identifier := fmt.Sprintf("saml:%s:%s", user.IdPID, user.NameID)

if sp.hooks.UserLoader != nil {
    ident, err := sp.hooks.UserLoader(ctx, user.NameID, user.IdPID)
    if err == nil && ident != nil {
        return ident, nil
    }
}

cred, err := sp.identityRepo.GetCredentialByIdentifier(ctx, identifier, "saml")
if err == nil {
    return sp.identityRepo.GetIdentity(ctx, sp.factory, cred.IdentityID)
}

if sp.hooks.UserFactory != nil {
    return sp.hooks.UserFactory(ctx, user)
}

ident := sp.factory()
traits := identity.JSON(fmt.Sprintf(`{"email":"%s","first_name":"%s","last_name":"%s"}`,
    user.Email, user.FirstName, user.LastName))
if ts, ok := ident.(interface{ SetTraits(identity.JSON) }); ok {
    ts.SetTraits(traits)
}
return ident, sp.identityRepo.CreateIdentity(ctx, ident)
```

Namespacing the credential identifier as `saml:<idp>:<nameid>` is what keeps two
IdPs from colliding — the same `NameID` at Okta and at Azure AD are different
users.

**The built-in fallback is a demo, and its defaults are permissive.** Two
specific problems.

It **auto-provisions**: an unrecognized `NameID` from a configured IdP creates an
account. Whether that is right depends on whether your IdP's user population is
exactly your intended user population. If the IdP is a large directory and only a
subset should have access here, auto-provisioning grants access to all of it.

And it builds traits by **string-formatting attribute values into a JSON literal
without escaping**. A `NameID` or an email attribute containing a double quote
produces malformed JSON at best and injected trait fields at worst — the values
come from the assertion, which is signed by the IdP, so this is not an anonymous
attacker's input, but it is still user-influenced data reaching a JSON document
through `fmt.Sprintf`.

Supply `Hooks.UserFactory` or `Hooks.UserLoader` for anything beyond a demo, and
decide deliberately whether an unrecognized `NameID` should provision an account
at all.

Note also that the fallback path **does not create a credential** with the
`saml:` identifier it just looked up. The next sign-on for the same user will
miss the credential lookup again and create another identity. A production
`UserFactory` should write the credential.

### What SAML does not cover

**No Single Logout.** `Config.SLOUrl` and `IdPConfig.SLOUrl` exist as
configuration fields, and nothing anywhere parses, validates, or emits a
`LogoutRequest` or `LogoutResponse`. Signing out of your application does not
sign the user out of the IdP or of other SPs in the federation.

**No encrypted assertions.** `EncryptedAssertion` is not supported. Assertions
travel protected by TLS and nothing else, so anything with visibility into the
browser's POST body sees the attribute values.

**Metadata parsing is simplified and unauthenticated.** `ParseIdPMetadata`
extracts the entity ID, one SSO URL, and the first usable signing certificate.
`RegisterIdPFromMetadata` fetches over plain `http.Get` with no timeout and no
signature check on the document — anyone who can answer that request installs a
certificate that will then be trusted to assert identities. Treat metadata
ingestion as an operation you review, not one you automate from an untrusted URL.

---

## Related

- [Architecture Overview](./README.md) — module topology and the one-way
  dependency rule
- [Security Model](./security-model.md) — what fails closed, the adversarial
  test corpora, and the honest gap list
- [Strategy Internals](./strategy-internals.md) — managers, decorators, and
  hooks in detail
- [Storage Layer](./storage-layer.md) — the `domain.Storage` contract, token
  expiry, and the conformance suite
- [Extending Kayan](./extending-kayan.md) — writing a strategy, an adapter, or a
  verifier
- [Authorization Models](./authorization-models.md) — what happens after
  authentication
- [Sessions](../concepts/sessions.md) · [Strategies](../concepts/strategies.md)
- [Multi-Tenancy](../concepts/multi-tenancy.md) — resolving the tenant before any
  credential lookup
- [SAML reference](../reference/saml.md) ·
  [OIDC provider reference](../reference/oidc-provider.md)
- [AGENTS.md](../../AGENTS.md) — the `ctx`, fail-closed, and adversarial-testing
  rules
