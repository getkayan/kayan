# Strategies

An authentication method in Kayan is a strategy: a small object that knows how
to turn an identifier and a secret into an identity, and nothing else. Password
login, a magic link, a TOTP code, an API key, and an LDAP bind are all the same
shape. That is what lets a service add a second method without rewriting the
first, and what lets rate limiting and lockout wrap any of them without knowing
which one they wrapped.

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

Two methods each. `ID()` returns the method name a caller passes to the
manager — `"password"`, `"otp"`, `"webauthn"` — and the other method does the
work.

The return type is `any` because the identity is your struct. See
[BYOS](./byos.md) for why that is `any` plus a factory rather than a type
parameter.

---

## Why the interface is this small

A strategy is the place where a credential is checked, and everything it does
not have to do is something it cannot get wrong. It does not read an HTTP
request, so it cannot be confused by a header a proxy rewrote. It does not
create a session, so a strategy that returns an identity has not yet granted
anything — the caller decides what a successful authentication is worth. It does
not decide policy, so "this account is locked" and "this password is wrong" stay
separate concerns handled by separate code.

The cost is that a two-step method — send a code, then check it — does not fit
in one method call. That is what `Initiator` is for.

---

## Initiator: methods that take two steps

```go
type Initiator interface {
    Initiate(ctx context.Context, identifier string) (any, error)
}
```

A magic link and an OTP both need something to happen before the user can
present a secret: a token has to be generated, stored, and delivered. `Initiate`
does that half and returns whatever the caller needs to carry on — for a magic
link, the `*domain.AuthToken` whose `Token` field goes into the URL you email.

```go
result, err := login.InitiateLogin(ctx, "magic_link", "ada@example.com")
if err != nil {
    return err
}
token := result.(*domain.AuthToken)
// You send the email. Kayan does not.

// Later, from the link the user clicked:
user, err := login.Authenticate(ctx, "magic_link", "ada@example.com", token.Token)
```

`InitiateLogin` type-asserts the registered strategy to `Initiator` and returns
an error naming the method if it does not implement it. Calling it on the
password strategy is a programming error reported at the call, not a silent
no-op.

`Initiate` is deliberately not part of `LoginStrategy`. Making it part would
force every single-step strategy to write a method that returns "not
supported", and a method that exists but always fails is one somebody
eventually calls in a path where the failure is swallowed. `Attacher` below is
the same pattern for a different optional capability.

---

## Attacher: adding a method to an existing account

```go
type Attacher interface {
    Attach(ctx context.Context, ident any, identifier, secret string) error
}
```

Attaching is not authenticating. `Attach` takes an identity that is *already*
authenticated and binds a new credential to it — a user who signed in with a
password enrolling a passkey, or a user who arrived through Google setting a
password.

```go
// ident came from a completed Authenticate call in this request.
err := login.LinkMethod(ctx, ident, "password", "ada@example.com", newPassword)
```

`LoginManager.LinkMethod` asserts `Attacher` and returns an error for methods
that do not implement it, the same way `InitiateLogin` does for `Initiator`.

**The caller is responsible for the identity being genuine.** `LinkMethod`
attaches a credential to whatever identity it is handed; it has no way to know
whether the caller authenticated it a millisecond ago or read the ID out of a
query parameter. Passing an attacker-controlled identity here attaches the
attacker's credential to somebody else's account. Only pass an identity that
came from an `Authenticate` call in the same request.

`PasswordStrategy` and `OIDCManager` implement `Attacher`. Most others do not,
because enrollment for them is a ceremony with its own methods — WebAuthn
registration is `BeginRegistration` and `FinishRegistration`, not `Attach`.

---

## Registering strategies

```go
login := flow.NewLoginManager(repo, factory)
login.RegisterStrategy(flow.NewPasswordStrategy(repo, hasher, "Email", factory))
login.RegisterStrategy(flow.NewTOTPStrategy(totpRepo, factory, "Email"))
```

`RegisterStrategy` takes the lock, reads `s.ID()`, and stores the strategy in a
map under that key. There is no return value and no error.

Two consequences follow from it being a map keyed on `ID()`:

**Registering twice under the same ID replaces the first.** This is how the
decorators work — you register the wrapped strategy, not both — but it also
means a second `NewPasswordStrategy` registered later silently wins. If two
call sites both register `"password"`, the last one to run is the one that
authenticates users, and nothing reports that the first was discarded.

**The map is guarded by a mutex, so registration after startup is safe.** That
is what `ReloadStrategies` uses to rebuild strategies from a
`domain.StrategyStore` at runtime.

`Authenticate` looks the method up and returns `login: unknown method "x"` when
it is absent. An unregistered method is an error, never a fallthrough to some
default.

```go
user, err := login.Authenticate(ctx, "password", "ada@example.com", password)
```

`RegistrationManager.RegisterStrategy` is the same shape over
`RegistrationStrategy`, and `Submit` is its `Authenticate`:

```go
reg := flow.NewRegistrationManager(repo, factory)
reg.RegisterStrategy(pwStrategy)

user, err := reg.Submit(ctx, "password", traits, secret)
```

Most methods are login-only. `PasswordStrategy` is the one shipped type that
implements both interfaces; OTP explicitly does not, because a one-time code
proves possession of a phone number, not that an account should be created.

### MFA and the second factor

`Authenticate` checks whether the returned identity implements `MFAIdentity`
and reports `flow.ErrMFARequired` when `MFAConfig()` says MFA is enabled —
returning the identity *alongside* the error, so the caller can carry it into
the second step:

```go
user, err := login.Authenticate(ctx, "password", email, password)
switch {
case errors.Is(err, flow.ErrMFARequired):
    ok, err := login.VerifyMFA(ctx, user, totpCode)
    if err != nil || !ok {
        return errUnauthorized
    }
case err != nil:
    return errUnauthorized
}
```

A caller that checks `err != nil` and stops treats an MFA prompt as a failed
login, which is annoying but safe. A caller that ignores the error and creates
a session has skipped the second factor. Check for `ErrMFARequired` explicitly.

---

## The shipped strategies

Each entry says what the caller supplies. Where a strategy takes an interface
you have to implement, the reason is at the end of this section.

### Password — `"password"`

```go
strategy := flow.NewPasswordStrategy(repo, hasher, "Email", factory)
strategy.SetPasswordPolicy(&flow.PasswordPolicy{MinLength: 12, RequireDigit: true})
strategy.MapFields([]string{"Email", "Username"}, "PasswordHash")
```

Implements `LoginStrategy`, `RegistrationStrategy`, and `Attacher` — the only
shipped strategy that does all three. `hasher` is a `domain.Hasher`; bcrypt is
the default and argon2id is one implementation away.

`MapFields` names the fields that may be used as a login identifier and the
field holding the hash. Listing several identifiers is how a service accepts
either a username or an email address.

The whole thing is available in one call:

```go
reg, login := flow.PasswordAuth(repo, factory, "email",
    flow.WithPasswordPolicy(&flow.PasswordPolicy{MinLength: 12}),
)
```

`DefaultPasswordPolicy` is a minimum of 8 and a maximum of 128 with no
complexity rules. The maximum is not cosmetic: bcrypt truncates past 72 bytes,
and an unbounded input is a hashing-cost denial-of-service vector.

### Magic link — `"magic_link"`

```go
strategy := flow.NewMagicLinkStrategy(repo, tokenStore)
```

`LoginStrategy` and `Initiator`. `Initiate` looks up the credential for the
identifier, generates a token, saves it to the `domain.TokenStore` with a
15-minute TTL, and returns the `*domain.AuthToken`. **Kayan does not send the
email.** The token comes back to you and delivery is yours.

`Authenticate` takes the token as the secret, checks the type and expiry,
loads the identity, and deletes the token. Single use — a link that worked once
does not work twice, so a forwarded email or a link sitting in a proxy log is
spent.

### One-time password — `"otp"`

```go
otp := flow.NewOTPStrategy(repo, tokenStore, sender,
    flow.WithOTPTTL(5*time.Minute),
    flow.WithOTPCodeLength(6),
)
```

`LoginStrategy` and `Initiator`. It is **not** a `RegistrationStrategy`.

`sender` is an `OTPSender` you implement:

```go
type OTPSender interface {
    Send(ctx context.Context, recipient, code string) error
}
```

`Initiate` generates the code, stores it, and calls `Send`. `Authenticate`
takes the phone number or email as the identifier and the code as the secret.

### TOTP — `"totp"`

```go
strategy := flow.NewTOTPStrategy(totpRepo, factory, "Email")
```

`totpRepo` is a `TOTPRepository` you implement:

```go
type TOTPRepository interface {
    FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
    FindTOTPSecret(ctx context.Context, identityID any) (string, error)
    MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error
}
```

`Authenticate` accepts codes from the current, previous, and next 30-second
windows, which tolerates one step of clock drift. It then calls `MarkTOTPUsed`
with the time-step counter that matched.

**`MarkTOTPUsed` must return an error if that counter was already used.** That
is the replay defense, and it lives in your implementation because Kayan cannot
enforce uniqueness in a store it does not own. Without it a code shoulder-surfed
or captured from a phishing page stays valid for its whole window — the
strategy will happily accept the same six digits twice.

The failure modes are named: `ErrTOTPCodeInvalid`, `ErrTOTPReplay`,
`ErrTOTPSecretNotFound`.

`TOTPStrategy.Verify(secret, code string) bool` is a stateless helper —
`LoginManager.VerifyMFA` uses it. It takes no context and **does not enforce
replay protection**, because it has no repository to record the counter in. Use
it for the second factor after a primary authentication, not as a primary
credential check.

### WebAuthn — `"webauthn"`

```go
strategy, err := flow.NewWebAuthnStrategy(repo, flow.WebAuthnConfig{
    RPDisplayName: "Example",
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com"},
    SessionTTL:    5 * time.Minute,
}, factory, sessionStore)
```

WebAuthn is a ceremony, not a single call, and the real API is the four ceremony
methods rather than `Authenticate`:

```go
opts, sessionID, err := strategy.BeginRegistration(ctx, ident, userName, displayName)
cred, err := strategy.FinishRegistration(ctx, ident, sessionID, userName, displayName, response)

opts, sessionID, err := strategy.BeginLogin(ctx, identifier)
user, err := strategy.FinishLogin(ctx, identifier, sessionID, response)
```

`response` is a `*protocol.ParsedCredentialCreationData` or
`*protocol.ParsedCredentialAssertionData` from the go-webauthn protocol
package — you parse the client's JSON, Kayan verifies it.

`sessionStore` is a `WebAuthnSessionStore` holding the challenge between the two
halves of a ceremony:

```go
type WebAuthnSessionStore interface {
    SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error
    GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error)
    DeleteSession(ctx context.Context, sessionID string) error
}
```

`flow.NewMemoryWebAuthnSessionStore()` exists and is per-process. Behind a load
balancer, `BeginLogin` on one replica and `FinishLogin` on another will not find
the challenge, and every other login attempt fails. Use
`kayanredis.NewRedisWebAuthnSessionStore(client, prefix)` for more than one
instance.

`WebAuthnHooks.OnCloneWarning` fires when the authenticator's signature counter
goes backwards, which suggests a cloned credential. It is a security signal
worth logging.

### API key — `"api_key"`

```go
strategy := flow.NewAPIKeyStrategy(apiKeyRepo, factory)
```

Machine-to-machine. The key is the **secret** argument; the identifier is
ignored for lookup and exists only so you can pass a key-ID prefix for logging.

```go
sa, err := login.Authenticate(ctx, "api_key", "", rawKey)
```

`apiKeyRepo` is an `APIKeyRepository`:

```go
type APIKeyRepository interface {
    FindIdentityByAPIKeyHash(ctx context.Context, keyHash string, factory func() any) (any, error)
}
```

Only the hex-encoded SHA-256 hash is looked up. Issuing a key:

```go
rawKey, keyHash, err := flow.GenerateAPIKey(32)
// Store keyHash. Show rawKey to the user once — it cannot be recovered.
```

`flow.HashAPIKey(rawKey)` computes the same hash if you are importing existing
keys. Comparison inside the strategy uses `subtle.ConstantTimeCompare`.

Your implementation is responsible for the "active, unexpired" half of the
contract. `ErrAPIKeyExpired` and `ErrAPIKeyScopeInsufficient` exist for it to
return.

### Recovery code — `"recovery_code"`

```go
strategy := flow.NewRecoveryCodeStrategy(recoveryRepo, hasher, factory, "Email")
```

The escape hatch for a user who lost their second factor. Each code is single
use.

```go
type RecoveryCodeRepository interface {
    FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
    FindUnusedRecoveryCode(ctx context.Context, identityID any) (*RecoveryCodeRecord, error)
    MarkRecoveryCodeUsed(ctx context.Context, identityID any, codeID string) error
}
```

Issuing codes:

```go
plaintexts, hashes, err := flow.GenerateRecoveryCodes(hasher, 10)
// Show plaintexts once. Store hashes.
```

Errors: `ErrRecoveryCodeInvalid`, `ErrRecoveryCodeAlreadyUsed`,
`ErrNoRecoveryCodesRemaining`.

### LDAP — `"ldap"`

```go
strategy := flow.NewLDAPStrategy(dialer, flow.LDAPConfig{
    Addr:                   "ldap.example.com:636",
    BaseDN:                 "ou=users,dc=example,dc=com",
    UsernameAttribute:      "uid",
    ServiceAccountDN:       "cn=svc,dc=example,dc=com",
    ServiceAccountPassword: os.Getenv("LDAP_SERVICE_PASSWORD"),
    TraitAttributes:        map[string]string{"email": "mail"},
}, factory)
```

`Authenticate` binds as the service account to find the user's DN, then re-binds
as that user with the supplied password. The password is verified by the
directory and never stored on your side.

`dialer` is an `LDAPDialer`:

```go
type LDAPDialer interface {
    DialTLS(ctx context.Context, addr string) (LDAPConn, error)
}
```

The `kayan-ldap` module implements it over go-ldap:

```go
dialer := kayanldap.NewDialer(kayanldap.WithRootCAs(pool))
```

Only `DialTLS` exists. There is no plaintext dial, because an LDAP simple bind
sends the password in the clear.

Errors: `ErrLDAPInvalidCredentials`, `ErrLDAPUserNotFound`,
`ErrLDAPConnectionFailed`.

### Kayan OIDC — `"kayan_oidc"`

"Log in with Kayan" — the client side of authenticating against another Kayan
instance acting as the OIDC provider.

```go
strategy := flow.NewKayanOIDCStrategy(
    issuer, clientID, redirectURI,
    oauthConfig,  // OAuthConfiger
    tokenParser,  // IDTokenParser
    repo,         // KayanOIDCRepository
    factory,
)
```

`LoginStrategy` and `Initiator`. `Initiate` generates state, a PKCE verifier,
and a nonce, stores them, and returns the authorization URL. `Authenticate`
takes the **state** as the identifier and the **authorization code** as the
secret — the two query parameters from the callback URL:

```go
user, err := login.Authenticate(ctx, "kayan_oidc", r.URL.Query().Get("state"), r.URL.Query().Get("code"))
```

`OAuthConfiger` and `IDTokenParser` are interfaces so `core` does not import
`golang.org/x/oauth2` or a JWKS client. `KayanOIDCRepository` requires
`ConsumeOIDCState` to be single-use — that is the CSRF defense, and a state
value that can be consumed twice makes the check decorative.

Errors: `ErrKayanOIDCStateInvalid`, `ErrKayanOIDCStateExpired`,
`ErrKayanOIDCMissingIDToken`, `ErrKayanOIDCTokenInvalid`,
`ErrKayanOIDCNonceMismatch`.

### Social / OIDC — `OIDCManager`

Google, GitHub, Microsoft, and anything else OIDC. This one is a manager rather
than a `LoginStrategy`, because the redirect and the callback do not fit
`Authenticate`:

```go
mgr, err := flow.NewOIDCManager(repo, configs, factory)

url, err := mgr.GetAuthURL(providerID, state)
user, err := mgr.HandleCallback(ctx, providerID, code)
```

It implements `Attacher`, with the subject as the identifier and the provider ID
as the secret, so a social account can be linked to an existing identity.
`SetClaimMapper` controls how provider claims become traits, and `SetLinker`
controls account unification.

**You own the `state` parameter here.** `GetAuthURL` takes it and does not
generate or store it. Generate it with a cryptographically random source,
store it against the user's pre-login session, and compare it on the callback
before calling `HandleCallback` — otherwise the callback endpoint accepts a
code an attacker obtained, which is login CSRF.

---

## Why some strategies need an interface from you

Five strategies take an interface the caller must implement: `OTPSender`,
`TOTPRepository`, `APIKeyRepository`, `LDAPDialer`, and
`WebAuthnSessionStore`.

The reason is the same in each case, and it is architectural rather than
stylistic: **`core` never imports a sibling module, and it never imports a
protocol client.** There is no Twilio dependency in `core`, no SMTP client, no
`go-ldap`, and no Redis. If OTP delivery were built in, `core` would have to
pick a provider, and every user of Kayan would compile that provider's SDK
whether or not they send a single message — and the choice would be wrong for
most of them, since delivery is SMS in one deployment and an internal
notification bus in the next.

The storage-shaped ones are the same argument with a security edge.
`TOTPRepository.MarkTOTPUsed` has to be atomic against your database to be
replay-proof; a generic implementation over `domain.Storage` would either be
wrong under concurrency or force a locking model onto your schema. Kayan states
the contract and enforces the parts it can see.

What you give up is that these contracts are yours to get right, and the
document says which part matters: `MarkTOTPUsed` must reject a reused counter,
`ConsumeOIDCState` must be single-use, `FindIdentityByAPIKeyHash` must exclude
expired keys.

---

## Decorator strategies

`RateLimitStrategy` and `LockoutStrategy` are `LoginStrategy` implementations
that hold another `LoginStrategy` and delegate to it. Because they satisfy the
same interface, the manager cannot tell the difference — you register the
wrapper and the inner strategy is never registered at all.

```go
password := flow.NewPasswordStrategy(repo, hasher, "Email", factory)

limited := flow.NewRateLimitStrategy(password, limiter, flow.RateLimitConfig{
    Limit:  5,
    Window: time.Minute,
})

protected := flow.NewLockoutStrategy(limited, lockoutStore, 5, 15*time.Minute, 15*time.Minute)

login.RegisterStrategy(protected)   // ID() is still "password"
```

Both decorators forward `ID()` from the strategy they wrap, which is what makes
this transparent — the caller still authenticates with `"password"`. Both also
implement `Initiator` and forward `Initiate`, so wrapping a magic-link or OTP
strategy protects the send step too. That matters: without it, an attacker can
trigger unlimited SMS messages to a victim's phone at your expense.

### Ordering

Outermost runs first. In the example above, lockout is checked before the rate
limiter, and the rate limiter before the password comparison.

Put lockout outside rate limiting when you want a locked account rejected
without consuming rate-limit budget. Put rate limiting outside lockout when you
want to cap how often the lockout store is queried. Either is defensible; be
deliberate, because the order determines which store absorbs an attack.

### Rate limiting

```go
type RateLimiter interface {
    Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
    Reset(ctx context.Context, key string) error
}
```

Three in-process implementations ship: `NewMemoryRateLimiter` (sliding window),
`NewFixedWindowRateLimiter`, and `NewTokenBucketRateLimiter`. All three are
per-process. Behind four replicas, a limit of 5 is effectively 20, and an
attacker who round-robins across them gets the full multiple. Use
`kayanredis.NewRedisRateLimiter(client, prefix)` for anything with more than
one instance.

`RateLimitConfig.KeyFunc` decides what is being limited. The default is the
identifier itself — that is per-account, which stops a password-spray against
one account but not a spray across many. `flow.IPKeyFunc`, `flow.PrefixKeyFunc`,
`flow.ContextKeyFunc`, and `flow.CompositeKeyFunc` build composite keys:

```go
config := flow.RateLimitConfig{
    Limit:  5,
    Window: time.Minute,
    KeyFunc: flow.CompositeKeyFunc(
        flow.PrefixKeyFunc("login"),
        flow.IPKeyFunc(":"),
    ),
}
```

**`FailOpen` defaults to false**, so a rate limiter that errors denies the
request. That is the right default — a limiter whose Redis is down should not
become an open door — but it does mean a Redis outage stops logins. Set
`FailOpen: true` only when you have decided availability matters more than the
limit, and know that an attacker who can break your limiter has then disabled
it.

Denial returns a `*RateLimitError` carrying `RetryAfter` and `Remaining`.
Extract it with `flow.AsRateLimitError(err)` or test with
`flow.IsRateLimitError(err)` to set a `Retry-After` header.

### Lockout

```go
type LockoutStore interface {
    RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)
    ClearFailures(ctx context.Context, identifier string) error
    Lock(ctx context.Context, identifier string, duration time.Duration) error
    IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
}
```

`NewLockoutStrategy(next, store, maxFailures, lockoutDuration, failureWindow)`
covers the common case. `NewLockoutStrategyWithConfig` takes a `LockoutConfig`
with hooks — `OnLocked` for alerting, `OnFailure` for counting,
`ShouldRecordFailure` to skip counting certain errors, `CreateLockError` to
control what the caller sees.

`FailOpen` defaults to false here too: a lockout store that errors denies.

`flow.NewMemoryLockoutStore()` is per-process, with the same replica caveat.
`kayanredis.NewRedisLockoutStore(client, prefix)` is shared.

**Account lockout is a denial-of-service tool as well as a defense.** Locking on
a public identifier means anyone who knows a user's email can lock them out with
five wrong guesses. Consider a `KeyFunc` that includes the source address, a
lockout duration measured in minutes rather than until an administrator
intervenes, and rate limiting as the first line with lockout as the second.

---

## Step-up authentication

Step-up is not a strategy. It answers a different question: this session is
already authenticated, but is it authenticated *enough* for what it is about to
do?

```go
type StepUpPolicy interface {
    RequiredLevel(ctx context.Context, action string, resource any) StepUpLevel
}
```

Four levels: `StepUpNone`, `StepUpRecent`, `StepUpMFA`, `StepUpPassword`.

```go
mgr := flow.NewStepUpManager(store,
    flow.WithStepUpPolicy(&BankingPolicy{}),
    flow.WithRecencyWindow(15*time.Minute),
)

result, err := mgr.Evaluate(ctx, sessionID, "transfer_funds", nil)
if err != nil {
    return err
}
if !result.Allowed {
    // result.RequiredLevel and result.ChallengeType say what to ask for.
    return errStepUpRequired
}
```

After the user re-authenticates:

```go
err := mgr.RecordStepUp(ctx, sessionID, flow.StepUpPassword)
```

`StepUpStore` persists the records. `flow.NewMemoryStepUpStore()` is for tests
and single-process use; on restart every step-up is forgotten, which re-prompts
every user mid-flow.

**`Evaluate` returns an answer; it does not enforce one.** Nothing stops a
handler from ignoring `result.Allowed`. The check belongs at the top of the
sensitive handler, and a handler that forgets it has no step-up at all.

---

## Writing your own strategy

Two methods. Return the identity on success, an error on failure.

```go
type SSHKeyStrategy struct {
    repo    SSHKeyRepository
    factory func() any
}

func (s *SSHKeyStrategy) ID() string { return "ssh_key" }

func (s *SSHKeyStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
    ident, err := s.repo.FindIdentityBySSHFingerprint(ctx, identifier, s.factory)
    if err != nil {
        return nil, ErrInvalidCredentials
    }
    if !s.verifySignature(ident, secret) {
        return nil, ErrInvalidCredentials
    }
    return ident, nil
}
```

Four things to get right, each of which has been got wrong somewhere:

**Take the context and pass it down.** Not for style. The ambient tenant lives
in the context, so a storage call without one cannot be tenant-scoped — see
[Multi-Tenancy](./multi-tenancy.md). It is also how cancellation reaches your
database.

**Return one error for both "no such identity" and "wrong secret".** Different
errors let an attacker enumerate accounts by reading the response, and the
timing difference between an early return and a full hash comparison leaks the
same thing. If your lookup misses, compare against a dummy hash anyway.

**Compare secrets in constant time.** `subtle.ConstantTimeCompare` for raw
bytes; a `domain.Hasher` for anything password-shaped. `==` on a token leaks
its prefix through timing.

**Do not create a session.** Return the identity and let the caller decide.
A strategy that issues its own session has taken a decision that belongs to the
application, and it will be the wrong one somewhere.

If your method needs a preparation step, add `Initiate` and it becomes an
`Initiator`. If it can be enrolled onto an existing account, add `Attach` and it
becomes an `Attacher`. Neither requires changing anything else — the manager
type-asserts at the point of use.

### Registering a strategy from configuration

`StrategyRegistry` builds strategies from `*domain.StrategyConfig` records,
which is how strategies get enabled and disabled without a redeploy:

```go
login.Registry().RegisterFactory("ssh_key", func(cfg *domain.StrategyConfig) (flow.LoginStrategy, error) {
    return &SSHKeyStrategy{repo: repo, factory: factory}, nil
})

login := flow.NewLoginManager(repo, factory, flow.WithStrategyStore(store))
if err := login.ReloadStrategies(ctx); err != nil {
    return err
}
```

`ReloadStrategies` reads every config, builds the enabled ones, and deletes the
disabled ones from the map. A strategy that fails to build is logged and
skipped — the reload does not abort — so a broken config silently disables one
method rather than taking down every other. Watch for that in your logs; the
symptom otherwise is a login method that stopped existing.

---

## Related

- [BYOS](./byos.md) — why strategies return `any` and take a factory
- [Sessions](./sessions.md) — what to do with the identity a strategy returns
- [Multi-Tenancy](./multi-tenancy.md) — why every strategy method takes a context
- [Authorization](./authorization.md) — deciding what the authenticated identity may do
- [Strategy Internals](../architecture/strategy-internals.md) — how the managers dispatch
- [Authentication Flows](../architecture/authentication-flows.md) — the flows end to end
