# Sessions

A session is what turns one successful authentication into many authorized
requests. Kayan ships two strategies behind one interface, and the choice
between them is a genuine trade rather than a default with an exotic
alternative.

```go
type Strategy interface {
    Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
    Validate(ctx context.Context, sessionID any) (*identity.Session, error)
    Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
    Delete(ctx context.Context, sessionID any) error
}
```

Every method takes a context. That is not decoration: a database-backed
strategy issues queries, and those queries need to be cancellable and
tenant-scoped like any other.

---

## The trade

**Stateless (JWT).** The token carries its own claims and a signature.
Validating it is a signature check and an expiry comparison — no database, no
shared state, no coordination between replicas.

The cost is that you cannot take it back. A token is valid until it expires,
which is why a stateless session should be short-lived. "Log out everywhere"
does not work, because there is nothing to delete.

**Revocable (database).** Every validation is a lookup, and deleting the row
ends the session immediately. Logout works. Administrative revocation works.
Compromise response works.

The cost is a database round trip on every authenticated request, and a store
that has to be available for anyone to stay logged in.

**Neither is the correct answer.** Short-lived stateless access tokens with a
revocable refresh token is the common compromise, and Kayan supports that
directly.

---

## Stateless sessions

```go
sessions := session.NewManager(
    session.NewHS256Strategy(os.Getenv("SESSION_SECRET"), 15*time.Minute),
)

sess, err := sessions.Create(ctx, uuid.NewString(), userID)
// sess.ID is the token to return to the client.
```

`NewHS256Strategy` is a convenience for a symmetric secret. The general form
takes any algorithm:

```go
sessions := session.NewManager(session.NewJWTStrategy(session.JWTConfig{
    SigningMethod: jwt.SigningMethodES256,
    SigningKey:    ecPrivateKey,
    VerifyingKey:  &ecPrivateKey.PublicKey,
    Expiry:        15 * time.Minute,

    // Refresh tokens may use a different key, and usually a longer life.
    RefreshSigningMethod: jwt.SigningMethodES256,
    RefreshSigningKey:    ecPrivateKey,
    RefreshVerifyingKey:  &ecPrivateKey.PublicKey,
    RefreshExpiry:        7 * 24 * time.Hour,
}))
```

RS256, ES256, EdDSA, and HS256 all work through identical wiring. When the
refresh fields are left unset, refresh tokens use the access-token key.

### Algorithm confusion is pinned out

Every parse path checks that the token's `alg` matches the algorithm the
strategy was configured with.

The attack this prevents: under an asymmetric configuration the verifying key
is public. An attacker re-signs a token as `HS256` using that public key as
the HMAC secret. A verifier that trusts the token's own `alg` header will
happily verify it, because the "secret" is a value the attacker has.

`Validate`, `Refresh`, and `Delete` share one `keyFunc` rather than each
implementing the check. The reason is direct: the check was once copy-pasted
into two of the three and missed on the third, and a per-path check is a check
that can go missing on one path.

### Revoking a stateless token

Attach a revocation store and the strategy gains a denylist:

```go
strategy := session.NewJWTStrategy(config).
    WithRevocationStore(session.NewMemoryRevocationStore())
```

`Delete` then records the token until its natural expiry, and `Validate`
consults the list.

**Without a revocation store, `Delete` returns an error.** There is genuinely
nothing server-side to remove, so the strategy refuses to report a successful
logout while the token remains valid.

`MemoryRevocationStore` is per-process. Several replicas each keep their own
list, so a token revoked on one is still accepted by the others — use a shared
store for anything running more than one instance.

---

## Revocable sessions

```go
sessions := session.NewManager(session.NewDatabaseStrategy(repo))
```

`repo` is any `domain.SessionStorage`. Sessions are rows; `Delete` removes
one; validation reads it.

Refresh rotates: redeeming a refresh token issues a new session and deletes
the old row, so the presented token stops working.

---

## Refresh and rotation

```go
sess, err := sessions.Refresh(ctx, refreshToken)
```

Rotation on every refresh limits the value of a stolen token — it works until
the legitimate client next refreshes, not indefinitely.

Detecting the theft is a separate problem, and one Kayan solves in the OAuth 2.0
provider rather than here. There, refresh tokens carry a family identifier and
a used marker: presenting a token that was already redeemed revokes the whole
family, because two parties holding the same token means one of them stole it.
See the [OIDC provider reference](../reference/oidc-provider.md).

**The stateless session path cannot do this.** A JWT refresh token is valid
because it is signed, not because a server remembers it, so a replay is
indistinguishable from a legitimate use. Rotation there limits exposure; it
does not detect compromise. That limitation is stated in the API
documentation rather than left for you to discover.

---

## Single sign-on across applications

`SSOManager` models one authentication shared by several applications:

```go
sso := session.NewSSOManager(session.NewMemorySSOStore())
```

A parent session is created once; each application joins it and receives its
own child session. Global logout ends the parent and returns the child
sessions for the caller to tear down — Kayan does not call other services, so
propagation is yours.

**`MemorySSOStore` is the only implementation that ships**, which makes single
sign-on single-process today. This is listed in the root
[README](../../README.md) as a known gap rather than left to be discovered.

---

## Session binding

`identity.Session` records what a session is, not where it came from:

```go
type Session struct {
    ID               string
    IdentityID       string
    RefreshToken     string
    ExpiresAt        time.Time
    RefreshExpiresAt time.Time
    IssuedAt         time.Time
    Active           bool
}
```

There is no IP address or user-agent field, and no binding to either. That is
a deliberate omission rather than an oversight: IP binding breaks users on
mobile networks and behind rotating proxies, and user-agent binding breaks on
browser update. Both are commonly requested and both cause more support load
than they prevent attacks.

If your threat model justifies it, `core/device` provides device
identification and `core/risk` scores signals — but note that a device
fingerprint is supplied by the client and therefore spoofable. It identifies a
device; it does not authenticate one.

---

## Practical guidance

**Keep stateless access tokens short.** Fifteen minutes is a reasonable
default. The window is exactly how long a stolen token stays useful.

**Read the secret from the environment.** Never from source. A secret
committed in a repository is the one that ends up signing production sessions;
the examples enforce this by refusing to start without `SESSION_SECRET`.

**Give logout something to do.** Either a database strategy or a revocation
store. Otherwise the endpoint returns 200 and changes nothing.

**Rotate keys with `core/keys`.** `keys.StaticProvider` serves an active key
for signing and retains superseded ones for verification, so rotation does not
invalidate every live session at once.

---

## Related

- [core reference](../reference/core.md) — `session` in full
- [Strategies](./strategies.md) — producing the identity a session is created for
- [Security Model](../architecture/security-model.md) — what session handling defends against
