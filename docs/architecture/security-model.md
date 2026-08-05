# Security Model

This document describes what Kayan actually enforces, where each check lives,
and what happens when a check cannot be satisfied. It also states, explicitly,
what is **not** covered — because a security document that only lists strengths
teaches a reader to trust things that were never built.

Two principles run through everything below.

**Fail closed.** When a security-relevant question cannot be answered, the
answer is refusal, not permission and not a silent default. A scoped query with
no tenant errors rather than returning every tenant's rows. An unknown PKCE
method fails rather than degrading to plaintext comparison. A confidential
client with no stored secret hash is refused rather than treated as needing no
secret.

**A wrong `allow` is worse than a crash.** An authorization path that fails
loudly can be fixed. One that silently permits — or silently denies — looks
identical to correct behavior and its outcome may depend on which replica
served the request. Kayan reports the error.

---

## SAML 2.0

`kayan-saml` is where cryptographic correctness is hardest, and it is the part
of the library with the most adversarial test coverage. SAML assertions are
bearer credentials delivered through the user's browser: the attacker controls
the transport, can capture and modify the message, and can replay it.

### Signature verification behind a swappable interface

XML-DSig is the only signature format SAML defines, so the *format* is not
configurable. The *implementation* is:

```go
type SignatureVerifier interface {
    Verify(ctx context.Context, doc []byte, certs []*x509.Certificate) (*ValidatedDocument, error)
}
```

The default is `XMLDSigVerifier`, backed by `github.com/russellhaering/goxmldsig`.
It is installed automatically — `NewServiceProvider` sets it when no verifier
was supplied, because signature verification is the only thing authenticating
an assertion and must be opted *out* of rather than in to.

The interface documents three obligations on any implementation:

> - reject a document with no signature;
> - verify the signature against the supplied certificates only;
> - return the *signed* element, so callers cannot read unsigned content.

Replace it with `WithSignatureVerifier` to verify through an HSM or apply a
stricter policy. The corresponding `Signer` interface exists so a private key
can stay in a KMS — Kayan calls `Sign` and never holds key material.

`WithAllowUnsigned` exists and its doc comment is unambiguous about the cost:

> This disables authentication of the assertion entirely: anyone able to reach
> the assertion consumer endpoint can then assert any identity. It exists for
> interoperability testing against a local IdP. Never enable it in production.

Certificates come from the resolved IdP's configuration, including
`ExtraCertificates` for signing-key rollover, so an assertion is verified
against that issuer's keys and no one else's.

### The XSW defense is structural

XML Signature Wrapping is the attack where a document carries a legitimately
signed element *and* an attacker-injected one, arranged so the verifier checks
the genuine element while the application parses the forged one. Every SAML
implementation that has been broken this way was broken the same way: it
verified a signature over document A and then read claims from document B.

Kayan's defense is not a check that can be forgotten. It is the shape of the
types.

```go
// ValidatedDocument is the portion of a SAML message whose signature has been
// verified.
//
// Claims must be read only from here. The unverified document is not carried
// alongside it, so the Signature Wrapping family of attacks — where a valid
// signature covers a decoy element while the parser reads an attacker's
// injected one — cannot be expressed: there is no unverified tree to read.
type ValidatedDocument struct {
    Element         *etree.Element
    XML             []byte
    SignedAssertion bool
    CoveredResponse bool
}
```

`Verify` returns the element the signature actually covers, serialized to
`XML`. The unverified tree is not attached. Then:

```go
// parseVerified unmarshals an assertion from verified bytes.
verified, err := sp.verify(ctx, responseBytes, idp)
assertion, verifiedResponse, err := parseVerified(verified)
```

The assertion is unmarshaled from `verified.XML` — the bytes the signature
covered — never from `responseBytes`.

And the final link, which is what makes the property hold under future edits:

```go
// extractUser reads user information from a verified assertion.
//
// It deliberately takes an *Assertion rather than a *Response: the signed
// element is the only thing that may contribute identity claims, and taking
// the envelope here would make it possible to read unverified content.
func (sp *ServiceProvider) extractUser(assertion *Assertion, idp *IdPConfig) *SAMLUser
```

**The unsafe path is uncallable, not merely discouraged.** A future contributor
who wants to read an attribute from the envelope cannot do it by accident —
`extractUser` has no `*Response` in scope. Making it possible would require
changing the signature, which is a visible, reviewable act rather than a
one-line oversight.

The envelope *is* parsed, but only for routing: the status code and the relay
state used to find the pending request. That is stated at the parse site:

```go
// The envelope is parsed only to read routing fields — the relay state
// correlation and the status code. Nothing from it reaches the identity.
var envelope Response
```

`TestSignatureWrappingRejected` in `attack_test.go` is the corpus. It builds a
genuinely signed response, then constructs an unsigned forged assertion naming
`admin@example.com`, and places it three ways: before the signed assertion (for
a parser taking the first match), after it (for one taking the last), and with
the signed assertion relocated into an `<Extensions>` element so the forged one
sits where the schema expects. The assertion is not merely that an error is
returned:

> Rejecting outright is the expected outcome. Accepting is only tolerable if
> the identity is the signed one, never the injected one — that assertion is
> what makes this test meaningful even if the underlying library changes
> behavior.

That is the right shape for this test. A test that only checks `err != nil`
would pass if goxmldsig started rejecting the payload for an unrelated reason,
and would stop testing Kayan's own defense.

### `CoveredResponse` and when envelope attributes are trustworthy

SAML permits signing the `Response`, the `Assertion`, or both. This distinction
is security-relevant and most implementations ignore it.

When only the assertion is signed, the enclosing `Response` element is
**attacker-controlled**. Its `Destination`, `InResponseTo`, and `Issuer`
attributes carry no authentication whatsoever — an attacker who captures a
signed assertion can wrap it in a `Response` of their own construction with any
attribute values they like.

`ValidatedDocument.CoveredResponse` records which case applies:

```go
// CoveredResponse reports whether the signature covered the enclosing
// Response. When it did, the response's own attributes — Destination,
// InResponseTo, Issuer — are authenticated and may be validated. When only
// the assertion was signed they are attacker-controlled and must not be.
```

The consuming logic:

```go
// The envelope's own attributes — Destination, InResponseTo, Issuer — are
// only trustworthy when the signature covered the Response. When just the
// assertion was signed, the SubjectConfirmationData inside it carries the
// equivalent bindings and is what validation relies on instead.
envelopeForValidation := verifiedResponse
if envelopeForValidation == nil && verified.CoveredResponse {
    envelopeForValidation = &envelope
}
```

If the response was signed, `parseVerified` returns it from the verified bytes
and validation uses that. If only the assertion was signed,
`envelopeForValidation` stays nil and the envelope-level checks are skipped —
deliberately, because checking an unauthenticated value proves nothing while
creating the appearance of a check.

The bindings are not lost in that case. `SubjectConfirmationData` lives *inside*
the signed assertion and carries `Recipient`, `NotOnOrAfter`, and
`InResponseTo`. Those are covered by the signature and are what validation
relies on. The security property is preserved; it is just enforced from the
element that actually carries authentication.

When the verifier finds both a signed response and a signed assertion, it
prefers the assertion, since that is the element asserting the identity and
verifying the response alone would leave it unverified.

### Assertion validation

Every check in `validateAssertion` maps to a distinct attack. The function's
doc comment names them:

```go
// Each is load-bearing:
//   - Issuer: without it, any identity provider whose certificate is
//     configured can assert users belonging to another.
//   - Audience: without it, an assertion minted for a different service is
//     accepted here.
//   - Destination and Recipient: without them, an assertion captured at one
//     endpoint can be delivered to another.
//   - NotBefore/NotOnOrAfter: without them, an assertion is valid forever.
//   - InResponseTo: without it, an attacker can inject a response into a
//     sign-on the user did not begin.
//   - Replay: without it, a captured assertion works until it expires.
```

**Issuer.** Compared against the resolved IdP's `EntityID`. In a deployment
with several IdPs configured, omitting this check means Okta's certificate can
vouch for a user belonging to the Azure AD tenant.

**Validity window.** `NotBefore` and `NotOnOrAfter` are checked against the
injectable `domain.Clock` with a skew tolerance, `DefaultClockSkew =
time.Minute`. Skew exists because clocks between an SP and an IdP are rarely
aligned and a strict comparison rejects legitimately fresh assertions.

**Audience.** `Conditions.allowsAudience` requires an explicit match, and — this
is the important part — **conditions with no `AudienceRestriction` at all return
false**:

```go
func (c Conditions) allowsAudience(audience string) bool {
    if len(c.AudienceRestrictions) == 0 {
        return false
    }
    ...
}
```

SAML 2.0 section 2.5.1.4 says an assertion with no audience restriction is
unrestricted. Kayan refuses it anyway. An unrestricted assertion is one that
any service provider will accept, which makes it a universal credential — the
spec-compliant reading is the insecure one, and the test corpus includes
`"no audience restriction at all"` as a case that must be refused.

**Destination and Recipient.** The envelope `Destination` is checked only when
the envelope is trustworthy (above). The `SubjectConfirmationData.Recipient`
inside the signed assertion is checked unconditionally when present. Either
catches an assertion captured at one ACS endpoint and replayed at another.

**InResponseTo.** Three cases, and the middle one is the one implementations
miss:

```go
switch {
case opts.ExpectedInResponseTo != "":
    if response.InResponseTo != opts.ExpectedInResponseTo {
        return fmt.Errorf(...)
    }
case response.InResponseTo != "":
    // The response answers a request this service provider has no
    // record of.
    return fmt.Errorf("%w: InResponseTo %q matches no pending request", ErrUnsolicited, response.InResponseTo)
case !opts.AllowUnsolicited:
    return ErrUnsolicited
}
```

A response claiming to answer a request that this SP never made is refused even
when unsolicited flows are permitted, because it is not an unsolicited response
— it is a forged answer to a nonexistent question.

IdP-initiated SSO is off by default (`AllowIdPInitiated`). Such a response has
no `InResponseTo` to correlate, so nothing ties it to anything the user
started, which makes it a login CSRF primitive.

**Issuer resolution refuses unknown issuers.** For a solicited response the IdP
is known from the pending session. For an unsolicited one it is resolved by
issuer, and an unknown issuer is refused rather than falling back to a default
— otherwise any configured certificate could vouch for any issuer.

### Replay cache

```go
// A SAML assertion is a bearer credential: anyone holding a valid one can
// present it. Only single-use enforcement stops an attacker who captures one
// from replaying it until it expires.
type ReplayCache interface {
    // CheckAndStore records id, or returns [ErrReplay] if it was already
    // recorded. The check and the store must be atomic — two concurrent
    // presentations of the same assertion must not both succeed.
    CheckAndStore(ctx context.Context, id string, expiresAt time.Time) error
}
```

The atomicity requirement is explicit, because a check-then-store implemented
as two operations loses to two concurrent presentations of the same captured
assertion.

An assertion with no `ID` is refused with `ErrMissingAssertionID` rather than
being allowed through unchecked. An untrackable assertion is an infinitely
replayable one.

The default `MemoryReplayCache` is honest about its limits:

> It is correct for a single instance only. Running several replicas gives
> each its own cache, so an assertion can be replayed once per replica — use a
> shared cache (kayan-redis) in that case.

That is a real deployment constraint, not a theoretical one. Four replicas
means four uses of a captured assertion. Entries are swept on each call so the
cache does not grow for the life of the process.

### Denial of service on an unauthenticated endpoint

The ACS endpoint is reachable by anyone. `ParseRedirectBinding` inflates a
DEFLATE-compressed message, and DEFLATE can expand a tiny payload enormously:

```go
const maxDecodedMessageSize = 5 << 20 // 5 MiB
```

The read is bounded with `io.LimitReader(reader, maxDecodedMessageSize+1)` and
the result rejected if it exceeds the limit. `TestRedirectBindingRejectsDecompressionBomb`
covers it.

### What SAML does NOT cover

**No Single Logout.** `Config.SLOUrl` and `IdPConfig.SLOUrl` exist as
configuration fields, but there is no `LogoutRequest` or `LogoutResponse`
handling anywhere in the module. Nothing parses, validates, or emits SLO
messages. Signing out of Kayan does not sign the user out of the IdP or of
other service providers in the federation. If you need SLO, you are building it
yourself.

**No encrypted assertions.** `EncryptedAssertion` is not supported. An IdP
configured to encrypt assertions will not interoperate. Assertions travel
protected by TLS and nothing else, which means anything with visibility into
the browser's POST body sees the attribute values.

**Metadata parsing is simplified.** `ParseIdPMetadata` extracts the entity ID,
one SSO URL, and one signing certificate. It does not handle the full metadata
schema, does not verify metadata signatures, and takes the first usable
certificate it finds. Treat metadata ingestion as an operation you review, not
one you automate from an untrusted URL. `RegisterIdPFromMetadata` fetches over
plain `http.Get` with no timeout and no signature check on the document.

**Provisioning is opt-in.** The built-in `reconcileIdentity` refuses a NameID
with no existing identity, returning `ErrNoSuchIdentity`, unless the service
provider was built with `WithAutoProvision()`. Whether a valid assertion should
create an account is a policy question — the identity provider decides who may
authenticate, not who may exist here.

Traits are marshalled through `encoding/json`. They were previously built by
formatting attribute values into a JSON literal, so a display name containing
a double quote could add top-level keys to the trait object; a signed assertion
says nothing about what its attribute values contain. Supply
`Hooks.UserFactory` for any non-trivial identity model — it receives the whole
`SAMLUser` including the raw attribute map, and the `saml:` credential is
linked for you either way.

---

## OAuth 2.0

`kayan-oidc-provider/oauth2` implements the authorization code grant with PKCE,
refresh with rotation and reuse detection, and client credentials. Several of
the properties below exist because the opposite behavior was present earlier
and was fixed; the code comments say so, and this document preserves that
because the historical shape is exactly what a reviewer should check for.

### Client secrets are hashed, never compared directly

```go
// SecretHash is the hashed client secret, produced by the [domain.Hasher]
// the provider was configured with. It is never the secret itself: a
// database disclosure would otherwise hand over every client credential.
SecretHash string `json:"-"`
```

The field is `json:"-"`, so it cannot be serialized into a response by
accident. Verification goes through `domain.Hasher.Compare`, which is bcrypt's
constant-time comparison by default.

### Client authentication is mandatory

This is the fix worth understanding, because the bug class is common:

```go
// Confidential client: a secret is mandatory. Previously an empty secret
// skipped verification entirely, so omitting it authenticated the client.
if clientSecret == "" {
    return nil, ErrInvalidClient.WithDescription("client authentication failed")
}
if client.SecretHash == "" {
    // Registered as confidential but with no stored hash. Fail closed:
    // treating this as "no secret required" authenticates anyone.
    return nil, ErrInvalidClient.WithDescription("client authentication failed")
}
if !p.hasher.Compare(clientSecret, client.SecretHash) {
    return nil, ErrInvalidClient.WithDescription("client authentication failed")
}
```

An empty secret used to skip the check, which meant impersonating any
confidential client required *omitting* a parameter rather than guessing one.
The empty-secret path and the empty-hash path both now fail closed.

`Exchange` and `Refresh` both authenticate **before** touching the code or
token store:

```go
// Authenticate before touching the code store. Client authentication was
// previously skipped whenever the secret was empty, so a confidential
// client could be impersonated by simply omitting it.
if _, err := p.authenticate(ctx, clientID, clientSecret, GrantAuthorizationCode); err != nil {
```

Ordering matters beyond the bypass: an unauthenticated caller learns nothing
about whether a code exists.

A client is confidential unless it says otherwise — `authMethod()` defaults an
empty `TokenEndpointAuthMethod` to `client_secret_basic`. A public client
(`AuthMethodNone`) that presents a secret is **refused** rather than having it
ignored, since presenting one means the caller is confused about the
registration.

The error is identical whether the client is unknown or the secret is wrong, and
the unknown-client path performs a dummy bcrypt comparison against a fixed
valid hash so response timing does not distinguish the two. The client
credentials grant is refused to public clients, which by definition cannot hold
a secret.

### PKCE is required and cannot be downgraded

PKCE defaults to required (`requirePKCE: true` in `NewProvider`), and is
enforced at both ends — request parsing and code verification — so a client
cannot opt out by omitting the challenge:

```go
func (p *Provider) verifyCodeChallenge(authCode *AuthCode, verifier string) error {
    if authCode.CodeChallenge == "" {
        if p.requirePKCE {
            return ErrInvalidGrant.WithDescription("code_challenge is required")
        }
        return nil
    }
    ...
}
```

**An empty method must not mean plain.** This is subtle and it is the reason
`normalizeChallengeMethod` exists:

```go
// An empty method is *not* treated as "plain". RFC 7636 defaults an omitted
// method to plain, but accepting that at verification lets an attacker who
// intercepts an authorization request strip the method and replay the
// challenge as its own verifier. GenerateAuthCode resolves the method up
// front, so by the time a code is verified the field is always explicit.
func normalizeChallengeMethod(method string) string {
    switch strings.ToUpper(method) {
    case "S256":
        return challengeMethodS256
    case "PLAIN":
        return challengeMethodPlain
    default:
        return ""
    }
}
```

The attack: with S256, the challenge is `SHA256(verifier)` and an attacker who
intercepts the authorization request sees only the hash. If verification treats
an absent method as plain, the attacker strips `code_challenge_method` from the
request and later presents the *challenge itself* as the verifier — a plain
comparison of the challenge against itself succeeds. Following the RFC's
default here converts PKCE from a defense into a formality.

Verification fails closed on anything unrecognized:

```go
func (p *Provider) verifyPKCE(challenge, method, verifier string) bool {
    switch normalizeChallengeMethod(method) {
    case challengeMethodS256:
        sum := sha256.Sum256([]byte(verifier))
        expected := base64.RawURLEncoding.EncodeToString(sum[:])
        return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1

    case challengeMethodPlain:
        // Only reachable when the provider was explicitly built to allow it.
        if !p.allowPlainCC {
            return false
        }
        return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1

    default:
        // An unknown or absent method fails closed rather than degrading to a
        // plaintext comparison.
        return false
    }
}
```

`plain` requires `WithAllowPlainCodeChallenge(true)` and is checked a second
time inside `verifyPKCE`, so a stored `plain` code cannot be verified by a
provider not built to allow it. Both comparisons are constant-time.

`TestPKCECannotBeDowngradedToPlain` covers the downgrade directly.

### `redirect_uri` is an exact-match allowlist

```go
// AllowsRedirectURI reports whether uri is registered for this client.
//
// The comparison is exact. Prefix matching would let
// https://good.example.com.attacker.test through, and any form of wildcard
// matching has the same failure mode.
func (c *Client) AllowsRedirectURI(uri string) bool {
    for _, allowed := range c.RedirectURIs {
        if allowed == uri {
            return true
        }
    }
    return false
}
```

The `redirect_uri` is where the authorization code is delivered. Anything that
widens the match hands codes to an attacker-controlled endpoint, and every
convenience relaxation of this rule has produced a real vulnerability
somewhere.

Prefix matching fails because `https://app.example.test` is a prefix of
`https://app.example.test.evil.test`. Host-suffix matching fails because
`app.example.test@evil.test` is a valid URL whose *host* is `evil.test`.
Path-prefix matching fails because `/callback/../../evil` normalizes elsewhere.
Each of these looks safe until it is written out.

`TestRedirectURIAllowlist` is the adversarial corpus, and every entry is a real
technique:

```go
hostile := []string{
    "https://evil.example.test/callback",
    "https://app.example.test.evil.test/callback",    // suffix on the host
    "https://app.example.test@evil.test/callback",    // userinfo confusion
    "https://evil.test/?x=https://app.example.test/", // registered URI in a parameter
    "https://app.example.test/callback/../../evil",   // path traversal
    "https://app.example.test/callback/extra",        // prefix of a longer path
    "https://app.example.test:8443/callback",         // different port
    "http://app.example.test/callback",               // downgraded scheme
    "https://app.example.test/callback#evil",         // fragment
    "https://app.example.test/callback?next=//evil",  // open redirect in a query
    "https://аpp.example.test/callback",              // Cyrillic 'а' homoglyph
    "https://app.example.test/Callback",              // case differs
    "https://app.example.test/callback/",             // trailing slash
    "",                                               // empty
}
```

The homoglyph case is worth dwelling on: that first `а` is U+0430 CYRILLIC
SMALL LETTER A, visually identical to ASCII `a` in most fonts. Any matching
scheme that normalizes, lowercases, or Unicode-folds before comparing risks
accepting it. Byte equality does not.

The test also asserts the registered URI still works — a matcher that rejects
everything is not a passing implementation.

Two related behaviors. When `redirect_uri` is omitted, RFC 6749 allows
defaulting to the registered one only if exactly one is registered; with
several there is no safe way to choose and Kayan errors. And a rejected
`redirect_uri` error is **never redirected**:

```go
// Never redirect this error: sending it to an unregistered URI is the
// open redirect the allowlist exists to prevent.
```

### Authorization codes

Single-use, unconditionally:

```go
// The code is single-use regardless of what happens next. Leaving it live
// after a failed exchange would allow retrying the other checks.
defer func() { _ = p.authCodeStore.DeleteAuthCode(ctx, code) }()
```

The `defer` placement is the point: a code is consumed even when the exchange
fails on expiry, client mismatch, `redirect_uri` mismatch, or PKCE. Deleting
only on success would let an attacker brute-force the code verifier against a
live code.

The code is bound to its client, and a mismatch is treated as what it is:

```go
if authCode.ClientID != clientID {
    // The code belongs to another client: this is a code injection
    // attempt, not a mistake.
```

It is also bound to the `redirect_uri` from the authorization request, and to a
`Nonce` when one was supplied, which binds the resulting ID token to that
sign-in (OIDC Core 15.5.2).

### Refresh token reuse detection

Rotation alone is not theft detection. If a stolen refresh token is redeemed
and the spent one is deleted, the thief now holds the only valid token and the
legitimate client's next refresh merely fails — indistinguishable from an
expired session.

```go
// FamilyID links every token descended from one authorization. Rotation
// issues a new token in the same family, so presenting a token that was
// already redeemed can revoke the whole chain.
FamilyID string `json:"family_id"`

// UsedAt records when the token was redeemed. A redeemed token is kept
// rather than deleted: deleting it makes a replay indistinguishable from
// an unknown token, and the difference is what detects theft.
UsedAt *time.Time `json:"used_at,omitempty"`
```

Keeping the spent token resolvable is what creates the signal. On redemption of
an already-used token:

```go
// Reuse detection. A token presented twice means two parties hold it, so
// every token descended from the same authorization is revoked and the
// legitimate client is forced to re-authenticate.
if gr.IsUsed() {
    p.logAudit(ctx, "oauth2.refresh.reuse", clientID, gr.IdentityID, "failure",
        "refresh token replayed; revoking the token family")
    if hasFamily && gr.FamilyID != "" {
        if err := family.RevokeFamily(ctx, gr.FamilyID); err != nil {
            return nil, ErrServerError.WithCause(err)
        }
    }
    return nil, ErrInvalidGrant.WithDescription("invalid refresh token")
}
```

Whichever party presents the spent token proves the chain is compromised —
either the thief replaying it or the legitimate client whose token was stolen
after it rotated. Revoking the whole family is correct in both cases.

This requires the store to implement `RefreshTokenFamilyStore`. With a plain
`RefreshTokenStore`, rotation still happens and the spent token is deleted, so
**a replay is reported as invalid but the thief's own token keeps working**.
That degradation is documented on `Refresh` and is worth checking in any
deployment: reuse detection is a property of your store, not of the provider.

Lifetimes are `accessTokenTTL = time.Hour` and `refreshTokenTTL = 7 * 24 * time.Hour`.

### What OAuth 2.0 does NOT cover

Per the [README](../../README.md): `authorization_code`, `refresh_token`, and
`client_credentials` only. **No device code, no token exchange, no DPoP, no
`private_key_jwt`, and no dynamic client registration.** Only the code response
type is accepted — `token` and `id_token` are refused rather than silently
ignored, so no implicit flow is advertised that does not exist.

Scope enforcement is opt-in by registration: a client with no declared scopes is
unrestricted, and declaring any scope opts into enforcement. The same applies to
`GrantTypes`. This keeps existing registrations working, but it means a client
record created without scopes is not scope-limited. Populate both fields.

---

## Sessions

### Algorithm pinning on every parse path

The attack: a service verifies JWTs with an RSA public key. An attacker takes a
valid token, re-signs it with HS256 using the PEM text of that **public** key as
the HMAC secret, and submits it. A library that reads `alg` from the token
header and picks the verification method accordingly will HMAC-verify against a
value that is not secret — the public key is published, often at a JWKS
endpoint. The forgery verifies.

Kayan pins the algorithm to the configured one and routes every parse through a
single function:

```go
// keyFunc returns a jwt.Keyfunc that accepts only tokens signed with expected.
//
// Pinning the algorithm is what stops an attacker re-signing an RS256 token as
// HS256 using the PEM of the public key as the HMAC secret: the forged token
// verifies against the public key, which is not a secret. Every parse in this
// package goes through here so the check cannot be present on some paths and
// missing on others.
func (s *JWTStrategy) keyFunc(expected jwt.SigningMethod, key any) jwt.Keyfunc {
    return func(token *jwt.Token) (any, error) {
        if expected == nil {
            return nil, fmt.Errorf("session: no signing method configured")
        }
        if token.Method.Alg() != expected.Alg() {
            return nil, fmt.Errorf("session: unexpected signing method: %v", token.Header["alg"])
        }
        return key, nil
    }
}
```

"Every parse path" is the load-bearing phrase. `Validate`, `Refresh`, and
`Delete` all use it. `Delete` is the one that gets missed in other codebases,
because parsing there only reads the expiry:

```go
// Parse the token to read its expiry. The algorithm is pinned here for
// the same reason as on every other path: without it, a token forged
// with the public key as an HMAC secret would revoke an arbitrary
// session.
```

An unpinned `Delete` is a denial-of-service primitive: forge a token naming
someone else's session and revoke it.

`Refresh` pins independently, against `RefreshSigningMethod` when configured
and falling back to `SigningMethod`, so a separately-keyed refresh token is
still pinned.

`core/session/algconfusion_test.go` covers this with
`TestAlgorithmConfusionRejectedOnEveryPath`, `TestGenuineTokenStillWorks` (the
negative control that keeps the test honest), and
`TestHMACStrategyRejectsAsymmetricTokens` for the reverse direction.

### Stateless versus revocable

`NewHS256Strategy` and the general `NewJWTStrategy` are stateless: validation
touches no database. The cost is that a token cannot be revoked before it
expires, which is why examples use short expiries.

`Delete` on a stateless strategy with no revocation store is a **no-op**. That
is documented rather than hidden, because a logout that silently does nothing
is worse than one that fails. Attach `WithRevocationStore` or use
`NewDatabaseStrategy` when immediate revocation matters.

Per the [README](../../README.md), the cross-application SSO store in
`core/session` is **in-memory only**, so single sign-on is single-process.

---

## Password authentication

### Response timing does not reveal whether an account exists

`PasswordStrategy.Authenticate` performs a hash comparison on both outcomes. An
identifier with no account is compared against a dummy hash, so it costs
roughly what a real one does.

Identical error strings are not sufficient on their own. Skipping the hash on
the not-found path made a miss return in microseconds while a hit paid for a
full bcrypt comparison — around 250ms at the default cost. That gap is
measurable over a network and enumerates accounts without any special tooling.

The dummy hash is produced by the configured `domain.Hasher` rather than by
bcrypt directly, so the property survives a caller swapping in argon2id, and it
is computed once per strategy. Both the classic credential lookup and the BYOS
field-mapped query are covered — they return from different branches.

Only a genuine miss pays for it. A wrong password against a real identity has
already done its comparison, and adding a second would create the inverse leak.

### Registration does not hand back an existing identity

With a `Linker` configured, password registration against an address that
already has an identity returns `ErrIdentityAlreadyExists`. The submitted
password is never compared against the stored credential, so returning the
existing identity would make the registration endpoint hand out other people's
accounts to whoever types their address — and a handler that issues a session
on "registration succeeded" would log the attacker in as the victim.

Unification still applies to federated methods, where an identity provider
vouched for the address. `WithAllowPasswordCapture()` restores the previous
behaviour for callers migrating off it, and should be paired with separate
proof of control over the address.

### Lockout covers both entry points

`LockoutStrategy` checks the lockout store in `Authenticate` **and** in
`Initiate`. For a single-step strategy only the former runs, but `Initiate` is
where authentication begins for OTP and magic link — a lockout that skipped it
would let a locked account be made to send codes indefinitely, and would not
apply at all to a strategy whose real check happens there.

Both go through one `checkLocked` helper rather than two copies, so a third
entry point cannot silently omit it.

---

## Multi-tenancy

Isolation fails closed. This is the shortest section and one of the most
important.

```go
// ErrNoTenant reports that a tenant-scoped operation was attempted with no
// tenant in the context.
//
// Storage adapters must treat this as a failure rather than as "return
// everything": silently widening a scoped query is how one customer's data
// reaches another.
ErrNoTenant = errors.New("tenant: no tenant in context")
```

A scoped query with no tenant in context **errors**. It does not run unscoped.
Silently returning every tenant's rows to a caller who believes they asked a
narrow question is the worst available outcome — it produces no error, no log
line, and no symptom until the data is somewhere it should not be.

Enforcement is at the storage layer, applied by callback rather than by each
repository method:

> Isolation is applied by a callback rather than by each repository method
> remembering to add a predicate. Per-method application is how leaks happen:
> the one query somebody forgets is the one that returns another customer's
> rows, and nothing fails until it does.

Deliberate cross-tenant work is explicit and greppable:

```go
// A background job that spans tenants by design.
ctx = tenant.WithSystemContext(ctx)
```

`tenant.Verify` handles adapters that cannot push a predicate into the query,
returning `ErrCrossTenant` for a record belonging to someone else. Its error
message deliberately does not name the record's actual tenant — doing so would
confirm the record exists and disclose its owner.

One adapter-author trap: `RequireID` returns `("", true)` for a system context
— empty ID with `ok` true. Checking only `ok` and appending `tenant_id = ""`
breaks every system-context operation. See
[Storage Layer](./storage-layer.md) for the full contract.

---

## RBAC

An undefined role is reported, not silently treated as granting nothing:

```go
ErrRoleNotFound = errors.New("rbac: role is not defined")
```

A dangling role assignment — a role deleted while assignments still name it, or
a typo — produces `ErrRoleNotFound` from `GetPermissions` and `HasPermission`
rather than an empty permission set. `AssignRole` also refuses to assign an
undefined role, so a typo surfaces at write time.

The reason, from the resolution code:

```go
// A missing parent is a broken definition, not an absence of
// permission. Reporting it lets an operator fix the role instead
// of debugging a mysterious denial.
```

A legitimate refusal and a broken configuration need different responses.
Collapsing both into `false` hides the second behind the first, and the
resulting incident presents as "permissions randomly stopped working" — with
behavior that may differ per replica if roles are held in process memory.

Wildcards are honored only in grants, never in the permission being checked;
otherwise a caller could ask "may I do anything?" and be answered yes because
some narrow grant matched. Matching is segment-based string comparison, not
regex — a regex in a permission string is a denial-of-service vector and its
semantics are unclear to whoever authors the grant. See
[Authorization Models](./authorization-models.md) for the full matcher.

---

## Token entropy

`IDGenerator` and `TokenGenerator` are separate types, and that separation is a
security control rather than a typing preference:

```go
// IDGenerator is a function that generates a new ID.
//
// It is for record identifiers, where any scheme works — UUIDv4, UUIDv7,
// ULID, or a database sequence. Use [TokenGenerator] for anything an attacker
// must not be able to predict.
type IDGenerator func() any

// TokenGenerator produces a security token: an authorization code, refresh
// token, or session identifier.
//
// The two are separate types so that a generator chosen for readable record
// IDs cannot be wired into a credential path by accident.
type TokenGenerator func() (string, error)
```

Record IDs legitimately optimize for sortability and readability — UUIDv7 is
time-ordered by design, and a database sequence is trivially enumerable. Those
same properties are catastrophic in an authorization code or a magic-link
token, where the entire security property is that an attacker cannot guess the
next value.

Because they are distinct named types, a UUIDv7 generator cannot be passed
where a `TokenGenerator` is expected. The compiler refuses. The failure mode
this prevents is real and quiet: predictable tokens produce no error and pass
every functional test.

```go
const DefaultTokenBytes = 32
var DefaultTokenGenerator = NewTokenGenerator(DefaultTokenBytes)
```

32 bytes from `crypto/rand`, well beyond the 128-bit floor RFC 6749 section
10.10 sets for authorization codes. `NewTokenGenerator` **panics** for `n < 16`
rather than quietly producing a weak generator.

`TestAuthCodesAreUnpredictable` covers the OAuth 2.0 path.

Password hashing defaults to bcrypt at `DefaultBcryptCost = 12`, and the hasher
**rejects** secrets over 72 bytes rather than truncating — bcrypt silently
ignores input past 72 bytes, which would mean two passwords sharing a 72-byte
prefix both verify.

---

## Testing posture

Two rules from [AGENTS.md](../../AGENTS.md) shape the security tests, and both
exist because this repository has had tests that violated them.

> **Security tests must be adversarial, and must be able to fail.** A test
> asserting `err != nil` often passes for the wrong reason — a dependency
> rejecting the input, a nil pointer, an unrelated validation. Assert the
> specific error, then verify by reverting the fix and confirming the test
> fails. Several tests in this repo were worthless until that check was run on
> them.

### Adversarial corpora

Security tests are tables of hostile inputs, not single happy-path negatives.
Three of them are described above:

- **XSW variants** — forged assertion first, forged assertion last, signed
  assertion relocated into `<Extensions>`. Asserts on the *resulting identity*,
  not just on error presence.
- **`redirect_uri`** — fourteen entries covering host suffix, userinfo
  confusion, path traversal, port, scheme downgrade, fragment, Cyrillic
  homoglyph, case, and trailing slash, plus a positive control.
- **Algorithm confusion** — every parse path, in both directions, with a
  genuine-token control.

Plus `TestConditionCorpus` for the SAML validity checks: expired, not yet
valid, wrong audience, and no audience restriction at all.

Each corpus asserts a **specific** sentinel — `errors.Is(err, ErrInvalidRequest)`,
`errors.Is(err, ErrReplay)` — rather than `err != nil`. A bare non-nil check
passes when the input is rejected for an unrelated reason, which means it stops
testing the defense the moment the code around it changes.

### Fuzzing

Nine fuzz targets across three modules:

| Module | Targets |
|---|---|
| `kayan-oidc-provider/oauth2` | `FuzzParseAuthorizeRequest`, `FuzzParseTokenRequest`, `FuzzVerifyPKCE` |
| `kayan-saml` | `FuzzParseRedirectBinding`, `FuzzParsePostBinding`, `FuzzProcessResponse` |
| `kayan-scim` | `FuzzParseFilter`, `FuzzParsePath`, `FuzzParsePatchOp` |

They target exactly the parsers that accept attacker-controlled bytes on
unauthenticated endpoints. CI discovers targets by grep and runs each for 30
seconds on every push, across three parallel runners.

Anything under `testdata/fuzz/` is a previously-found crasher and runs as a
regression test regardless of the fuzzing budget. **Do not delete those files.**
There is currently one: a `FuzzParseFilter` crasher in `kayan-scim`.

```bash
cd kayan-saml && go test -run '^$' -fuzz FuzzProcessResponse -fuzztime 30s ./...
```

### Mutation verification

> For a security fix, also revert it and confirm the test fails. A test that
> passes either way proves nothing, and this repository has had several.

Every security fix in this repository was reverted to confirm its test fails.
This is the only way to know a test is testing anything. A test written
alongside a fix, run only against the fixed code, has never been observed to
fail — and a test that cannot fail is documentation with a `func Test` prefix.

The failures this catches are mundane and common: asserting `err != nil` where
some other error was always going to occur; a table where the hostile input was
malformed and rejected by the parser before reaching the check; a mock that
returns an error unconditionally.

The comments preserved in the source — "Previously an empty secret skipped this
entirely", "Client authentication was previously skipped whenever the secret
was empty" — exist so that a reviewer knows which regressions to check for.

### Other CI enforcement

`govulncheck` runs per module. CodeQL runs with `security-extended`. `gosec`
runs `continue-on-error: true` — it is advisory, not blocking. The examples job
rejects hardcoded placeholder secrets. Tests run with `-race`.

---

## Honest summary of gaps

Consolidated, so nothing above needs to be hunted for. The
[README](../../README.md) is the canonical list and is kept current.

**SAML**
- No Single Logout. `SLOUrl` fields exist; no SLO message handling does.
- No encrypted assertion support.
- Metadata parsing is simplified; metadata signatures are not verified.
- The default replay cache is per-process — an assertion is replayable once per
  replica.

**OAuth 2.0 / OIDC**
- `authorization_code`, `refresh_token`, `client_credentials` only. No device
  code, token exchange, DPoP, `private_key_jwt`, or dynamic client
  registration.
- Refresh reuse detection requires a store implementing
  `RefreshTokenFamilyStore`. With a plain store, a replay is reported invalid
  but the thief's token keeps working.

**Sessions**
- The cross-application SSO store is in-memory only; SSO is single-process.
- `Delete` on a stateless strategy with no revocation store is a no-op.

**ReBAC**
- `ListDirectObjects` returns direct grants only and does not walk the relation
  graph, so it can omit access that `Check` allows. `Check` is the
  authoritative answer. Do not use `ListDirectObjects` to build an access list
  or filter a result set.
- Exceeding `DefaultMaxDepth = 25` returns an error that aborts the whole
  check, not merely that branch.

**ABAC**
- Policies are **compiled Go, not data**. There is no policy store, no runtime
  authoring, and no hot reload. Changing a rule means redeploying. Tenant-
  authored policy needs a different engine behind the `policy.Engine` seam.
- One rule per action; `AddRule` overwrites silently.
- Under `AllowOverrides`, a `HybridStrategy` **swallows engine errors** — an
  engine that fails is treated as a non-objection.

**WebAuthn**
- Only `OnCloneWarning` is invoked. The other nine `WebAuthnHooks` fields are
  declared and never called, so setting them has no effect. `CredentialSaver`
  and `UserLoader` are the ones most likely to mislead — both document
  themselves as replacing default behavior they do not currently replace.

**Storage**
- `kayantesting.StorageSuite` does not cover `audit.AuditStore` or tenancy.
- `kayan-gorm` does not currently run the suite; it has equivalent bespoke
  tests.
- The bundled `gormIdentity`/`gormCredential`/`gormSession` models do not
  implement `tenant.Scoped`, so the isolation callbacks skip them.

**General**
- Pre-1.0. The public API changes without a deprecation cycle. See
  [VERSIONING.md](../../VERSIONING.md).

---

## Integration guidance

Things Kayan cannot do for you, because they are properties of your deployment.

**Use bearer tokens in an `Authorization` header.** Browsers do not attach
custom headers to cross-origin requests, so this pattern is CSRF-safe by
construction. All Kayan examples use it. If you put session tokens in cookies
instead, you must add CSRF protection — `SameSite` at minimum, or a
double-submit or synchronizer token pattern.

**Never expose internal error text at a public endpoint.** Return a generic
message and log the detail. Kayan's OAuth 2.0 errors are deliberately identical
across "unknown client" and "wrong secret"; preserve that at the handler.

**Resolve the tenant before any credential lookup**, and pass `r.Context()`
rather than `context.Background()`.

**Back lockout and rate limiting with shared storage** when running more than
one replica. The in-process implementations do not slow an attacker who is
load-balanced across four instances. The same applies to the SAML replay cache
and the RBAC `MemoryStrategy`.

**Give MFA and device trust a persistent store.** The in-memory implementations
lose every enrollment on restart, which locks out every user who enrolled a
second factor — they cannot re-enroll without signing in first.

**Keep the session secret out of source.** The examples read `SESSION_SECRET`
and refuse to start without it, because a secret committed in a sample is the
one that ends up signing real sessions.

**Use versioned migrations.** `AutoMigrateDev` has no way back.

Report vulnerabilities per [SECURITY.md](../../SECURITY.md).

---

## Related

- [Architecture Overview](./README.md) — module topology and why protocols were
  extracted
- [Authentication Flows](./authentication-flows.md) — where each check happens
  in a request
- [Authorization Models](./authorization-models.md) — RBAC, ABAC, ReBAC
  evaluation in detail
- [Storage Layer](./storage-layer.md) — the contract, tenancy, and the
  conformance suite
- [Strategy Internals](./strategy-internals.md) — managers, decorators, hooks
- [Sessions](../concepts/sessions.md) · [Multi-Tenancy](../concepts/multi-tenancy.md)
- [SAML reference](../reference/saml.md) · [OIDC provider reference](../reference/oidc-provider.md)
- [SECURITY.md](../../SECURITY.md) · [VERSIONING.md](../../VERSIONING.md)
- [AGENTS.md](../../AGENTS.md) — the adversarial-testing and fail-closed rules
