# SAML 2.0

```go
import "github.com/getkayan/kayan/kayan-saml"
```

`kayan-saml` implements both halves of SAML 2.0 web single sign-on: a service
provider that consumes assertions from Okta, Entra ID, OneLogin, and any other
conforming identity provider, and an identity provider that issues them. It
covers SP-initiated and IdP-initiated flows, XML-DSig signature verification and
signing, assertion replay detection, and metadata generation and parsing.

This is the module where cryptographic correctness is hardest, and the API is
shaped by that. A SAML assertion is a bearer credential delivered through the
user's browser — the attacker holds the message and can rewrite it before it
arrives. The defense is not to validate more carefully; it is to make the
unverified document unreachable. `SignatureVerifier` returns the signed element
rather than a boolean, claims are read only from that element, and
`extractUser` takes an `*Assertion` rather than a `*Response` so the unsafe path
cannot be written at all. The XML Signature Wrapping section below explains why
that shape, and not a more thorough check, is what closes the attack.

---

## Service provider

### ServiceProvider

```go
type ServiceProvider struct {
    // Has unexported fields.
}

func NewServiceProvider(
    config Config,
    sessionStore SessionStore,
    identityRepo domain.IdentityStorage,
    factory func() any,
    opts ...SPOption,
) *ServiceProvider
```

The `factory` is the BYOS seam: it returns a fresh instance of your identity
struct, so Kayan reconciles a SAML subject into your model without knowing its
shape.

```go
sp := saml.NewServiceProvider(
    saml.Config{
        EntityID: "https://app.example.com/saml/metadata",
        ACSUrl:   "https://app.example.com/saml/acs",
        SessionTTL: 5 * time.Minute,
    },
    sessionStore,
    repo,
    func() any { return &User{} },
    saml.WithReplayCache(redisReplayCache),
)

sp.RegisterIdP(&saml.IdPConfig{
    ID:          "okta",
    EntityID:    "http://www.okta.com/exk1234",
    SSOUrl:      "https://example.okta.com/app/.../sso/saml",
    Certificate: idpCert,
    AttributeMapping: map[string]string{
        "email":      "email",
        "first_name": "firstName",
        "last_name":  "lastName",
    },
})
```

### SPOption

```go
type SPOption func(*ServiceProvider)
```

```go
func WithSignatureVerifier(v SignatureVerifier) SPOption
```

Replaces the signature verifier. The default requires a valid XML signature.
Supply your own to verify through an HSM, to pin a policy the default does not
express, or to use a different library.

```go
func WithReplayCache(c ReplayCache) SPOption
```

Replaces the assertion replay cache. The default is in-process, which is correct
for a single instance. Several replicas each keep their own, so an assertion can
be replayed once per replica — use a shared cache in that case. This is the
option a multi-replica deployment must set; the default silently degrades rather
than failing, because there is no way for the library to know how many copies of
itself are running.

```go
func WithSPSigner(s Signer) SPOption
```

Sets the signer for enveloped XML-DSig signatures, used on outgoing
`LogoutResponse` documents.

It does not sign redirect-binding messages. Those carry a detached signature in
the URL query, which needs a different primitive:

```go
func WithRedirectSigner(s RedirectSigner) SPOption
```

Sets the signer for HTTP-Redirect binding messages, which is what signs an
outgoing `AuthnRequest`. When `Config.SignRequests` is true and no redirect
signer is supplied, one is derived from `Config.PrivateKey`; supply this to
keep the key in an HSM. `Config.SignRequests` with neither a private key nor a
signer is an error at login rather than a silent downgrade to unsigned.

```go
func WithSPClock(c domain.Clock) SPOption
```

Sets the clock used for validity windows. Tests use a fake clock to drive an
assertion to the exact boundary of `NotOnOrAfter`.

```go
func WithAutoProvision() SPOption
```

Allows a valid assertion for a NameID with no existing identity to create one.

Off by default: whether an unknown user signing in should get an account is a
policy question, and for most deployments the identity provider decides who may
authenticate, not who may exist here. Without it such an assertion is refused
with [`ErrNoSuchIdentity`](#errors), which the caller can handle by directing
the user through its own onboarding.

When enabled, the `saml:` credential is written for the new identity so the
next sign-on finds it rather than provisioning again. That holds whether the
identity came from the built-in path or from `Hooks.UserFactory`.

### Config

```go
type Config struct {
    // EntityID is the unique identifier for this SP (usually a URL).
    EntityID string

    // ACSUrl is the Assertion Consumer Service URL where IdP sends responses.
    ACSUrl string

    // MetadataURL is where this SP's metadata is served (optional).
    MetadataURL string

    // SLOUrl is the Single Logout Service URL (optional).
    SLOUrl string

    // Certificate is this SP's public certificate for signature verification.
    Certificate *x509.Certificate

    // PrivateKey is this SP's private key for signing requests.
    PrivateKey *rsa.PrivateKey

    // AllowIdPInitiated allows IdP-initiated SSO (security consideration).
    AllowIdPInitiated bool

    // SignRequests determines if AuthnRequests should be signed.
    SignRequests bool

    // SignatureMethod for signing (default: RSA-SHA256).
    SignatureMethod string

    // SessionTTL for pending authentication sessions.
    SessionTTL time.Duration

    // ClockSkew tolerates clock differences against the identity provider when
    // checking assertion validity. Defaults to [DefaultClockSkew].
    ClockSkew time.Duration
}
```

`EntityID` is what the assertion's `AudienceRestriction` is checked against.
Getting it wrong means every assertion is refused with `ErrWrongAudience`, which
is the correct failure — an assertion minted for someone else must not be
accepted here.

`ACSUrl` is checked against the response `Destination` and the
`SubjectConfirmationData` `Recipient`. It must be the externally reachable URL,
not the internal one a reverse proxy forwards to, because the identity provider
put the external URL in the assertion.

`AllowIdPInitiated` is off by default and is a real security decision. An
IdP-initiated response has no `InResponseTo`, so nothing correlates it with a
request this service provider made. An attacker who obtains any valid assertion
for any user of that identity provider can deliver it to your assertion consumer
endpoint and be signed in as that user. Enable it only when a business
requirement demands it, and understand that CSRF protection on the endpoint
becomes the only remaining defense against a forced sign-in.

`ClockSkew` defaults to `DefaultClockSkew`.

### IdPConfig

```go
type IdPConfig struct {
    // ID is a unique identifier for this IdP (e.g., "okta", "azure-ad").
    ID string

    // EntityID is the IdP's entity ID from their metadata.
    EntityID string

    // SSOUrl is the IdP's Single Sign-On URL.
    SSOUrl string

    // SLOUrl is the IdP's Single Logout URL (optional).
    SLOUrl string

    // Certificate is the IdP's public certificate for verifying responses.
    Certificate *x509.Certificate

    // ExtraCertificates are additional certificates accepted during a signing
    // key rollover, when the identity provider may sign with either.
    ExtraCertificates []*x509.Certificate

    // NameIDFormat preferred format.
    NameIDFormat string

    // AttributeMapping maps SAML attributes to identity fields.
    AttributeMapping map[string]string

    // TenantID associates this IdP with a specific tenant (optional).
    TenantID string

    // Metadata is the raw IdP metadata XML (if loaded from URL).
    Metadata []byte
}

func ParseIdPMetadata(id string, metadata []byte) (*IdPConfig, error)
```

`Certificate` is the trust anchor for the entire integration. Every claim your
application acts on is trusted because a signature verified against this
certificate, so it must come from the identity provider's metadata over a
channel you trust, not from a field a tenant administrator can edit without
review.

`ExtraCertificates` exists because key rollover would otherwise require an
outage. During a rollover the identity provider may sign with either the old or
the new key; listing both means neither cutover instant breaks sign-in. Remove
the retired certificate once the rollover is complete — a certificate left in
the list is a key that can still mint assertions your service accepts.

`AttributeMapping` maps Kayan's canonical names (`email`, `first_name`,
`last_name`) to the attribute names this identity provider actually sends, which
differ between products. With no mapping, `extractUser` falls back to `email`,
`firstName`, and `lastName`, plus the WS-Federation email claim URI that Entra
ID uses.

### Registering identity providers

```go
func (sp *ServiceProvider) RegisterIdP(idp *IdPConfig)
func (sp *ServiceProvider) RegisterIdPFromMetadata(ctx context.Context, id, metadataURL string) error
func (sp *ServiceProvider) GetIdP(id string) (*IdPConfig, bool)
func (sp *ServiceProvider) GetMetadata() ([]byte, error)
func (sp *ServiceProvider) SetHooks(hooks Hooks)
```

`GetMetadata` returns this service provider's own metadata XML, which you serve
for the identity provider administrator to import.

### InitiateLogin

```go
func (sp *ServiceProvider) InitiateLogin(ctx context.Context, idpID string, returnURL string) (string, error)
```

Starts the SAML authentication flow and returns the redirect URL to the identity
provider. It generates an `AuthnRequest`, stores a pending `Session` recording
the request ID and the return URL, and encodes the request into the HTTP-Redirect
binding.

The pending session is what makes the eventual response solicited: it records
the request ID that the response's `InResponseTo` must match. Without it, every
response would have to be treated as unsolicited, with the correlation weakness
described above.

```go
url, err := sp.InitiateLogin(ctx, "okta", "/dashboard")
if err != nil {
    return err
}
http.Redirect(w, r, url, http.StatusFound)
```

### ProcessResponse

```go
func (sp *ServiceProvider) ProcessResponse(ctx context.Context, samlResponse, relayState string) (any, error)
```

Handles the SAML response from the identity provider and returns the
authenticated identity — a value of your own type, produced by the factory or by
the `UserFactory` hook.

The signature is verified before anything is trusted, and every claim is read
from the verified element rather than from the received document. That ordering
is what defeats XML Signature Wrapping: an attacker who wraps a legitimately
signed assertion around injected content cannot have the injected content read,
because the unverified tree is never parsed for claims.

The full sequence is: decode the base64 payload; verify the signature against
the identity provider's certificates, obtaining a `ValidatedDocument`; resolve
which identity provider sent it; unmarshal the assertion **from the verified
element only**; validate the assertion's conditions, audience, destination,
issuer, subject confirmation, and replay status; extract claims from the
assertion; reconcile the identity.

```go
func acsHandler(w http.ResponseWriter, r *http.Request) {
    if err := r.ParseForm(); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    ident, err := sp.ProcessResponse(ctx, r.PostFormValue("SAMLResponse"), r.PostFormValue("RelayState"))
    if err != nil {
        // Log err with detail; return nothing specific to the browser.
        http.Error(w, "authentication failed", http.StatusUnauthorized)
        return
    }

    user := ident.(*User)
    // Establish your own session here. Kayan does not write cookies.
}
```

---

## XML Signature Wrapping and how this API forecloses it

XML Signature Wrapping (XSW) is the attack this module is designed around, and
it is worth understanding why the usual mitigation — "validate carefully" — does
not work.

The attacker starts with a legitimately signed assertion, obtained by signing in
as themselves. XML-DSig signs a *reference* to an element, identified by its
`ID` attribute, and the reference still resolves after the document is
rearranged. So the attacker builds a new response containing both the original
signed assertion, moved somewhere the parser will not look, and a forged
assertion naming the victim, placed where the parser will look. The signature
still verifies, because the element it covers is present and unmodified. The
parser still finds an assertion, because one is exactly where it expects.

The historical bypasses in other libraries all have the same structure: a
verification step that answered "is this document signed?" with a boolean, and a
separate parsing step that read claims from the document. Those two steps
disagreed about *which element* was in question, and every disagreement is an
authentication bypass. Hardening the parser does not fix it, because the next
attacker finds a different position the parser and the verifier disambiguate
differently.

Kayan removes the disagreement by removing the second document.

**The verifier returns the element, not a verdict.**

```go
type SignatureVerifier interface {
    Verify(ctx context.Context, doc []byte, certs []*x509.Certificate) (*ValidatedDocument, error)
}
```

There is no `Verify(doc) bool`. The only thing a caller receives on success is
the portion of the message whose signature actually verified.

**The validated document carries no unverified tree.**

```go
type ValidatedDocument struct {
    Element *etree.Element

    XML []byte

    SignedAssertion bool

    CoveredResponse bool
}
```

`Element` is the signed element as verified, and `XML` is that element
serialized. Unmarshal from `XML`, never from the original request body. Because
the original document is not carried alongside, the Signature Wrapping family of
attacks cannot be expressed here: there is no unverified tree to read.

`SignedAssertion` reports whether the verified element was an `Assertion` rather
than the enclosing `Response`.

`CoveredResponse` reports whether the signature covered the enclosing `Response`.
This distinction decides which fields may be validated. When the signature
covered the response, the response's own attributes — `Destination`,
`InResponseTo`, `Issuer` — are authenticated and may be checked. When only the
assertion was signed, those attributes are attacker-controlled and must not be
used for any decision; validation relies instead on the equivalent bindings
inside the signed assertion, where `SubjectConfirmationData` carries `Recipient`,
`InResponseTo`, and `NotOnOrAfter`.

Getting that backwards is a subtle bypass in its own right: checking
`Response.Destination` when only the assertion was signed validates a value the
attacker wrote, which passes and proves nothing.

**The claim extractor cannot be handed a response.**

```go
func (sp *ServiceProvider) extractUser(assertion *Assertion, idp *IdPConfig) *SAMLUser
```

This is unexported, but its signature is the load-bearing detail. It takes an
`*Assertion` rather than a `*Response`, so the signed element is the only thing
that can contribute identity claims. Taking the envelope would make it *possible*
to read unverified content, and the goal is for the unsafe path to be
uncallable rather than merely discouraged. A future change that reintroduces the
attack has to change this signature, which is a visible edit in review, rather
than adding one field access that looks like every other field access.

---

## Signature verification

```go
type XMLDSigVerifier struct {
    // Has unexported fields.
}

func NewXMLDSigVerifier(opts ...VerifierOption) *XMLDSigVerifier

func (v *XMLDSigVerifier) Verify(_ context.Context, doc []byte, certs []*x509.Certificate) (*ValidatedDocument, error)
```

The default `SignatureVerifier`, backed by goxmldsig. `NewXMLDSigVerifier`
returns a verifier that requires a valid signature.

`Verify` returns the element the signature actually covers. When a `Response` and
its `Assertion` are both signed, the `Assertion` is returned, since that is the
element carrying the identity claims.

```go
type VerifierOption func(*XMLDSigVerifier)

func WithIDAttribute(name string) VerifierOption
func WithAllowUnsigned() VerifierOption
```

`WithIDAttribute` sets the attribute used to resolve signature references,
defaulting to `ID`, which is what SAML 2.0 uses.

`WithAllowUnsigned` accepts documents carrying no signature. **This disables
authentication of the assertion entirely: anyone able to reach the assertion
consumer endpoint can then assert any identity.** It exists for interoperability
testing against a local identity provider. Never enable it in production. There
is no partial version of this trade — an unsigned assertion is an unauthenticated
claim of identity, and accepting one means the endpoint will sign in whoever
asks.

### Implementing your own verifier

Implementations must:

- reject a document with no signature;
- verify the signature against the supplied certificates only;
- return the *signed* element, so callers cannot read unsigned content.

The third requirement is the one that is easy to get wrong. Returning the whole
document with a "yes, something in here was signed" flag reopens XSW completely.
If your implementation verifies through an HSM, the HSM returns a verdict — you
must still resolve which element the verified reference points at and return
that element, not the input.

XML-DSig is the only signature format SAML defines, so the format is not
configurable. The implementation is: supply your own to verify through an HSM,
to pin a policy the default does not express, or to use a different library.

## Signing

```go
type Signer interface {
    Sign(ctx context.Context, doc []byte) ([]byte, error)
}
```

Signs an outgoing SAML message. Implement it to keep the private key in an HSM
or KMS: Kayan calls `Sign` and never holds key material.

```go
type XMLDSigSigner struct {
    // Has unexported fields.
}

func NewXMLDSigSigner(key *rsa.PrivateKey, cert *x509.Certificate) (*XMLDSigSigner, error)

func (s *XMLDSigSigner) Sign(_ context.Context, doc []byte) ([]byte, error)
```

The default `Signer`. Signatures are RSA-SHA256. To use a different algorithm,
an HSM, or a KMS, implement `Signer` directly.

---

## Replay detection

```go
type ReplayCache interface {
    CheckAndStore(ctx context.Context, id string, expiresAt time.Time) error
}
```

Records assertion IDs that have been accepted.

A SAML assertion is a bearer credential: anyone holding a valid one can present
it. Only single-use enforcement stops an attacker who captures one — from a
proxy log, a browser history, a referrer header — from replaying it until it
expires. The validity window is typically five minutes, which is ample.

`CheckAndStore` records `id`, or returns `ErrReplay` if it was already recorded.
**The check and the store must be atomic.** Two concurrent presentations of the
same assertion must not both succeed. A read-then-write implementation has a
window between the two operations wide enough to drive a parallel request
through, and an attacker replaying an assertion will send both copies at once
precisely to hit it. In Redis, `SET key value NX EX ttl` is the atomic form; in
SQL, an insert against a unique index, treating the constraint violation as the
replay signal.

`expiresAt` lets an implementation expire entries: an assertion past its validity
window is refused by the time check anyway, so the cache needs to retain an ID
only until then.

```go
type MemoryReplayCache struct {
    // Has unexported fields.
}

func NewMemoryReplayCache(clock domain.Clock) *MemoryReplayCache

func (c *MemoryReplayCache) CheckAndStore(_ context.Context, id string, expiresAt time.Time) error
```

An in-process `ReplayCache`, and the default. It is correct for a single
instance only. Running several replicas gives each its own cache, so an
assertion can be replayed once per replica — use a shared cache (`kayan-redis`)
in that case.

---

## Assertion validation

```go
type ValidationOptions struct {
    Audience string

    Destination string

    ExpectedIssuer string

    ExpectedInResponseTo string

    AllowUnsolicited bool

    ClockSkew time.Duration
}
```

Carries what an assertion is checked against. Each field corresponds to a check
that, if skipped, allows a distinct attack.

**`Audience`** is this service provider's entity ID. An assertion whose
`AudienceRestriction` names someone else was minted for a different service and
must not be accepted here. Skipping this check means any assertion from the same
identity provider — including one minted for a low-value application the attacker
legitimately uses — is accepted by your high-value one.

**`Destination`** is this endpoint's URL, checked against the `Destination`
attribute and the `SubjectConfirmationData` `Recipient`. Skipping it means an
assertion captured at one endpoint can be delivered to another.

**`ExpectedIssuer`** is the identity provider's entity ID. Skipping it means an
assertion signed by any certificate you happen to trust is accepted regardless of
which identity provider minted it, which matters as soon as more than one is
registered.

**`ExpectedInResponseTo`** is the ID of the `AuthnRequest` this responds to. Empty
means the response is unsolicited.

**`AllowUnsolicited`** permits identity-provider-initiated sign-on. Such a
response has no `InResponseTo` to correlate, so nothing ties it to a request this
service provider made.

**`ClockSkew`** tolerates clock differences, defaulting to `DefaultClockSkew`.

### Constants

```go
const DefaultClockSkew = time.Minute
```

The tolerance applied to assertion validity windows. Clocks between a service
provider and an identity provider are rarely exactly aligned, and a strict
comparison rejects assertions that are legitimately fresh. One minute is a
deliberate compromise: large enough to absorb ordinary NTP drift, small enough
that it does not meaningfully extend the window in which a captured assertion is
replayable.

```go
const ConfirmationMethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
```

The bearer confirmation method used by web SSO. It names the property that makes
everything above necessary: possession of the assertion is sufficient to claim
the subject.

```go
const StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
```

The SAML status code for a successful response. Any other status means the
identity provider refused, and the response carries no usable assertion.

---

## Errors

### Signature handling

| Sentinel | Meaning |
|---|---|
| `ErrUnsigned` | The document carries no signature. |
| `ErrInvalidSignature` | The signature did not verify. |
| `ErrNoSigner` | Signing was requested with no signer configured. |
| `ErrNoVerifier` | Verification was requested with no verifier configured. |

```go
var (
    ErrUnsigned         = errors.New("saml: document is not signed")
    ErrInvalidSignature = errors.New("saml: signature verification failed")
    ErrNoSigner         = errors.New("saml: no signer configured")
    ErrNoVerifier       = errors.New("saml: no signature verifier configured")
)
```

`ErrNoVerifier` is a fail-closed error rather than a fallback to accepting
everything. A misconfiguration that leaves no verifier configured refuses every
sign-in, which is loud and immediately fixed, instead of accepting every
assertion, which looks identical to working.

### Assertion validation

```go
var (
    ErrReplay               = errors.New("saml: assertion replayed")
    ErrAssertionExpired     = errors.New("saml: assertion is expired")
    ErrAssertionNotYetValid = errors.New("saml: assertion is not yet valid")
    ErrWrongAudience        = errors.New("saml: assertion audience does not match this service provider")
    ErrWrongDestination     = errors.New("saml: assertion destination does not match this endpoint")
    ErrWrongIssuer          = errors.New("saml: assertion issuer does not match the configured identity provider")
    ErrUnsolicited          = errors.New("saml: unsolicited response")
    ErrMissingAssertionID   = errors.New("saml: assertion has no ID")
    ErrNoSuchIdentity       = errors.New("saml: no identity for this NameID")
)
```

Each corresponds to a check that, if skipped, allows a distinct attack.

| Sentinel | The attack it prevents |
|---|---|
| `ErrReplay` | A captured assertion presented a second time. |
| `ErrAssertionExpired` | An assertion presented after its validity window, extending a bearer credential indefinitely. |
| `ErrAssertionNotYetValid` | An assertion whose `NotBefore` is ahead of now, beyond the skew tolerance. |
| `ErrWrongAudience` | An assertion minted for a different service provider, replayed into this one. |
| `ErrWrongDestination` | An assertion captured at one endpoint, delivered to another. |
| `ErrWrongIssuer` | An assertion from an unexpected identity provider among several registered. |
| `ErrUnsolicited` | A response with no `InResponseTo` where one was required, so nothing ties it to a request this service provider made. |
| `ErrMissingAssertionID` | An assertion with no ID, which cannot be tracked for replay — refused rather than accepted untracked. |
| `ErrNoSuchIdentity` | Not an attack — a valid assertion for someone with no account here, refused because provisioning is opt-in. See [`WithAutoProvision`](#spoption). |

`ErrMissingAssertionID` deserves emphasis. An assertion without an ID is not
merely malformed; it is unreplayable-detectable, because there is nothing to
record in the replay cache. Accepting it would create a class of assertion
exempt from single-use enforcement, so it is refused instead.

Do not surface these distinctions to the browser. They tell an attacker exactly
which check their forged assertion failed, which turns each rejection into a
step of a working attack. Log them with full detail and return one generic
failure.

---

## Bindings

```go
func ParseRedirectBinding(values url.Values, parameter string) ([]byte, error)
func ParsePostBinding(values url.Values, parameter string) ([]byte, error)
```

`ParseRedirectBinding` decodes a SAML message from HTTP-Redirect query
parameters: base64, then DEFLATE decompression. `ParsePostBinding` decodes a
message from HTTP-POST form values: base64 only.

Both are transport-neutral. Pass `url.Values` from wherever the request arrived;
Kayan does not read from an `*http.Request` or write to a `ResponseWriter`.

```go
msg, err := saml.ParsePostBinding(r.PostForm, "SAMLResponse")
```

The `parameter` argument is the form or query key, which is `SAMLRequest` for a
message travelling toward the identity provider and `SAMLResponse` for one
travelling back.

```go
func (idp *IdentityProvider) PostBindingForm(acsURL string, response []byte, relayState string) ([]byte, error)
```

Renders the HTML form that delivers a SAML response to the service provider over
the HTTP-POST binding — the self-submitting form that carries an assertion too
large for a URL.

It returns bytes rather than writing to an `http.ResponseWriter`: transport
belongs to the caller.

```go
form, err := idp.PostBindingForm(acsURL, response, relayState)
if err != nil { /* ... */ }
w.Header().Set("Content-Type", "text/html; charset=utf-8")
w.Write(form)
```

---

## Identity provider

### IdentityProvider

```go
type IdentityProvider struct {
    // Has unexported fields.
}

func NewIdentityProvider(
    config IdPServerConfig,
    identityRepo domain.IdentityStorage,
    sessionStore SessionStore,
    opts ...IdPOption,
) *IdentityProvider
```

Kayan acting as a SAML identity provider, issuing assertions to registered
service providers.

```go
func (idp *IdentityProvider) RegisterSP(sp *SPRegistration)
func (idp *IdentityProvider) GetSP(id string) (*SPRegistration, error)
func (idp *IdentityProvider) GetMetadata() ([]byte, error)
func (idp *IdentityProvider) SetHooks(hooks IdPHooks)
func (idp *IdentityProvider) HandleSSORequest(w http.ResponseWriter, r *http.Request)
```

`HandleSSORequest` processes an incoming SSO request from a service provider and
is the main entry point for SP-initiated SSO. It is the one method in this module
that writes to an `http.ResponseWriter`, which makes it an exception to the
headless rule rather than an example of it. Prefer composing `ParseRedirectBinding`,
your own authentication check, and `PostBindingForm` when you want the transport
to stay yours.

### IdPServerConfig

```go
type IdPServerConfig struct {
    // EntityID is this IdP's unique identifier.
    EntityID string

    // SSOUrl is where SPs send authentication requests.
    SSOUrl string

    // SLOUrl is where SPs send logout requests (optional).
    SLOUrl string

    // MetadataURL is where this IdP serves its metadata.
    MetadataURL string

    // Certificate is this IdP's public certificate.
    Certificate *x509.Certificate

    // PrivateKey is for signing assertions.
    PrivateKey *rsa.PrivateKey

    // AssertionTTL is how long assertions are valid.
    AssertionTTL time.Duration

    // Issuer is the issuer value in assertions.
    Issuer string
}
```

`AssertionTTL` is the window during which a captured assertion can be replayed
against a service provider whose replay cache is absent or per-replica. Keep it
short — minutes, not hours. It is not a session lifetime; the service provider
establishes its own session once the assertion is consumed.

`PrivateKey` is only used by the default signer. Supply `WithIdPSigner` instead
to keep the key in an HSM.

### IdPOption

```go
type IdPOption func(*IdentityProvider)

func WithIdPSigner(s Signer) IdPOption
func WithIdPClock(c domain.Clock) IdPOption
```

`WithIdPSigner` sets the signer used for outgoing assertions. Implement `Signer`
yourself to keep the private key in an HSM or KMS.

### SPRegistration

```go
type SPRegistration struct {
    // ID is a unique identifier for this SP.
    ID string

    // EntityID is the SP's entity ID.
    EntityID string

    // ACSUrl is the SP's Assertion Consumer Service URL.
    ACSUrl string

    // SLOUrl is the SP's Single Logout URL (optional).
    SLOUrl string

    // Certificate is the SP's public certificate (optional, for signed requests).
    Certificate *x509.Certificate

    // NameIDFormat specifies the format for the user identifier.
    NameIDFormat string

    // AttributeMapping maps identity fields to SAML attributes.
    AttributeMapping map[string]string

    // TenantID associates this SP with a specific tenant.
    TenantID string

    // AllowedRedirectURIs for security validation.
    AllowedRedirectURIs []string
}
```

`ACSUrl` becomes the assertion's `Destination` and `Recipient`, and is the
address the assertion is delivered to. It is the identity provider's side of the
same allowlist concern the OAuth redirect URI has: an assertion is a credential,
and sending it to an attacker-supplied URL hands the credential over. Take it
from the registration, never from the request.

`AttributeMapping` maps your identity fields to the SAML attribute names this
service provider expects — the inverse direction of `IdPConfig.AttributeMapping`.

---

## XML types

These mirror the SAML 2.0 schema, simplified to what web SSO uses. Namespaces
are pinned in the struct tags, so an element in the wrong namespace does not
unmarshal into the field an attacker was aiming for.

### Response

```go
type Response struct {
    XMLName      xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
    ID           string     `xml:"ID,attr"`
    InResponseTo string     `xml:"InResponseTo,attr"`
    Version      string     `xml:"Version,attr"`
    IssueInstant time.Time  `xml:"IssueInstant,attr"`
    Destination  string     `xml:"Destination,attr"`
    Issuer       Issuer     `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Status       Status     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
    Assertion    *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}
```

The envelope. Its attributes are trustworthy only when
`ValidatedDocument.CoveredResponse` is true.

### Assertion

```go
type Assertion struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

    ID                 string             `xml:"ID,attr"`
    Version            string             `xml:"Version,attr"`
    IssueInstant       time.Time          `xml:"IssueInstant,attr"`
    Issuer             Issuer             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Subject            Subject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
    Conditions         Conditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
    AuthnStatement     *AuthnStatement    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement,omitempty"`
    AttributeStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}
```

The element that carries identity claims, and the element the signature must
cover. `ID` is required by SAML 2.0 and is what makes replay detectable — an
assertion with no ID cannot be tracked, and is refused with
`ErrMissingAssertionID`.

### Subject and confirmation

```go
type Subject struct {
    NameID NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`

    SubjectConfirmations []SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

type SubjectConfirmation struct {
    Method                  string                  `xml:"Method,attr"`
    SubjectConfirmationData SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

type SubjectConfirmationData struct {
    Recipient    string    `xml:"Recipient,attr,omitempty"`
    NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr,omitempty"`
    InResponseTo string    `xml:"InResponseTo,attr,omitempty"`
}

type NameID struct {
    Value  string `xml:",chardata"`
    Format string `xml:"Format,attr"`
}
```

`SubjectConfirmations` bind the assertion to a recipient and a moment in time.
Without them a captured assertion can be delivered to any endpoint.

`SubjectConfirmationData` is where those bindings live, and it is inside the
signed assertion — which is why it, rather than the response envelope, is what
validation relies on when only the assertion was signed. `Recipient` must match
this endpoint, `NotOnOrAfter` bounds the window, and `InResponseTo` correlates
with the `AuthnRequest`.

`Method` is `ConfirmationMethodBearer` for web SSO.

### Conditions

```go
type Conditions struct {
    NotBefore    time.Time `xml:"NotBefore,attr"`
    NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`

    AudienceRestrictions []AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

type AudienceRestriction struct {
    Audiences []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}
```

`AudienceRestrictions` name the service providers this assertion was minted for.
Without checking them, an assertion issued to one service is accepted by
another — which is the cross-service replay that `ErrWrongAudience` prevents.

`NotBefore` and `NotOnOrAfter` bound validity, compared against the configured
clock with `ClockSkew` tolerance.

### AuthnStatement

```go
type AuthnStatement struct {
    AuthnInstant time.Time     `xml:"AuthnInstant,attr"`
    SessionIndex string        `xml:"SessionIndex,attr,omitempty"`
    AuthnContext *AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext,omitempty"`
}

type AuthnContext struct {
    AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef,omitempty"`
}
```

Records how and when the subject authenticated. `AuthnInstant` is the SAML
equivalent of the OIDC `auth_time` claim, and matters for the same reason: an
assertion issued from a months-old identity provider session is
indistinguishable from one issued after a fresh password prompt unless you look.

`SessionIndex` identifies the identity provider session, and is what a single
logout request references. `AuthnContextClassRef` names the authentication
method, which is how a service provider can require multi-factor authentication
rather than trusting that it happened.

### Remaining protocol and metadata types

```go
type AuthnRequest struct {
    XMLName                     xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
    ID                          string        `xml:"ID,attr"`
    Version                     string        `xml:"Version,attr"`
    IssueInstant                time.Time     `xml:"IssueInstant,attr"`
    Destination                 string        `xml:"Destination,attr"`
    AssertionConsumerServiceURL string        `xml:"AssertionConsumerServiceURL,attr"`
    ProtocolBinding             string        `xml:"ProtocolBinding,attr"`
    Issuer                      Issuer        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    NameIDPolicy                *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`
}

type NameIDPolicy struct {
    XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
    Format      string   `xml:"Format,attr,omitempty"`
    AllowCreate bool     `xml:"AllowCreate,attr,omitempty"`
}

type Issuer struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Value   string   `xml:",chardata"`
}

type Status struct {
    StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type StatusCode struct {
    Value string `xml:"Value,attr"`
}

type Attribute struct {
    Name         string           `xml:"Name,attr"`
    FriendlyName string           `xml:"FriendlyName,attr"`
    Values       []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type AttributeStatement struct {
    Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type AttributeValue struct {
    Value string `xml:",chardata"`
}
```

An `AuthnRequest` naming its own `AssertionConsumerServiceURL` is why an identity
provider must take the delivery address from the service provider registration
rather than from the request.

Metadata types:

```go
type EntityDescriptor struct {
    XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
    EntityID         string            `xml:"entityID,attr"`
    IDPSSODescriptor *IDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
    RoleDescriptors  []interface{}     `xml:"-"`
}

type IDPSSODescriptor struct {
    XMLName             xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
    KeyDescriptors      []KeyDescriptor       `xml:"KeyDescriptor"`
    SingleSignOnService []SingleSignOnService `xml:"SingleSignOnService"`
}

type KeyDescriptor struct {
    Use     string  `xml:"use,attr"`
    KeyInfo KeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type KeyInfo struct {
    X509Data X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type X509Data struct {
    X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type SingleSignOnService struct {
    Binding  string `xml:"Binding,attr"`
    Location string `xml:"Location,attr"`
}
```

---

## Sessions, users, and hooks

```go
type Session struct {
    ID         string
    RequestID  string
    IdPID      string
    RelayState string
    CreateTime time.Time
    ExpiresAt  time.Time
    ReturnURL  string
}

type SessionStore interface {
    Save(ctx context.Context, session *Session) error
    Get(ctx context.Context, id string) (*Session, error)
    GetByRequestID(ctx context.Context, requestID string) (*Session, error)
    Delete(ctx context.Context, id string) error
}
```

Pending SAML authentication state, holding the `RequestID` that the eventual
response's `InResponseTo` must match. `GetByRequestID` is the lookup
`ProcessResponse` performs, and it must return an error for an unknown request
ID rather than a nil session and nil error — a nil session there would turn a
solicited flow into an unsolicited one.

```go
type SAMLUser struct {
    NameID       string
    NameIDFormat string
    IdPID        string
    SessionIndex string
    Attributes   map[string][]string

    Email       string
    FirstName   string
    LastName    string
    DisplayName string
    Groups      []string
}

func (u *SAMLUser) GetAttribute(name string) string
func (u *SAMLUser) GetAttributes(name string) []string
```

User information extracted from a verified assertion. `GetAttribute` returns the
first value; `GetAttributes` returns all of them, which is what group membership
needs.

Every field here originated in the signature-verified assertion. Nothing in a
`SAMLUser` came from the unverified envelope.

```go
type Hooks struct {
    BeforeAuthnRequest func(ctx context.Context, idpID string, req *AuthnRequest) error
    AfterAuthnRequest  func(ctx context.Context, idpID string, sessionID string)

    BeforeProcessResponse func(ctx context.Context, response *Response) error
    AfterProcessResponse  func(ctx context.Context, user *SAMLUser)

    OnError func(ctx context.Context, err error, idpID string)

    UserFactory func(ctx context.Context, user *SAMLUser) (any, error)
    UserLoader  func(ctx context.Context, nameID string, idpID string) (any, error)
    LinkUser    func(ctx context.Context, ident any, user *SAMLUser) error

    IDGenerator func() string
}
```

`BeforeProcessResponse` receives a `*Response` and runs before validation
completes. Use it for logging and metrics. Do not read identity claims from it
and do not make authorization decisions on its contents — that response has not
been verified, which is the whole reason `AfterProcessResponse` receives a
`*SAMLUser` built from the verified assertion instead.

`UserFactory`, `UserLoader`, and `LinkUser` are the reconciliation seam:
`UserLoader` finds an existing identity for a subject, `UserFactory` creates one
on first sign-in, and `LinkUser` attaches a SAML subject to an identity that
already exists. Just-in-time provisioning through `UserFactory` means anyone the
identity provider will authenticate gets an account in your system, so the
identity provider's own access policy becomes yours.

```go
type IdPHooks struct {
    BeforeSSO func(ctx context.Context, spID string, authnRequest *AuthnRequest) error
    AfterSSO  func(ctx context.Context, spID string, userID string)

    BeforeAssertion func(ctx context.Context, sp *SPRegistration, attrs map[string][]string) error

    AuthenticateUser  func(ctx context.Context, r *http.Request) (any, error)
    GetUserAttributes func(ctx context.Context, ident any, sp *SPRegistration) (map[string][]string, error)
    GetNameID         func(ctx context.Context, ident any, sp *SPRegistration) (string, error)

    OnError func(ctx context.Context, err error, spID string)
}
```

`AuthenticateUser` is called to authenticate the user. If nil, the identity
provider assumes the user is already authenticated via session. `GetNameID` and
`GetUserAttributes` are the BYOS seam on the issuing side: Kayan cannot know
which field of your model is the subject identifier a given service provider
expects.

---

## Login strategy

```go
type Strategy struct {
    // Has unexported fields.
}

func NewStrategy(sp *ServiceProvider, factory func() any) *Strategy

func (s *Strategy) ID() string
func (s *Strategy) BeginAuth(ctx context.Context, idpID string, returnURL string) (string, error)
func (s *Strategy) Authenticate(ctx context.Context, identifier, secret string) (any, error)
```

Adapts a `ServiceProvider` to `core/flow`'s `LoginStrategy` so SAML can be
registered alongside password and OIDC strategies.

`Authenticate` is not directly used for SAML, which is redirect-based; it is
called after the SAML response is processed. `BeginAuth` is the entry point,
delegating to `InitiateLogin`.
