# OAuth 2.0 and OpenID Connect Provider

```go
import (
    "github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
    "github.com/getkayan/kayan/kayan-oidc-provider/oidc"
    "github.com/getkayan/kayan/kayan-oidc-provider/gormstore"
)
```

`kayan-oidc-provider` turns a Go service into an OAuth 2.0 authorization server
and an OpenID Provider. It implements the authorization code grant with PKCE,
the refresh token grant with rotation and reuse detection, and the client
credentials grant, plus ID token issuance, discovery metadata, JWKS
publication, introspection, revocation, and back-channel logout. It has no
router and never writes to an `http.ResponseWriter`: the shape of every entry
point is `url.Values` in, validated struct out, or struct in, bytes out. That
is not an ergonomic preference. The redirect URI allowlist, the PKCE policy,
and the response type check all live inside `ParseAuthorizeRequest`, so a
caller who hand-parses the query string has to reimplement all three, and that
is exactly where open redirectors come from.

---

## Package `oauth2`

### Provider

```go
type Provider struct {
    // Has unexported fields.
}

func NewProvider(
    cs ClientStore,
    acs AuthCodeStore,
    rts RefreshTokenStore,
    issuer string,
    signingKey any,
    keyID string,
    opts ...ProviderOption,
) *Provider
```

`NewProvider` takes the three stores it cannot function without, the issuer
identifier that goes into every token's `iss` claim, and a signing key with its
key identifier. Everything else is an option with a secure default.

The `signingKey` parameter is the fallback path. A provider constructed with
only a bare key can sign tokens but cannot publish a JWKS document, because
there is no way to enumerate a single key — `JWKS` returns an error. Supply
`WithKeyProvider` when relying parties need to fetch your public keys, which is
every deployment that issues ID tokens to a third party.

```go
provider := oauth2.NewProvider(
    repo, repo, repo,
    "https://auth.example.com",
    privateKey, "2026-01",
    oauth2.WithKeyProvider(keyProvider),
    oauth2.WithClientSecretHasher(hasher),
)
```

### ProviderOption

```go
type ProviderOption func(*Provider)
```

```go
func WithKeyProvider(kp keys.Provider) ProviderOption
```

Supplies the signing keys used for tokens and published in JWKS. Without it,
the provider signs with the key passed to `NewProvider` and cannot publish a key
set. A `keys.Provider` is also what makes key rotation expressible: it can hold
the current signing key alongside recently retired verification keys, so tokens
minted before a rotation keep validating.

```go
func WithClientSecretHasher(h domain.Hasher) ProviderOption
```

Sets the hasher used to verify client secrets. It must be the same one used to
produce `Client.SecretHash` at registration — a mismatch makes every
confidential client fail authentication with `ErrInvalidClient`, which looks
identical to a wrong secret and is correspondingly hard to diagnose. Defaults
to bcrypt.

```go
func WithRequirePKCE(require bool) ProviderOption
```

Controls whether an authorization code must carry a PKCE challenge. Defaults to
`true`. Disabling it allows an authorization code interception attack against
public clients (RFC 7636 section 1): a malicious application registered for the
same custom URI scheme receives the code from the system browser and, with no
verifier to present, can redeem it. Turn it off only for a legacy confidential
client that cannot be updated, and prefer scoping that decision to the client
rather than to the whole provider.

```go
func WithAllowPlainCodeChallenge(allow bool) ProviderOption
```

Permits the `plain` PKCE method. Defaults to `false`. With `plain` the challenge
*is* the verifier, so anyone who intercepts the authorization request has
everything needed to complete the exchange — the protection is nominal. The
method exists in RFC 7636 section 4.2 only for clients that cannot compute
SHA-256.

```go
func WithRevocationStore(rs RevocationStore) ProviderOption
```

Enables token revocation. Without it, `Revoke` has nowhere to record the
revocation. Access tokens are stateless JWTs, so revocation requires a store the
introspection path can consult.

```go
func WithTokenGenerator(g domain.TokenGenerator) ProviderOption
```

Sets the source of authorization codes and refresh tokens. Defaults to
`domain.DefaultTokenGenerator`. Replace it only if you need a specific entropy
source or format; the default is cryptographically random.

```go
func WithProviderClock(c domain.Clock) ProviderOption
```

Sets the clock used for expiry. Defaults to `domain.SystemClock`. Tests use a
fake clock to drive a token to the exact instant of its expiry rather than
sleeping.

---

### Client

```go
type Client struct {
    ID string `json:"id"`

    SecretHash string `json:"-"`

    RedirectURIs []string `json:"redirect_uris"`

    GrantTypes []string `json:"grant_types"`

    Scopes  []string `json:"scopes"`
    AppName string   `json:"app_name"`

    TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`

    BackChannelLogoutURI string `json:"back_channel_logout_uri"`
}
```

**`SecretHash`** is the hashed client secret, produced by the `domain.Hasher`
the provider was configured with. It is never the secret itself: a database
disclosure would otherwise hand over every client credential in one read. The
`json:"-"` tag keeps it out of any marshalled representation, so a client
registration API cannot leak it by accident. Leave it empty for public clients,
which must set `TokenEndpointAuthMethod` to `AuthMethodNone`.

**`RedirectURIs`** is the allowlist this client may redirect to, enforced by
exact string match. A prefix or wildcard match turns the authorization endpoint
into an open redirector, and the failure is not theoretical: prefix matching
lets `https://good.example.com.attacker.test` through, because it does begin
with the registered prefix.

**`GrantTypes`** limits which grants this client may use. A client with no
declared grants is unrestricted, which keeps existing registrations working;
declaring any grant opts into enforcement. Register the grants explicitly for
anything new — a browser application that never uses `client_credentials`
should not be able to.

**`TokenEndpointAuthMethod`** is how this client authenticates. It defaults to
`AuthMethodClientSecretBasic` when empty, so a client is confidential unless it
says otherwise. The default direction matters: a registration that forgets the
field ends up requiring a secret rather than accepting none.

```go
func (c *Client) AllowsRedirectURI(uri string) bool
func (c *Client) AllowsGrantType(grant string) bool
func (c *Client) IsPublic() bool
```

`AllowsRedirectURI` compares exactly, for the reason above. `AllowsGrantType`
reports whether this client may use the given grant, treating an empty
`GrantTypes` as unrestricted. `IsPublic` reports whether the client
authenticates with no secret.

### Auth method constants

```go
const (
    AuthMethodClientSecretBasic = "client_secret_basic"
    AuthMethodClientSecretPost  = "client_secret_post"
    AuthMethodNone              = "none"
)
```

Token endpoint authentication methods, per RFC 8414.
`client_secret_basic` sends the secret in the `Authorization` header;
`client_secret_post` sends it in the request body. `none` is for public clients,
which cannot keep a secret — a client using it must use PKCE, since PKCE is then
the only thing binding the authorization code to the application that requested
it.

### Grant type and response type constants

```go
const (
    GrantAuthorizationCode = "authorization_code"
    GrantRefreshToken      = "refresh_token"
    GrantClientCredentials = "client_credentials"
)

const ResponseTypeCode = "code"
```

These are the grants this provider understands and the only response type it
supports. There is no implicit flow and no hybrid flow: `id_token` and
`token` response types return tokens through the front channel, where they land
in browser history and referrer headers. Advertising a response type that is not
implemented is an interoperability bug that surfaces inside the relying party,
which is why `BuildDiscovery` derives the advertised list from configuration
rather than hardcoding it.

---

### Storage interfaces

Kayan does not choose your database. The provider is constructed from three
interfaces, and any backend satisfying them drops in without changes elsewhere.
`kayan-oidc-provider/gormstore` is one implementation, not a requirement.

```go
type ClientStore interface {
    GetClient(ctx context.Context, id string) (*Client, error)
    CreateClient(ctx context.Context, client *Client) error
    DeleteClient(ctx context.Context, id string) error
}
```

`GetClient` must return an error for an unknown client rather than a nil client
and a nil error. The provider translates that error into `ErrInvalidClient`,
which is the same error a wrong secret produces, so the token endpoint cannot be
used to enumerate client IDs.

```go
type AuthCodeStore interface {
    SaveAuthCode(ctx context.Context, code *AuthCode) error
    GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
    DeleteAuthCode(ctx context.Context, code string) error
}
```

An authorization code is single-use. `Exchange` deletes it after redemption, so
`DeleteAuthCode` must actually remove the row; a soft delete that leaves
`GetAuthCode` resolving the code makes a captured code redeemable twice.

```go
type RefreshTokenStore interface {
    SaveRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
    DeleteRefreshToken(ctx context.Context, token string) error
}
```

```go
type RefreshTokenFamilyStore interface {
    RefreshTokenStore

    MarkRefreshTokenUsed(ctx context.Context, token string, usedAt time.Time) error

    RevokeFamily(ctx context.Context, familyID string) error
}
```

`RefreshTokenFamilyStore` is an optional extension supporting refresh token
reuse detection (OAuth 2.1, RFC 9700 section 4.14.2). When a store implements
it, `Refresh` marks a redeemed token used rather than deleting it, and
presenting an already-used token revokes every token descended from the same
authorization.

The distinction is the whole detection mechanism. A stolen refresh token gives
the thief and the legitimate client each a token from the same chain. Whichever
presents a spent one proves the chain is compromised — but only if a spent token
is still resolvable. With a plain `RefreshTokenStore` the redeemed token is
deleted, a replay is reported as invalid because the token is unknown, and the
thief's own token keeps working indefinitely. Implement the family store for
anything holding real accounts.

`MarkRefreshTokenUsed` and `RevokeFamily` must be durable before `Refresh`
returns, and `RevokeFamily` must remove every token sharing the family
identifier, including the one just issued.

```go
type RevocationStore interface {
    RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error
    IsRevoked(ctx context.Context, jti string) (bool, error)
}
```

`IsRevoked` is consulted on the introspection path, so it fails closed only if
your implementation returns an error rather than `false` when the backing store
is unreachable. Returning `false, nil` on a Redis timeout means a revoked token
introspects as active.

```go
type MemoryRevocationStore struct{ /* ... */ }

func NewMemoryRevocationStore() *MemoryRevocationStore
func (s *MemoryRevocationStore) CleanExpired()
func (s *MemoryRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error)
func (s *MemoryRevocationStore) RevokeToken(_ context.Context, jti string, expiresAt time.Time) error
```

An in-memory `RevocationStore` suitable for testing and single-instance
deployments. Several replicas each keep their own, so a token revoked on one
replica remains active on the others. `CleanExpired` removes entries past their
expiry; nothing calls it for you.

---

### AuthCode

```go
type AuthCode struct {
    Code                string   `json:"code"`
    ClientID            string   `json:"client_id"`
    IdentityID          string   `json:"identity_id"`
    RedirectURI         string   `json:"redirect_uri"`
    Scopes              []string `json:"scopes"`
    CodeChallenge       string   `json:"code_challenge"`
    CodeChallengeMethod string   `json:"code_challenge_method"`

    Nonce     string    `json:"nonce,omitempty"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

`RedirectURI` is stored on the code and checked again at redemption: RFC 6749
requires the redirect URI presented at the token endpoint to match the one used
at the authorization endpoint, which stops a code obtained through one
registered URI being redeemed as though it came through another.

`Nonce` binds the ID token to this authorization request, so a token captured
from one sign-in cannot be replayed into another (OIDC Core section 15.5.2). It
is carried from `AuthorizeRequest` through the code to the ID token, which is
why `GenerateAuthCodeFor` is preferred over `GenerateAuthCode`.

### RefreshToken

```go
type RefreshToken struct {
    Token      string    `json:"token"`
    ClientID   string    `json:"client_id"`
    IdentityID string    `json:"identity_id"`
    Scopes     []string  `json:"scopes"`
    ExpiresAt  time.Time `json:"expires_at"`

    FamilyID string `json:"family_id"`

    UsedAt *time.Time `json:"used_at,omitempty"`
}

func (t *RefreshToken) IsUsed() bool
```

`FamilyID` links every token descended from one authorization. Rotation issues a
new token in the same family, so presenting a token that was already redeemed
can revoke the whole chain.

`UsedAt` records when the token was redeemed. A redeemed token is kept rather
than deleted, because deleting it makes a replay indistinguishable from an
unknown token — and that difference is what detects theft. `IsUsed` reports
whether `UsedAt` is set.

---

### Parsing requests

```go
func (p *Provider) ParseAuthorizeRequest(ctx context.Context, values url.Values) (*AuthorizeRequest, error)
```

Validates authorization request parameters. Pass the query string from wherever
the request arrived; Kayan does not read from an `*http.Request`.

```go
req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
if err != nil {
    // Redirect the error to req.RedirectURI only if the URI was validated;
    // otherwise render it, since redirecting an unvalidated URI is itself
    // the vulnerability.
}
```

That comment is the important part of the contract. When the redirect URI
itself failed validation, there is no safe place to send the error — bouncing
the user to an attacker-supplied URI to tell them the URI was wrong is the open
redirect you were trying to prevent. Render the error instead.

```go
type AuthorizeRequest struct {
    Client              *Client
    ClientID            string
    RedirectURI         string
    ResponseType        []string
    Scopes              []string
    State               string
    Nonce               string
    CodeChallenge       string
    CodeChallengeMethod string
    Prompt              []string
}
```

Every value here has already been checked: the client exists, the redirect URI
is registered, the response type is supported, and PKCE satisfies the provider's
policy. A caller holding one of these does not need to know which checks exist —
that is the point.

```go
func (p *Provider) ParseTokenRequest(ctx context.Context, values url.Values, authorization string) (*TokenRequest, error)
```

Validates a token request and authenticates the client. Credentials are taken
from the `Authorization` header when present, falling back to the request body
(RFC 6749 section 2.3.1). Pass the header value verbatim; an empty string means
none was sent.

```go
type TokenRequest struct {
    Client    *Client
    GrantType string

    // Authorization code grant.
    Code         string
    RedirectURI  string
    CodeVerifier string

    // Refresh token grant.
    RefreshToken string

    // Client credentials grant.
    Scopes []string
}
```

`Client` is non-nil and authenticated by the time you hold a `TokenRequest`.
The remaining fields are populated according to `GrantType`.

---

### Issuing authorization codes

```go
func (p *Provider) GenerateAuthCodeFor(ctx context.Context, req *AuthorizeRequest, identityID string) (string, error)
```

Issues an authorization code for a validated request. **Prefer this over
`GenerateAuthCode`**: the request has already been checked by
`ParseAuthorizeRequest`, and the nonce is carried through to the ID token. A
flow built on `GenerateAuthCode` cannot produce a nonce-bearing ID token,
because the nonce never reaches the code.

```go
func (p *Provider) GenerateAuthCode(ctx context.Context, clientID, identityID, redirectURI string, scopes []string, challenge, challengeMethod string) (string, error)
```

Issues an authorization code from loose parameters. The redirect URI is checked
against the client's registered allowlist, and a PKCE challenge is required
unless the provider was built with `WithRequirePKCE(false)`. Both checks happen
here, so a caller cannot reach the token endpoint with a code that was never
validated — but the nonce cannot be supplied, so the resulting ID token carries
none.

A complete authorization endpoint looks like this:

```go
req, err := provider.ParseAuthorizeRequest(ctx, r.URL.Query())
if err != nil {
    renderError(w, err) // The redirect URI is not yet trustworthy.
    return
}

identityID, ok := currentUser(r)
if !ok {
    redirectToLogin(w, r)
    return
}

code, err := provider.GenerateAuthCodeFor(ctx, req, identityID)
if err != nil {
    return
}

u, _ := url.Parse(req.RedirectURI) // Validated by ParseAuthorizeRequest.
q := u.Query()
q.Set("code", code)
q.Set("state", req.State)
u.RawQuery = q.Encode()
http.Redirect(w, r, u.String(), http.StatusFound)
```

---

### Token endpoint operations

```go
func (p *Provider) Exchange(ctx context.Context, code, clientID, clientSecret, redirectURI, verifier string) (*TokenResponse, error)
```

Exchanges an authorization code for an access token response. The client is
authenticated first, so an unauthenticated caller learns nothing about whether a
code exists. The code's stored redirect URI must match the one presented, and
the PKCE verifier must hash to the stored challenge under the stored method.

```go
func (p *Provider) Refresh(ctx context.Context, tokenValue, clientID, clientSecret string) (*TokenResponse, error)
```

Exchanges a refresh token for a new access token, rotating the refresh token.

When the store implements `RefreshTokenFamilyStore`, a redeemed token stays
resolvable and a second presentation revokes the whole family. That is the only
signal available that a refresh token was stolen: the legitimate client and the
thief both hold a token from the same chain, and whichever presents a spent one
proves the chain is compromised. With a plain `RefreshTokenStore` the redeemed
token is deleted instead, so a replay is reported as invalid but the thief's
token continues to work.

The consequence is worth stating plainly, because it decides a deployment
choice: with the plain store, refresh token theft is undetectable and permanent
until the token expires.

```go
func (p *Provider) ClientCredentials(ctx context.Context, req *TokenRequest) (*TokenResponse, error)
```

Issues an access token for the client itself. The token authenticates the
client, not a user, so it carries no subject identity and no refresh token: the
client can always request another by re-authenticating (RFC 6749 section 4.4.3).
Issuing a refresh token here would add a long-lived credential that buys
nothing, since the client already holds the secret that mints tokens.

```go
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int64  `json:"expires_in"`
    RefreshToken string `json:"refresh_token,omitempty"`
    IDToken      string `json:"id_token,omitempty"`
    Sub          string `json:"sub,omitempty"`
}
```

```go
func (p *Provider) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error)
```

Authenticates a client at the token endpoint. Confidential clients must present
a secret; it is verified against the stored hash with the configured
`domain.Hasher`, never compared directly. Public clients — those registered with
`AuthMethodNone` — authenticate with no secret and rely on PKCE instead. The
error is the same whether the client is unknown or the secret is wrong, so the
endpoint cannot be used to enumerate client IDs.

```go
func (p *Provider) GenerateAccessToken(clientID string, identityID string, scopes []string) (string, error)
```

Generates a signed JWT access token for a user, without going through a grant.

---

### PKCE

PKCE (RFC 7636) binds an authorization code to the application that requested
it. The client generates a random `code_verifier`, sends
`code_challenge = BASE64URL(SHA256(verifier))` with `code_challenge_method=S256`
at the authorization endpoint, and presents the verifier at the token endpoint.
An attacker who intercepts the code does not hold the verifier and cannot redeem
it.

Kayan requires PKCE by default (`WithRequirePKCE(true)`) and refuses the `plain`
method by default (`WithAllowPlainCodeChallenge(false)`). The two settings
compose: with the defaults, `S256` is the only accepted method, which is the
posture OAuth 2.1 mandates.

`plain` sets the challenge equal to the verifier. Anyone who sees the
authorization request holds everything needed to complete the exchange, so the
binding is decorative. Enable it only for a client that provably cannot compute
SHA-256.

The provider's setting must match what discovery advertises. Use
`oidc.WithServerAllowPlainCodeChallenge` on the OIDC server with the same value
you passed to `oauth2.WithAllowPlainCodeChallenge`; advertising a method that is
refused, or omitting one that is accepted, misleads relying parties into
failures they cannot diagnose from their side.

---

### Introspection, revocation, and JWKS

```go
func (p *Provider) Introspect(ctx context.Context, tokenString string) (*IntrospectionResponse, error)

type IntrospectionResponse struct {
    Active   bool   `json:"active"`
    Scope    string `json:"scope,omitempty"`
    ClientID string `json:"client_id,omitempty"`
    Sub      string `json:"sub,omitempty"`
    Exp      int64  `json:"exp,omitempty"`
    Iat      int64  `json:"iat,omitempty"`
    Iss      string `json:"iss,omitempty"`
    Username string `json:"username,omitempty"`
}
```

Validates a token and returns its metadata, per RFC 7662. `Active` is the field
that matters; the rest is populated only for an active token, because the
metadata of an inactive one tells a caller about tokens they do not hold.

Introspection is an authenticated endpoint in the specification. Kayan does not
enforce that for you — it has no router — so the caller must authenticate the
resource server before calling `Introspect`.

```go
func (p *Provider) Revoke(ctx context.Context, tokenString string) error
```

Invalidates a token by storing its JTI in the revocation store. Per RFC 7009,
the token is parsed without full verification to extract claims. This requires
`WithRevocationStore`; without one there is nowhere to record the revocation.

RFC 7009 also requires the revocation endpoint to return success for an unknown
or already-invalid token, so that it cannot be used as an oracle for whether a
token exists.

```go
func (p *Provider) JWKS(ctx context.Context) (keys.JWKS, error)
```

Returns the key set to publish at the JWKS endpoint. It requires a key provider
(`WithKeyProvider`). The caller serves the result; Kayan does not write HTTP
responses.

```go
set, err := provider.JWKS(ctx)
if err != nil {
    return
}
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(set)
```

```go
type JWK struct {
    Kty string `json:"kty"`
    Alg string `json:"alg"`
    Use string `json:"use"`
    Kid string `json:"kid"`
    N   string `json:"n"`
    E   string `json:"e"`
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}

func PublicKeyToJWK(key *rsa.PublicKey, kid string) JWK
```

These are the package's own RSA-shaped JWK types. `Provider.JWKS` returns
`keys.JWKS` from `core/keys`, which is not limited to RSA — that is the type to
serve, and the reason algorithm choice stays the caller's.

---

### Errors

```go
type Error struct {
    Code string `json:"error"`

    Description string `json:"error_description,omitempty"`

    URI string `json:"error_uri,omitempty"`

    State string `json:"state,omitempty"`

    // Has unexported fields.
}
```

An OAuth 2.0 protocol error (RFC 6749 sections 4.1.2.1 and 5.2). It marshals
directly to the wire format and reports the status code the specification
assigns, so the caller can respond without a translation table:

```go
var oerr *oauth2.Error
if errors.As(err, &oerr) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(oerr.StatusCode())
    json.NewEncoder(w).Encode(oerr)
}
```

`Description` reaches the client, so it must not disclose whether a client ID
exists, which credential was wrong, or any other detail useful for enumeration.

```go
func (e *Error) Error() string
func (e *Error) Is(target error) bool
func (e *Error) StatusCode() int
func (e *Error) Unwrap() error
func (e *Error) WithCause(err error) *Error
func (e *Error) WithDescription(description string) *Error
func (e *Error) WithDescriptionf(format string, args ...any) *Error
func (e *Error) WithState(state string) *Error
func (e *Error) WithURI(uri string) *Error
```

`Is` reports whether the target is an `*Error` with the same code, so
`errors.Is(err, oauth2.ErrInvalidGrant)` matches a copy carrying a description.

`WithCause` returns a copy wrapping the underlying error. The cause is available
to the server through `errors.Is` and `errors.As`, and is never serialized to
the client — which is the split you want: full detail in your logs, nothing
enumerable on the wire.

`WithDescriptionf` interpolates. Never interpolate attacker-controlled input
into a description that is returned to the client.

Every `With*` method returns a copy. The sentinels are values, not templates, so
a sentinel is never mutated and can be compared with `errors.Is` from concurrent
requests.

#### Sentinels and their HTTP status

| Sentinel | `error` code | Status | Meaning |
|---|---|---|---|
| `ErrInvalidRequest` | `invalid_request` | 400 | The request is malformed or has a duplicate parameter. |
| `ErrInvalidClient` | `invalid_client` | 401 | Client authentication failed. |
| `ErrInvalidGrant` | `invalid_grant` | 400 | The grant or refresh token is invalid, expired, revoked, or was issued to another client. |
| `ErrUnauthorizedClient` | `unauthorized_client` | 400 | This client may not use this grant type. |
| `ErrUnsupportedGrantType` | `unsupported_grant_type` | 400 | The authorization server does not support this grant. |
| `ErrUnsupportedResponseType` | `unsupported_response_type` | 400 | The authorization server does not support this response type. |
| `ErrInvalidScope` | `invalid_scope` | 400 | The requested scope is unknown, malformed, or exceeds what was granted. |
| `ErrAccessDenied` | `access_denied` | 403 | The resource owner or authorization server refused the request. |
| `ErrServerError` | `server_error` | 500 | An unexpected condition prevented fulfilling the request. |
| `ErrTemporarilyUnavailable` | `temporarily_unavailable` | 503 | The server is overloaded or under maintenance. |
| `ErrInvalidToken` | `invalid_token` | 401 | The access token is expired, revoked, or malformed (RFC 6750 section 3.1). |

`ErrInvalidGrant` deliberately covers several distinct causes. Distinguishing
"this code does not exist" from "this code belongs to another client" would let
a caller probe for valid codes.

---

## Package `oidc`

### Server

```go
type Server struct {
    // Has unexported fields.
}

func NewServer(issuer string, signingKey any, keyID string, opts ...ServerOption) *Server
```

```go
type ServerOption func(*Server)

func WithClaimsSource(c ClaimsSource) ServerOption
func WithServerKeyProvider(kp keys.Provider) ServerOption
func WithServerClock(c domain.Clock) ServerOption
func WithServerAllowPlainCodeChallenge(allow bool) ServerOption
```

`WithClaimsSource` supplies the claims placed in ID tokens. Without one, tokens
carry only the reserved claims, because Kayan cannot guess where `email` or
`name` live in your identity model — that is what BYOS costs and what it buys.

`WithServerKeyProvider` supplies the signing keys, so discovery can advertise the
algorithms actually in use and JWKS can publish them.

`WithServerAllowPlainCodeChallenge` records that the provider accepts the `plain`
PKCE method, so discovery advertises it. It must match the setting on the OAuth
2.0 provider.

### Discovery

```go
func (s *Server) BuildDiscovery(ctx context.Context, opts DiscoveryOptions) (Discovery, error)
```

Assembles the OpenID Provider metadata document. The result is derived from
configuration rather than written out by hand.

```go
type DiscoveryOptions struct {
    Endpoints Endpoints

    // Scopes advertised. Defaults to openid, profile, email.
    Scopes []string

    // Claims advertised. Defaults to the claims the ID token always carries.
    Claims []string

    // GrantTypes advertised. Defaults to the grants the provider implements.
    GrantTypes []string
}

type Endpoints struct {
    Authorization string
    Token         string
    UserInfo      string
    JWKS          string
    Introspection string
    Revocation    string
    EndSession    string
}
```

`Endpoints` locates the routes a deployment serves. Kayan does not choose URLs —
it has no router. Supply the paths your service actually exposes; anything left
empty is omitted from the document rather than guessed. An advertised endpoint
that 404s is worse than an absent one, because a relying party will try it.

```go
type Discovery struct {
    Issuer                            string   `json:"issuer"`
    AuthorizationEndpoint             string   `json:"authorization_endpoint"`
    TokenEndpoint                     string   `json:"token_endpoint"`
    UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
    IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
    RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
    EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
    JwksURI                           string   `json:"jwks_uri"`
    ResponseTypesSupported            []string `json:"response_types_supported"`
    SubjectTypesSupported             []string `json:"subject_types_supported"`
    IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
    ScopesSupported                   []string `json:"scopes_supported"`
    GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
    CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
    TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
    ClaimsSupported                   []string `json:"claims_supported"`
}
```

The caller serves the result:

```go
doc, err := server.BuildDiscovery(ctx, oidc.DiscoveryOptions{
    Endpoints: oidc.Endpoints{
        Authorization: "https://auth.example.com/oauth2/authorize",
        Token:         "https://auth.example.com/oauth2/token",
        UserInfo:      "https://auth.example.com/oidc/userinfo",
        JWKS:          "https://auth.example.com/oauth2/jwks",
    },
})
json.NewEncoder(w).Encode(doc)
```

```go
func (s *Server) GetDiscovery(baseURL string) Discovery
```

**Deprecated: use `Server.BuildDiscovery`.** This version hardcodes its values,
so it advertises the `id_token` response type although no implicit flow exists,
and RS256 regardless of the key in use. It also assumes endpoint paths this
library does not choose. Both failures land inside the relying party, where
they are hard to diagnose: a relying party that trusts
`response_types_supported` will attempt an implicit flow that cannot succeed,
and one that trusts `id_token_signing_alg_values_supported` will reject
correctly signed Ed25519 tokens.

### ID tokens

```go
func (s *Server) IssueIDToken(ctx context.Context, req IDTokenRequest) (string, error)

type IDTokenRequest struct {
    ClientID   string
    IdentityID string
    Scopes     []string

    Nonce string

    AuthTime time.Time

    TTL time.Duration
}

const DefaultIDTokenTTL = time.Hour
```

`IssueIDToken` mints an ID token for a request. Claims come from the configured
`ClaimsSource`, filtered by the granted scopes. Reserved claims are set here and
cannot be overridden by the source: a source that could set `sub` or `aud` would
be able to mint a token for another subject or audience, which is a complete
authentication bypass in any relying party that trusts the token.

`Nonce` echoes the authorization request's nonce. The relying party compares it
against the value it sent, which is what stops an ID token captured from one
sign-in being replayed into another (OIDC Core section 3.1.3.7).

`AuthTime` is when the user actually authenticated, as opposed to when the token
was issued. A relying party asking for `max_age` needs it — without it, a token
minted from a months-old session looks as fresh as one minted from a password
prompt a second ago.

`TTL` overrides the token lifetime, defaulting to `DefaultIDTokenTTL`.

```go
func (s *Server) GenerateIDToken(clientID string, identityID string, traits identity.JSON) (string, error)
```

**Deprecated: use `Server.IssueIDToken`.** This version emits the entire traits
blob regardless of which scopes were granted, and carries no nonce, so a relying
party cannot bind the token to its authorization request. Both are real
disclosures rather than stylistic complaints: a client granted only `openid`
receives every trait on the identity, including any your application stores
there for internal use.

### ClaimsSource

```go
type ClaimsSource interface {
    Claims(ctx context.Context, identityID string, scopes []string) (map[string]any, error)
}

type ClaimsSourceFunc func(ctx context.Context, identityID string, scopes []string) (map[string]any, error)

func (f ClaimsSourceFunc) Claims(ctx context.Context, identityID string, scopes []string) (map[string]any, error)
```

Kayan cannot know where a claim lives in your model — whether `email` is a
column, a key in a JSON blob, or a lookup against another service — so the
mapping is yours. Return only the claims the granted scopes permit; the result
is placed in the ID token as-is.

The scope filtering is the implementer's responsibility, and it is the one thing
that must not be skipped. A source that ignores `scopes` and returns everything
turns every client granted `openid` into a client granted `profile` and `email`.

```go
server := oidc.NewServer(issuer, key, kid,
    oidc.WithClaimsSource(oidc.ClaimsSourceFunc(
        func(ctx context.Context, id string, scopes []string) (map[string]any, error) {
            u, err := repo.GetIdentity(ctx, factory, id)
            if err != nil {
                return nil, err
            }
            user := u.(*User)

            claims := map[string]any{}
            for _, s := range scopes {
                switch s {
                case "email":
                    claims["email"] = user.Email
                    claims["email_verified"] = user.EmailVerified
                case "profile":
                    claims["name"] = user.DisplayName
                }
            }
            return claims, nil
        })),
)
```

Note what the example does not do: it never sets `sub`, `aud`, `iss`, `exp`,
`iat`, or `nonce`. `IssueIDToken` sets those and ignores any attempt to override
them.

### Back-channel logout

```go
type BackChannelLogoutNotifier struct {
    // Has unexported fields.
}

func NewBackChannelLogoutNotifier(issuer string, signingKey any, keyID string, cs oauth2.ClientStore, opts ...BackChannelLogoutOption) *BackChannelLogoutNotifier

func (n *BackChannelLogoutNotifier) NotifyClient(ctx context.Context, clientID string, logoutURI string, sid string, identityID string) error
func (n *BackChannelLogoutNotifier) NotifyLogout(sid string, identityID string) error
```

Implements the OIDC Back-Channel Logout notification. `NotifyClient` sends a
signed logout token to one client's `BackChannelLogoutURI`. `NotifyLogout` fans
out to every registered client.

```go
type LogoutNotifier interface {
    NotifyLogout(sid string, identityID string) error
}

type ClientLister interface {
    ListClients(ctx context.Context) ([]*oauth2.Client, error)
}

var ErrClientListingUnavailable = errors.New("oidc: client store does not support client listing")
```

Fan-out needs to enumerate clients, which `oauth2.ClientStore` does not require.
The store is type-asserted to `ClientLister` at runtime; if it is not
implemented, `NotifyLogout` is a no-op.

```go
type BackChannelLogoutOption func(*BackChannelLogoutNotifier)

func WithStrictClientListing() BackChannelLogoutOption
```

Makes `NotifyLogout` fail with `ErrClientListingUnavailable` when the client
store does not implement `ClientLister`, instead of silently skipping fan-out.
Enable it. A logout that silently notifies nobody looks exactly like a logout
that worked, and the sessions it was supposed to end stay open.

---

## Package `gormstore`

```go
import "github.com/getkayan/kayan/kayan-oidc-provider/gormstore"
```

Persists OAuth 2.0 clients, authorization codes, and refresh tokens with GORM.
It is one implementation of the `oauth2` storage interfaces. Any other backend
satisfies the same interfaces and drops in without changes elsewhere.

```go
type OAuth2Repository struct {
    // Has unexported fields.
}

func NewOAuth2Repository(db *gorm.DB) *OAuth2Repository
```

`OAuth2Repository` implements `ClientStore`, `AuthCodeStore`,
`RefreshTokenStore`, `RefreshTokenFamilyStore`, and `oidc.ClientLister`, so one
value satisfies all three constructor parameters:

```go
repo := gormstore.NewOAuth2Repository(db)
provider := oauth2.NewProvider(repo, repo, repo, issuer, key, kid)
```

```go
func (r *OAuth2Repository) AutoMigrate() error
```

Creates the tables this repository needs. **For development only.** Production
deployments should run versioned migrations; see the module README.

```go
func (r *OAuth2Repository) MarkRefreshTokenUsed(ctx context.Context, token string, usedAt time.Time) error
func (r *OAuth2Repository) RevokeFamily(ctx context.Context, familyID string) error
```

These implement `oauth2.RefreshTokenFamilyStore`, so a provider built on this
repository gets reuse detection without further configuration. The token is
retained rather than deleted so that a later replay is detectable — deleting it
would make a stolen token indistinguishable from an unknown one.

```go
func (r *OAuth2Repository) DeleteExpiredRefreshTokens(ctx context.Context, olderThan time.Time) (int64, error)
```

Removes tokens past their expiry, including spent ones retained for replay
detection. Retention is what makes detection work, so the table grows until
something prunes it; run this on a schedule with `olderThan` set far enough back
that a replay would be pointless anyway.

```go
func (r *OAuth2Repository) ListClients(ctx context.Context) ([]*oauth2.Client, error)
```

Returns all registered OAuth 2.0 clients. This implements the
`oidc.ClientLister` interface for back-channel logout fan-out.

The remaining methods are the plain store implementations:

```go
func (r *OAuth2Repository) CreateClient(ctx context.Context, client *oauth2.Client) error
func (r *OAuth2Repository) GetClient(ctx context.Context, id string) (*oauth2.Client, error)
func (r *OAuth2Repository) DeleteClient(ctx context.Context, id string) error

func (r *OAuth2Repository) SaveAuthCode(ctx context.Context, code *oauth2.AuthCode) error
func (r *OAuth2Repository) GetAuthCode(ctx context.Context, code string) (*oauth2.AuthCode, error)
func (r *OAuth2Repository) DeleteAuthCode(ctx context.Context, code string) error

func (r *OAuth2Repository) SaveRefreshToken(ctx context.Context, token *oauth2.RefreshToken) error
func (r *OAuth2Repository) GetRefreshToken(ctx context.Context, token string) (*oauth2.RefreshToken, error)
func (r *OAuth2Repository) DeleteRefreshToken(ctx context.Context, token string) error
```

## Authentication context and `max_age`

`ParseAuthorizeRequest` parses `max_age` and `acr_values` into the embedded
`AuthenticationRequirements`:

```go
type AuthenticationRequirements struct {
    MaxAge    *int
    ACRValues []string
}

func (r AuthenticationRequirements) Requested() bool
func (r AuthenticationRequirements) NeedsReauthentication(lastAuth, now time.Time) bool
func (r AuthenticationRequirements) SatisfiedBy(lastAuth, now time.Time) bool
```

`max_age=0` is meaningful, which is why `MaxAge` is a pointer. Before reusing a
login session, call `NeedsReauthentication`. A zero or stale authentication
time does not satisfy the requirement.

After authentication, issue the code with what actually happened:

```go
type AuthenticationInfo struct {
    Nonce    string
    AuthTime time.Time
    ACR      string
    AMR      []string
}

func (p *Provider) GenerateAuthCodeForAuthentication(
    ctx context.Context,
    req *AuthorizeRequest,
    identityID string,
    auth AuthenticationInfo,
) (string, error)
```

A request carrying `max_age` is refused when `AuthTime` is missing or too old.
The consumed code returns the same values in `TokenResponse.Authentication`;
pass them to `IDTokenRequest` so the ID token carries `nonce`, `auth_time`,
`acr`, and `amr`. `acr_values` is a preference in OIDC, not a mandatory class
ordering: authenticate according to deployment policy and report the class
actually reached.

Set `DiscoveryOptions.ACRValues` only to classes the deployment can really
produce. They become `acr_values_supported`.

## Pushed authorization requests (PAR)

```go
type PushedRequestStore interface {
    SavePushedRequest(ctx context.Context, request *PushedRequest) error
    ConsumePushedRequest(ctx context.Context, uri string) (*PushedRequest, error)
}

func WithPushedRequests(store PushedRequestStore) ProviderOption
func WithPushedRequestTTL(ttl time.Duration) ProviderOption
func WithRequirePushedRequests(required bool) ProviderOption
func (p *Provider) PushAuthorizationRequest(ctx context.Context, values url.Values, authorization string) (*PushedRequest, error)
```

`PushAuthorizationRequest` authenticates the client, validates the complete
authorization request, strips client credentials before storage, and returns a
short-lived `request_uri`. Redemption consumes it atomically and uses the
pushed parameters alone; query parameters cannot override its client or
redirect URI.

`MemoryPushedRequestStore` is for a single process. A load-balanced deployment
must implement the atomic store in shared storage or a URI pushed to one
replica will fail on another. `WithRequirePushedRequests(true)` rejects the
ordinary authorization path, as required by FAPI 2.0.

Discovery advertises PAR only when both sides are wired:

```go
server := oidc.NewServer(
    issuer,
    signingKey,
    keyID,
    oidc.WithPushedRequestSupport(provider),
)
```

Set `Endpoints.PushedAuthorizationRequest` in `DiscoveryOptions`. Configuring
the URL without the provider is an error rather than an advertised endpoint
that cannot serve requests.

## `private_key_jwt` client authentication

```go
type ClientAssertionStore interface {
    ConsumeAssertionID(ctx context.Context, clientID, jti string, expiresAt time.Time) error
}

type ClientKeyResolver interface {
    ClientKeys(ctx context.Context, client *Client) (keys.JWKS, error)
}

func WithClientAssertions(store ClientAssertionStore) ProviderOption
func WithClientKeyResolver(resolver ClientKeyResolver) ProviderOption
func WithTokenEndpointURL(url string) ProviderOption
func WithMaxClientAssertionLifetime(d time.Duration) ProviderOption
```

Register public keys in `Client.JWKS`, or supply a resolver that fetches and
caches the client's registered `jwks_uri`. Kayan performs no outbound fetches.
Assertions require `iss == sub == client_id`, a valid audience, `exp`, `iat`,
and a non-empty `jti`; only asymmetric algorithms are accepted.

The assertion store must atomically consume `jti`. Without one,
`private_key_jwt` is refused rather than downgraded to a replayable bearer
credential. `MemoryClientAssertionStore` is suitable only for one process;
replicas need shared storage.

Pass the provider to `oidc.WithClientAuthMethods` so discovery derives
`token_endpoint_auth_methods_supported` from the methods actually configured.

## RP-initiated logout

```go
func WithClientStore(store oauth2.ClientStore) ServerOption

func (s *Server) ParseEndSessionRequest(ctx context.Context, values url.Values) (*EndSessionRequest, error)

type EndSessionRequest struct {
    ClientID                 string
    Subject                  string
    SessionID                string
    PostLogoutRedirectURI    string
    State                    string
    LogoutHint               string
    ConfirmationRequired     bool
}

func (r *EndSessionRequest) RedirectURL() string
```

Configure `WithClientStore` and register each client's
`PostLogoutRedirectURIs`. A present `id_token_hint` must verify; an invalid one
never falls back to an unauthenticated `client_id`. Redirects are exact-match
allowlisted, and `RedirectURL` appends `state` only to a validated target.

End the session identified by the verified `SessionID`. `LogoutHint` is
untrusted display or lookup text, not authorization to select another user's
session. Ask for confirmation whenever `ConfirmationRequired` is true. Discovery
refuses to advertise `end_session_endpoint` without a client store capable of
validating redirect targets.

---

## Known gaps

The provider implements `authorization_code`, `refresh_token`, and
`client_credentials`. `private_key_jwt` and pushed authorization requests are
implemented and advertised only when their required stores are configured.
There is no device code grant, token exchange, DPoP, RFC 9101 request object, or
dynamic client registration. Client registration is your application's, which
also means client-secret hashing at registration must use the same
`domain.Hasher` the provider verifies with.
