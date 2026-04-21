---
description: "Implement a new Kayan authentication strategy (registration and/or login). Covers password, magic link, TOTP, WebAuthn, SMS OTP, social login, API key, recovery codes, and more."
name: "New Auth Strategy"
argument-hint: "Describe the strategy to implement, e.g. 'magic link via email', 'TOTP login', 'WebAuthn passkey', 'social login with GitHub'"
agent: "agent"
tools: ["read_file", "grep_search", "file_search", "replace_string_in_file", "create_file", "get_errors"]
---

Implement a new Kayan authentication strategy following the patterns and constraints in [AGENTS.md](../../AGENTS.md) and the skill at [.github/skills/new-auth-strategy/SKILL.md](.github/skills/new-auth-strategy/SKILL.md).

**Target strategy**: ${{ARGUMENTS}}

---

## Quick Reference: Use Case Examples

Choose the example that best matches the requested strategy. Use it as your implementation template.

---

### Example 1 — Password (single-step, both registration + login)

The canonical reference. Already implemented at [core/flow/strategy_password.go](../../core/flow/strategy_password.go).

```
Strategy ID : "password"
Interfaces  : RegistrationStrategy + LoginStrategy
Storage     : FindIdentityByField, CreateIdentity, SetCredential, FindCredential
Security    : bcrypt via domain.Hasher, subtle.ConstantTimeCompare for tokens
Multi-step  : No
```

Use this as the baseline template for any credential-based scheme.

---

### Example 2 — Magic Link (multi-step login only)

Reference test: [core/flow/magic_test.go](../../core/flow/magic_test.go)

```
Strategy ID : "magic_link"
Interfaces  : LoginStrategy + Initiator (two-step)
Storage     : FindIdentityByEmail, StoreToken(ctx, identityID, token, expiry), ConsumeToken(ctx, token)
Multi-step  : Yes — Initiate() sends the link, Authenticate() verifies the token
Security    : crypto/rand token (≥32 bytes, hex-encoded), expiry enforced server-side,
              subtle.ConstantTimeCompare on verify, token deleted after single use
```

Implementation outline:

```go
func (s *MagicLinkStrategy) ID() string { return "magic_link" }

// Step 1: generate token, store it, trigger email delivery
func (s *MagicLinkStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
    token, _ := generateSecureToken(32)
    expiry := time.Now().Add(15 * time.Minute)
    if err := s.repo.StoreToken(ctx, identityID, token, expiry); err != nil { ... }
    return s.mailer.SendMagicLink(ctx, identifier, token)
}

// Step 2: verify token and return identity
func (s *MagicLinkStrategy) Authenticate(ctx context.Context, identifier, token string) (any, error) {
    stored, err := s.repo.ConsumeToken(ctx, token) // deletes on read
    if !tokenValid(stored, token) { return nil, ErrMagicLinkTokenInvalid }
    ...
}
```

Sentinel errors to add to `errors.go`:
- `ErrMagicLinkTokenInvalid`
- `ErrMagicLinkTokenExpired`

---

### Example 3 — TOTP (Time-Based One-Time Password, login only)

```
Strategy ID : "totp"
Interfaces  : LoginStrategy
Storage     : FindIdentityByField, FindTOTPSecret(ctx, identityID) ([]byte, error)
External    : golang.org/x/crypto or a TOTP library such as github.com/pquerna/otp
Multi-step  : No (TOTP code is the "secret" argument to Authenticate)
Security    : Validate with 30-second window + 1 step drift tolerance,
              track last-used counter to prevent replay (store in storage),
              never log the TOTP secret or code
```

Implementation outline:

```go
func (s *TOTPStrategy) ID() string { return "totp" }

func (s *TOTPStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error) {
    identity, err := s.repo.FindIdentityByField(ctx, s.identifierField, identifier, s.factory)
    secret, err := s.repo.FindTOTPSecret(ctx, getID(identity))
    if !totp.Validate(code, secret) { return nil, ErrTOTPCodeInvalid }
    if err := s.repo.MarkTOTPUsed(ctx, getID(identity), code); err != nil {
        return nil, ErrTOTPReplay // replay protection
    }
    return identity, nil
}
```

Sentinel errors:
- `ErrTOTPCodeInvalid`
- `ErrTOTPReplay`
- `ErrTOTPSecretNotFound`

---

### Example 4 — WebAuthn / Passkey (multi-step, login + registration)

```
Strategy ID : "webauthn"
Interfaces  : RegistrationStrategy + LoginStrategy + Initiator
Storage     : FindIdentityByField, StoreChallenge, ConsumeChallenge,
              StoreCredential(credentialID, publicKey, counter),
              FindCredentialByID, UpdateCredentialCounter
External    : github.com/go-webauthn/webauthn (add to core/go.mod only if approved;
              prefer an interface so the caller injects the webauthn.WebAuthn instance)
Multi-step  : Yes — Initiate() returns the challenge options, Authenticate() verifies the assertion
Security    : challenge must be cryptographically random (≥32 bytes),
              always verify rpID and origin server-side,
              increment and verify the credential counter to detect cloned authenticators
```

Implementation outline:

```go
// RegistrationStrategy — step 1: generate credential creation options
func (s *WebAuthnStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
    challenge, _ := generateSecureToken(32)
    _ = s.repo.StoreChallenge(ctx, identifier, challenge, 5*time.Minute)
    return s.webauthn.BeginRegistration(user)
}

// RegistrationStrategy — step 2: verify and persist the new credential
func (s *WebAuthnStrategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) {
    // secret carries the JSON-encoded ClientRegistrationResponse
    ...
    credential, err := s.webauthn.FinishRegistration(user, sessionData, parsedResponse)
    _ = s.repo.StoreCredential(ctx, identityID, credential.ID, credential.PublicKey, credential.Authenticator.SignCount)
    return identity, nil
}

// LoginStrategy — verify assertion and update counter
func (s *WebAuthnStrategy) Authenticate(ctx context.Context, identifier, assertionJSON string) (any, error) {
    ...
    if credential.Authenticator.SignCount <= storedCounter { return nil, ErrWebAuthnClonedAuthenticator }
    _ = s.repo.UpdateCredentialCounter(ctx, credential.ID, credential.Authenticator.SignCount)
    return identity, nil
}
```

Sentinel errors:
- `ErrWebAuthnChallengeInvalid`
- `ErrWebAuthnChallengeExpired`
- `ErrWebAuthnCredentialNotFound`
- `ErrWebAuthnClonedAuthenticator`

---

### Example 5 — SMS OTP (multi-step login only)

```
Strategy ID : "sms_otp"
Interfaces  : LoginStrategy + Initiator
Storage     : FindIdentityByPhone, StoreOTP(ctx, identityID, hashedOTP, expiry),
              FindOTP(ctx, identityID) (hashedOTP string, expiry time.Time, err error),
              DeleteOTP(ctx, identityID)
Multi-step  : Yes — Initiate() sends the SMS, Authenticate() verifies the code
Security    : 6-digit code from crypto/rand (not math/rand),
              hash the OTP before storing (bcrypt or SHA-256 with HMAC key),
              rate-limit Initiate calls (use flow.RateLimiter),
              max 5 verify attempts before invalidation,
              single-use (delete after success or exhausted attempts)
```

Implementation outline:

```go
func (s *SMSOTPStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
    if err := s.rateLimiter.Allow(ctx, "sms_otp:"+identifier); err != nil {
        return nil, ErrSMSOTPRateLimited
    }
    code := generateOTPCode(6) // crypto/rand
    hashed, _ := s.hasher.Hash(code)
    _ = s.repo.StoreOTP(ctx, identityID, hashed, time.Now().Add(10*time.Minute))
    return nil, s.sms.Send(ctx, phone, "Your code: "+code)
}

func (s *SMSOTPStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error) {
    stored, expiry, err := s.repo.FindOTP(ctx, identityID)
    if time.Now().After(expiry) { return nil, ErrSMSOTPExpired }
    if err := s.hasher.Compare(stored, code); err != nil { return nil, ErrSMSOTPInvalid }
    _ = s.repo.DeleteOTP(ctx, identityID)
    return identity, nil
}
```

Sentinel errors:
- `ErrSMSOTPInvalid`
- `ErrSMSOTPExpired`
- `ErrSMSOTPRateLimited`

---

### Example 6 — Social Login / OAuth2 (multi-step login, optional registration)

```
Strategy ID : "oauth2_<provider>" (e.g. "oauth2_github", "oauth2_google")
Interfaces  : LoginStrategy + Initiator (registration may be auto-created on first login)
Storage     : FindIdentityByProviderID(ctx, provider, providerUserID, factory),
              CreateIdentityFromProvider(ctx, providerID, traits, factory),
              StoreOAuthState(ctx, state, expiry), ConsumeOAuthState(ctx, state)
External    : golang.org/x/oauth2 (acceptable in core/oauth2 or a framework adapter)
Multi-step  : Yes — Initiate() returns the authorization URL + state,
              Authenticate() exchanges the code and fetches the userinfo
Security    : state must be cryptographically random (≥32 bytes), validated on callback (CSRF),
              always use PKCE (code_challenge + code_verifier) for public clients,
              never store the access token long-term; exchange for a Kayan session
```

Implementation outline:

```go
func (s *OAuth2Strategy) Initiate(ctx context.Context, identifier string) (any, error) {
    state, _ := generateSecureToken(32)
    verifier := oauth2.GenerateVerifier()
    _ = s.repo.StoreOAuthState(ctx, state, verifier, 10*time.Minute)
    url := s.config.AuthCodeURL(state,
        oauth2.S256ChallengeOption(verifier),
        oauth2.AccessTypeOnline,
    )
    return map[string]string{"redirect_url": url, "state": state}, nil
}

func (s *OAuth2Strategy) Authenticate(ctx context.Context, state, code string) (any, error) {
    verifier, err := s.repo.ConsumeOAuthState(ctx, state) // validates + deletes
    if err != nil { return nil, ErrOAuth2StateInvalid }
    token, err := s.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
    userInfo, err := s.fetchUserInfo(ctx, token)
    identity, err := s.repo.FindOrCreateByProvider(ctx, s.providerID, userInfo.ID, userInfo.Traits, s.factory)
    return identity, nil
}
```

Sentinel errors:
- `ErrOAuth2StateInvalid`
- `ErrOAuth2StateExpired`
- `ErrOAuth2UserInfoFetch`

---

### Example 7 — API Key (single-step, login only — for machine-to-machine)

```
Strategy ID : "api_key"
Interfaces  : LoginStrategy only
Storage     : FindIdentityByAPIKeyHash(ctx, keyHash, factory)
Multi-step  : No — the API key is passed directly as the "secret" argument
Security    : store only the SHA-256 hash of the key (never the raw key),
              use subtle.ConstantTimeCompare when comparing hashes,
              support key rotation (multiple active keys per identity),
              enforce key expiry and scope claims
```

Implementation outline:

```go
func (s *APIKeyStrategy) ID() string { return "api_key" }

func (s *APIKeyStrategy) Authenticate(ctx context.Context, identifier, rawKey string) (any, error) {
    // identifier is the key ID prefix (first 8 chars), rawKey is the full key
    hash := sha256.Sum256([]byte(rawKey))
    identity, err := s.repo.FindIdentityByAPIKeyHash(ctx, hex.EncodeToString(hash[:]), s.factory)
    if err != nil { return nil, ErrAPIKeyInvalid }
    return identity, nil
}
```

Sentinel errors:
- `ErrAPIKeyInvalid`
- `ErrAPIKeyExpired`
- `ErrAPIKeyScopeInsufficient`

---

### Example 8 — Recovery Codes (single-step login, MFA fallback)

```
Strategy ID : "recovery_code"
Interfaces  : LoginStrategy only
Storage     : FindIdentityByField, FindUnusedRecoveryCode(ctx, identityID, hashedCode),
              MarkRecoveryCodeUsed(ctx, identityID, codeID)
Multi-step  : No — the recovery code is the "secret" argument
Security    : codes are generated as crypto/rand hex strings,
              stored as bcrypt hashes (never plaintext),
              single-use (marked used immediately after validation),
              each identity has a fixed set (e.g. 10) generated at MFA enrollment
```

Implementation outline:

```go
func (s *RecoveryCodeStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error) {
    identity, err := s.repo.FindIdentityByField(ctx, s.identifierField, identifier, s.factory)
    codeRecord, err := s.repo.FindUnusedRecoveryCode(ctx, getID(identity))
    if err := s.hasher.Compare(codeRecord.Hash, code); err != nil {
        return nil, ErrRecoveryCodeInvalid
    }
    if err := s.repo.MarkRecoveryCodeUsed(ctx, getID(identity), codeRecord.ID); err != nil {
        return nil, fmt.Errorf("flow: recovery_code: mark used: %w", err)
    }
    return identity, nil
}
```

Sentinel errors:
- `ErrRecoveryCodeInvalid`
- `ErrRecoveryCodeAlreadyUsed`
- `ErrNoRecoveryCodesRemaining`

---

### Example 9 — Email OTP (multi-step, passwordless login)

Differs from magic link: the user enters a short numeric code (e.g. 6 digits) rather than clicking a link.

```
Strategy ID : "email_otp"
Interfaces  : LoginStrategy + Initiator
Storage     : FindIdentityByEmail, StoreOTP, FindOTP, DeleteOTP (same shape as SMS OTP)
Multi-step  : Yes — Initiate() emails the code, Authenticate() verifies it
Security    : same as SMS OTP but delivered by email; apply rate limiting on Initiate
```

---

### Example 10 — LDAP / Active Directory (single-step, login only)

```
Strategy ID : "ldap"
Interfaces  : LoginStrategy only
Storage     : No Kayan storage needed for auth itself; optionally sync identity on first login
External    : github.com/go-ldap/ldap/v3 — inject as an interface, not a direct import in core/
Multi-step  : No — bind with DN + password
Security    : always use LDAPS (TLS) or StartTLS,
              use a service-account bind for the initial search, then re-bind as the user to verify credentials,
              never log the bind password
```

Implementation outline:

```go
func (s *LDAPStrategy) Authenticate(ctx context.Context, username, password string) (any, error) {
    conn, err := s.dialer.DialTLS(s.addr, s.tlsConfig) // injected dialer interface
    defer conn.Close()
    // 1. Bind as service account to search for user DN
    _ = conn.Bind(s.serviceAccountDN, s.serviceAccountPassword)
    result, _ := conn.Search(ldap.NewSearchRequest(s.baseDN, ...username filter...))
    userDN := result.Entries[0].DN
    // 2. Re-bind as the user to verify password
    if err := conn.Bind(userDN, password); err != nil { return nil, ErrLDAPInvalidCredentials }
    // 3. Map LDAP attributes to Kayan identity
    return s.mapEntry(ctx, result.Entries[0])
}
```

Sentinel errors:
- `ErrLDAPInvalidCredentials`
- `ErrLDAPUserNotFound`
- `ErrLDAPConnectionFailed`

---

### Example 11 — "Login with Kayan" (Kayan as OIDC Provider, multi-step)

Use this when a service or app wants to delegate authentication to **a Kayan instance acting as the IdP** — the same pattern as "Login with Google", but the provider is your own Kayan server. Kayan's `core/oauth2` and `core/oidc` packages provide the server side; this strategy implements the **client side**.

```
Strategy ID : "kayan_oidc"
Interfaces  : LoginStrategy + Initiator (two-step: redirect → callback)
Storage     : StoreOIDCState(ctx, state, codeVerifier, nonce, expiry),
              ConsumeOIDCState(ctx, state) (codeVerifier, nonce string, err error),
              FindOrCreateByProviderSub(ctx, sub, traits, factory)
External    : golang.org/x/oauth2 + encoding/json for token exchange;
              inject an HTTP client interface — no direct net/http import in core/
Multi-step  : Yes — Initiate() builds the authorization URL,
              Authenticate() handles the callback (code exchange + ID token validation)
Security    : state is cryptographically random (≥32 bytes), single-use, validated on callback (CSRF),
              always use PKCE (S256 code_challenge + code_verifier),
              include and validate the `nonce` claim in the ID token to prevent replay,
              verify the ID token signature using Kayan's JWKS endpoint (or injected public key),
              verify `iss`, `aud`, `exp`, `nonce` claims before trusting the token,
              never store the access token long-term — exchange for a Kayan session immediately
```

The Kayan OIDC provider exposes standard endpoints your strategy must target:

| Endpoint | Path |
|----------|------|
| Discovery | `<issuer>/.well-known/openid-configuration` |
| Authorization | `<issuer>/oauth2/auth` |
| Token | `<issuer>/oauth2/token` |
| UserInfo | `<issuer>/oidc/userinfo` |
| JWKS | `<issuer>/oauth2/jwks` |

Implementation outline:

```go
// KayanOIDCStrategy authenticates users via a Kayan OIDC provider.
type KayanOIDCStrategy struct {
    issuer       string         // e.g. "https://auth.example.com"
    clientID     string
    clientSecret string
    redirectURI  string
    oauthConfig  OAuthConfiger  // injected interface wrapping golang.org/x/oauth2.Config
    tokenParser  IDTokenParser  // injected interface: ParseAndVerify(rawIDToken, issuer, clientID, nonce) (claims, error)
    repo         KayanOIDCRepository
    factory      func() any
}

// KayanOIDCRepository is the storage contract for the kayan_oidc strategy.
type KayanOIDCRepository interface {
    StoreOIDCState(ctx context.Context, state, codeVerifier, nonce string, expiry time.Duration) error
    ConsumeOIDCState(ctx context.Context, state string) (codeVerifier, nonce string, err error)
    FindOrCreateByProviderSub(ctx context.Context, sub string, traits identity.JSON, factory func() any) (any, error)
}

func (s *KayanOIDCStrategy) ID() string { return "kayan_oidc" }

// Step 1: generate state + PKCE + nonce, redirect user to Kayan's authorization endpoint
func (s *KayanOIDCStrategy) Initiate(ctx context.Context, _ string) (any, error) {
    state, err := generateSecureToken(32)
    if err != nil { return nil, fmt.Errorf("flow: kayan_oidc: generate state: %w", err) }
    verifier, err := generateSecureToken(32)
    if err != nil { return nil, fmt.Errorf("flow: kayan_oidc: generate verifier: %w", err) }
    nonce, err := generateSecureToken(16)
    if err != nil { return nil, fmt.Errorf("flow: kayan_oidc: generate nonce: %w", err) }

    if err := s.repo.StoreOIDCState(ctx, state, verifier, nonce, 10*time.Minute); err != nil {
        return nil, fmt.Errorf("flow: kayan_oidc: store state: %w", err)
    }

    url := s.oauthConfig.AuthCodeURL(state,
        pkceChallenge(verifier),   // S256 code_challenge
        oauth2Param("nonce", nonce),
    )
    return map[string]string{"redirect_url": url, "state": state}, nil
}

// Step 2: exchange code, verify ID token, resolve local identity
// identifier = state from query param, secret = authorization code from query param
func (s *KayanOIDCStrategy) Authenticate(ctx context.Context, state, code string) (any, error) {
    verifier, nonce, err := s.repo.ConsumeOIDCState(ctx, state) // deletes on read
    if err != nil { return nil, ErrKayanOIDCStateInvalid }

    // Exchange authorization code for tokens (includes PKCE verifier)
    oauthToken, err := s.oauthConfig.Exchange(ctx, code, verifierOption(verifier))
    if err != nil { return nil, fmt.Errorf("flow: kayan_oidc: token exchange: %w", err) }

    rawIDToken, ok := oauthToken.Extra("id_token").(string)
    if !ok { return nil, ErrKayanOIDCMissingIDToken }

    // Verify signature, iss, aud, exp, nonce — using Kayan's JWKS or injected public key
    claims, err := s.tokenParser.ParseAndVerify(rawIDToken, s.issuer, s.clientID, nonce)
    if err != nil { return nil, fmt.Errorf("flow: kayan_oidc: id token invalid: %w", err) }
    // `claims.Sub` is the Kayan identity ID from the upstream provider

    traits := identity.JSON{"sub": claims.Sub, "email": claims.Email}
    identity, err := s.repo.FindOrCreateByProviderSub(ctx, claims.Sub, traits, s.factory)
    if err != nil { return nil, fmt.Errorf("flow: kayan_oidc: resolve identity: %w", err) }
    return identity, nil
}
```

**IDTokenParser interface** (defined in the consuming package, satisfied by an OIDC verifier backed by Kayan's JWKS):

```go
// IDTokenParser verifies a raw ID token JWT and returns its claims.
// Implementations fetch Kayan's public keys from <issuer>/oauth2/jwks.
type IDTokenParser interface {
    ParseAndVerify(rawIDToken, issuer, audience, expectedNonce string) (*IDTokenClaims, error)
}

type IDTokenClaims struct {
    Sub   string
    Email string
    // extend with Kayan-specific claims as needed
}
```

**Wire-up example** (in the caller's setup code):

```go
// kayanIssuer is your Kayan server, e.g. "https://auth.mycompany.com"
strategy := flow.NewKayanOIDCStrategy(
    kayanIssuer,
    "my-client-id",
    "my-client-secret",
    "https://app.mycompany.com/auth/kayan/callback",
    kayanOAuthConfig,   // *oauth2.Config pointing at Kayan endpoints
    jwksParser,         // fetches Kayan's /oauth2/jwks
    repo,
    func() any { return &User{} },
)
loginManager.RegisterStrategy(strategy)
```

**Key difference from Example 6 (external social login)**:
- The authorization server is your own Kayan instance — use `core/oidc.Server` / `core/oauth2.Provider` on the server side.
- ID tokens are signed by Kayan's RSA/ECDSA key; verify against `<issuer>/oauth2/jwks`.
- The `sub` claim is Kayan's `identity.GetID()` — a UUID or whatever your identity model returns.
- You can skip `userinfo` fetch if the ID token carries sufficient claims (Kayan embeds traits in `core/oidc`).
- No external OAuth2 library needed in `core/` — inject the config/parser as interfaces.

Sentinel errors:
- `ErrKayanOIDCStateInvalid`
- `ErrKayanOIDCStateExpired`
- `ErrKayanOIDCMissingIDToken`
- `ErrKayanOIDCTokenInvalid`
- `ErrKayanOIDCNonceMismatch`

---

## Implementation Steps

1. **Read** the canonical reference before writing any code:
   - [core/flow/strategy_password.go](../../core/flow/strategy_password.go)
   - [core/flow/flow.go](../../core/flow/flow.go) — interface definitions
   - [core/flow/errors.go](../../core/flow/errors.go) — existing sentinel errors
   - [core/domain/storage.go](../../core/domain/storage.go) — storage interfaces
   - [core/flow/magic_test.go](../../core/flow/magic_test.go) — multi-step test pattern

2. **Identify** which example above maps to the requested strategy and adapt it.

3. **Create** `core/flow/strategy_<name>.go`:
   - `ID() string` returning the strategy ID
   - Storage interface defined in this file (consumer-defined)
   - `New<Name>Strategy(repo, factory, ...opts)` constructor
   - `Register`, `Authenticate`, and/or `Initiate` as required
   - BYOS field mapping via `MapFields` if the strategy reads user model fields

4. **Add** sentinel errors to `core/flow/errors.go`.

5. **Create** `core/flow/strategy_<name>_test.go`:
   - Table-driven tests with a stub/mock storage (no real DB)
   - Cover: success path, expired token, invalid input, replay attack (if applicable)
   - Must pass `go test -race ./...` from `core/`

6. **Verify** the completion checklist from the skill file before finishing.

## Hard Constraints (never violate)

- No Go generics — use `any` + type assertions
- No HTTP framework imports in `core/`
- No direct DB imports — use the storage interface you define
- Token comparison: always `subtle.ConstantTimeCompare`, never `==`
- Random tokens: always `crypto/rand`, never `math/rand`
- Secrets/tokens: never logged
- Audit: emit events for success and failure via the audit store (check `if auditStore != nil` first)
- Thread safety: strategies must be safe for concurrent use
