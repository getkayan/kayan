# Authentication Strategies

Kayan uses a strategy pattern for authentication, allowing you to mix and match methods.

## Available Strategies

| Strategy | Use Case | Stateless |
|----------|----------|-----------|
| Password | Traditional email/password | ✅ |
| OIDC | Social login (Google, GitHub) | ❌ |
| WebAuthn | Passkeys/biometrics | ❌ |
| SAML | Enterprise SSO | ❌ |
| Magic Link | Passwordless email | ❌ |
| TOTP | Two-factor authentication | ✅ |

---

## Password Strategy

The most common authentication method.

```go
hasher := flow.NewBcryptHasher(10) // Cost factor 4-31
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)

// Register with both managers
regManager.RegisterStrategy(pwStrategy)
loginManager.RegisterStrategy(pwStrategy)

// Authenticate
ident, err := loginManager.Authenticate(ctx, "password", email, password)
```

### Bcrypt Cost

| Cost | Time (approx) | Use Case |
|------|---------------|----------|
| 10 | ~100ms | Development |
| 12 | ~300ms | Standard production |
| 14 | ~1s | High security |

---

## OIDC Strategy (Social Login)

Support Google, GitHub, Microsoft, and any OIDC provider.

```go
configs := map[string]config.OIDCProvider{
    "google": {
        Issuer:       "https://accounts.google.com",
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/api/v1/oidc/google/callback",
        Scopes:       []string{"openid", "email", "profile"},
    },
    "github": {
        Issuer:       "https://github.com",
        ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/api/v1/oidc/github/callback",
    },
}

oidcManager, _ := flow.NewOIDCManager(repo, configs, factory)
```

### Flow

```
1. GET /api/v1/oidc/google      → Redirect to Google
2. User authenticates at Google
3. GET /api/v1/oidc/google/callback  → Exchange code, create session
```

---

## WebAuthn Strategy (Passkeys)

Passwordless authentication using biometrics or security keys.

```go
config := flow.WebAuthnConfig{
    RPDisplayName: "My App",
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com"},
    SessionTTL:    5 * time.Minute,
}

webauthn, _ := flow.NewWebAuthnStrategy(repo, config, factory, sessionStore)
```

### Ceremony Flow

```
Registration:
1. POST /webauthn/registration/begin  → Get challenge
2. Browser creates credential
3. POST /webauthn/registration/finish → Save credential

Login:
1. POST /webauthn/login/begin  → Get challenge
2. Browser signs challenge
3. POST /webauthn/login/finish → Verify & create session
```

---

## Magic Link Strategy

Passwordless email authentication.

```go
config := flow.MagicLinkConfig{
    TokenTTL:    15 * time.Minute,
    TokenLength: 32,
    BaseURL:     "https://example.com",
}

magicStrategy := flow.NewMagicLinkStrategy(repo, config, factory)
magicStrategy.MapIdentifierField("Email")
```

### Flow

```
1. User enters email
2. Server generates token, sends email
3. User clicks link: /auth/verify?token=xxx
4. Server validates token, creates session
```

---

## TOTP Strategy (2FA)

Time-based one-time passwords for MFA.

```go
totpStrategy := flow.NewTOTPStrategy(repo)

// Enrollment
secret, qrCode, _ := totpStrategy.Enroll(ctx, userID)
// Show QR code to user

// Verification
valid, _ := totpStrategy.Verify(ctx, userID, "123456")
```

---

## Combining Strategies

Register multiple strategies with the same manager:

```go
regManager.RegisterStrategy(passwordStrategy)
regManager.RegisterStrategy(magicStrategy)
loginManager.RegisterStrategy(oidcStrategy)
loginManager.RegisterStrategy(webauthnStrategy)
```

The strategy is selected by the `method` parameter:

```go
regManager.Submit(ctx, "password", traits, secret)
loginManager.Authenticate(ctx, "webauthn", identifier, "")
```

---

## See Also

- [Example: webauthn_passkeys](../../../kayan-examples/webauthn_passkeys/)
- [Example: magic_link](../../../kayan-examples/magic_link/)
