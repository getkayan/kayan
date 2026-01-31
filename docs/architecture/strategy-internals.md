# Kayan Internals: Strategy System

This document explains how Kayan's strategy pattern works internally, enabling pluggable authentication methods.

---

## Strategy Pattern Overview

Kayan uses the Strategy pattern to decouple authentication logic from flow management. Each authentication method (password, OIDC, WebAuthn) is a strategy implementing common interfaces.

```
┌───────────────────────────────┐
│     RegistrationManager       │
│                               │
│  strategies map[string]Strategy
│                               │
│  Submit(method, traits, secret)
│       │                       │
│       ▼ lookup strategy       │
│  strategy.Register(traits, secret)
└───────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│                    STRATEGIES                            │
├───────────────┬───────────────┬───────────────┬─────────┤
│   Password    │     OIDC      │   WebAuthn    │  SAML   │
├───────────────┼───────────────┼───────────────┼─────────┤
│ - Bcrypt hash │ - OAuth flow  │ - FIDO2/WebAuthn│ - XML  │
│ - Field map   │ - ID token    │ - Ceremonies  │ - SAML2 │
│ - Verify      │ - Claims map  │ - Attestation │ - ACS   │
└───────────────┴───────────────┴───────────────┴─────────┘
```

---

## Core Interfaces

### RegistrationStrategy

```go
type RegistrationStrategy interface {
    // Unique identifier for this strategy
    ID() string
    
    // Register creates a new identity
    // traits: User attributes (email, name, etc)
    // secret: Authentication secret (password, empty for OIDC)
    Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}
```

### LoginStrategy

```go
type LoginStrategy interface {
    // Unique identifier for this strategy
    ID() string
    
    // Authenticate verifies credentials and returns identity
    // identifier: Lookup key (email, username)
    // secret: Authentication proof (password, token)
    Authenticate(ctx context.Context, identifier, secret string) (any, error)
}
```

---

## Password Strategy Internals

### Field Mapping

The password strategy uses reflection to map Kayan operations to your struct fields:

```go
type PasswordStrategy struct {
    repo           IdentityRepository
    hasher         Hasher
    identifierField string              // Single field (deprecated)
    identifierFields []string           // Multiple lookup fields
    secretField    string               // Where to store hash
    factory        func() any           // Creates new identity instances
    idGenerator    func() any           // Generates IDs
}

// MapFields configures field mapping
func (s *PasswordStrategy) MapFields(identifiers []string, secret string) {
    s.identifierFields = identifiers
    s.secretField = secret
}
```

### Registration Flow

```go
func (s *PasswordStrategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) {
    // 1. Create identity instance
    identity := s.factory()
    
    // 2. Generate ID if generator set
    if s.idGenerator != nil {
        id := s.idGenerator()
        setField(identity, "ID", id)  // reflection
    }
    
    // 3. Map traits to fields
    var traitMap map[string]any
    json.Unmarshal(traits, &traitMap)
    for field, value := range traitMap {
        setField(identity, field, value)  // reflection
    }
    
    // 4. Hash password and set
    hash, err := s.hasher.Hash(secret)
    setField(identity, s.secretField, hash)
    
    // 5. Persist
    return identity, s.repo.CreateIdentity(identity)
}
```

### Authentication Flow

```go
func (s *PasswordStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
    // 1. Try each identifier field
    var identity any
    for _, field := range s.identifierFields {
        query := map[string]any{strings.ToLower(field): identifier}
        identity, _ = s.repo.FindIdentity(s.factory, query)
        if identity != nil {
            break
        }
    }
    
    if identity == nil {
        return nil, ErrNotFound
    }
    
    // 2. Get stored hash
    hash := getField(identity, s.secretField).(string)
    
    // 3. Verify password
    if err := s.hasher.Verify(secret, hash); err != nil {
        return nil, ErrInvalidCredentials
    }
    
    return identity, nil
}
```

---

## OIDC Strategy Internals

### Provider Configuration

```go
type OIDCProvider struct {
    Issuer       string   // https://accounts.google.com
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Scopes       []string
    
    // Internal
    oauth2Config *oauth2.Config
    verifier     *oidc.IDTokenVerifier
}
```

### Authorization Flow

```go
func (s *OIDCStrategy) BeginAuth(ctx context.Context, provider string) (string, error) {
    p := s.providers[provider]
    
    // Generate state for CSRF protection
    state := generateSecureRandom(32)
    
    // Generate PKCE verifier
    verifier := generateSecureRandom(32)
    challenge := sha256Base64URL(verifier)
    
    // Store state -> verifier mapping
    s.sessions.Store(state, verifier, 5*time.Minute)
    
    // Build authorization URL
    url := p.oauth2Config.AuthCodeURL(state,
        oauth2.SetAuthURLParam("code_challenge", challenge),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
    )
    
    return url, nil
}

func (s *OIDCStrategy) CompleteAuth(ctx context.Context, provider, code, state string) (any, error) {
    p := s.providers[provider]
    
    // Verify state and get PKCE verifier
    verifier, ok := s.sessions.Load(state)
    if !ok {
        return nil, ErrInvalidState
    }
    
    // Exchange code for tokens
    token, err := p.oauth2Config.Exchange(ctx, code,
        oauth2.SetAuthURLParam("code_verifier", verifier),
    )
    
    // Verify ID token
    idToken, err := p.verifier.Verify(ctx, token.IDToken)
    
    // Extract claims
    var claims struct {
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
        Name          string `json:"name"`
        Picture       string `json:"picture"`
    }
    idToken.Claims(&claims)
    
    // Find or create identity
    ...
}
```

---

## WebAuthn Strategy Internals

### Credential Store

```go
type WebAuthnCredential struct {
    CredentialID []byte
    PublicKey    []byte
    UserID       string
    SignCount    uint32
    AAGUID       []byte
    CreatedAt    time.Time
}
```

### Registration Ceremony

```go
func (s *WebAuthnStrategy) BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
    // 1. Generate challenge
    challenge := generateSecureRandom(32)
    
    // 2. Create session
    sessionID := generateSecureRandom(16)
    s.sessions.Store(sessionID, &registrationSession{
        UserID:    userID,
        Challenge: challenge,
        ExpiresAt: time.Now().Add(5 * time.Minute),
    })
    
    // 3. Build options
    options := &protocol.CredentialCreation{
        PublicKey: protocol.PublicKeyCredentialCreationOptions{
            Challenge: challenge,
            RelyingParty: protocol.RelyingPartyEntity{
                ID:   s.config.RPID,
                Name: s.config.RPDisplayName,
            },
            User: protocol.UserEntity{
                ID:          []byte(userID),
                DisplayName: username,
            },
            PubKeyCredParams: []protocol.CredentialParameter{
                {Type: "public-key", Alg: -7},   // ES256
                {Type: "public-key", Alg: -257}, // RS256
            },
            AuthenticatorSelection: protocol.AuthenticatorSelection{
                UserVerification: protocol.VerificationPreferred,
            },
            Timeout: 60000, // 60 seconds
        },
    }
    
    return options, hex.EncodeToString(sessionID), nil
}
```

---

## Hook System

Hooks allow intercepting strategy operations:

```go
type RegistrationManager struct {
    strategies map[string]RegistrationStrategy
    preHooks   []func(context.Context, any) error
    postHooks  []func(context.Context, any) error
}

func (m *RegistrationManager) Submit(ctx context.Context, method string, traits identity.JSON, secret string) (any, error) {
    // Pre-hooks (identity is nil)
    for _, hook := range m.preHooks {
        if err := hook(ctx, nil); err != nil {
            return nil, err
        }
    }
    
    // Strategy execution
    strategy := m.strategies[method]
    identity, err := strategy.Register(ctx, traits, secret)
    if err != nil {
        return nil, err
    }
    
    // Post-hooks (identity is populated)
    for _, hook := range m.postHooks {
        if err := hook(ctx, identity); err != nil {
            // Log but don't fail - identity already created
            log.Warn("Post-hook failed", "error", err)
        }
    }
    
    return identity, nil
}
```

### Common Hook Use Cases

```go
// Send welcome email
regManager.AddPostHook(func(ctx context.Context, ident any) error {
    user := ident.(*User)
    return emailService.SendWelcome(user.Email)
})

// Audit logging
loginManager.AddPostHook(func(ctx context.Context, ident any) error {
    user := ident.(*User)
    return auditLog.Record("login.success", user.ID, ctx)
})

// Rate limit check
loginManager.AddPreHook(func(ctx context.Context, _ any) error {
    ip := getIPFromContext(ctx)
    if !rateLimiter.Allow(ip) {
        return ErrRateLimited
    }
    return nil
})
```

---

## Implementing Custom Strategies

### Example: SMS OTP Strategy

```go
type SMSOTPStrategy struct {
    repo      IdentityRepository
    smsSender SMSSender
    otpStore  OTPStore
    factory   func() any
}

func (s *SMSOTPStrategy) ID() string { return "sms_otp" }

func (s *SMSOTPStrategy) RequestOTP(ctx context.Context, phone string) error {
    // Generate 6-digit OTP
    otp := fmt.Sprintf("%06d", rand.Intn(1000000))
    
    // Store with expiry
    s.otpStore.Set(phone, otp, 5*time.Minute)
    
    // Send SMS
    return s.smsSender.Send(phone, "Your code is: "+otp)
}

func (s *SMSOTPStrategy) Authenticate(ctx context.Context, phone, otp string) (any, error) {
    // Verify OTP
    stored, ok := s.otpStore.Get(phone)
    if !ok || stored != otp {
        return nil, ErrInvalidOTP
    }
    
    // Clear OTP
    s.otpStore.Delete(phone)
    
    // Find or create identity
    identity, err := s.repo.FindIdentity(s.factory, map[string]any{"phone": phone})
    if err != nil {
        // Auto-register on first login
        identity = s.factory()
        setField(identity, "Phone", phone)
        s.repo.CreateIdentity(identity)
    }
    
    return identity, nil
}
```

Register with managers:

```go
smsStrategy := &SMSOTPStrategy{...}
loginManager.RegisterStrategy(smsStrategy)
```
