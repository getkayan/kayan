# Kayan Security Model

This document describes the security architecture, threat model, and security controls implemented in Kayan.

---

## Threat Model

### Assets Protected
1. **User credentials** (password hashes, WebAuthn keys)
2. **Session tokens** (access to authenticated resources)
3. **Personal data** (email, profile, traits)
4. **Authorization state** (roles, permissions)

### Threat Actors
| Actor | Capability | Mitigation |
|-------|------------|------------|
| External attacker | Brute force, credential stuffing | Rate limiting, account lockout |
| MITM | Traffic interception | TLS requirement, secure cookies |
| Malicious admin | Privilege abuse | Audit logging, separation of duties |
| Compromised database | Data exfiltration | Password hashing, encryption at rest |

---

## Authentication Security

### Password Hashing

Kayan uses **bcrypt** by default with configurable cost:

```go
// Default cost: 10 (~100ms per hash)
hasher := flow.NewBcryptHasher(10)

// Higher security (cost 14 = ~1s per hash)
hasher := flow.NewBcryptHasher(14)
```

**Why bcrypt?**
- Memory-hard, resistant to GPU attacks
- Built-in salt generation
- Adaptive cost factor

**Custom Hasher Interface:**
```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(password, hash string) error
}
```

### Password Policy Enforcement

Per-tenant or global policies:

```go
type PasswordPolicy struct {
    MinLength        int
    MaxLength        int
    RequireUppercase bool
    RequireLowercase bool
    RequireNumbers   bool
    RequireSymbols   bool
    DisallowCommon   bool      // Check against common passwords
    DisallowPrevious int       // Prevent N previous passwords
}
```

### Credential Storage

| Credential Type | Storage Method |
|-----------------|----------------|
| Password | bcrypt hash in database |
| WebAuthn | Public key in database, private key on device |
| TOTP | Encrypted secret in database |
| OAuth tokens | Encrypted, short-lived |

---

## Session Security

### JWT Sessions

```go
type JWTClaims struct {
    Subject   string    `json:"sub"`  // Identity ID
    SessionID string    `json:"sid"`  // Unique session ID
    IssuedAt  time.Time `json:"iat"`
    ExpiresAt time.Time `json:"exp"`
    Issuer    string    `json:"iss"`
}
```

**Security Properties:**
- **Signing**: HS256 (shared secret) or RS256 (asymmetric)
- **Expiry**: Configurable, typically 15min-24h
- **Revocation**: Not possible (use short expiry + refresh tokens)

### Database Sessions

```sql
CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,      -- Cryptographically random
    identity_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    revoked_at TIMESTAMP             -- NULL = active
);
```

**Security Properties:**
- **Immediate revocation**: Set `revoked_at`
- **Audit trail**: Full session history
- **Server-side control**: Limited exposure

### Session Token Generation

```go
// 32 bytes of crypto/rand → 64 hex chars
token := make([]byte, 32)
rand.Read(token)
sessionID := hex.EncodeToString(token)
```

### Cookie Security

When using cookies:
```go
http.SetCookie(w, &http.Cookie{
    Name:     "kayan_session",
    Value:    token,
    Path:     "/",
    HttpOnly: true,              // No JavaScript access
    Secure:   true,              // HTTPS only
    SameSite: http.SameSiteStrictMode,
    MaxAge:   int(expiry.Seconds()),
})
```

---

## Brute Force Protection

### Rate Limiting

```go
type RateLimitConfig struct {
    MaxAttempts  int           // Requests allowed
    Window       time.Duration // Time window
    LockoutTime  time.Duration // Lockout after exceeded
}

// Per-IP login limiting
loginLimiter := flow.NewMemoryRateLimiter()
allowed, retryAfter := loginLimiter.Allow("login:"+ip, config)
```

**Implementation:**
- Sliding window algorithm
- In-memory (default) or Redis-backed
- Returns `Retry-After` header on limit

### Account Lockout

```go
type LockoutConfig struct {
    MaxFailedAttempts int           // Failures before lock
    LockoutDuration   time.Duration // How long locked
    ResetOnSuccess    bool          // Reset counter on success
}

// Per-identity lockout
lockout := flow.NewLockoutManager(store, config)
locked, unlockAt := lockout.IsLocked(ctx, identifier)
```

---

## OAuth2/OIDC Security

### State Parameter

```go
// Generate state for CSRF protection
state := base64.URLEncoding.EncodeToString(randBytes(32))
session.Set("oauth_state", state)

// Validate on callback
if r.URL.Query().Get("state") != session.Get("oauth_state") {
    return ErrInvalidState
}
```

### PKCE (Proof Key for Code Exchange)

```go
// Generate verifier and challenge
verifier := base64.URLEncoding.EncodeToString(randBytes(32))
challenge := sha256.Sum256([]byte(verifier))
challengeStr := base64.URLEncoding.EncodeToString(challenge[:])

// Send challenge in authorization request
// Send verifier in token exchange
```

### Token Storage

- Access tokens: Memory only (never persisted)
- Refresh tokens: Encrypted in database
- ID tokens: Validated, claims extracted, token discarded

---

## WebAuthn Security

### Relying Party Configuration

```go
type WebAuthnConfig struct {
    RPID      string   // Domain (no port, no protocol)
    RPOrigins []string // Allowed origins
}
```

**Critical**: `RPID` must exactly match the domain where passkeys are registered.

### Ceremony Security

| Check | Purpose |
|-------|---------|
| Origin validation | Prevent relay attacks |
| Challenge freshness | Prevent replay |
| User verification | Confirm biometric/PIN |
| Counter increment | Detect cloned keys |

### Credential Storage

```go
type WebAuthnCredential struct {
    ID             []byte // Credential ID
    PublicKey      []byte // COSE public key
    AttestationType string
    Transport      []string
    Counter        uint32 // For clone detection
}
```

---

## Data Protection

### Encryption at Rest

Sensitive fields can be encrypted:

```go
// Encrypt before storage
encrypted := compliance.Encrypt(key, sensitiveData)

// Decrypt on retrieval
decrypted, _ := compliance.Decrypt(key, encrypted)
```

**Algorithm**: AES-256-GCM

### PII Handling

```go
// Mark fields as PII for compliance
type User struct {
    Email     string `kayan:"pii"`         // Logged with masking
    Password  string `kayan:"secret,omit"` // Never logged
    SessionID string `kayan:"sensitive"`   // Logged as hash
}
```

### Data Retention

```go
retention := compliance.NewRetentionPolicy(compliance.Config{
    SessionMaxAge:    30 * 24 * time.Hour,  // 30 days
    AuditLogMaxAge:   365 * 24 * time.Hour, // 1 year
    DeletedUserGrace: 30 * 24 * time.Hour,  // 30 days
})

// Run cleanup
retention.Cleanup(ctx, repo)
```

---

## Audit Logging

### Event Format

```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "authentication.success",
    "identity_id": "user_abc123",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "method": "password",
    "tenant_id": "tenant_acme",
    "metadata": {
        "mfa_used": false
    }
}
```

### Event Types

| Event | Description |
|-------|-------------|
| `registration.started` | Registration attempt |
| `registration.success` | Account created |
| `registration.failed` | Registration error |
| `authentication.started` | Login attempt |
| `authentication.success` | Successful login |
| `authentication.failed` | Invalid credentials |
| `session.created` | New session |
| `session.revoked` | Session ended |
| `password.changed` | Password update |
| `mfa.enrolled` | MFA enabled |
| `mfa.verified` | MFA check passed |

---

## Security Checklist

### Deployment

- [ ] TLS/HTTPS enforced
- [ ] Secure cookie flags enabled
- [ ] Rate limiting configured
- [ ] Bcrypt cost ≥ 12 for production
- [ ] JWT secret ≥ 32 bytes
- [ ] Database connections encrypted
- [ ] Audit logging enabled

### Configuration

- [ ] Admin endpoints protected
- [ ] CORS properly configured
- [ ] Security headers set (CSP, HSTS, X-Frame-Options)
- [ ] Session expiry configured
- [ ] Password policy enforced

### Monitoring

- [ ] Failed login alerts
- [ ] Brute force detection
- [ ] Session anomaly detection
- [ ] Admin action logging
