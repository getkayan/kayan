# Authentication Flows

This document details all authentication flows supported by Kayan.

## Table of Contents

- [Password Authentication](#password-authentication)
- [OIDC/Social Login](#oidcsocial-login)
- [WebAuthn/Passkeys](#webauthnpasskeys)
- [SAML 2.0](#saml-20)
- [Magic Link](#magic-link)
- [Multi-Factor Authentication](#multi-factor-authentication)

---

## Password Authentication

### Registration

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan
    participant DB as Database
    
    User->>App: Submit registration form
    App->>K: POST /api/v1/registration
    Note right of App: { traits: { email }, password }
    
    K->>K: Validate email format
    K->>K: Check password policy
    K->>DB: Check email uniqueness
    
    alt Email exists
        K-->>App: 409 Conflict
        App-->>User: Email already registered
    end
    
    K->>K: Hash password (bcrypt)
    K->>K: Generate identity ID
    K->>DB: Create identity record
    K->>K: Execute PostHooks
    K->>K: Create session (optional)
    K-->>App: 201 Created + session
    App-->>User: Registration successful
```

### Login

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan
    participant RL as RateLimiter
    participant LO as Lockout
    participant DB as Database
    
    User->>App: Submit login form
    App->>K: POST /api/v1/login
    
    K->>RL: Check rate limit
    alt Rate limited
        RL-->>App: 429 Too Many Requests
        App-->>User: Please wait before retrying
    end
    
    K->>LO: Check account lockout
    alt Account locked
        LO-->>App: 423 Locked
        App-->>User: Account locked until X
    end
    
    K->>DB: Find by identifier
    alt User not found
        K->>LO: Record failure
        K-->>App: 401 Unauthorized
    end
    
    K->>K: Verify password hash
    alt Invalid password
        K->>LO: Record failure
        alt Max failures reached
            LO->>DB: Lock account
        end
        K-->>App: 401 Unauthorized
    end
    
    K->>LO: Clear failure count
    K->>K: Create session
    K->>DB: Store session
    K-->>App: 200 OK + session token
    App-->>User: Login successful
```

---

## OIDC/Social Login

### Authorization Code Flow

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan
    participant IdP as OIDC Provider
    
    User->>App: Click "Login with Google"
    App->>K: GET /api/v1/oidc/google
    
    K->>K: Generate state token
    K->>K: Build authorization URL
    K-->>App: 302 Redirect to IdP
    App-->>User: Redirect to Google
    
    User->>IdP: Authenticate
    IdP-->>User: 302 Redirect to callback
    
    User->>K: GET /api/v1/oidc/google/callback
    Note right of User: ?code=XXX&state=YYY
    
    K->>K: Validate state token
    K->>IdP: Exchange code for tokens
    IdP-->>K: Access token + ID token
    
    K->>IdP: Fetch userinfo
    IdP-->>K: User profile
    
    K->>K: Find or create identity
    K->>K: Link OIDC credential
    K->>K: Create session
    K-->>User: 302 Redirect to app + session
```

### Supported Providers

| Provider | Discovery URL | Scopes |
|----------|---------------|--------|
| Google | `https://accounts.google.com` | openid, email, profile |
| GitHub | N/A (manual config) | user:email |
| Microsoft | `https://login.microsoftonline.com/{tenant}/v2.0` | openid, email, profile |
| Apple | `https://appleid.apple.com` | openid, email, name |

---

## WebAuthn/Passkeys

### Registration (Attestation)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant App as Application
    participant K as Kayan
    
    User->>App: Click "Add Passkey"
    App->>K: POST /webauthn/registration/begin
    K->>K: Generate challenge
    K->>K: Build creation options
    K-->>App: PublicKeyCredentialCreationOptions
    
    App->>Browser: navigator.credentials.create()
    Browser->>User: Biometric/PIN prompt
    User->>Browser: Authenticate
    Browser-->>App: AuthenticatorAttestationResponse
    
    App->>K: POST /webauthn/registration/finish
    K->>K: Verify attestation
    K->>K: Store credential
    K-->>App: Success + credential ID
    App-->>User: Passkey registered
```

### Login (Assertion)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant App as Application
    participant K as Kayan
    
    User->>App: Enter email, click "Login with Passkey"
    App->>K: POST /webauthn/login/begin
    K->>K: Look up user credentials
    K->>K: Generate challenge
    K-->>App: PublicKeyCredentialRequestOptions
    
    App->>Browser: navigator.credentials.get()
    Browser->>User: Select passkey + biometric
    User->>Browser: Authenticate
    Browser-->>App: AuthenticatorAssertionResponse
    
    App->>K: POST /webauthn/login/finish
    K->>K: Verify assertion signature
    K->>K: Update sign counter
    K->>K: Create session
    K-->>App: Session token
    App-->>User: Login successful
```

---

## SAML 2.0

### SP-Initiated SSO

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan SP
    participant IdP as SAML IdP
    
    User->>App: Access protected resource
    App->>K: GET /saml/{idp}/login
    
    K->>K: Generate AuthnRequest
    K->>K: Sign request (optional)
    K-->>User: 302 Redirect to IdP
    Note right of K: SAMLRequest in query/POST
    
    User->>IdP: Login page
    IdP->>User: Authenticate
    User->>IdP: Submit credentials
    IdP->>IdP: Validate credentials
    IdP->>IdP: Build SAML Response
    IdP-->>User: 302 POST to ACS
    
    User->>K: POST /saml/{idp}/acs
    Note right of User: SAMLResponse + RelayState
    
    K->>K: Validate XML signature
    K->>K: Verify conditions
    K->>K: Extract assertions
    K->>K: Map attributes to traits
    K->>K: Find or create identity
    K->>K: Create session
    K-->>User: 302 Redirect to RelayState
```

### IdP-Initiated SSO

```mermaid
sequenceDiagram
    actor User
    participant IdP as SAML IdP
    participant K as Kayan SP
    participant App as Application
    
    User->>IdP: Select Kayan app
    IdP->>IdP: Build unsolicited Response
    IdP-->>User: POST to ACS
    
    User->>K: POST /saml/{idp}/acs
    K->>K: Validate (AllowIdPInitiated=true)
    K->>K: Process assertions
    K->>K: Create session
    K-->>User: 302 Redirect to default URL
```

---

## Magic Link

### Request Link

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan
    participant Email as Email Service
    
    User->>App: Enter email, click "Send Magic Link"
    App->>K: POST /api/v1/magic/request
    
    K->>K: Generate secure token
    K->>K: Store token with expiry
    K->>Email: Send magic link email
    K-->>App: 202 Accepted
    App-->>User: Check your email
```

### Verify Link

```mermaid
sequenceDiagram
    actor User
    participant Email as Email Client
    participant K as Kayan
    participant App as Application
    
    User->>Email: Open email
    User->>K: GET /api/v1/magic/verify?token=XXX
    
    K->>K: Validate token
    alt Token invalid/expired
        K-->>User: 401 Invalid token
    end
    
    K->>K: Find or create identity
    K->>K: Delete used token
    K->>K: Create session
    K-->>User: 302 Redirect to app
```

---

## Multi-Factor Authentication

### TOTP Enrollment

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan
    participant Auth as Authenticator App
    
    User->>App: Enable MFA
    App->>K: POST /mfa/totp/enroll
    
    K->>K: Generate TOTP secret
    K->>K: Build otpauth:// URI
    K->>K: Generate QR code
    K-->>App: Secret + QR code
    
    App-->>User: Show QR code
    User->>Auth: Scan QR code
    Auth-->>User: Shows 6-digit code
    
    User->>App: Enter verification code
    App->>K: POST /mfa/totp/verify
    
    K->>K: Validate TOTP
    alt Valid
        K->>K: Mark MFA enabled
        K-->>App: MFA enrolled
    else Invalid
        K-->>App: 401 Invalid code
    end
```

### MFA Challenge during Login

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant K as Kayan
    
    User->>App: Login with password
    App->>K: POST /api/v1/login
    
    K->>K: Verify password ✓
    K->>K: Check MFA required
    K-->>App: 200 + mfa_required: true
    
    App-->>User: Enter MFA code
    User->>App: Submit TOTP code
    App->>K: POST /mfa/totp/verify
    
    K->>K: Validate TOTP
    K->>K: Upgrade session to AAL2
    K-->>App: Session with AAL2
    App-->>User: Login complete
```

---

## Session Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: Login/Register
    Created --> Active: Valid token
    Active --> Refreshed: Refresh token used
    Refreshed --> Active: New token issued
    Active --> Expired: TTL exceeded
    Active --> Revoked: Logout/Admin
    Expired --> [*]
    Revoked --> [*]
```

### Token Refresh Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant K as Kayan
    
    App->>K: POST /sessions/refresh
    Note right of App: { refresh_token: "XXX" }
    
    K->>K: Validate refresh token
    alt JWT Strategy
        K->>K: Verify JWT signature
        K->>K: Generate new access/refresh tokens
    else Database Strategy
        K->>K: Find session by refresh token
        K->>K: Rotate: new session ID + refresh token
        K->>K: Invalidate old session
    end
    
    K-->>App: New session tokens
```
