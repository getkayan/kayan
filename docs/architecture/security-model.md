# Security Model

Kayan includes multiple security controls, but the library expects the integrating application to compose them deliberately. This document explains the intended security posture of the core packages.

## Credential Security

### Password hashing

Password strategies use bcrypt by default and can be configured with cost-based tuning. The repository rules explicitly prohibit weak or legacy password hashing such as MD5, SHA-1, or plain SHA-256.

### Secret comparison

Sensitive comparisons use constant-time techniques where appropriate. The MFA manager and related flows are designed to avoid naive string comparison on verification paths.

### Credential separation

When you need multiple factors or authenticators, use discrete credential records or MFA enrollments rather than overloading a single password field.

## Session Security

### Rotation

Refresh operations rotate tokens. Database sessions rotate session identity and refresh token. OAuth 2.0 refresh operations rotate refresh tokens as well.

### Revocation

JWT strategies support revocation stores. In multi-instance production, treat a shared revocation backend as mandatory if logout or emergency invalidation must be immediate.

### Expiry

Keep access-token lifetimes short. Extend user experience with refresh tokens rather than long-lived bearer tokens.

## Authentication Abuse Controls

### Rate limiting

Credential endpoints should be wrapped with a rate limiter. Use Redis-backed implementations in horizontally scaled environments.

### Account lockout

Lockout should be based on failure windows, not only lifetime counts. Tune lockout windows so they slow attackers without permanently trapping legitimate users.

### Device and risk signals

Device fingerprinting and adaptive risk scoring are meant to influence assurance level. Unknown device plus geo anomaly plus repeated failures should escalate to MFA or step-up, not simply be logged.

## OAuth 2.0 and OIDC

### PKCE

Authorization code flows support PKCE. Public clients should use PKCE by default.

### JWT signing

OAuth 2.0 and OIDC tokens are designed for asymmetric signing with key IDs. Protect private keys externally and rotate them on a schedule appropriate for your compliance posture.

### Introspection and revocation

Use introspection when a resource server cannot validate everything locally or when active revocation state is required.

## SAML Security

SAML support includes request signing and response validation hooks. Because SAML deployments are highly environment-specific, treat certificate management, metadata ingestion, and allowed bindings as high-scrutiny operational controls.

Allow IdP-initiated flows only when the business need is explicit and the surrounding controls are understood.

## Audit and Compliance

Authentication and authorization controls are only useful if you can prove how they behaved.

Use `core/audit` to store:

- actor and subject IDs
- tenant IDs
- event types and statuses
- device, geo, and request metadata
- state transitions for admin and consent changes

Use `core/compliance` and `core/consent` when retention, deletion, export, and consent evidence are part of your contractual or regulatory requirements.

## CSRF Protection

Kayan is **CSRF-safe by default** when using the recommended Bearer token pattern in `Authorization` headers. Browsers do not auto-attach custom headers to cross-origin requests, making this pattern immune to CSRF attacks.

### Recommended (CSRF-Safe)

```go
// Client sends token in header
Authorization: Bearer <token>

// Server validates from header
func bearerToken(r *http.Request) string {
    parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
    if len(parts) == 2 && parts[0] == "Bearer" {
        return parts[1]
    }
    return ""
}
```

All Kayan examples use this pattern. No additional CSRF protection is needed.

### Cookie-Based Sessions (Requires CSRF Protection)

If you choose to store session tokens in cookies instead of Authorization headers, **you must implement CSRF protection**:

```go
// Set SameSite attribute (preferred)
http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    sess.ID,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode, // or Lax for most apps
})

// OR implement double-submit cookie / synchronizer token pattern
```

**Cookie + CSRF token is required for:**
- Traditional web apps with server-rendered forms
- Scenarios where JavaScript cannot access tokens (HttpOnly cookies)
- Legacy frontend code expecting cookie-based auth

### OAuth2/OIDC State Parameter

OAuth2 and OIDC strategies use cryptographically random state tokens (≥32 bytes) validated on callback. This protects redirect-based flows from CSRF. State tokens are:
- Single-use
- Time-limited
- Stored in `domain.TokenStore`
- Validated before completing authentication

## Integration Guidance

- Do not expose raw internal error details to public endpoints.
- Do not hardcode secrets or signing keys in source.
- Resolve tenant context before credential lookups when tenants partition identities.
- Correlate audit, telemetry, and application request IDs.
- Test rate limit, lockout, revocation, and step-up paths as first-class security behavior.
- Use Bearer tokens in headers, not cookies, to avoid CSRF vulnerabilities.
- If using cookies, implement `SameSite` attribute or synchronizer token pattern.