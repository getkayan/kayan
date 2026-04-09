---
trigger: always_on
---

## 7. Security Rules

### 7.1 Secrets
- Never log passwords, tokens, or hashed secrets.
- Password hashes must use `bcrypt` (default) or `argon2`. Never use MD5, SHA-1, or SHA-256 for password hashing.
- JWT secrets must not be hardcoded. Always accept them via configuration.

### 7.2 OIDC/OAuth
- OIDC state parameters must be **cryptographically random** and validated on callback.
- Always use PKCE (`code_challenge`/`code_verifier`) for OAuth2 authorization code flows.
- Never return raw tokens in API responses meant for production use.

### 7.3 Timing Safety
- Use constant-time comparison (`subtle.ConstantTimeCompare`) for token validation.
- Use the `Hasher.Compare()` interface (which uses bcrypt's constant-time comparison) for passwords.

---
