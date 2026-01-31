# API Reference

Kayan exposes a RESTful API for identity management. Full OpenAPI specification: [openapi.yaml](../openapi/openapi.yaml)

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

Most endpoints require a session token:

```bash
# Header
Authorization: Bearer <token>

# Alternative header
X-Session-Token: <token>

# Cookie
kayan_session=<token>
```

---

## Endpoints

### Registration

| Method | Path | Description |
|--------|------|-------------|
| POST | `/registration` | Register new identity |

```bash
curl -X POST http://localhost:8080/api/v1/registration \
  -H "Content-Type: application/json" \
  -d '{"traits": {"email": "user@example.com"}, "password": "secret123"}'
```

**Response:**
```json
{
  "id": "user_abc123",
  "traits": {"email": "user@example.com"},
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

### Login

| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | Authenticate with credentials |

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "user@example.com", "password": "secret123"}'
```

**Response:**
```json
{
  "session_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2024-01-16T10:30:00Z"
}
```

---

### Session

| Method | Path | Description |
|--------|------|-------------|
| GET | `/whoami` | Get current identity |
| POST | `/logout` | End session |
| POST | `/sessions/refresh` | Refresh session token |

```bash
curl http://localhost:8080/api/v1/whoami \
  -H "Authorization: Bearer $TOKEN"
```

---

### OIDC (Social Login)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oidc/{provider}` | Start OIDC flow |
| GET | `/oidc/{provider}/callback` | OIDC callback |

```bash
# Redirects to Google
curl -L http://localhost:8080/api/v1/oidc/google
```

---

### WebAuthn

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webauthn/registration/begin` | Start passkey registration |
| POST | `/webauthn/registration/finish` | Complete registration |
| POST | `/webauthn/login/begin` | Start passkey login |
| POST | `/webauthn/login/finish` | Complete login |

---

### MFA

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mfa/totp/enroll` | Start TOTP enrollment |
| POST | `/mfa/totp/verify` | Verify TOTP code |

---

### Recovery

| Method | Path | Description |
|--------|------|-------------|
| POST | `/recovery/request` | Request password reset |
| POST | `/recovery/complete` | Complete password reset |

---

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe |
| GET | `/health` | Detailed health status |

---

## Admin API

Admin endpoints require elevated permissions.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List users |
| POST | `/admin/users` | Create user |
| GET | `/admin/users/{id}` | Get user |
| PATCH | `/admin/users/{id}` | Update user |
| DELETE | `/admin/users/{id}` | Delete user |
| GET | `/admin/users/{id}/sessions` | List user sessions |
| DELETE | `/admin/users/{id}/sessions` | Revoke all sessions |

---

## Error Responses

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid credentials"
  }
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `BAD_REQUEST` | 400 | Invalid input |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Permission denied |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Already exists |
| `LOCKED` | 423 | Account locked |
| `RATE_LIMITED` | 429 | Too many requests |
