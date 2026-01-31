# Session Management

Kayan provides flexible session management with both stateless (JWT) and stateful (database) options.

## Session Strategies

| Strategy | Pros | Cons | Use Case |
|----------|------|------|----------|
| JWT | No DB lookup, scalable | Can't revoke early | Microservices, APIs |
| Database | Revocable, auditable | DB lookup per request | Web apps, admin panels |

---

## JWT Strategy (Stateless)

Sessions are encoded into the token itself.

```go
import "github.com/getkayan/kayan/core/session"

// Create strategy
jwtStrategy := session.NewHS256Strategy(
    "your-secret-key",   // JWT signing key
    24 * time.Hour,      // Token expiry
)

// Initialize manager
sessManager := session.NewManager(jwtStrategy)

// Create session
sess, _ := sessManager.Create("session_id", "user_123")
fmt.Println(sess.ID) // JWT token

// Validate
sess, err := sessManager.Validate(token)
if err != nil {
    // Invalid or expired
}
```

### JWT Claims

```json
{
  "sub": "user_123",
  "sid": "session_id",
  "exp": 1706745600,
  "iat": 1706659200
}
```

### Delete Behavior

```go
// No-op for JWT - tokens remain valid until expiry
sessManager.Delete(token)
```

---

## Database Strategy (Stateful)

Sessions are stored in the database for full control.

```go
// Create strategy with repository
dbStrategy := session.NewDatabaseStrategy(repo)

sessManager := session.NewManager(dbStrategy)

// Create session
sess, _ := sessManager.Create("session_id", "user_123")

// Revoke immediately
sessManager.Delete(sess.ID)

// Now validation fails
_, err := sessManager.Validate(sess.ID) // Error!
```

### Session Table

```sql
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    identity_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Session Rotation

Implement access/refresh token patterns:

```go
config := session.RotationConfig{
    AccessTTL:  15 * time.Minute,
    RefreshTTL: 7 * 24 * time.Hour,
}

rotator := session.NewRotator(sessManager, config)

// Initial login
tokens, _ := rotator.CreatePair("user_123")
// tokens.AccessToken, tokens.RefreshToken

// Refresh (rotates both tokens)
newTokens, _ := rotator.Refresh(tokens.RefreshToken)
```

### Rotation Flow

```
1. Login → Get access + refresh tokens
2. Access token expires (15 min)
3. POST /refresh with refresh token
4. Get new access + new refresh tokens
5. Old refresh token invalidated
```

---

## Middleware Integration

### Echo

```go
authMiddleware := func(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        token := c.Request().Header.Get("Authorization")
        token = strings.TrimPrefix(token, "Bearer ")
        
        sess, err := sessManager.Validate(token)
        if err != nil {
            return c.JSON(401, map[string]string{"error": "Unauthorized"})
        }
        
        c.Set("session", sess)
        c.Set("user_id", sess.IdentityID)
        return next(c)
    }
}

e.GET("/protected", handler, authMiddleware)
```

### Generic HTTP

```go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        
        sess, err := sessManager.Validate(token)
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        
        ctx := context.WithValue(r.Context(), "session", sess)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

---

## Session Hooks

Execute logic on session events:

```go
sessManager.OnCreate(func(sess *session.Session) {
    log.Printf("New session: %s for user %s", sess.ID, sess.IdentityID)
})

sessManager.OnDelete(func(sessionID string) {
    log.Printf("Session revoked: %s", sessionID)
    // Clear cache, notify user, etc.
})
```

---

## See Also

- [Example: session_jwt](../../../kayan-examples/session_jwt/)
- [Example: session_database](../../../kayan-examples/session_database/)
- [Example: session_rotation](../../../kayan-examples/session_rotation/)
