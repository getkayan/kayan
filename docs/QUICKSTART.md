# Kayan Quick Start Guide

**5-minute integration guide for AI assistants and developers.**

---

## 1. Install Kayan

```bash
go get github.com/getkayan/kayan/core
go get github.com/getkayan/kayan/kgorm  # For SQL databases
```

---

## 2. Define Your User Model

```go
package main

import "github.com/getkayan/kayan/core/flow"

// Use your existing model — Kayan adapts to YOUR schema
type User struct {
    ID        string `gorm:"primaryKey"`
    Email     string `gorm:"uniqueIndex"`
    Name      string
    CreatedAt time.Time
}

// Only requirement: implement FlowIdentity
func (u *User) GetID() any { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }
```

---

## 3. Set Up Storage

```go
import (
    "github.com/getkayan/kayan/kgorm"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

// Connect to your database
db, _ := gorm.Open(postgres.Open("postgres://user:pass@localhost/dbname"), &gorm.Config{})

// Auto-migrate Kayan's default tables (or use your own schema)
db.AutoMigrate(&identity.Identity{}, &identity.Credential{}, &identity.Session{})

// Create storage adapter
repo := kgorm.New(db)
```

---

## 4. Configure Authentication

```go
import (
    "github.com/getkayan/kayan/core/flow"
    "github.com/getkayan/kayan/core/session"
    "time"
)

// Set up password authentication (one-liner)
reg, login := flow.PasswordAuth(
    repo,
    func() any { return &User{} },
    "email", // identifier field name in your User struct
)

// Set up JWT sessions
sessions := session.NewHS256Strategy(
    os.Getenv("JWT_SECRET"), // Use environment variable in production
    24 * time.Hour,          // Access token expiry
)
```

---

## 5. Add HTTP Handlers

### Registration Endpoint

```go
func handleRegister(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&body)
    
    // Validate input
    if body.Email == "" || body.Password == "" {
        http.Error(w, "email and password required", http.StatusBadRequest)
        return
    }
    
    // Register user
    traits := identity.JSON(fmt.Sprintf(`{"email":%q}`, body.Email))
    ident, err := reg.Submit(r.Context(), "password", traits, body.Password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    user := ident.(*User)
    json.NewEncoder(w).Encode(map[string]string{"id": user.ID, "email": body.Email})
}
```

### Login Endpoint

```go
func handleLogin(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&body)
    
    // Authenticate
    ident, err := login.Authenticate(r.Context(), "password", body.Email, body.Password)
    if err != nil {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }
    
    user := ident.(*User)
    
    // Create session
    sess, _ := sessions.Create(uuid.New().String(), user.ID)
    
    // Return tokens
    json.NewEncoder(w).Encode(map[string]string{
        "token":         sess.ID,
        "refresh_token": sess.RefreshToken,
    })
}
```

### Protected Endpoint (Me)

```go
func handleMe(w http.ResponseWriter, r *http.Request) {
    // Extract Bearer token
    auth := r.Header.Get("Authorization")
    token := strings.TrimPrefix(auth, "Bearer ")
    
    // Validate session
    sess, err := sessions.Validate(token)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    
    // Get user from database
    ident, _ := repo.GetIdentity(func() any { return &User{} }, sess.IdentityID)
    user := ident.(*User)
    
    json.NewEncoder(w).Encode(map[string]string{
        "id":    user.ID,
        "email": user.Email,
        "name":  user.Name,
    })
}
```

### Logout Endpoint

```go
func handleLogout(w http.ResponseWriter, r *http.Request) {
    auth := r.Header.Get("Authorization")
    token := strings.TrimPrefix(auth, "Bearer ")
    
    sess, err := sessions.Validate(token)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    
    // Invalidate session (best-effort)
    _ = sessions.Delete(sess.ID)
    
    json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}
```

---

## 6. Wire Everything Together

```go
func main() {
    // Set up routes
    http.HandleFunc("/register", handleRegister)
    http.HandleFunc("/login", handleLogin)
    http.HandleFunc("/me", handleMe)
    http.HandleFunc("/logout", handleLogout)
    
    // Start server
    log.Println("Server running on :8080")
    http.ListenAndServe(":8080", nil)
}
```

---

## Complete Example

See [`examples/01-password/backend/main.go`](../examples/01-password/backend/main.go) for a working implementation with CORS, proper error handling, and in-memory storage (for testing).

---

## Next Steps

### Add More Auth Methods

```go
// Magic Link (passwordless email)
magic := flow.NewMagicLinkStrategy(repo, emailSender, func() any { return &User{} })
login.RegisterStrategy(magic)

// TOTP (Google Authenticator)
totp := flow.NewTOTPStrategy(repo, func() any { return &User{} })
login.RegisterStrategy(totp)

// WebAuthn (Passkeys)
webauthn := flow.NewWebAuthnStrategy(repo, webauthnConfig, func() any { return &User{} })
reg.RegisterStrategy(webauthn)
```

### Add Authorization

```go
import "github.com/getkayan/kayan/core/rbac"

// Define roles and permissions
rbac := rbac.New()
rbac.AddRole("admin", []string{"users:read", "users:write", "users:delete"})
rbac.AddRole("user", []string{"users:read"})

// Check permissions
if rbac.Can("admin", "users:delete") {
    // Allow action
}
```

### Add Multi-Tenancy

```go
import "github.com/getkayan/kayan/core/tenant"

// Resolve tenant from request
resolver := tenant.NewSubdomainResolver()
tenantID, _ := resolver.Resolve(ctx, r)

// Scope queries to tenant
ident, _ := repo.GetIdentity(func() any { return &User{} }, userID, tenant.WithTenant(tenantID))
```

---

## Framework Integration

Kayan works with **any HTTP framework**. See [`docs/adapters/http-frameworks.md`](adapters/http-frameworks.md) for complete examples with:
- Go Fiber
- Echo
- Gin
- Chi
- net/http (stdlib)

---

## Common Patterns

### Custom Response Shape

```go
type LoginResponse struct {
    Token        string    `json:"token"`
    RefreshToken string    `json:"refresh_token"`
    User         UserDTO   `json:"user"`
    ExpiresAt    time.Time `json:"expires_at"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    // ... authenticate ...
    
    resp := LoginResponse{
        Token:        sess.ID,
        RefreshToken: sess.RefreshToken,
        User:         toUserDTO(user),
        ExpiresAt:    sess.ExpiresAt,
    }
    json.NewEncoder(w).Encode(resp)
}
```

### Add Validation

```go
import "github.com/go-playground/validator/v10"

validate := validator.New()

type RegisterRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8"`
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
    var req RegisterRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    if err := validate.Struct(&req); err != nil {
        http.Error(w, "validation failed", http.StatusBadRequest)
        return
    }
    
    // ... proceed with registration ...
}
```

### Add Rate Limiting

```go
import "github.com/getkayan/kayan/kredis"
import "github.com/redis/go-redis/v9"

rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
limiter := kredis.NewRateLimiter(rdb)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    // Check rate limit (5 attempts per 15 minutes)
    if !limiter.Allow(r.RemoteAddr, 5, 15*time.Minute) {
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
    
    // ... proceed with login ...
}
```

---

## Environment Variables

```bash
# Production checklist
export JWT_SECRET="random-256-bit-secret"
export DATABASE_URL="postgres://user:pass@localhost/prod_db"
export REDIS_URL="redis://localhost:6379"
```

---

## Testing

```go
func TestRegistration(t *testing.T) {
    // Use in-memory database for tests
    db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    db.AutoMigrate(&identity.Identity{}, &identity.Credential{})
    
    repo := kgorm.New(db)
    reg, _ := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")
    
    ident, err := reg.Submit(context.Background(), "password", 
        identity.JSON(`{"email":"test@example.com"}`), "password123")
    
    assert.NoError(t, err)
    assert.NotNil(t, ident)
}
```

---

## Production Checklist

- ✅ Use environment variables for secrets
- ✅ Enable HTTPS/TLS
- ✅ Add rate limiting (`kredis.NewRateLimiter`)
- ✅ Add account lockout (`kredis.NewLockoutStore`)
- ✅ Enable audit logging (built into Kayan)
- ✅ Set up monitoring (Prometheus/OTLP via `core/telemetry`)
- ✅ Use strong JWT secrets (256-bit minimum)
- ✅ Implement refresh token rotation
- ✅ Add CORS middleware for web clients

---

## Troubleshooting

**"Identity not found" error**  
→ Check that your User model implements `FlowIdentity`

**"Type assertion failed"**  
→ Ensure you're using the correct factory function: `func() any { return &YourModel{} }`

**"Duplicate key error"**  
→ User already exists with that email. Handle in your app logic.

**Session validation fails**  
→ Check JWT secret matches and token hasn't expired

---

## Learn More

- **Architecture**: `docs/architecture/README.md`
- **BYOS Concepts**: `docs/concepts/byos.md`
- **Extending Kayan**: `docs/architecture/extending-kayan.md`
- **Complete Examples**: `examples/` directory
- **AI Instructions**: `.ai-instructions.md`

---

**You're ready to build!** 🚀
