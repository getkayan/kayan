# Getting Started with Kayan

This guide will help you integrate Kayan into your Go application in under 10 minutes.

## Installation

```bash
go get github.com/getkayan/kayan
```

## Quick Start

### 1. Basic Setup

```go
package main

import (
    "github.com/getkayan/kayan/core/flow"
    "github.com/getkayan/kayan/kgorm"
    "github.com/glebarez/sqlite"
    "gorm.io/gorm"
)

func main() {
    // 1. Initialize database
    db, _ := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
    storage, _ := kgorm.NewStorage("sqlite", "auth.db", nil)

    // 2. Create managers with factory function
    factory := func() any { return &identity.Identity{} }
    regManager := flow.NewRegistrationManager(storage, factory)
    loginManager := flow.NewLoginManager(storage)

    // 3. Setup password strategy
    hasher := flow.NewBcryptHasher(10)
    pwStrategy := flow.NewPasswordStrategy(storage, hasher, "email", factory)
    
    regManager.RegisterStrategy(pwStrategy)
    loginManager.RegisterStrategy(pwStrategy)

    // Ready to use!
}
```

### 2. Register a User

```go
ctx := context.Background()
traits := identity.JSON(`{"email": "user@example.com", "name": "John"}`)

ident, err := regManager.Submit(ctx, "password", traits, "secretpassword")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created user: %s\n", ident.(*identity.Identity).ID)
```

### 3. Authenticate

```go
ident, err := loginManager.Authenticate(ctx, "password", "user@example.com", "secretpassword")
if err != nil {
    log.Fatal("Invalid credentials")
}

fmt.Printf("Authenticated: %s\n", ident.(*identity.Identity).ID)
```

### 4. Create a Session

```go
import "github.com/getkayan/kayan/core/session"

// JWT (stateless)
jwtStrategy := session.NewHS256Strategy("your-secret-key", 24*time.Hour)
sessManager := session.NewManager(jwtStrategy)

sess, _ := sessManager.Create("session_1", user.ID)
fmt.Printf("Token: %s\n", sess.ID)

// Validate
sess, err := sessManager.Validate(token)
```

---

## Next Steps

1. **[BYOS Guide](./concepts/byos.md)** - Use your own user models
2. **[Authentication Strategies](./concepts/strategies.md)** - Add OIDC, WebAuthn, SAML
3. **[Authorization](./concepts/authorization.md)** - Implement RBAC/ABAC
4. **[Examples](../../kayan-examples/)** - 20+ working examples

---

## Common Patterns

### With Echo (HTTP Framework)

```go
import (
    kayanecho "github.com/getkayan/kayan-echo"
)

h := kayanecho.NewHandler(regManager, loginManager, sessManager, nil)

e := echo.New()
g := e.Group("/api/v1")
h.RegisterRoutes(g)

// Protected route
e.GET("/protected", handler, h.AuthMiddleware)
```

### Custom User Model (BYOS)

```go
type MyUser struct {
    ID           string `gorm:"primaryKey"`
    Email        string `gorm:"uniqueIndex"`
    PasswordHash string
}

func (u *MyUser) GetID() any   { return u.ID }
func (u *MyUser) SetID(id any) { u.ID = id.(string) }

// Use field mapping
pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
```

### Add Hooks

```go
regManager.AddPostHook(func(ctx context.Context, ident any) error {
    user := ident.(*MyUser)
    // Send welcome email, create profile, etc.
    return sendWelcomeEmail(user.Email)
})
```

---

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `DB_TYPE` | Database type (`sqlite`, `postgres`, `mysql`) | `sqlite` |
| `DSN` | Database connection string | - |
| `JWT_SECRET` | JWT signing secret | - |
