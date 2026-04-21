# HTTP Framework Integration

Kayan is a **library**, not a service. It provides zero framework-specific dependencies in `core/`, making it compatible with any Go HTTP framework.

This guide shows manual integration patterns for popular frameworks. The examples are intentionally complete (~30-40 lines per endpoint) so you can customize validation, error handling, response shapes, and business logic.

---

## Philosophy: No Official Adapters

Kayan does **not** provide official framework adapters (like `kayan-fiber`, `kayan-echo`) because:

1. **Integration is trivial** — most endpoints are 20-30 lines
2. **Adapters restrict customization** — production apps need custom responses, validation, rate limiting
3. **Maintenance burden** — supporting 5+ frameworks adds significant surface area
4. **BYOS extends to BYOF** — "Bring Your Own Framework" is part of the philosophy

Instead, this document provides **reference implementations** you copy and adapt to your needs.

---

## Common Pattern

All frameworks follow the same flow:

```
1. Parse request body
2. Call Kayan manager (RegistrationManager, LoginManager, etc.)
3. Create session if auth succeeds
4. Return custom response
```

The only framework-specific code is request/response handling (~10 lines).

---

## Go Fiber v2

### Setup

```go
package main

import (
    "github.com/getkayan/kayan/core/flow"
    "github.com/getkayan/kayan/core/identity"
    "github.com/getkayan/kayan/core/session"
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
)

type Server struct {
    reg      *flow.RegistrationManager
    login    *flow.LoginManager
    sessions *session.JWTStrategy
    repo     domain.IdentityStorage
}

func main() {
    // Initialize Kayan (see examples/ for storage setup)
    reg, login := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")
    sessions := session.NewHS256Strategy(os.Getenv("JWT_SECRET"), time.Hour)
    
    s := &Server{reg: reg, login: login, sessions: sessions, repo: repo}
    
    app := fiber.New()
    app.Post("/register", s.handleRegister)
    app.Post("/login", s.handleLogin)
    app.Delete("/logout", s.requireAuth, s.handleLogout)
    app.Get("/me", s.requireAuth, s.handleMe)
    app.Listen(":8080")
}
```

### Middleware: requireAuth

```go
func (s *Server) requireAuth(c *fiber.Ctx) error {
    auth := c.Get("Authorization")
    if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing token"})
    }
    
    token := strings.TrimPrefix(auth, "Bearer ")
    sess, err := s.sessions.Validate(token)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired session"})
    }
    
    c.Locals("session", sess)
    return c.Next()
}

func sessionFromCtx(c *fiber.Ctx) *identity.Session {
    s, _ := c.Locals("session").(*identity.Session)
    return s
}
```

### Handler: POST /register

```go
func (s *Server) handleRegister(c *fiber.Ctx) error {
    var body struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := c.BodyParser(&body); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
    }
    
    if body.Email == "" || body.Password == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
    }
    
    traits := identity.JSON(fmt.Sprintf(`{"email":%q}`, body.Email))
    identRaw, err := s.reg.Submit(c.Context(), "password", traits, body.Password)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }
    
    ident := identRaw.(*identity.Identity)
    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "id":    ident.ID,
        "email": body.Email,
    })
}
```

### Handler: POST /login

```go
func (s *Server) handleLogin(c *fiber.Ctx) error {
    var body struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := c.BodyParser(&body); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
    }
    
    if body.Email == "" || body.Password == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
    }
    
    identRaw, err := s.login.Authenticate(c.Context(), "password", body.Email, body.Password)
    if err != nil {
        // Generic message — never reveal why authentication failed
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
    }
    
    ident := identRaw.(*identity.Identity)
    sess, err := s.sessions.Create(uuid.New().String(), ident.ID)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create session"})
    }
    
    return c.JSON(fiber.Map{
        "token":         sess.ID,
        "refresh_token": sess.RefreshToken,
    })
}
```

### Handler: DELETE /logout

```go
func (s *Server) handleLogout(c *fiber.Ctx) error {
    sess := sessionFromCtx(c)
    if sess == nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "not authenticated"})
    }
    
    _ = s.sessions.Delete(sess.ID) // Best-effort invalidation
    return c.JSON(fiber.Map{"status": "logged out"})
}
```

### Handler: GET /me

```go
func (s *Server) handleMe(c *fiber.Ctx) error {
    sess := sessionFromCtx(c)
    if sess == nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "not authenticated"})
    }
    
    identRaw, err := s.repo.GetIdentity(func() any { return &identity.Identity{} }, sess.IdentityID)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "identity not found"})
    }
    
    ident := identRaw.(*identity.Identity)
    var email string
    var m map[string]any
    if json.Unmarshal(ident.Traits, &m) == nil {
        email, _ = m["email"].(string)
    }
    
    return c.JSON(fiber.Map{
        "id":    ident.ID,
        "email": email,
    })
}
```

---

## Echo

### Setup

```go
import (
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
)

func main() {
    // Initialize Kayan (same as Fiber)
    reg, login := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")
    sessions := session.NewHS256Strategy(os.Getenv("JWT_SECRET"), time.Hour)
    
    s := &Server{reg: reg, login: login, sessions: sessions, repo: repo}
    
    e := echo.New()
    e.Use(middleware.Logger())
    
    e.POST("/register", s.handleRegister)
    e.POST("/login", s.handleLogin)
    
    protected := e.Group("")
    protected.Use(s.requireAuth)
    protected.DELETE("/logout", s.handleLogout)
    protected.GET("/me", s.handleMe)
    
    e.Start(":8080")
}
```

### Middleware: requireAuth

```go
func (s *Server) requireAuth(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        auth := c.Request().Header.Get("Authorization")
        if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
            return echo.NewHTTPError(http.StatusUnauthorized, "missing token")
        }
        
        token := strings.TrimPrefix(auth, "Bearer ")
        sess, err := s.sessions.Validate(token)
        if err != nil {
            return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired session")
        }
        
        c.Set("session", sess)
        return next(c)
    }
}

func sessionFromCtx(c echo.Context) *identity.Session {
    s, _ := c.Get("session").(*identity.Session)
    return s
}
```

### Handler: POST /login

```go
func (s *Server) handleLogin(c echo.Context) error {
    var body struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := c.Bind(&body); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
    }
    
    if body.Email == "" || body.Password == "" {
        return echo.NewHTTPError(http.StatusBadRequest, "email and password required")
    }
    
    identRaw, err := s.login.Authenticate(c.Request().Context(), "password", body.Email, body.Password)
    if err != nil {
        return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
    }
    
    ident := identRaw.(*identity.Identity)
    sess, err := s.sessions.Create(uuid.New().String(), ident.ID)
    if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "could not create session")
    }
    
    return c.JSON(http.StatusOK, map[string]string{
        "token":         sess.ID,
        "refresh_token": sess.RefreshToken,
    })
}
```

---

## Gin

### Setup

```go
import "github.com/gin-gonic/gin"

func main() {
    // Initialize Kayan (same as above)
    reg, login := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")
    sessions := session.NewHS256Strategy(os.Getenv("JWT_SECRET"), time.Hour)
    
    s := &Server{reg: reg, login: login, sessions: sessions, repo: repo}
    
    r := gin.Default()
    r.POST("/register", s.handleRegister)
    r.POST("/login", s.handleLogin)
    
    protected := r.Group("")
    protected.Use(s.requireAuth)
    {
        protected.DELETE("/logout", s.handleLogout)
        protected.GET("/me", s.handleMe)
    }
    
    r.Run(":8080")
}
```

### Middleware: requireAuth

```go
func (s *Server) requireAuth(c *gin.Context) {
    auth := c.GetHeader("Authorization")
    if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
        c.Abort()
        return
    }
    
    token := strings.TrimPrefix(auth, "Bearer ")
    sess, err := s.sessions.Validate(token)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
        c.Abort()
        return
    }
    
    c.Set("session", sess)
    c.Next()
}

func sessionFromCtx(c *gin.Context) *identity.Session {
    v, _ := c.Get("session")
    s, _ := v.(*identity.Session)
    return s
}
```

### Handler: POST /login

```go
func (s *Server) handleLogin(c *gin.Context) {
    var body struct {
        Email    string `json:"email" binding:"required"`
        Password string `json:"password" binding:"required"`
    }
    
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "email and password required"})
        return
    }
    
    identRaw, err := s.login.Authenticate(c.Request.Context(), "password", body.Email, body.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }
    
    ident := identRaw.(*identity.Identity)
    sess, err := s.sessions.Create(uuid.New().String(), ident.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create session"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "token":         sess.ID,
        "refresh_token": sess.RefreshToken,
    })
}
```

---

## net/http (stdlib)

See [`examples/01-password/backend/main.go`](../../examples/01-password/backend/main.go) for a complete stdlib example.

---

## Customization Examples

### Custom Response Shape

```go
type LoginResponse struct {
    Token        string    `json:"token"`
    RefreshToken string    `json:"refresh_token"`
    User         UserDTO   `json:"user"`
    ExpiresAt    time.Time `json:"expires_at"`
}

func (s *Server) handleLogin(c *fiber.Ctx) error {
    // ... authenticate ...
    
    return c.JSON(LoginResponse{
        Token:        sess.ID,
        RefreshToken: sess.RefreshToken,
        User:         s.toUserDTO(ident),
        ExpiresAt:    sess.ExpiresAt,
    })
}
```

### Add Rate Limiting

```go
func (s *Server) handleLogin(c *fiber.Ctx) error {
    if !s.rateLimiter.Allow(c.IP()) {
        return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
            "error": "rate limit exceeded",
        })
    }
    
    // ... rest of handler ...
}
```

### Add Request Validation

```go
func (s *Server) handleRegister(c *fiber.Ctx) error {
    var body RegisterRequest
    if err := c.BodyParser(&body); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
    }
    
    if err := s.validator.Struct(&body); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error":  "validation failed",
            "fields": parseValidationErrors(err),
        })
    }
    
    // ... call Kayan registration ...
}
```

### Add Audit Logging

```go
func (s *Server) handleLogin(c *fiber.Ctx) error {
    identRaw, err := s.login.Authenticate(c.Context(), "password", body.Email, body.Password)
    if err != nil {
        s.logger.Warn("login_failed",
            zap.String("email", body.Email),
            zap.String("ip", c.IP()),
        )
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
    }
    
    // ... rest of handler ...
}
```

---

## Summary

**Why no adapters?**  
The integration code is ~100 lines total for all endpoints. An adapter would save ~20 lines but remove your ability to customize responses, validation, rate limiting, and error handling.

**Recommended approach:**  
Copy the patterns above into your project and adapt them to your needs. Treat them as **templates**, not dependencies.

**For storage adapters**, see [`kgorm/`](../../kgorm) and [`kredis/`](../../kredis) — those solve real complexity and justify being maintained packages.
