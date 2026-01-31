# Configuration Reference

Environment variables and code configuration for Kayan.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `DB_TYPE` | Database: `sqlite`, `postgres`, `mysql` | `sqlite` |
| `DSN` | Database connection string | - |
| `JWT_SECRET` | JWT signing key (required for JWT sessions) | - |
| `LOG_LEVEL` | Logging level: `debug`, `info`, `warn`, `error` | `info` |

### Database Connection Strings

```bash
# SQLite
DB_TYPE=sqlite
DSN=./data/auth.db

# PostgreSQL
DB_TYPE=postgres
DSN=postgres://user:pass@localhost:5432/kayan?sslmode=disable

# MySQL
DB_TYPE=mysql
DSN=user:pass@tcp(localhost:3306)/kayan?parseTime=true
```

---

## OIDC Configuration

```bash
OIDC_PROVIDERS='
{
  "google": {
    "issuer": "https://accounts.google.com",
    "client_id": "xxx.apps.googleusercontent.com",
    "client_secret": "xxx",
    "redirect_url": "http://localhost:8080/api/v1/oidc/google/callback"
  },
  "github": {
    "issuer": "https://github.com",
    "client_id": "xxx",
    "client_secret": "xxx",
    "redirect_url": "http://localhost:8080/api/v1/oidc/github/callback"
  }
}'
```

---

## Code Configuration

### Password Strategy

```go
// Hash cost (4-31, higher = slower but more secure)
hasher := flow.NewBcryptHasher(12)

// Identifier field(s)
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)
// Or multiple fields
pwStrategy.MapFields([]string{"Email", "Username"}, "PasswordHash")
```

### Session Strategy

```go
// JWT (stateless)
jwtStrategy := session.NewHS256Strategy(
    os.Getenv("JWT_SECRET"),
    24 * time.Hour, // Expiry
)

// Database (stateful)
dbStrategy := session.NewDatabaseStrategy(repo)
```

### WebAuthn

```go
config := flow.WebAuthnConfig{
    RPDisplayName: "My App",
    RPID:          "example.com",       // Domain (no port)
    RPOrigins:     []string{            // Allowed origins
        "https://example.com",
        "https://www.example.com",
    },
    SessionTTL:    5 * time.Minute,     // Challenge validity
}
```

### Rate Limiting

```go
config := flow.RateLimitConfig{
    MaxAttempts:  5,              // Max requests
    Window:       1 * time.Minute, // Per time window
    LockoutTime:  5 * time.Minute, // Lockout duration
}
```

### Account Lockout

```go
config := flow.LockoutConfig{
    MaxFailedAttempts: 3,              // Failed attempts before lock
    LockoutDuration:   15 * time.Minute,
    ResetOnSuccess:    true,           // Reset counter on success
}
```

---

## Storage Initialization

```go
// Using kgorm helper
storage, err := kgorm.NewStorage(
    "postgres",                    // Driver
    os.Getenv("DSN"),              // Connection string
    nil,                           // Optional GORM config
    &User{}, &Session{}, &Tenant{}, // Models to migrate
)

// Manual GORM setup
db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
repo := kgorm.NewRepository(db)
repo.AutoMigrate()
```

---

## Logging

```go
import "github.com/getkayan/kayan/core/logger"

// Configure logger
logger.SetLevel(logger.LevelDebug)
logger.SetOutput(os.Stdout)

// Structured logging
logger.Info("User registered",
    "user_id", user.ID,
    "email", user.Email,
)
```

---

## Telemetry

### OpenTelemetry

```go
import "github.com/getkayan/kayan/core/telemetry"

// Initialize tracing
tp := telemetry.InitTracer("kayan-auth", "http://jaeger:14268/api/traces")
defer tp.Shutdown(context.Background())
```

### Prometheus Metrics

```go
// Metrics are automatically exposed
e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
```

Available metrics:
- `kayan_registrations_total`
- `kayan_logins_total`
- `kayan_login_failures_total`
- `kayan_sessions_active`
