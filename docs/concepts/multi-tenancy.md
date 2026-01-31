# Multi-Tenancy

Kayan provides full multi-tenancy support for SaaS applications.

## Overview

Multi-tenancy isolates data between different organizations (tenants) in a single deployment.

```
┌─────────────────────────────────────────┐
│              Single Deployment           │
├─────────────┬─────────────┬─────────────┤
│  Tenant A   │  Tenant B   │  Tenant C   │
│  (Acme Inc) │  (Startup)  │  (Corp XYZ) │
└─────────────┴─────────────┴─────────────┘
```

---

## Tenant Resolution

Kayan supports multiple ways to identify which tenant a request belongs to.

### Header-Based

```go
import "github.com/getkayan/kayan/core/tenant"

resolver := tenant.NewHeaderResolver("X-Tenant-ID")
manager := tenant.NewManager(store, resolver)

// Request: X-Tenant-ID: tenant_acme
```

### Domain-Based

```go
resolver := tenant.NewDomainResolver()

// Request: acme.myapp.com → tenant_acme
// Request: startup.myapp.com → tenant_startup
```

### Path-Based

```go
resolver := tenant.NewPathResolver()

// Request: /t/acme/api/users → tenant_acme
// Request: /t/startup/api/users → tenant_startup
```

---

## Tenant Model

```go
type Tenant struct {
    ID        string          `json:"id"`
    Name      string          `json:"name"`
    Domain    string          `json:"domain"`
    Slug      string          `json:"slug"`
    Settings  json.RawMessage `json:"settings"`
    Active    bool            `json:"active"`
    CreatedAt time.Time       `json:"created_at"`
}
```

---

## Per-Tenant Settings

Configure different behaviors per tenant:

```go
type TenantSettings struct {
    AllowedStrategies []string       `json:"allowed_strategies"`
    SessionTTL        time.Duration  `json:"session_ttl"`
    MFARequired       bool           `json:"mfa_required"`
    PasswordPolicy    *PasswordPolicy `json:"password_policy"`
}

type PasswordPolicy struct {
    MinLength        int  `json:"min_length"`
    RequireUppercase bool `json:"require_uppercase"`
    RequireNumbers   bool `json:"require_numbers"`
    RequireSymbols   bool `json:"require_symbols"`
}
```

### Example Usage

```go
// Strict tenant
settingsA := TenantSettings{
    AllowedStrategies: []string{"password", "webauthn"},
    MFARequired:       true,
    PasswordPolicy: &PasswordPolicy{
        MinLength:        16,
        RequireSymbols:   true,
    },
}

// Relaxed tenant
settingsB := TenantSettings{
    AllowedStrategies: []string{"password", "oidc"},
    PasswordPolicy: &PasswordPolicy{
        MinLength: 8,
    },
}
```

---

## TenantAware Interface

Make your user model tenant-aware:

```go
type User struct {
    ID       string `gorm:"primaryKey"`
    TenantID string `gorm:"index"`
    Email    string `gorm:"uniqueIndex:idx_tenant_email"`
}

// Implement TenantAware
func (u *User) GetTenantID() string   { return u.TenantID }
func (u *User) SetTenantID(id string) { u.TenantID = id }
```

---

## Middleware Integration

```go
e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        ctx := c.Request().Context()
        
        // Resolve tenant from request
        t, err := tenantManager.Resolve(ctx, c.Request())
        if err != nil {
            return c.JSON(400, map[string]string{"error": "Invalid tenant"})
        }
        
        // Add to context
        ctx = tenant.WithTenant(ctx, t)
        c.SetRequest(c.Request().WithContext(ctx))
        c.Set("tenant", t)
        
        return next(c)
    }
})
```

### In Handlers

```go
func CreateUser(c echo.Context) error {
    t := c.Get("tenant").(*tenant.Tenant)
    
    // Validate against tenant's password policy
    var settings TenantSettings
    json.Unmarshal(t.Settings, &settings)
    
    if len(password) < settings.PasswordPolicy.MinLength {
        return c.JSON(400, map[string]string{
            "error": fmt.Sprintf("Password must be %d+ chars for %s",
                settings.PasswordPolicy.MinLength, t.Name),
        })
    }
    
    // Create user with tenant ID
    user.TenantID = t.ID
    // ...
}
```

---

## Tenant Isolation

Ensure queries are scoped to tenant:

```go
// GORM scope
db.Where("tenant_id = ?", tenantID).Find(&users)

// Or use middleware
func TenantScope(tenantID string) func(db *gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        return db.Where("tenant_id = ?", tenantID)
    }
}

db.Scopes(TenantScope(t.ID)).Find(&users)
```

---

## Lifecycle Hooks

```go
manager.SetHooks(tenant.Hooks{
    BeforeCreate: func(ctx context.Context, t *tenant.Tenant) error {
        // Validate, provision resources, etc.
        return nil
    },
    AfterResolve: func(ctx context.Context, t *tenant.Tenant, r *http.Request) {
        log.Printf("Request for tenant: %s", t.Name)
    },
    OnResolveFailed: func(ctx context.Context, r *http.Request, err error) {
        log.Printf("Tenant resolution failed: %v", err)
    },
})
```

---

## See Also

- [Example: multi_tenancy](../../../kayan-examples/multi_tenancy/)
