# Authorization: RBAC & ABAC

Kayan provides multiple authorization models that can be used independently or combined.

## Overview

| Model | Description | Best For |
|-------|-------------|----------|
| **RBAC** | Role-Based Access Control | Simple permission checks |
| **ABAC** | Attribute-Based Access Control | Complex, dynamic rules |
| **Hybrid** | RBAC + ABAC combined | Enterprise requirements |

---

## RBAC (Role-Based Access Control)

Users have roles, roles grant access.

### Setup

```go
import "github.com/getkayan/kayan/core/rbac"

// Create strategy with storage
strategy := rbac.NewBasicStrategy(repo)
manager := rbac.NewManager(strategy)

// Check authorization
isAdmin, _ := manager.Authorize("user_123", "admin")

// Require role (returns error if denied)
err := manager.RequireRole("user_123", "admin")
```

### Storing Roles

Roles are stored as JSON in the identity:

```go
type User struct {
    ID    string `gorm:"primaryKey"`
    Roles json.RawMessage // ["admin", "editor"]
}

// Or implement RoleSource interface
func (u *User) GetRoles() []string {
    return u.roles
}
```

### HTTP Middleware

```go
rbacMw := rbac.NewMiddleware(manager, sessManager)

// Require specific role
e.GET("/admin", handler, authMw, rbacMw.RequireRole("admin"))

// Require specific permission
e.POST("/posts", handler, authMw, rbacMw.RequirePermission("blog:create"))
```

---

## ABAC (Attribute-Based Access Control)

Rules based on user attributes, resource attributes, and context.

### Setup

```go
import "github.com/getkayan/kayan/core/policy"

abac := policy.NewABACStrategy()

// Define rules
abac.AddRule("document:read", func(ctx context.Context, subject, resource any, pctx policy.Context) (bool, error) {
    user := subject.(*User)
    doc := resource.(*Document)
    
    // Owner can always read
    if doc.OwnerID == user.ID {
        return true, nil
    }
    // Public docs readable by all
    if doc.IsPublic {
        return true, nil
    }
    return false, nil
})

// Check
allowed, _ := abac.Can(ctx, user, "document:read", document)
```

### Passing Context

```go
// Add extra context for rule evaluation
ctx := policy.WithContext(ctx, policy.Context{
    "time_of_day": "business_hours",
    "ip_address":  "10.0.0.1",
})

allowed, _ := abac.Can(ctx, user, "action", resource)
```

### Rule Examples

```go
// Time-based access
abac.AddRule("report:access", func(ctx, subject, resource any, pctx policy.Context) (bool, error) {
    timeOfDay := pctx["time_of_day"].(string)
    if timeOfDay != "business_hours" {
        return false, nil
    }
    return true, nil
})

// Clearance level
abac.AddRule("classified:access", func(ctx, subject, resource any, pctx policy.Context) (bool, error) {
    user := subject.(*User)
    doc := resource.(*Document)
    return user.ClearanceLevel >= doc.RequiredClearance, nil
})
```

---

## Hybrid (RBAC + ABAC)

Combine role checks with attribute checks for defense-in-depth.

```go
hybrid := policy.NewHybridEngine(rbacStrategy, abacStrategy)

// Check both layers
// 1. RBAC: Does user have required role?
// 2. ABAC: Do attributes satisfy rules?
allowed := hybrid.Authorize(ctx, userID, "document:edit", document)
```

### Typical Flow

```
Request: User wants to edit document
    │
    ▼
┌───────────────┐
│   RBAC Check  │ → Does user have "editor" role?
└───────────────┘
    │ yes
    ▼
┌───────────────┐
│   ABAC Check  │ → Is user the owner OR same department?
└───────────────┘
    │ yes
    ▼
   ALLOWED
```

---

## Integration Patterns

### Echo Middleware

```go
// Combined RBAC + custom check
func RequireDocumentAccess(abac *policy.ABACStrategy) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            user := c.Get("user").(*User)
            docID := c.Param("id")
            doc := loadDocument(docID)
            
            allowed, _ := abac.Can(c.Request().Context(), user, "document:access", doc)
            if !allowed {
                return c.JSON(403, map[string]string{"error": "Forbidden"})
            }
            return next(c)
        }
    }
}
```

### Per-Resource Authorization

```go
// In handler
func GetDocument(c echo.Context) error {
    user := c.Get("user").(*User)
    doc := loadDocument(c.Param("id"))
    
    if allowed, _ := abac.Can(ctx, user, "document:read", doc); !allowed {
        return c.JSON(403, map[string]string{"error": "Access denied"})
    }
    
    return c.JSON(200, doc)
}
```

---

## See Also

- [Example: rbac_basic](../../../kayan-examples/rbac_basic/)
- [Example: abac_policy](../../../kayan-examples/abac_policy/)
- [Example: hybrid_policy](../../../kayan-examples/hybrid_policy/)
