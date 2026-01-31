# BYOS: Bring Your Own Schema

BYOS (Bring Your Own Schema) is Kayan's flagship feature that allows you to use your existing database models without modification.

## Why BYOS?

Most IAM solutions require you to:
- Use their predefined table structures
- Embed their base models
- Migrate existing data to their schema

Kayan takes a different approach: **your models, your way**.

---

## Two Approaches

### 1. Field Mapping (Recommended)

Map Kayan's requirements directly to your existing struct fields:

```go
type MyUser struct {
    ID           uuid.UUID `gorm:"primaryKey"`
    Email        string    `gorm:"uniqueIndex"`
    Username     string    `gorm:"uniqueIndex"`
    PasswordHash string    // Your own field name
    DisplayName  string
}

// Required: FlowIdentity interface
func (u *MyUser) GetID() any   { return u.ID }
func (u *MyUser) SetID(id any) { u.ID = id.(uuid.UUID) }

// Setup with field mapping
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "", factory)
pwStrategy.MapFields(
    []string{"Email", "Username"},  // Identifier fields
    "PasswordHash",                  // Secret field
)
```

**Benefits:**
- No schema changes required
- Works with any existing table
- Multiple identifier fields (email, username, phone)

### 2. Optional Interfaces

For advanced features, implement optional interfaces:

```go
// TraitSource - Dynamic JSON traits
type TraitSource interface {
    GetTraits() identity.JSON
    SetTraits(identity.JSON)
}

// CredentialSource - Multiple credentials (WebAuthn + Password)
type CredentialSource interface {
    GetCredentials() []identity.Credential
    SetCredentials([]identity.Credential)
}
```

---

## Complete Example

```go
package main

import (
    "github.com/getkayan/kayan/core/flow"
    "github.com/getkayan/kayan/kgorm"
)

// Your existing user model
type User struct {
    ID           string `gorm:"primaryKey"`
    Email        string `gorm:"uniqueIndex"`
    PasswordHash string
    Profile      Profile `gorm:"foreignKey:UserID"`
}

func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }

func main() {
    // Initialize with your model
    storage, _ := kgorm.NewStorage("sqlite", "app.db", nil, &User{})
    
    factory := func() any { return &User{} }
    regManager := flow.NewRegistrationManager(storage, factory)
    
    hasher := flow.NewBcryptHasher(10)
    pwStrategy := flow.NewPasswordStrategy(storage, hasher, "", factory)
    pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
    
    regManager.RegisterStrategy(pwStrategy)
    
    // Register returns *User, not identity.Identity!
    ident, _ := regManager.Submit(ctx, "password", traits, password)
    user := ident.(*User)
}
```

---

## ID Generation

Kayan supports any ID type:

```go
// UUID
pwStrategy.SetIDGenerator(func() any { return uuid.New() })

// Snowflake
pwStrategy.SetIDGenerator(func() any { return snowflake.Generate() })

// ULID
pwStrategy.SetIDGenerator(func() any { return ulid.Make() })

// Auto-increment (let database handle it)
pwStrategy.SetIDGenerator(nil)
```

---

## Multi-Field Lookup

Support login by email OR username:

```go
pwStrategy.MapFields(
    []string{"Email", "Username", "Phone"}, // Any of these work
    "PasswordHash",
)

// All of these will work:
loginManager.Authenticate(ctx, "password", "user@example.com", "pass")
loginManager.Authenticate(ctx, "password", "johndoe", "pass")
loginManager.Authenticate(ctx, "password", "+1234567890", "pass")
```

---

## See Also

- [Example: byos_schema](../../../kayan-examples/byos_schema/)
- [Example: full_custom_schema](../../../kayan-examples/full_custom_schema/)
