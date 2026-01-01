# Kayan 🪁

Kayan is a **headless, non-generic, and highly extensible authentication service** built for Go. It prioritizes developer flexibility, allowing you to "Bring Your Own Schema" (BYOS) and integrate authentication into existing databases without refactoring your entire data model.

---

## 🚀 Key Features

- **Non-Generic Architecture**: Works with any ID type (UUID, int, string, etc.) using a clean, interface-based design.
- **BYOS (Bring Your Own Schema)**: Use your existing structs as identity models. No mandatory embedding or specific table structures.
- **Strategy-Based Auth**: Plug-and-play strategies like Password (Bcrypt) and OIDC.
- **Hook System**: Intercept Registration and Login flows with Pre and Post hooks for synchronization, logging, or custom validation.
- **Storage Agnostic**: Built-in GORM repository for SQL databases, but easily adaptable to MongoDB, Redis, or legacy systems.
- **Headless API**: Simple RESTful endpoints designed for modern frontend frameworks or mobile apps.

---

## 📦 Installation

```bash
go get github.com/getkayan/kayan
```

---

## 🏗️ Core Concepts

### 1. The Identity Model
Kayan works with any struct you provide. To use your own schema, you have two paths: **Field Mapping** (e.g., direct fields in your table) or **Interface Implementation** (e.g., Kayan's default JSON traits).

---

## 🛠️ How to Implement Your Own Schema (BYOS)

Any struct used as a Kayan Identity **must** implement the `FlowIdentity` interface.

### Step 1: Mandatory Interface
```go
type MyUser struct {
    ID    string `gorm:"primaryKey"`
    Email string
    Hash  string
}

// MANDATORY: Used by Kayan to manage IDs
func (u *MyUser) GetID() any   { return u.ID }
func (u *MyUser) SetID(id any) { u.ID = id.(string) }
```

### Step 2: Choose Your Path

#### A. The Simple Way: Field Mapping (Recommended)
Use your own table columns directly. Kayan uses reflection to read/write these fields.

```go
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)

// Map 'Email' trait to MyUser.Email
// Map password secret directly to MyUser.Hash
pwStrategy.MapFields([]string{"Email"}, "Hash")
```

#### B. The Flexible Way: Optional Interfaces
Implement these if you want to use Kayan's built-in JSON trait system or its default `Credential` table.

- **`TraitSource`**: Implement `GetTraits()` and `SetTraits(identity.JSON)` to use Kayan's dynamic traits.
- **`CredentialSource`**: Implement `GetCredentials()` and `SetCredentials([]identity.Credential)` to store multiple credentials (e.g., Password + WebAuthn) in a separate table.

### Step 3: Provide a Factory
Since Kayan is non-generic, you must provide a `factory` function so Kayan can instantiate your struct in its managers.

```go
factory := func() any { return &MyUser{} }
regManager := flow.NewRegistrationManager(repo, factory)
```

---

## 🛠️ Usage

### Quick Start (Default Schema)
```go
db, _ := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
regManager := kayan.NewDefaultRegistrationManager(db)
loginManager := kayan.NewDefaultLoginManager(db)

// Register strategies...
```

### Advanced: Hooks for Synchronization
Useful for creating companion profiles or sending welcome emails.

```go
regManager.AddPostHook(func(ctx context.Context, ident any) error {
    u := ident.(*User)
    return appDB.Create(&Profile{UserID: u.ID}).Error
})
```

### 3. Bcrypt Hasher Customization
You can control the computational cost of password hashing.
```go
hasher := flow.NewBcryptHasher(14) // Cost factor (4-31)
```

---

## 🌐 API Reference

### Configuration
Environment variables:
- `PORT`: Server port (default: 8080)
- `DB_TYPE`: `sqlite`, `postgres`, `mysql`
- `DSN`: Database connection string
- `OIDC_PROVIDERS`: JSON configuration for OIDC (see OIDC section)

### Endpoints
- `POST /api/v1/registration`: Accepts traits (JSON) and secret. Returns the created identity.
- `POST /api/v1/login`: Issues a session token in the response body.
- `GET /api/v1/whoami`: Returns current identity details for the provided token.
- `POST /api/v1/oidc/:provider`: Initiates OIDC flow.

---

## 🔑 OIDC Configuration
Kayan supports multiple OIDC providers (Google, GitHub, etc.) simultaneously.

```go
configs := map[string]config.OIDCProvider{
    "google": {
        Issuer: "https://accounts.google.com",
        ClientID: "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURL: "http://localhost:8080/api/v1/oidc/google/callback",
    },
}
oidcManager, _ := flow.NewOIDCManager(repo, configs, factory)
```

---

## 🔧 Customization

### ID Generation
```go
pwStrategy.SetIDGenerator(func() any { return uuid.New() })
```

### Token Parsing
```go
handler.SetTokenParser(func(token string) (any, error) {
    return uuid.Parse(token)
})
```

---

## 🧪 Testing
Run the comprehensive test suite to ensure everything is working correctly:
```bash
go test ./...
```

---

## 📚 Examples
Check out the `examples/` directory for advanced patterns:
- [`byos_schema`](file:///d:/Projects/kayan/examples/byos_schema/main.go): The ultimate one-table custom schema.
- [`companion_profile`](file:///d:/Projects/kayan/examples/companion_profile/main.go): Syncing Kayan IDs with an application-specific profile table.
- [`custom_storage`](file:///d:/Projects/kayan/examples/custom_storage/main.go): Implementing a MongoDB adapter.

---

## 🛡️ License
MIT License. See [LICENSE](LICENSE) for details.
