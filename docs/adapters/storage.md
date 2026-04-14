# Storage Adapters

Kayan is strictly decoupled from any specific database or ORM. It interacts with persistence through the `domain` storage interfaces. 

## Standard Usage: GORM Adapter (kgorm)

The official GORM adapter is the fastest way to get Kayan running on PostgreSQL, MySQL, SQLite, or SQL Server.

### 1. Initialize the Repository
```go
import "github.com/getkayan/kayan/kgorm"

db, _ := gorm.Open(postgres.Open(dsn))
userFactory := func() identity.FlowIdentity { return &User{} }

repo := kgorm.NewRepository(db, userFactory)

// Optional: Enable Multi-tenancy isolation at the database level
scopedRepo := kgorm.NewScopedRepository(repo, "tenant-123")
```

---

## Custom Implementation: Vanilla SQL Adapter

If you don't use GORM or need maximum performance with raw SQL, you can implement the `domain.IdentityStorage` interface directly.

### Example: Raw SQL Repository
```go
type SqlRepository struct {
    db      *sql.DB
    factory func() identity.FlowIdentity
}

// 1. Implementation of GetIdentity
func (r *SqlRepository) GetIdentity(factory func() identity.FlowIdentity, id any) (identity.FlowIdentity, error) {
    ident := factory() // Create new instance of user model
    
    // Query row and scan into the identity instance
    row := r.db.QueryRow("SELECT id, traits, state FROM users WHERE id = ?", id)
    var traits string
    err := row.Scan(ident.GetID(), &traits, ident.GetState()) // Simplified
    
    return ident, err
}

// 2. Implementation of FindIdentity
func (r *SqlRepository) FindIdentity(factory func() identity.FlowIdentity, query map[string]any) (identity.FlowIdentity, error) {
    // Dynamically build WHERE clause based on 'query' map
    // (e.g. traits ->> 'email' = 'bob@example.com')
    return nil, nil
}
```

---

## Common Mistakes

> [!CAUTION]
> **Returning Concrete Types**
> Storage methods must always return the `identity.FlowIdentity` interface (which you get from calling the `factory()`). Never return your concrete `*User` struct directly from the storage layer to the core library, as this violates the decoupled architecture.

> [!WARNING]
> **Incorrect Factory Usage**
> The `factory func() identity.FlowIdentity` passed to storage methods is your **only** way to know what the user model looks like at runtime. If you ignore the factory and hardcode a `&User{}` inside your adapter, your storage adapter will only work for that specific project and cannot be reused or extended.

> [!TIP]
> **Use JSON-Ready Databases**
> Kayan heavily uses the `identity.JSON` type for traits and configurations. To ensure high performance for searching within traits (e.g., finding a user by email in a JSON column), use a database with native JSONB support (like PostgreSQL) and ensure you have GIN indexes on the traits column.
