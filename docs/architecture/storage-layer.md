# Kayan Storage Layer

This document describes the storage abstraction layer and how to implement custom storage adapters.

---

## Storage Architecture

Kayan uses a repository pattern to abstract away database details:

```
┌─────────────────────────────────────────────────┐
│               APPLICATION CODE                   │
├─────────────────────────────────────────────────┤
│                                                  │
│   RegistrationManager    LoginManager            │
│         │                     │                  │
│         └──────────┬──────────┘                  │
│                    ▼                             │
│   ┌────────────────────────────────────────┐    │
│   │        IdentityRepository Interface     │    │
│   ├────────────────────────────────────────┤    │
│   │  CreateIdentity(identity any)           │    │
│   │  GetIdentity(factory, id) (any, error)  │    │
│   │  FindIdentity(factory, query) (any, error) │ │
│   │  UpdateIdentity(identity any)           │    │
│   │  DeleteIdentity(id any)                 │    │
│   └────────────────────────────────────────┘    │
│                    │                             │
│         ┌──────────┼──────────┐                 │
│         ▼          ▼          ▼                 │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│   │  kgorm   │ │  MongoDB │ │  Custom  │       │
│   │ (GORM)   │ │ Adapter  │ │ Storage  │       │
│   └──────────┘ └──────────┘ └──────────┘       │
│         │          │          │                 │
│         ▼          ▼          ▼                 │
│   PostgreSQL    MongoDB    Any Backend          │
│   MySQL         CosmosDB                        │
│   SQLite                                        │
└─────────────────────────────────────────────────┘
```

---

## IdentityRepository Interface

Every storage adapter must implement:

```go
type IdentityRepository interface {
    // CreateIdentity persists a new identity
    // identity: Pointer to your model (e.g., *User)
    CreateIdentity(identity any) error
    
    // GetIdentity retrieves by primary key
    // factory: Creates empty instance for scanning
    // id: Primary key value (any type)
    GetIdentity(factory func() any, id any) (any, error)
    
    // FindIdentity retrieves by arbitrary query
    // query: Map of field -> value for WHERE clause
    FindIdentity(factory func() any, query map[string]any) (any, error)
    
    // UpdateIdentity saves changes to existing identity
    UpdateIdentity(identity any) error
    
    // DeleteIdentity removes by primary key
    DeleteIdentity(id any) error
    
    // ListIdentities paginated list
    ListIdentities(factory func() any, page, limit int) ([]any, error)
}
```

### Extended Interfaces

For advanced features:

```go
// CredentialRepository - WebAuthn, multiple credentials
type CredentialRepository interface {
    GetCredentialByIdentifier(identifier, method string) (*Credential, error)
    UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
    GetCredentialsByIdentity(identityID string) ([]*Credential, error)
}

// SessionRepository - Database sessions
type SessionRepository interface {
    CreateSession(session *Session) error
    GetSession(id string) (*Session, error)
    DeleteSession(id string) error
    DeleteSessionsByIdentity(identityID string) error
    ListSessionsByIdentity(identityID string) ([]*Session, error)
}

// TenantRepository - Multi-tenancy
type TenantRepository interface {
    CreateTenant(tenant *Tenant) error
    GetTenant(id string) (*Tenant, error)
    GetTenantByDomain(domain string) (*Tenant, error)
    UpdateTenant(tenant *Tenant) error
}
```

---

## kgorm: GORM Adapter

The default adapter using GORM:

### Initialization

```go
import (
    "github.com/getkayan/kayan/kgorm"
    "gorm.io/gorm"
    "gorm.io/driver/postgres"
)

// Open database
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

// Create repository
repo := kgorm.NewRepository(db)

// Optional: Auto-migrate models
repo.AutoMigrate(&User{}, &Session{}, &Tenant{})
```

### Using Helper

```go
// All-in-one initialization
storage, err := kgorm.NewStorage(
    "postgres",                   // Driver
    "host=localhost user=...",    // DSN
    &gorm.Config{},               // Optional GORM config
    &User{}, &Session{},          // Models to migrate
)
```

### Implementation Details

```go
type GormRepository struct {
    db *gorm.DB
}

func (r *GormRepository) CreateIdentity(identity any) error {
    return r.db.Create(identity).Error
}

func (r *GormRepository) GetIdentity(factory func() any, id any) (any, error) {
    identity := factory()
    result := r.db.First(identity, "id = ?", id)
    if result.Error != nil {
        return nil, result.Error
    }
    return identity, nil
}

func (r *GormRepository) FindIdentity(factory func() any, query map[string]any) (any, error) {
    identity := factory()
    result := r.db.Where(query).First(identity)
    if result.Error != nil {
        return nil, result.Error
    }
    return identity, nil
}
```

---

## Implementing Custom Storage

### MongoDB Example

```go
type MongoRepository struct {
    collection *mongo.Collection
}

func NewMongoRepository(db *mongo.Database, collectionName string) *MongoRepository {
    return &MongoRepository{
        collection: db.Collection(collectionName),
    }
}

func (r *MongoRepository) CreateIdentity(identity any) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    _, err := r.collection.InsertOne(ctx, identity)
    return err
}

func (r *MongoRepository) GetIdentity(factory func() any, id any) (any, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    identity := factory()
    filter := bson.M{"_id": id}
    
    err := r.collection.FindOne(ctx, filter).Decode(identity)
    if err == mongo.ErrNoDocuments {
        return nil, ErrNotFound
    }
    return identity, err
}

func (r *MongoRepository) FindIdentity(factory func() any, query map[string]any) (any, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    identity := factory()
    filter := bson.M{}
    for k, v := range query {
        filter[k] = v
    }
    
    err := r.collection.FindOne(ctx, filter).Decode(identity)
    if err == mongo.ErrNoDocuments {
        return nil, ErrNotFound
    }
    return identity, err
}

func (r *MongoRepository) UpdateIdentity(identity any) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    // Extract ID using reflection
    id := reflect.ValueOf(identity).Elem().FieldByName("ID").Interface()
    
    filter := bson.M{"_id": id}
    _, err := r.collection.ReplaceOne(ctx, filter, identity)
    return err
}

func (r *MongoRepository) DeleteIdentity(id any) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    filter := bson.M{"_id": id}
    _, err := r.collection.DeleteOne(ctx, filter)
    return err
}
```

### Usage

```go
// Initialize MongoDB
client, _ := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
db := client.Database("myapp")

// Create Kayan repository
repo := NewMongoRepository(db, "identities")

// Use with Kayan
factory := func() any { return &User{} }
regManager := flow.NewRegistrationManager(repo, factory)
```

---

## Redis Session Store

For distributed session storage:

```go
type RedisSessionStore struct {
    client *redis.Client
    prefix string
    ttl    time.Duration
}

func (s *RedisSessionStore) CreateSession(sess *session.Session) error {
    data, _ := json.Marshal(sess)
    key := s.prefix + sess.ID
    return s.client.Set(context.Background(), key, data, s.ttl).Err()
}

func (s *RedisSessionStore) GetSession(id string) (*session.Session, error) {
    key := s.prefix + id
    data, err := s.client.Get(context.Background(), key).Bytes()
    if err == redis.Nil {
        return nil, ErrNotFound
    }
    
    var sess session.Session
    json.Unmarshal(data, &sess)
    return &sess, nil
}

func (s *RedisSessionStore) DeleteSession(id string) error {
    key := s.prefix + id
    return s.client.Del(context.Background(), key).Err()
}
```

---

## Database Schema Patterns

### Single Table Identity

```sql
CREATE TABLE identities (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    traits JSONB,
    roles JSONB,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Identity + Credentials Split

```sql
CREATE TABLE identities (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    traits JSONB,
    created_at TIMESTAMP
);

CREATE TABLE credentials (
    id VARCHAR(255) PRIMARY KEY,
    identity_id VARCHAR(255) REFERENCES identities(id),
    method VARCHAR(50),           -- 'password', 'webauthn', 'totp'
    identifier VARCHAR(255),       -- email for password, null for others
    secret_hash VARCHAR(255),      -- bcrypt hash, TOTP secret, etc
    metadata JSONB,                -- WebAuthn public key, etc
    created_at TIMESTAMP
);
```

### Multi-Tenant Schema

```sql
CREATE TABLE tenants (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    domain VARCHAR(255) UNIQUE,
    settings JSONB,
    active BOOLEAN DEFAULT true
);

CREATE TABLE identities (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) REFERENCES tenants(id),
    email VARCHAR(255),
    UNIQUE(tenant_id, email)      -- Email unique per tenant
);
```

---

## Query Patterns

### Field Mapping Translation

When `FindIdentity` receives `{"email": "user@example.com"}`:

```go
// kgorm translates to:
db.Where("email = ?", "user@example.com")

// MongoDB adapter translates to:
bson.M{"email": "user@example.com"}
```

### Case Insensitive Queries

```go
// Custom repository can normalize
func (r *Repository) FindIdentity(factory func() any, query map[string]any) (any, error) {
    // Lowercase email lookups
    if email, ok := query["email"].(string); ok {
        query["email"] = strings.ToLower(email)
    }
    return r.db.Where(query).First(factory()).Error
}
```

---

## Connection Pooling

### PostgreSQL with GORM

```go
db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})

sqlDB, _ := db.DB()
sqlDB.SetMaxIdleConns(10)
sqlDB.SetMaxOpenConns(100)
sqlDB.SetConnMaxLifetime(time.Hour)
```

### Health Checks

```go
func (r *GormRepository) Ping() error {
    sqlDB, _ := r.db.DB()
    return sqlDB.Ping()
}
```
