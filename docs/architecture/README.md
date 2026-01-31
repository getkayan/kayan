# Kayan Architecture

Kayan is a **headless, non-generic, and highly extensible authentication service** built for Go applications.

## System Overview

```mermaid
graph TB
    subgraph Clients
        Web[Web App]
        Mobile[Mobile App]
        API[API Consumer]
    end
    
    subgraph "Kayan Core"
        Gateway[API Gateway / Router]
        
        subgraph "Authentication Flows"
            Reg[Registration Manager]
            Login[Login Manager]
            Session[Session Manager]
        end
        
        subgraph "Auth Strategies"
            Password[Password Strategy]
            OIDC[OIDC Strategy]
            WebAuthn[WebAuthn Strategy]
            SAML[SAML SP/IdP]
            Magic[Magic Link]
            TOTP[TOTP MFA]
        end
        
        subgraph "Authorization"
            RBAC[RBAC Engine]
            ABAC[ABAC Engine]
            Policy[Hybrid Policy]
        end
        
        subgraph "Security"
            RateLimit[Rate Limiter]
            Lockout[Account Lockout]
            Audit[Audit Logger]
        end
    end
    
    subgraph Storage
        DB[(Database)]
        Cache[(Redis)]
    end
    
    subgraph "External IdPs"
        Google[Google]
        GitHub[GitHub]
        SAMLP[SAML IdP]
    end
    
    Web --> Gateway
    Mobile --> Gateway
    API --> Gateway
    
    Gateway --> Reg
    Gateway --> Login
    Gateway --> Session
    
    Login --> Password
    Login --> OIDC
    Login --> WebAuthn
    Login --> SAML
    Login --> Magic
    
    Password --> RateLimit
    Password --> Lockout
    
    OIDC --> Google
    OIDC --> GitHub
    SAML --> SAMLP
    
    Reg --> DB
    Session --> DB
    Session --> Cache
    Audit --> DB
    RateLimit --> Cache
```

## Core Components

### 1. Identity Model

Kayan uses a **non-generic architecture** with the `any` interface, allowing any ID type:

```go
type FlowIdentity interface {
    GetID() any
    SetID(id any)
}
```

### 2. Authentication Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `PasswordStrategy` | Bcrypt-based password auth | Traditional login |
| `OIDCStrategy` | OpenID Connect social login | Google, GitHub, etc. |
| `WebAuthnStrategy` | Passkeys/FIDO2 | Passwordless, MFA |
| `SAMLStrategy` | SAML 2.0 SP/IdP | Enterprise SSO |
| `MagicLinkStrategy` | Email-based login | Passwordless |
| `TOTPStrategy` | Time-based OTP | MFA |

### 3. Security Decorators

Strategies can be wrapped with security decorators:

```
LoginStrategy
     │
     ▼
 RateLimitStrategy (decorator)
     │
     ▼
 LockoutStrategy (decorator)
     │
     ▼
 PasswordStrategy (actual implementation)
```

### 4. Session Management

Two session strategies:
- **DatabaseStrategy** - Opaque tokens stored in DB
- **JWTStrategy** - Stateless JWT tokens

### 5. Authorization

| Model | File | Description |
|-------|------|-------------|
| RBAC | `policy/rbac.go` | Role-based access control |
| ABAC | `policy/abac.go` | Attribute-based access control |
| Hybrid | `policy/hybrid.go` | Combine multiple engines |

---

## Data Flow

### Registration Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant K as Kayan
    participant S as Strategy
    participant DB as Database
    
    C->>K: POST /api/v1/registration
    K->>K: Validate traits
    K->>S: Register(traits, password)
    S->>S: Hash password
    S->>S: Generate ID
    S->>DB: Create identity
    DB-->>S: Identity created
    S-->>K: Identity
    K->>K: Create session (optional)
    K-->>C: 201 + session token
```

### Login Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant RL as RateLimiter
    participant LO as Lockout
    participant S as Strategy
    participant DB as Database
    
    C->>RL: POST /api/v1/login
    RL->>RL: Check rate limit
    alt Rate limited
        RL-->>C: 429 Too Many Requests
    end
    RL->>LO: Forward request
    LO->>LO: Check lockout status
    alt Account locked
        LO-->>C: 423 Locked
    end
    LO->>S: Authenticate(identifier, password)
    S->>DB: Find by identifier
    DB-->>S: Identity + hash
    S->>S: Verify password
    alt Invalid credentials
        S-->>LO: Error
        LO->>LO: Record failure
        LO-->>C: 401 Unauthorized
    end
    S-->>LO: Success
    LO->>LO: Clear failures
    LO-->>C: 200 + session
```

---

## Multi-Tenancy

Kayan supports full multi-tenancy with tenant isolation:

```mermaid
graph LR
    subgraph "Request"
        R[HTTP Request]
    end
    
    subgraph "Resolution"
        H[Header: X-Tenant-ID]
        D[Domain-based]
        P[Path-based]
    end
    
    subgraph "Context"
        CTX[Context with Tenant]
    end
    
    subgraph "Scoped Operations"
        Storage[Tenant-Scoped Storage]
        Policies[Tenant Policies]
        Config[Tenant Config]
    end
    
    R --> H
    R --> D
    R --> P
    H --> CTX
    D --> CTX
    P --> CTX
    CTX --> Storage
    CTX --> Policies
    CTX --> Config
```

---

## Storage Architecture

### Repository Pattern

```go
type IdentityRepository interface {
    Create(ctx context.Context, identity any) error
    FindByIdentifier(ctx context.Context, identifier string) (any, error)
    FindByID(ctx context.Context, id any) (any, error)
    Update(ctx context.Context, identity any) error
    Delete(ctx context.Context, id any) error
}
```

### GORM Implementation

The `kgorm` package provides GORM-based implementations:

- `IdentityRepository` - User storage
- `SessionRepository` - Session storage
- `OAuth2Repository` - OAuth2 client/token storage

---

## Deployment Patterns

### Single Instance

```
┌─────────────────────────────┐
│         Kayan Server        │
│  ┌───────────────────────┐  │
│  │    All Components     │  │
│  └───────────────────────┘  │
│             │               │
│  ┌──────────┴──────────┐    │
│  ▼                     ▼    │
│ [PostgreSQL]       [Redis]  │
└─────────────────────────────┘
```

### High Availability

```
         ┌─────────────────┐
         │  Load Balancer  │
         └────────┬────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌───────┐    ┌───────┐    ┌───────┐
│Kayan 1│    │Kayan 2│    │Kayan 3│
└───┬───┘    └───┬───┘    └───┬───┘
    │            │            │
    └────────────┼────────────┘
                 │
    ┌────────────┴────────────┐
    ▼                         ▼
┌─────────────┐       ┌──────────────┐
│ PostgreSQL  │       │ Redis Cluster│
│  Primary    │       │              │
│     │       │       └──────────────┘
│   Replica   │
└─────────────┘
```

---

## Security Model

### Defense in Depth

1. **Network Layer** - TLS, firewall rules
2. **Rate Limiting** - Per-IP, per-user limits
3. **Account Lockout** - Brute force protection
4. **Password Hashing** - Bcrypt with configurable cost
5. **Session Security** - Rotation, expiry, revocation
6. **Audit Logging** - All security events logged

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Brute Force | Rate limiting + Account lockout |
| Credential Stuffing | Rate limiting + breach detection hooks |
| Session Hijacking | Secure cookies, rotation, binding |
| CSRF | Double-submit cookies, SameSite |
| Token Leakage | Short-lived tokens, refresh rotation |
