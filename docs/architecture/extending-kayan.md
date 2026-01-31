# Extending Kayan

This guide shows how to extend Kayan with custom strategies, storage adapters, and integrations.

---

## Extension Points

| Extension | Interface | Use Case |
|-----------|-----------|----------|
| Auth Strategy | `RegistrationStrategy`, `LoginStrategy` | Custom auth method |
| Storage | `IdentityRepository` | Different database |
| Session | `SessionStrategy` | Custom token format |
| Authorization | `policy.Engine` | Custom policy logic |
| Tenant Resolution | `tenant.Resolver` | Custom tenant lookup |
| Hashing | `flow.Hasher` | Argon2, scrypt |

---

## Custom Authentication Strategy

### Step 1: Define Strategy Struct

```go
type EmailOTPStrategy struct {
    repo      IdentityRepository
    otpStore  OTPStore
    emailer   EmailSender
    factory   func() any
}

func NewEmailOTPStrategy(repo IdentityRepository, emailer EmailSender, factory func() any) *EmailOTPStrategy {
    return &EmailOTPStrategy{
        repo:     repo,
        otpStore: NewMemoryOTPStore(),
        emailer:  emailer,
        factory:  factory,
    }
}
```

### Step 2: Implement Interfaces

```go
// Strategy ID (used in API calls)
func (s *EmailOTPStrategy) ID() string {
    return "email_otp"
}

// Registration (optional for OTP - users auto-register on first use)
func (s *EmailOTPStrategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) {
    // Extract email from traits
    var t struct{ Email string }
    json.Unmarshal(traits, &t)
    
    // Create identity
    ident := s.factory()
    setField(ident, "Email", t.Email)
    setField(ident, "ID", uuid.New().String())
    
    if err := s.repo.CreateIdentity(ident); err != nil {
        return nil, err
    }
    
    return ident, nil
}

// Authentication
func (s *EmailOTPStrategy) Authenticate(ctx context.Context, email, otp string) (any, error) {
    // Verify OTP
    storedOTP, exists := s.otpStore.Get(email)
    if !exists || storedOTP != otp {
        return nil, ErrInvalidOTP
    }
    
    // Clear used OTP
    s.otpStore.Delete(email)
    
    // Find identity
    ident, err := s.repo.FindIdentity(s.factory, map[string]any{"email": email})
    if err != nil {
        // Auto-register on first login
        ident = s.factory()
        setField(ident, "Email", email)
        setField(ident, "ID", uuid.New().String())
        s.repo.CreateIdentity(ident)
    }
    
    return ident, nil
}
```

### Step 3: Add Custom Methods

```go
// RequestOTP sends OTP to email
func (s *EmailOTPStrategy) RequestOTP(ctx context.Context, email string) error {
    // Generate 6-digit OTP
    otp := fmt.Sprintf("%06d", rand.Intn(1000000))
    
    // Store with TTL
    s.otpStore.Set(email, otp, 10*time.Minute)
    
    // Send email
    return s.emailer.Send(email, "Your Code", fmt.Sprintf("Your login code is: %s", otp))
}
```

### Step 4: Register Strategy

```go
otpStrategy := NewEmailOTPStrategy(repo, emailer, factory)
loginManager.RegisterStrategy(otpStrategy)

// Optional: Registration flow
regManager.RegisterStrategy(otpStrategy)
```

### Step 5: HTTP Handler

```go
// Request OTP endpoint
e.POST("/auth/otp/request", func(c echo.Context) error {
    var req struct{ Email string `json:"email"` }
    c.Bind(&req)
    
    if err := otpStrategy.RequestOTP(c.Request().Context(), req.Email); err != nil {
        return c.JSON(500, map[string]string{"error": err.Error()})
    }
    
    return c.JSON(200, map[string]string{"message": "OTP sent"})
})

// Verify OTP endpoint
e.POST("/auth/otp/verify", func(c echo.Context) error {
    var req struct {
        Email string `json:"email"`
        OTP   string `json:"otp"`
    }
    c.Bind(&req)
    
    ident, err := loginManager.Authenticate(c.Request().Context(), "email_otp", req.Email, req.OTP)
    if err != nil {
        return c.JSON(401, map[string]string{"error": "Invalid OTP"})
    }
    
    // Create session...
})
```

---

## Custom Storage Adapter

### Step 1: Define Repository

```go
type DynamoDBRepository struct {
    client    *dynamodb.Client
    tableName string
}

func NewDynamoDBRepository(client *dynamodb.Client, table string) *DynamoDBRepository {
    return &DynamoDBRepository{
        client:    client,
        tableName: table,
    }
}
```

### Step 2: Implement Interface

```go
func (r *DynamoDBRepository) CreateIdentity(identity any) error {
    item, _ := attributevalue.MarshalMap(identity)
    
    _, err := r.client.PutItem(context.Background(), &dynamodb.PutItemInput{
        TableName: aws.String(r.tableName),
        Item:      item,
    })
    return err
}

func (r *DynamoDBRepository) GetIdentity(factory func() any, id any) (any, error) {
    key, _ := attributevalue.MarshalMap(map[string]any{"id": id})
    
    result, err := r.client.GetItem(context.Background(), &dynamodb.GetItemInput{
        TableName: aws.String(r.tableName),
        Key:       key,
    })
    if err != nil {
        return nil, err
    }
    
    identity := factory()
    attributevalue.UnmarshalMap(result.Item, identity)
    return identity, nil
}

func (r *DynamoDBRepository) FindIdentity(factory func() any, query map[string]any) (any, error) {
    // Build filter expression
    var conditions []string
    exprValues := map[string]types.AttributeValue{}
    exprNames := map[string]string{}
    
    i := 0
    for field, value := range query {
        placeholder := fmt.Sprintf(":v%d", i)
        namePlaceholder := fmt.Sprintf("#n%d", i)
        
        conditions = append(conditions, fmt.Sprintf("%s = %s", namePlaceholder, placeholder))
        exprValues[placeholder], _ = attributevalue.Marshal(value)
        exprNames[namePlaceholder] = field
        i++
    }
    
    result, err := r.client.Scan(context.Background(), &dynamodb.ScanInput{
        TableName:                 aws.String(r.tableName),
        FilterExpression:          aws.String(strings.Join(conditions, " AND ")),
        ExpressionAttributeValues: exprValues,
        ExpressionAttributeNames:  exprNames,
        Limit:                     aws.Int32(1),
    })
    if err != nil {
        return nil, err
    }
    
    if len(result.Items) == 0 {
        return nil, ErrNotFound
    }
    
    identity := factory()
    attributevalue.UnmarshalMap(result.Items[0], identity)
    return identity, nil
}

// ... UpdateIdentity, DeleteIdentity, ListIdentities
```

---

## Custom Session Strategy

### JWT with Custom Claims

```go
type CustomJWTStrategy struct {
    secret []byte
    expiry time.Duration
}

type CustomClaims struct {
    jwt.RegisteredClaims
    IdentityID string   `json:"uid"`
    SessionID  string   `json:"sid"`
    Roles      []string `json:"roles"`
    TenantID   string   `json:"tid,omitempty"`
}

func (s *CustomJWTStrategy) Create(sessionID, identityID string) (*session.Session, error) {
    // Lookup user to get roles (in real impl)
    claims := CustomClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.expiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
        IdentityID: identityID,
        SessionID:  sessionID,
        Roles:      []string{"user"},
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(s.secret)
    if err != nil {
        return nil, err
    }
    
    return &session.Session{
        ID:         tokenString,
        IdentityID: identityID,
        ExpiresAt:  time.Now().Add(s.expiry),
    }, nil
}

func (s *CustomJWTStrategy) Validate(tokenString string) (*session.Session, error) {
    token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
        return s.secret, nil
    })
    
    if err != nil || !token.Valid {
        return nil, ErrInvalidToken
    }
    
    claims := token.Claims.(*CustomClaims)
    return &session.Session{
        ID:         tokenString,
        IdentityID: claims.IdentityID,
        ExpiresAt:  claims.ExpiresAt.Time,
    }, nil
}
```

---

## Custom Tenant Resolver

```go
type JWTTenantResolver struct {
    secret []byte
}

func (r *JWTTenantResolver) Resolve(ctx context.Context, req *http.Request) (string, error) {
    // Extract tenant from API key JWT
    apiKey := req.Header.Get("X-API-Key")
    if apiKey == "" {
        return "", ErrNoAPIKey
    }
    
    token, err := jwt.Parse(apiKey, func(token *jwt.Token) (any, error) {
        return r.secret, nil
    })
    if err != nil {
        return "", err
    }
    
    claims := token.Claims.(jwt.MapClaims)
    tenantID, ok := claims["tenant_id"].(string)
    if !ok {
        return "", ErrNoTenantInToken
    }
    
    return tenantID, nil
}
```

---

## Custom Password Hasher

### Argon2id Implementation

```go
type Argon2Hasher struct {
    memory      uint32
    iterations  uint32
    parallelism uint8
    saltLength  uint32
    keyLength   uint32
}

func NewArgon2Hasher() *Argon2Hasher {
    return &Argon2Hasher{
        memory:      64 * 1024,  // 64 MB
        iterations:  3,
        parallelism: 2,
        saltLength:  16,
        keyLength:   32,
    }
}

func (h *Argon2Hasher) Hash(password string) (string, error) {
    salt := make([]byte, h.saltLength)
    rand.Read(salt)
    
    hash := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)
    
    // Encode: $argon2id$v=19$m=65536,t=3,p=2$salt$hash
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)
    
    return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version, h.memory, h.iterations, h.parallelism, b64Salt, b64Hash), nil
}

func (h *Argon2Hasher) Verify(password, encoded string) error {
    // Parse encoded string
    // Extract params, salt, hash
    // Re-compute hash with same params
    // Constant-time compare
    ...
}
```

Use with password strategy:

```go
hasher := NewArgon2Hasher()
pwStrategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)
```

---

## Middleware Extensions

### Custom Auth Middleware

```go
func CustomAuthMiddleware(sessManager *session.Manager, extra func(echo.Context, *session.Session) error) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            token := extractToken(c)
            
            sess, err := sessManager.Validate(token)
            if err != nil {
                return c.JSON(401, map[string]string{"error": "Unauthorized"})
            }
            
            c.Set("session", sess)
            
            // Custom logic (e.g., MFA check, tenant validation)
            if extra != nil {
                if err := extra(c, sess); err != nil {
                    return c.JSON(403, map[string]string{"error": err.Error()})
                }
            }
            
            return next(c)
        }
    }
}
```

---

## Event Hooks

### Audit Everything

```go
auditHook := func(eventType string) func(context.Context, any) error {
    return func(ctx context.Context, ident any) error {
        var userID string
        if ident != nil {
            userID = fmt.Sprintf("%v", reflect.ValueOf(ident).Elem().FieldByName("ID").Interface())
        }
        
        auditLog.Record(audit.Event{
            Type:      eventType,
            UserID:    userID,
            IP:        getIPFromContext(ctx),
            Timestamp: time.Now(),
        })
        return nil
    }
}

regManager.AddPostHook(auditHook("registration.success"))
loginManager.AddPostHook(auditHook("login.success"))
```
