# SCIM 2.0 (Automated Provisioning)

Kayan implements the SCIM 2.0 protocol (RFC 7644) to automate the management of users and groups from external systems like Okta, Azure AD, or Workday.

## Standard Usage: Provisioning Setup

### 1. Initialize the SCIM Manager
```go
config := scim.MapperConfig{
    // Map SCIM 'userName' to internal 'Email' field
    FieldMappings: map[string]string{"userName": "Email"},
}
mapper := scim.NewMapper(userFactory, nil, config)
manager := scim.NewManager(scimStorage, mapper)
```

### 2. Handling Requests
```go
// Create a user from incoming SCIM JSON
user, err := manager.CreateUser(ctx, &scim.User{
    UserName: "bob@example.com",
    Active:   true,
    Emails:   []scim.Email{{Value: "bob@example.com", Primary: true}},
})

// Search users using a SCIM filter
list, err := manager.ListUsers(ctx, `userName eq "bob@example.com"`, 1, 10)
```

---

## Custom Implementation: External Provisioning System

By default, SCIM operations go through the `ScimStorage` interface. You can implement this to proxy SCIM requests to a legacy system that doesn't support SCIM natively.

### Example: Custom Legacy SCIM Proxy
```go
type LegacyScimStorage struct {
    legacyApi *LegacyClient
}

func (s *LegacyScimStorage) CreateScimUser(ctx context.Context, u *scim.User) error {
    // Convert SCIM User to Legacy API format and Save
    return s.legacyApi.CreateUser(u.UserName, u.Active)
}

func (s *LegacyScimStorage) ListScimUsers(ctx context.Context, filter scim.Filter, start, count int) ([]*scim.User, int, error) {
    // 1. Traverse the 'filter' tree (e.g., userName eq "...")
    // 2. Map it to Legacy API query parameters
    return nil, 0, nil
}
```

---

## Common Mistakes

> [!CAUTION]
> **Inefficient Filter Processing**
> SCIM filters like `emails[type eq "work" and value sw "admin"]` can be complex. If you implement a custom storage, avoid processing these in-memory. Instead, use the `filter.Visit(visitor)` pattern to convert the SCIM filter directly into a SQL `WHERE` clause.

> [!WARNING]
> **Naming Conflicts**
> SCIM `userName` and `id` are distinct. `id` must be stable even if the `userName` (e.g., email) changes. If you use email as the ID, a user changing their email will break the SCIM sync from the IdP. Always use a UUID or internal surrogate key for the SCIM `id`.

> [!TIP]
> **Discovery is Mandatory**
> Most enterprise IdPs require a `/ServiceProviderConfig` endpoint to be available for automated setup. Ensure your SCIM server exposes the schema and resource type endpoints provided by Kayan.
