# OIDC (OpenID Connect)

Kayan supports the OIDC protocol, allowing you to act as an OIDC Provider (OP) or integrate as a Relying Party (RP).

## Standard Usage: OIDC Provider (OP)

Expose your Kayan instance as a centralized identity provider for your own microservices or external partners.

### 1. Initialize the Provider
```go
keys := oidc.NewStaticKeyProvider(privateKey) // Load from PKCS8
server := oidc.NewServer(keys, sessionManager, identityRepo)

// Serve the Discovery document automatically at 
// .well-known/openid-configuration
```

### 2. Authorization Code Flow
```go
// 1. Authorize (Redirect UI)
authURL, _ := server.Authorize(ctx, clientID, "code", scope, state, "http://app.com/callback")

// 2. Exchange Code for Tokens (POST /token)
tokens, _ := server.Exchange(ctx, code, clientID, clientSecret)
// Returns: Access Token, ID Token (JWT), Refresh Token
```

---

## Custom Implementation: Custom ID Token Claims

You can inject custom application-specific claims (e.g., `subscription_plan`, `preferred_color`) into the generated OIDC ID Token.

### Example: Custom Claims Provider
```go
type MyClaimsProvider struct{}

func (p *MyClaimsProvider) Provide(ctx context.Context, ident identity.FlowIdentity) (map[string]any, error) {
    user := ident.(*User)
    return map[string]any{
        "plan": user.SubscriptionPlan,
        "org":  user.OrganizationUnit,
    }, nil
}

server.SetClaimsProvider(&MyClaimsProvider{})
```

---

## Common Mistakes

> [!CAUTION]
> **Leaking the Authorization Code**
> Authorization codes must be short-lived (usually < 5 minutes) and can only be used **once**. If a code is re-used, Kayan's `oidc.Server` will automatically invalidate all tokens issued from the original code to prevent replay attacks.

> [!WARNING]
> **Insecure Callback URLs**
> Always validate that the `redirect_uri` provided in the request matches one of the pre-registered URLs for the `client_id`. Allowing arbitrary redirect URLs is a critical security vulnerability that leads to token theft.

> [!TIP]
> **Use Discovery**
> Don't hardcode OIDC endpoints in your client applications. Instead, point them to Kayan's `.well-known/openid-configuration` endpoint. This allows you to rotate keys and change URLs without updating client configuration.
