# SAML 2.0 (Service Provider & IdP)

Kayan provides a robust SAML 2.0 implementation for enterprise Single Sign-On (SSO). It can act as both a **Service Provider (SP)** and an **Identity Provider (IdP)**.

## Standard Usage: Service Provider (SP)

Integrating with enterprise IdPs like Okta, Azure AD, or Ping Identity.

### 1. Initialize the Service Provider
```go
config := saml.SPConfig{
    EntityID: "https://myapp.com/saml/metadata",
    ACSURL:   "https://myapp.com/saml/acs",
}
sp := saml.NewServiceProvider(config, sessionStore, identityRepo, userFactory)

// Register an external IdP (e.g., Okta)
sp.RegisterIdP(&saml.IdPConfig{
    ID:       "okta",
    EntityID: "https://okta.example.com/xxxx",
    SSOUrl:   "https://okta.example.com/sso",
})
```

### 2. The SSO Flow
```go
// 1. Initiate Login (Redirect user to Okta)
redirectURL, _ := sp.InitiateLogin(ctx, "okta", "/dashboard")

// 2. Handle Callback (In your ACS HTTP handler)
user, relayState, err := sp.ProcessResponse(ctx, samlResponse)
```

---

## Custom Implementation: Attribute Mapping

IdPs often send custom XML attributes. You can implement a custom `UserFactory` to map these to your internal user model.

### Example: Custom Attribute Mapper
```go
hooks := saml.Hooks{
    UserFactory: func(ctx context.Context, sUser *saml.SAMLUser) (identity.FlowIdentity, error) {
        // Map custom SAML attributes to your User struct
        return &User{
            Email:      sUser.GetAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
            Department: sUser.GetAttribute("department"),
            MemberID:   sUser.GetAttribute("custom_member_id"),
        }, nil
    },
}
sp.SetHooks(hooks)
```

---

## Common Mistakes

> [!CAUTION]
> **Expired Certificates**
> SAML relies on certificates for signing. Always monitor the expiration dates of both your SP certificate and the IdP certificates. Kayan provides `sp.ValidateCertificates()` which you should run periodically in a health check.

> [!WARNING]
> **Clock Skew**
> SAML responses are time-sensitive. If your server's clock is out of sync with the IdP's clock, all login attempts will fail with a "not yet valid" or "expired" error. Use NTP to keep your server time accurate within seconds.

> [!TIP]
> **Allow IdP-Initiated SSO**
> By default, Kayan blocks IdP-initiated SSO for security (to prevent login CSRF). If your customers need to log in directly from their Okta dashboard, you must explicitly enable `AllowIdPInitiated: true` in the `SPConfig`.
