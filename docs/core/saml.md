# SAML 2.0

`core/saml` implements service-provider-side SAML 2.0 support for enterprise SSO scenarios.

## What the Package Owns

- service-provider configuration
- IdP registration and metadata loading
- AuthnRequest generation
- response parsing and validation hooks
- pending login session tracking
- attribute extraction and user reconciliation hooks
- SP metadata generation

## Basic Setup

```go
sp := saml.NewServiceProvider(
	saml.Config{
		EntityID:     "https://app.example.com/saml",
		ACSUrl:       "https://app.example.com/saml/acs",
		MetadataURL:  "https://app.example.com/saml/metadata",
		PrivateKey:   privateKey,
		Certificate:  certificate,
		SignRequests: true,
	},
	sessionStore,
	identityRepo,
	func() any { return &User{} },
)
```

Register IdPs separately so one service provider can support multiple tenants or enterprise customers.

## IdP Configuration

Each `IdPConfig` captures:

- IdP identifier
- entity ID
- SSO and optional SLO URLs
- IdP signing certificate
- preferred NameID format
- attribute mapping
- optional tenant association

This lets your application map enterprise identity providers to tenant or customer boundaries cleanly.

## Sessions and Relay State

SAML login is not a single request. The package persists pending session state so that:

- requests can be matched to responses
- relay state can be validated and restored
- login attempts can expire cleanly

Treat the session store as part of the security boundary. It should not be ephemeral in multi-instance production.

## Hooks

Hooks exist around the key lifecycle points:

- before request creation
- after request creation
- before response processing
- after successful response processing
- error handling
- custom user creation, loading, and linking

This is where you integrate application-specific reconciliation logic without modifying the protocol parser itself.

## User Reconciliation

Most SAML deployments need deterministic rules for matching an incoming SAML identity to an internal account. Use the provided hooks to define whether matching is based on:

- NameID
- email
- immutable external employee ID
- tenant-scoped identifier

Be explicit here. Ambiguous linking is one of the highest-risk parts of SAML integration.

## Security Guidance

- sign requests when your IdP requires or benefits from it
- validate certificates and metadata provenance
- treat IdP-initiated SSO as an explicit security decision
- keep assertion and relay-state lifetimes short
- audit all SAML login and linking outcomes