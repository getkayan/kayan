# OAuth 2.0 and OpenID Connect

Kayan splits token issuance and OIDC identity assertions into two packages:

- `core/oauth2` for authorization codes, access tokens, refresh tokens, introspection, and revocation
- `core/oidc` for ID tokens, discovery metadata, JWKS-oriented integration, and logout helpers

## OAuth 2.0 Provider

The provider constructor is:

```go
provider := oauth2.NewProvider(
	clientStore,
	authCodeStore,
	refreshTokenStore,
	"https://auth.example.com",
	privateKey,
	"kid-1",
)
```

Main responsibilities:

- generate authorization codes
- exchange codes for access and refresh tokens
- refresh access tokens with refresh-token rotation
- validate client credentials
- introspect tokens
- optionally track revocation

## PKCE

PKCE is supported during authorization-code exchange. Public clients should use a `code_verifier` and `S256` challenge by default.

## Token Storage Model

The provider depends on store interfaces instead of a monolithic repository. That lets you place auth codes, refresh tokens, and clients in the storage backend that matches your deployment.

Use cases:

- relational database for client metadata
- Redis for short-lived auth codes
- shared durable storage for refresh tokens

## OIDC Server

The OIDC server is initialized independently:

```go
server := oidc.NewServer("https://auth.example.com", privateKey, "kid-1")
```

Responsibilities:

- generate ID tokens
- publish discovery metadata
- support userinfo-oriented integrations
- surface logout and end-session metadata

The package is intentionally focused on protocol artifacts. Your application still owns the actual HTTP handlers and endpoint routing.

## Recommended Handler Split

- handler layer parses requests and authenticates clients
- `oauth2.Provider` handles code, token, refresh, revocation, and introspection behavior
- `oidc.Server` handles discovery, ID token generation, and metadata documents
- your app decides how userinfo claims are assembled from your identity model

## Claims Strategy

Keep claims deliberate. The default OIDC token path can include traits, but in production you should define exactly which identity fields and traits are safe and stable enough to expose to clients.

## Key Management Guidance

- prefer RSA or ECDSA keys managed outside source control
- assign stable `kid` values and rotate keys deliberately
- keep verifying keys available to resource servers and discovery clients
- test introspection and token verification during rotation windows

## Interaction with Other Packages

- `core/flow/oidc.go` helps integrate external OIDC providers into auth flows
- `core/session` may still be used for your application sessions even if OAuth 2.0 is enabled
- `core/audit` should receive token-issue and token-revocation events for regulated deployments