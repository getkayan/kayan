# Configuration Reference

This page documents the configuration surfaces that exist directly in the repository. Many deployments will wrap these values inside a broader host application configuration system.

## core/config

`core/config.LoadConfig()` currently supports these environment variables:

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `DB_TYPE` | string | `sqlite` | Selects the primary database type |
| `DSN` | string | `kayan.db` | Connection string or database DSN |
| `SKIP_AUTO_MIGRATE` | bool | `false` | Disables adapter-driven automatic migrations |
| `LOG_LEVEL` | string | `info` | Logging verbosity |

OIDC providers are also loaded into the `OIDC_PROVIDERS` map using keys shaped like:

```text
OIDC_PROVIDERS_GOOGLE_ISSUER=https://accounts.google.com
OIDC_PROVIDERS_GOOGLE_CLIENT_ID=...
OIDC_PROVIDERS_GOOGLE_CLIENT_SECRET=...
OIDC_PROVIDERS_GOOGLE_REDIRECT_URL=https://app.example.com/callback
```

## Session Configuration

`core/session.JWTConfig` is code-driven, not environment-driven by default. You configure:

- signing method
- signing key
- verifying key
- access-token expiry
- refresh-token signing configuration
- refresh-token expiry
- optional refresh-token validator

Keep this configuration near your secret-loading layer so keys are never hardcoded.

## Telemetry Configuration

`core/telemetry.Config` includes:

- `ServiceName`
- `ServiceVersion`
- `Environment`
- `OTLPEndpoint`
- `InsecureOTLP`
- `SamplingRate`
- `Enabled`

Use `InsecureOTLP` only for local development or explicitly trusted internal environments.

## Health Configuration

`core/health.NewManager(version, opts...)` currently supports timeout customization through `health.WithTimeout`. Keep this timeout low enough that readiness checks do not pile up under incident conditions.

## Tenant Configuration

`core/tenant` is configured in code through resolver choice and options such as:

- `WithDefaultTenant`
- `WithOptionalTenant`
- `WithLightweight`
- `WithHooks`

Treat resolver choice as part of your external API contract. Changing from header to subdomain resolution is a breaking operational change.

## Consent and Compliance Configuration

These packages are mostly configured in code through manager options and policy structs. Keep policy versions, retention windows, and essential-purpose definitions under change control alongside your privacy or security documentation.