# Capability and Stability Matrix

Kayan is pre-1.0. This page is the source of truth for what the project supports
today and what must be proven before an API is declared stable.

Kayan is a headless library. It requires no database, ORM, cache, HTTP framework,
UI, or server runtime. `kayan-gorm` and `kayan-redis` are optional reference
adapters; applications may implement the consumer-defined interfaces instead.

Package-level freeze status and remaining evidence gates are tracked in the
[API stability map](api-stability.md).

## Current capabilities

| Area | Status | Notes |
|---|---|---|
| Identity contracts and BYOS | Release candidate | Arbitrary models and ID types through `FlowIdentity`, `any`, and factories |
| Password, OTP, TOTP, magic link, API key, recovery | Release candidate | Transient credentials have an atomic single-use storage contract; OTP codes are bound to the account they were issued to and `PasswordAuth` installs lockout by default; external review remains required |
| WebAuthn and social/OIDC login | Experimental | Security-sensitive multi-step flows are still being hardened |
| JWT and database sessions | Release candidate | Revocation is keyed on the session id, so logout also ends the refresh token, and `Delete` errors rather than reporting a logout it cannot perform; SSO has transport-neutral contracts plus optional GORM and Redis adapters; multi-node operation remains experimental |
| RBAC, ABAC, hybrid policy | Release candidate | ReBAC object enumeration remains incomplete |
| OAuth 2.0 and OIDC provider | Experimental | Authorization code uses PKCE; UserInfo, RP-initiated logout, and the `at_hash`/`c_hash` bindings are implemented; access tokens are signed and introspected through the key provider, so rotation applies to them; protocol audit persistence has an explicit failure callback; formal certification remains pending |
| SAML 2.0 | Experimental | Encrypted assertions are supported with RSA-OAEP key transport and AES-GCM content encryption; rsa-1_5 and CBC modes are refused. Single logout covers SP-initiated requests and verified inbound ones. Metadata generation emits key descriptors, endpoints, and NameID formats. Metadata retrieval is injectable, bounded, and public-HTTPS-only by default; interoperability evidence remains pending |
| SCIM 2.0 | Experimental | Discovery, value-path parsing, and filtered PATCH sub-attributes are implemented, including group-membership PATCH in the shapes Okta and Entra send; storage adapters may explicitly reject multi-valued shapes they cannot represent |
| GORM and Redis adapters | Experimental, optional | GORM passes the shared storage suite; CI exercises concurrent atomicity on real PostgreSQL/MySQL and SSO lifecycle/concurrency on real Redis |
| CLI | Experimental | Its remote administration API is not part of the stable library contract |

## Observability

Kayan emits domain events through `core/events`, which `core/flow` already
dispatches for login, registration, MFA challenges, session lifecycle, lockout,
and rate limiting. That is the instrumentation seam: subscribe to it and route
events wherever the deployment already sends telemetry.

The optional `kayan-observability` module provides an OpenTelemetry
implementation. `telemetry.Subscribe(dispatcher, provider)` connects a provider
to those events, giving login, MFA, session, and throttling metrics without
`core` importing OpenTelemetry -- the whole SDK stays out of the build for
deployments that do not ask for it.

Kayan writes nothing to stdout or stderr. A headless library cannot know where
a host wants its logs, and a log line the caller cannot intercept is not
observability.

## Multi-tenancy

Tenant isolation in `kayan-gorm` covers identities, credentials, sessions,
auth tokens, audit events, devices, MFA enrolments, role assignments, and SSO
sessions. Isolation is applied by GORM callbacks, so it must be installed with
`gormstore.RegisterTenantIsolation(db)`; without that call the callbacks are
absent and queries run unscoped.

One boundary is inherent to BYOS and cannot be closed from the adapter side.
`GetIdentity` and `FindIdentity` query the caller's own identity struct, so a
multi-tenant deployment must implement `tenant.Scoped` on that struct. A model
that does not is invisible to the isolation callbacks and is read across
tenants. The library does not own the type and cannot add the field to it.

## Deferred beyond 1.0

The first stable release does not include OAuth device authorization, token
exchange, DPoP, dynamic client registration, or SCIM bulk.
Unsupported capabilities must not be advertised by discovery metadata.

`private_key_jwt` is implemented. `client_secret_jwt` is not, and will not be:
signing an assertion with the client secret requires the provider to hold that
secret in a recoverable form, and Kayan stores only a one-way hash.
Discovery derives `token_endpoint_auth_methods_supported` from the provider's
configuration through `oidc.WithClientAuthMethods`, so a deployment without a
`ClientAssertionStore` does not advertise a method it would refuse.

## The 1.0 gate

A capability becomes stable only after its public contract is frozen, unit and
race tests pass, relevant integration and conformance suites pass, documentation
examples compile, and critical or high findings from the independent security
review are resolved. Compliance helpers are not claims of SOC 2, ISO 27001,
GDPR, or CCPA certification.
